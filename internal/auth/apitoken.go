package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Токены API (ИАФ.9; задача 2.10). Токен — aisec_pat_<id>_<секрет>, где
// id — 8 символов [a-z0-9], секрет — 32 случайных байта в base64url без
// выравнивания. В БД — только префикс aisec_pat_<id> (поиск и показ) и хеш
// профиля всего токена; сравнение за постоянное время. Токен действует от
// имени владельца: его права — пересечение области токена с текущими
// правами роли владельца (TokenGrants). Выпускает токен только сам
// владелец из сессии консоли; токену недоступны свои данные (self,
// session), функции безопасности и сами токены (TokenGrantable).
const (
	apiTokenScheme = "aisec_pat_"
	// APITokenDefaultDays — срок по умолчанию; срок обязателен.
	APITokenDefaultDays = 90
	APITokenMaxDays     = 365
	// MaxAPITokensPerUser — предел действующих (не отозванных и не
	// истёкших) токенов пользователя.
	MaxAPITokensPerUser = 20
	// apiTokenTouch — как часто отмечается использование токена.
	apiTokenTouch = time.Minute
)

// Причины отзыва токена API; те же — в CHECK миграции.
const (
	APITokenRevokedByOwner = "owner"
	APITokenRevokedByAdmin = "admin"
	// APITokenRevokedByPasswordReset — пароль владельца сброшен администратором (В8 ревью 2.r2).
	APITokenRevokedByPasswordReset = "password_reset"
	// APITokenRevokedBySessions — администратор завершил сессии владельца с отзывом токенов.
	APITokenRevokedBySessions = "sessions_revoked"
	// APITokenRevokedByBackupRestore — токен восстановлен из резервной копии
	// отозванным (В21 ревью 2.r4); автора отзыва нет.
	APITokenRevokedByBackupRestore = "backup_restore"
)

// reasonOwnerInactive — владелец токена деактивирован (api_token.auth_failed).
const reasonOwnerInactive = "owner_inactive"

var apiTokenRe = regexp.MustCompile(`^aisec_pat_([a-z0-9]{8})_([A-Za-z0-9_-]{43})$`)

// Ошибки токенов API.
var (
	ErrMalformedAPIToken = errors.New("токен API: неверный формат")
	ErrAPITokenNotFound  = errors.New("токен API не найден")
	ErrAPITokenRevoked   = errors.New("токен API уже отозван")
	ErrTooManyAPITokens  = errors.New("слишком много действующих токенов API")
)

// APIToken — сохранённый токен API. Секрета в нём нет.
type APIToken struct {
	ID     string
	OrgID  string
	UserID string
	Name   string
	// Prefix — aisec_pat_<id>: не секрет, по нему токен ищется и показывается.
	Prefix string
	// Hash — хеш профиля всего токена; HashAlg — имя алгоритма.
	Hash    []byte
	HashAlg string
	// Grants — область токена, заданная при выпуске; не меняется.
	Grants     Grants
	ExpiresAt  time.Time
	CreatedAt  time.Time
	LastUsedAt time.Time // нулевое — не использовался
	LastUsedIP netip.Addr
	RevokedAt  time.Time // нулевое — не отозван
	RevokedBy  string
	// RevokeReason — APITokenRevokedBy*.
	RevokeReason string
}

// Revoked — токен отозван.
func (t APIToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// Active — токен действует в момент now: не отозван и не истёк.
func (t APIToken) Active(now time.Time) bool { return !t.Revoked() && now.Before(t.ExpiresAt) }

func (t APIToken) actor(owner User) audit.Actor {
	return audit.Actor{Type: audit.ActorAPIToken, ID: t.ID, Name: owner.Login + " (" + t.Prefix + ")"}
}

func apiTokenObject(id string) audit.Object { return audit.Object{Type: "api_token", ID: id} }

// newAPIToken выпускает токен: строка для клиента (показывается один раз) и префикс.
func newAPIToken(rnd aisecCrypto.Random) (token, prefix string, err error) {
	idRaw, err := aisecCrypto.RandomBytes(rnd, keyIDLen)
	if err != nil {
		return "", "", err
	}
	var id strings.Builder
	for _, b := range idRaw {
		// Смещение остатка для идентификатора несущественно: он не секрет.
		id.WriteByte(keyIDAlphabet[int(b)%len(keyIDAlphabet)])
	}
	secret, err := aisecCrypto.RandomBytes(rnd, tokenBytes)
	if err != nil {
		return "", "", err
	}
	prefix = apiTokenScheme + id.String()
	return prefix + "_" + base64.RawURLEncoding.EncodeToString(secret), prefix, nil
}

// ParseAPIToken проверяет формат предъявленного токена и возвращает его
// префикс. Секрет не возвращается и не попадает в ошибки.
func ParseAPIToken(s string) (prefix string, err error) {
	if len(s) > MaxKeyLen {
		return "", ErrMalformedAPIToken
	}
	m := apiTokenRe.FindStringSubmatch(s)
	if m == nil {
		return "", ErrMalformedAPIToken
	}
	// Секрет — каноничный base64url ровно 32 байт: иначе у одного токена
	// было бы несколько записей.
	b, err := base64.RawURLEncoding.Strict().DecodeString(m[2])
	if err != nil || len(b) != tokenBytes {
		return "", ErrMalformedAPIToken
	}
	return apiTokenScheme + m[1], nil
}

// TokenGrants — права запроса по токену: разрешения области токена
// tokenGrants, которые можно давать токену и которые есть у роли
// владельца role, с меньшей из двух областей. Понижение роли сразу
// сужает токен.
func TokenGrants(tokenGrants, role Grants) Grants {
	out := Grants{}
	for p, sc := range tokenGrants {
		if !TokenGrantable(p) {
			continue
		}
		if rs := role.Scope(p); rs != ScopeNone && sc != ScopeNone {
			out[p] = min(sc, rs)
		}
	}
	return out
}

// APITokenStore — хранилище токенов API. Рабочая реализация — PGAPITokens;
// для тестов без PostgreSQL — authtest.Memory.
type APITokenStore interface {
	// CreateAPIToken в одной транзакции блокирует строку владельца,
	// перечитывает его роль и статус (Actor), передаёт их в fn и сохраняет
	// токен с записью аудита от fn. MaxAPITokensPerUser действующих —
	// ErrTooManyAPITokens.
	CreateAPIToken(ctx context.Context, t APIToken, fn func(owner Actor) (audit.Entry, error)) error
	// APITokenByPrefix — токен и его владелец; нет — ErrNotFound.
	APITokenByPrefix(ctx context.Context, prefix string) (APIToken, User, error)
	// APITokenByID — токен организации; нет — ErrAPITokenNotFound.
	APITokenByID(ctx context.Context, orgID, id string) (APIToken, error)
	// ListAPITokens — токены по (CreatedAt, ID) строго после курсора;
	// userID пусто — всех пользователей организации.
	ListAPITokens(ctx context.Context, orgID, userID string, after *UserCursor, limit int) ([]APIToken, error)
	// TouchAPIToken отмечает использование не отозванного токена.
	TouchAPIToken(ctx context.Context, id string, now time.Time, ip netip.Addr) error
	// RevokeAPIToken блокирует токен, передаёт его и владельца в fn (fn
	// проверяет права и возвращает причину отзыва и запись аудита) и
	// отмечает отзыв. Нет токена — ErrAPITokenNotFound.
	RevokeAPIToken(ctx context.Context, orgID, id, byID string, now time.Time,
		fn func(t APIToken, owner User) (reason string, rec audit.Entry, err error)) (APIToken, error)
}

// WithAPITokenStore подключает токены API; без него токены не выпускаются
// и не принимаются.
func WithAPITokenStore(ts APITokenStore) Option { return func(s *Service) { s.tokens = ts } }

var errNoTokenStore = errors.New("токены API: хранилище не подключено")

// APITokenInput — выпуск токена.
type APITokenInput struct {
	Name string
	// ExpiresInDays — срок в днях, 1–365; ноль — APITokenDefaultDays.
	ExpiresInDays int
	Permissions   []GrantInput
	// Password или Code — повторная проверка владельца сессии (ровно одно
	// из двух; код TOTP — при подключённом факторе): чужая оставленная
	// сессия не выпустит долгоживущий токен (В8 ревью 2.r2).
	Password string
	Code     string
}

const (
	patNameRule  = "Название: от 1 до 200 символов без управляющих символов."
	patDaysRule  = "Срок: от 1 до 365 дней."
	patPermsRule = "Разрешения: "
)

// parseAPITokenGrants проверяет область токена: хотя бы одно разрешение,
// только TokenGrantable, область own — только у Ownable.
func parseAPITokenGrants(in []GrantInput) (Grants, error) {
	if len(in) == 0 {
		return nil, &InputError{"permissions", patPermsRule + "укажите хотя бы одно."}
	}
	if len(in) > len(permissionCatalog) {
		return nil, &InputError{"permissions", patPermsRule + "повторяются."}
	}
	g := make(Grants, len(in))
	for _, gi := range in {
		p, ok := LookupPermission(gi.Permission)
		if !ok {
			return nil, &InputError{"permissions", patPermsRule + "неизвестное разрешение."}
		}
		if !TokenGrantable(p.Name) {
			return nil, &InputError{"permissions", patPermsRule + "«" + p.Name +
				"» токену не выдаётся: функции безопасности и токены — только из консоли."}
		}
		scope := ScopeAll
		if gi.Scope != "" {
			if scope, ok = ParseScope(gi.Scope); !ok {
				return nil, &InputError{"permissions", patPermsRule + "область — all или own."}
			}
		}
		if scope == ScopeOwn && !p.Ownable {
			return nil, &InputError{"permissions", patPermsRule + "«" + p.Name + "» выдаётся только на все объекты."}
		}
		if _, dup := g[p.Name]; dup {
			return nil, &InputError{"permissions", patPermsRule + "повторяются."}
		}
		g[p.Name] = scope
	}
	return g, nil
}

// grantList — разрешения с областью для подробностей аудита.
func grantList(g Grants) []string {
	out := make([]string, 0, len(g))
	for _, p := range g.Names() {
		out = append(out, p+":"+g.Scope(p).String())
	}
	return out
}

// CreateAPIToken выпускает токен пользователю by (ИАФ.9). Выпускает только
// сессия консоли: токен токенов не выпускает. Область токена должна
// входить в права пользователя (УПД.2). Возвращает сам токен —
// единственный раз; ни в журналы, ни в БД он не попадает.
func (s *Service) CreateAPIToken(ctx context.Context, by Caller, in APITokenInput) (APIToken, string, error) {
	if s.tokens == nil {
		return APIToken{}, "", errNoTokenStore
	}
	name, ok := CleanDisplayName(in.Name)
	if !ok {
		return APIToken{}, "", &InputError{"name", patNameRule}
	}
	days := in.ExpiresInDays
	if days == 0 {
		days = APITokenDefaultDays
	}
	if days < 1 || days > APITokenMaxDays {
		return APIToken{}, "", &InputError{"expires_in_days", patDaysRule}
	}
	g, err := parseAPITokenGrants(in.Permissions)
	if err != nil {
		return APIToken{}, "", err
	}
	if by.Token != nil {
		return APIToken{}, "", s.denied(ctx, by, "api_token.create", audit.Object{Type: "api_token"}, ErrEscalation)
	}
	if err := s.reauthenticate(ctx, by, in.Password, in.Code, "api_token.create"); err != nil {
		return APIToken{}, "", err
	}
	now := s.clock()
	raw, prefix, err := newAPIToken(s.random)
	if err != nil {
		return APIToken{}, "", err
	}
	id, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return APIToken{}, "", err
	}
	t := APIToken{
		ID: string(id), OrgID: s.orgID, UserID: by.User.ID, Name: name, Prefix: prefix,
		Hash: s.hasher.Sum([]byte(raw)), HashAlg: s.hasher.Name(), Grants: g,
		ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour), CreatedAt: now,
	}
	obj := apiTokenObject(t.ID)
	var deny error
	err = s.tokens.CreateAPIToken(ctx, t, func(a Actor) (audit.Entry, error) {
		mine := SessionGrants(by, a.Role.Grants)
		if !a.Active || !mine.Allows(PermAPITokensManage) || !mine.Covers(g) {
			deny = ErrEscalation
			return audit.Entry{}, deny
		}
		return s.entry(by.actor(), by.SourceIP, "api_token.create", obj, audit.ResultSuccess, map[string]any{
			"name": name, "prefix": prefix, "expires_at": t.ExpiresAt.Format(time.RFC3339), "permissions": grantList(g)}), nil
	})
	if deny != nil {
		return APIToken{}, "", s.denied(ctx, by, "api_token.create", obj, deny)
	}
	if err != nil {
		return APIToken{}, "", err
	}
	return t, raw, nil
}

// AuthenticateAPIToken проверяет токен из заголовка Authorization: Bearer.
// Сначала сравнивается хеш и только потом — отзыв, срок и владелец: без
// секрета по причине отказа не узнать, что префикс существует. Любой
// отказ — ErrUnauthenticated и запись api_token.auth_failed с префиксом и
// причиной (секрет не пишется).
func (s *Service) AuthenticateAPIToken(ctx context.Context, raw string, ip netip.Addr) (Caller, error) {
	if s.tokens == nil {
		return Caller{}, ErrUnauthenticated
	}
	prefix, err := ParseAPIToken(raw)
	if err != nil {
		return Caller{}, s.tokenFailed(ctx, nil, User{}, "", ReasonMalformed, ip)
	}
	sum := s.hasher.Sum([]byte(raw))
	t, u, err := s.tokens.APITokenByPrefix(ctx, prefix)
	if errors.Is(err, ErrNotFound) {
		// Сравнение с пустым хешем той же длины: работа та же, что у найденного.
		aisecCrypto.Equal(sum, make([]byte, len(sum)))
		return Caller{}, s.tokenFailed(ctx, nil, User{}, prefix, ReasonInvalid, ip)
	}
	if err != nil {
		return Caller{}, err
	}
	now := s.clock()
	match := aisecCrypto.Equal(sum, t.Hash)
	reason := ""
	switch {
	case !match || t.HashAlg != s.hasher.Name():
		return Caller{}, s.tokenFailed(ctx, nil, User{}, prefix, ReasonInvalid, ip)
	case t.Revoked():
		reason = ReasonRevoked
	case !now.Before(t.ExpiresAt):
		reason = ReasonExpired
	case u.Status != StatusActive || u.OrgID != t.OrgID:
		reason = reasonOwnerInactive
	}
	if reason != "" {
		return Caller{}, s.tokenFailed(ctx, &t, u, prefix, reason, ip)
	}
	if t.LastUsedAt.IsZero() || now.Sub(t.LastUsedAt) >= apiTokenTouch || t.LastUsedIP != ip {
		if err := s.tokens.TouchAPIToken(ctx, t.ID, now, ip); err != nil {
			return Caller{}, err
		}
		t.LastUsedAt, t.LastUsedIP = now, ip
	}
	return Caller{User: u, SourceIP: ip, Token: &t}, nil
}

// tokenFailed пишет api_token.auth_failed. Субъект — токен, только если
// секрет совпал (отозван, истёк, владелец деактивирован).
func (s *Service) tokenFailed(ctx context.Context, t *APIToken, owner User, prefix, reason string, ip netip.Addr) error {
	by := audit.Actor{Type: audit.ActorAPIToken, ID: unknownActor, Name: prefix}
	obj := audit.Object{Type: "api_token"}
	if prefix == "" {
		by.Name = "(неверный формат)"
	}
	if t != nil {
		by, obj = t.actor(owner), apiTokenObject(t.ID)
	}
	details := map[string]any{"reason": reason}
	if prefix != "" {
		details["prefix"] = prefix
	}
	if err := s.audit.Record(ctx, s.entry(by, ip, "api_token.auth_failed", obj, audit.ResultFailure, details)); err != nil {
		return err
	}
	return ErrUnauthenticated
}

// APITokenRateLimited пишет одну запись api_token.auth_failed с причиной
// rate_limited, когда адрес клиента заблокирован ограничителем неудач (В9
// ревью 2.r2). Дальнейшие запросы с адреса до конца блокировки отклоняются
// без записей: перебор не раздувает журнал аудита.
func (s *Service) APITokenRateLimited(ctx context.Context, ip netip.Addr, until time.Time) error {
	by := audit.Actor{Type: audit.ActorAPIToken, ID: unknownActor, Name: "(ограничение частоты)"}
	return s.audit.Record(ctx, s.entry(by, ip, "api_token.auth_failed", audit.Object{Type: "api_token"}, audit.ResultFailure,
		map[string]any{"reason": ReasonRateLimited, "blocked_until": until.UTC().Format(time.RFC3339)}))
}

// APITokenUsed пишет в аудит запрос по токену (РСБ.1): метод, шаблон пути
// и код ответа. Вызывается после обработчика каждого пропущенного запроса.
func (s *Service) APITokenUsed(ctx context.Context, c Caller, method, path string, status int) error {
	if c.Token == nil {
		return nil
	}
	res := audit.ResultSuccess
	if status >= 400 {
		res = audit.ResultFailure
	}
	return s.audit.Record(ctx, s.entry(c.actor(), c.SourceIP, "api_token.used", apiTokenObject(c.Token.ID), res,
		map[string]any{"method": method, "path": path, "status": status}))
}

// tokenScope — область разрешения perm у by; ScopeOwn — только свои токены.
func (s *Service) tokenScope(ctx context.Context, by Caller, perm string) (Grants, Scope, error) {
	g, err := s.CallerGrants(ctx, by)
	if err != nil {
		return nil, ScopeNone, err
	}
	return g, g.Scope(perm), nil
}

// APITokens — токены, которые видит by: свои при области own, все при all.
func (s *Service) APITokens(ctx context.Context, by Caller, after *UserCursor, limit int) ([]APIToken, error) {
	if s.tokens == nil {
		return nil, errNoTokenStore
	}
	_, sc, err := s.tokenScope(ctx, by, PermAPITokensRead)
	if err != nil {
		return nil, err
	}
	switch sc {
	case ScopeAll:
		return s.tokens.ListAPITokens(ctx, s.orgID, "", after, limit)
	case ScopeOwn:
		return s.tokens.ListAPITokens(ctx, s.orgID, by.User.ID, after, limit)
	}
	return nil, ErrAPITokenNotFound
}

// APITokenByID — токен; чужой при области own — ErrAPITokenNotFound (УПД.8).
func (s *Service) APITokenByID(ctx context.Context, by Caller, id string) (APIToken, error) {
	if s.tokens == nil {
		return APIToken{}, errNoTokenStore
	}
	_, sc, err := s.tokenScope(ctx, by, PermAPITokensRead)
	if err != nil {
		return APIToken{}, err
	}
	t, err := s.tokens.APITokenByID(ctx, s.orgID, id)
	if err != nil {
		return APIToken{}, err
	}
	if sc == ScopeNone || (sc == ScopeOwn && t.UserID != by.User.ID) {
		return APIToken{}, ErrAPITokenNotFound
	}
	return t, nil
}

// APITokenOwner — ID владельца токена без проверки прав вызывающего: для
// решений о доступе (3Н48 ревью 3.r4 — оповещение о действиях своего
// токена владелец не закрывает). Нет токена — ErrAPITokenNotFound.
func (s *Service) APITokenOwner(ctx context.Context, id string) (string, error) {
	if s.tokens == nil {
		return "", errNoTokenStore
	}
	t, err := s.tokens.APITokenByID(ctx, s.orgID, id)
	if err != nil {
		return "", err
	}
	return t.UserID, nil
}

// RevokeAPIToken отзывает токен (api_token.revoke). Свой — при любой
// области; чужой — только при области all и если права владельца входят в
// права отзывающего (УПД.2). Отозванный токен не оживает.
func (s *Service) RevokeAPIToken(ctx context.Context, by Caller, id string) (APIToken, error) {
	if s.tokens == nil {
		return APIToken{}, errNoTokenStore
	}
	mine, sc, err := s.tokenScope(ctx, by, PermAPITokensManage)
	if err != nil {
		return APIToken{}, err
	}
	obj := apiTokenObject(id)
	var deny error
	t, err := s.tokens.RevokeAPIToken(ctx, s.orgID, id, by.User.ID, s.clock(),
		func(t APIToken, owner User) (string, audit.Entry, error) {
			reason := APITokenRevokedByOwner
			if t.UserID != by.User.ID {
				if sc != ScopeAll {
					return "", audit.Entry{}, ErrAPITokenNotFound
				}
				og, err := s.Grants(ctx, owner.Role)
				if err != nil {
					return "", audit.Entry{}, err
				}
				if !mine.Covers(og) {
					deny = ErrEscalation
					return "", audit.Entry{}, deny
				}
				reason = APITokenRevokedByAdmin
			} else if sc == ScopeNone {
				return "", audit.Entry{}, ErrAPITokenNotFound
			}
			if t.Revoked() {
				return "", audit.Entry{}, ErrAPITokenRevoked
			}
			return reason, s.entry(by.actor(), by.SourceIP, "api_token.revoke", obj, audit.ResultSuccess,
				map[string]any{"prefix": t.Prefix, "owner": owner.Login, "reason": reason}), nil
		})
	if deny != nil {
		return APIToken{}, s.denied(ctx, by, "api_token.revoke", obj, deny)
	}
	return t, err
}
