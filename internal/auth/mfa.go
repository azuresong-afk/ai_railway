package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Второй фактор входа — TOTP (ТЗ 7.2 ИАФ.5; решения Р1, Р2; ADR-0006).

const (
	// mfaIssuer — имя системы в приложении-аутентификаторе.
	mfaIssuer = "AISec"
	// RecoveryCodeCount — сколько кодов восстановления выдаётся за раз.
	RecoveryCodeCount = 10
	// recoveryCodeBytes — случайная часть кода восстановления (80 бит).
	recoveryCodeBytes = 10
	// recoveryCodeLen — длина кода в base32 без дефисов.
	recoveryCodeLen = 16
	// mfaPendingTTL — сколько живёт сессия, ожидающая код второго фактора.
	mfaPendingTTL = 5 * time.Minute
	// mfaSetupTTL — сколько живёт сессия, в которой подключают второй фактор.
	mfaSetupTTL = 15 * time.Minute

	// Место хранения шифротекста секрета (AAD: таблица, столбец, ID строки).
	mfaTable  = "user_mfa"
	mfaColumn = "secret"
)

var (
	// ErrInvalidCode — код TOTP или код восстановления не принят (неверный,
	// повторный, просроченный). Причины наружу не различаются.
	ErrInvalidCode = errors.New("код второго фактора не принят")
	// ErrMFAEnabled — второй фактор уже подключён: заменить его можно только сбросом.
	ErrMFAEnabled = errors.New("второй фактор уже подключён")
	// ErrMFANotEnabled — второй фактор не подключён.
	ErrMFANotEnabled = errors.New("второй фактор не подключён")
	// ErrMFAUnavailable — на сервере не загружен ключ данных: секрет не зашифровать.
	ErrMFAUnavailable = errors.New("второй фактор недоступен: не загружен ключ данных")
	// ErrSessionState — действие недоступно в текущем состоянии сессии.
	ErrSessionState = errors.New("действие недоступно в этом состоянии сессии")
)

// base32NoPad — алфавит секрета и кодов восстановления (RFC 4648, без «=»).
var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// MFAState — состояние второго фактора.
type MFAState string

// Состояния второго фактора.
const (
	// MFAPending — секрет выдан, но не подтверждён кодом из приложения.
	MFAPending MFAState = "pending"
	// MFAEnabled — второй фактор подключён.
	MFAEnabled MFAState = "enabled"
)

// MFA — второй фактор пользователя. Секрет — шифротекст ключа данных.
type MFA struct {
	UserID    string
	State     MFAState
	Secret    []byte
	KeyID     string
	Alg       string
	LastStep  int64
	CreatedAt time.Time
	EnabledAt time.Time
}

// MFAStepKind — действие, которое выполняется по принятому коду.
type MFAStepKind int

// Действия с кодом второго фактора.
const (
	// MFAStepConfirm — подключение: фактор pending становится enabled.
	MFAStepConfirm MFAStepKind = iota + 1
	// MFAStepVerify — второй шаг входа (код TOTP или код восстановления).
	MFAStepVerify
	// MFAStepRegenerate — выпуск новых кодов восстановления.
	MFAStepRegenerate
	// MFAStepReauth — повторная проверка перед выпуском токена API (В8
	// ревью 2.r2): только код TOTP, запись об успехе пишет само действие.
	MFAStepReauth
)

// MFAStep — проверка кода второго фактора и действие по её итогу (Store.MFAStep).
type MFAStep struct {
	Kind      MFAStepKind
	UserID    string
	SessionID string
	// FromState — состояние, в котором должна быть сессия.
	FromState SessionState
	Now       time.Time
	// Check проверяет код TOTP по строке фактора (шаг больше LastStep);
	// nil — проверяется код восстановления RecoveryHash.
	Check func(MFA) (step int64, ok bool, err error)
	// RecoveryHash — хеш введённого кода восстановления; nil — код не разобран (неудача).
	RecoveryHash []byte
	// RecoveryHashes — хеши новых кодов восстановления (подключение, перевыпуск).
	RecoveryHashes [][]byte
	// NewSession — сессия, которая заменяет текущую по принятому коду (новые
	// токены, полное состояние); nil — текущая сессия не меняется.
	NewSession *Session
	// SessionLimit — предел полных сессий пользователя (УПД.4).
	SessionLimit int
	Threshold    int
	LockUntil    time.Time
	// Failed — записи аудита неудачи; пишутся в той же транзакции.
	Failed func(attempts int, lockedNow bool) []audit.Entry
}

// SecretBox шифрует секреты ключом данных (internal/keyring).
type SecretBox interface {
	KeyID() string
	Alg() string
	// SealKey возвращает и ID версии ключа данных, которой зашифровано
	// (ротация, ADR-0018).
	SealKey(ctx context.Context, plaintext []byte, table, column, rowID string) (string, []byte, error)
	Open(keyID string, sealed []byte, table, column, rowID string) ([]byte, error)
}

// WithSecretBox подключает ключ данных: без него второй фактор недоступен.
func WithSecretBox(b SecretBox) Option { return func(s *Service) { s.box = b } }

// MFAEnrollment — данные для подключения приложения-аутентификатора. Секрет
// показывается только здесь; QR — матрица модулей (строки из «0» и «1»).
type MFAEnrollment struct {
	Secret string
	URI    string
	QR     []string
}

// MFAInfo — состояние второго фактора для интерфейса.
type MFAInfo struct {
	Enabled  bool
	Required bool
}

// MFAStatus — подключён ли второй фактор и обязателен ли он пользователю.
func (s *Service) MFAStatus(ctx context.Context, u User) (MFAInfo, error) {
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return MFAInfo{}, err
	}
	enabled, err := s.mfaEnabled(ctx, u.ID)
	if err != nil {
		return MFAInfo{}, err
	}
	required, err := s.mfaRequired(ctx, u, pol)
	if err != nil {
		return MFAInfo{}, err
	}
	return MFAInfo{Enabled: enabled, Required: required}, nil
}

func (s *Service) mfaEnabled(ctx context.Context, userID string) (bool, error) {
	m, err := s.store.MFA(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return m.State == MFAEnabled, nil
}

// afterMFA — состояние сессии после второго фактора: смена пароля, если он
// временный или истёк, иначе полный доступ.
func afterMFA(u User, pol Policy, now time.Time) SessionState {
	if exp := u.PasswordExpires(pol); u.MustChangePassword || (!exp.IsZero() && !now.Before(exp)) {
		return SessionPasswordChange
	}
	return SessionActive
}

// StartMFA выдаёт новый секрет TOTP (состояние pending). Доступно сессии
// mfa_setup и полной сессии без подключённого фактора; повторный вызов
// заменяет неподтверждённый секрет. В полной сессии нужен текущий пароль:
// иначе укравший сессию подключил бы свой фактор и закрыл вход владельцу.
// Неверный пароль — неудачная попытка (ИАФ.4), как при смене пароля.
func (s *Service) StartMFA(ctx context.Context, c Caller, password string) (MFAEnrollment, error) {
	// Второй фактор внешней записи проверяет IdP (ADR-0025, 3.7).
	if c.User.External() {
		return MFAEnrollment{}, ErrExternalUser
	}
	if c.Session.State != SessionActive && c.Session.State != SessionMFASetup {
		return MFAEnrollment{}, ErrSessionState
	}
	if s.box == nil {
		return MFAEnrollment{}, ErrMFAUnavailable
	}
	if enabled, err := s.mfaEnabled(ctx, c.User.ID); err != nil || enabled {
		if err == nil {
			err = ErrMFAEnabled
		}
		return MFAEnrollment{}, err
	}
	now := s.clock()
	if c.Session.State == SessionActive {
		pol, err := s.store.Policy(ctx, s.orgID)
		if err != nil {
			return MFAEnrollment{}, err
		}
		if c.User.Locked(now) {
			return MFAEnrollment{}, ErrLocked
		}
		ok, err := s.verify(ctx, password, c.User.PasswordHash)
		if err != nil {
			return MFAEnrollment{}, err
		}
		if !ok {
			return MFAEnrollment{}, s.wrongCurrentPassword(ctx, c, pol, now)
		}
	}
	secret, err := aisecCrypto.RandomBytes(s.random, aisecCrypto.TOTPSecretSize)
	if err != nil {
		return MFAEnrollment{}, err
	}
	defer clear(secret)
	keyID, sealed, err := s.box.SealKey(ctx, secret, mfaTable, mfaColumn, c.User.ID)
	if err != nil {
		return MFAEnrollment{}, err
	}
	m := MFA{UserID: c.User.ID, State: MFAPending, Secret: sealed, KeyID: keyID, Alg: s.box.Alg(), CreatedAt: now}
	rec := s.entry(c.actor(), c.SourceIP, "auth.mfa_setup_started", userObject(c.User.ID), audit.ResultSuccess,
		map[string]any{"state": string(c.Session.State)})
	if err := s.store.SaveMFAPending(ctx, m, rec); err != nil {
		return MFAEnrollment{}, err
	}
	enc := base32NoPad.EncodeToString(secret)
	uri := otpauthURI(c.User.Login, enc)
	qr, err := qrMatrix(uri)
	if err != nil {
		return MFAEnrollment{}, err
	}
	return MFAEnrollment{Secret: enc, URI: uri, QR: qr}, nil
}

// preMFA — сессия до второго фактора (права роли в ней не действуют).
func preMFA(st SessionState) bool { return st == SessionMFAPending || st == SessionMFASetup }

// mfaStateTTL — предельный возраст сессии в состоянии второго фактора; 0 — без своего предела.
func mfaStateTTL(st SessionState) time.Duration {
	switch st {
	case SessionMFAPending:
		return mfaPendingTTL
	case SessionMFASetup:
		return mfaSetupTTL
	}
	return 0
}

// otpauthURI — ссылка для приложения-аутентификатора (формат Key Uri).
func otpauthURI(login, secret string) string {
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", mfaIssuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(aisecCrypto.TOTPDigits))
	q.Set("period", fmt.Sprint(int(aisecCrypto.TOTPPeriod/time.Second)))
	return "otpauth://totp/" + url.PathEscape(mfaIssuer+":"+login) + "?" + q.Encode()
}

// totpFor расшифровывает секрет и возвращает проверку кодов.
func (s *Service) totpFor(m MFA) (aisecCrypto.TOTP, error) {
	if s.box == nil {
		return nil, ErrMFAUnavailable
	}
	if m.Alg != s.box.Alg() {
		return nil, fmt.Errorf("второй фактор: секрет зашифрован алгоритмом %q, ключ данных — %q", m.Alg, s.box.Alg())
	}
	secret, err := s.box.Open(m.KeyID, m.Secret, mfaTable, mfaColumn, m.UserID)
	if err != nil {
		return nil, fmt.Errorf("второй фактор: секрет: %w", err)
	}
	defer clear(secret)
	return s.provider.NewTOTP(secret)
}

// totpCheck — проверка кода TOTP по строке фактора; выполняется хранилищем
// под блокировкой строки пользователя.
func (s *Service) totpCheck(code string, now time.Time) func(MFA) (int64, bool, error) {
	return func(m MFA) (int64, bool, error) {
		totp, err := s.totpFor(m)
		if err != nil {
			return 0, false, err
		}
		step, ok := totp.Verify(code, now, m.LastStep)
		return step, ok, nil
	}
}

// MFAResult — итог принятого кода. При выходе из состояния второго фактора
// сессия заменяется полной с новыми токенами (Token, CSRF выдаются клиенту
// один раз); иначе они пусты и сессия прежняя.
type MFAResult struct {
	Caller        Caller
	Token         string
	CSRF          string
	RecoveryCodes []string
}

// prepare заполняет общие поля шага: пользователь, сессия, порог блокировки
// и записи аудита неудачи (auth.mfa_failed, на пороге — auth.locked и
// auth.sessions_revoked).
func (s *Service) prepare(ctx context.Context, st *MFAStep, c Caller, pol Policy, kind string) error {
	until, err := s.lockUntil(ctx, c.User, pol, st.Now)
	if err != nil {
		return err
	}
	st.UserID, st.SessionID, st.FromState = c.User.ID, c.Session.ID, c.Session.State
	st.Threshold, st.LockUntil, st.SessionLimit = pol.LockoutThreshold, until, pol.SessionMaxPerUser
	st.Failed = func(attempts int, lockedNow bool) []audit.Entry {
		recs := []audit.Entry{s.entry(c.actor(), c.SourceIP, "auth.mfa_failed", userObject(c.User.ID),
			audit.ResultFailure, map[string]any{"kind": kind, "attempts": attempts})}
		if lockedNow {
			recs = append(recs, s.entry(c.actor(), c.SourceIP, "auth.locked", userObject(c.User.ID), audit.ResultSuccess,
				map[string]any{"threshold": pol.LockoutThreshold, "lockout_minutes": lockMinutes(until, st.Now)}))
		}
		if attempts >= pol.LockoutThreshold {
			recs = append(recs, s.entry(c.actor(), c.SourceIP, "auth.sessions_revoked", userObject(c.User.ID),
				audit.ResultSuccess, map[string]any{"reason": RevokeLocked}))
		}
		return recs
	}
	return nil
}

// fullSession готовит полную сессию в состоянии next взамен сессии до
// второго фактора: новые токен и CSRF-токен, абсолютный срок прежний.
func (s *Service) fullSession(c Caller, next SessionState, now time.Time) (*Session, string, string, error) {
	token, tokenHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return nil, "", "", err
	}
	csrf, csrfHash, err := newToken(s.random, s.hasher)
	if err != nil {
		return nil, "", "", err
	}
	id, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return nil, "", "", err
	}
	ns := c.Session
	ns.ID, ns.TokenHash, ns.CSRFHash, ns.State = string(id), tokenHash, csrfHash, next
	ns.MFAVerified = true
	ns.CreatedAt, ns.LastSeenAt = now, now
	return &ns, token, csrf, nil
}

// ConfirmMFA подтверждает подключение кодом из приложения и возвращает коды
// восстановления (показываются один раз). Сессия mfa_setup заменяется
// полной (смена пароля или полный доступ) с новыми токенами.
func (s *Service) ConfirmMFA(ctx context.Context, c Caller, code string) (MFAResult, error) {
	if c.Session.State != SessionActive && c.Session.State != SessionMFASetup {
		return MFAResult{}, ErrSessionState
	}
	if s.box == nil {
		return MFAResult{}, ErrMFAUnavailable
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return MFAResult{}, err
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return MFAResult{}, err
	}
	st := MFAStep{Kind: MFAStepConfirm, Now: s.clock(), RecoveryHashes: hashes}
	st.Check = s.totpCheck(code, st.Now)
	if err := s.prepare(ctx, &st, c, pol, "setup"); err != nil {
		return MFAResult{}, err
	}
	res := MFAResult{Caller: c, RecoveryCodes: codes}
	if c.Session.State == SessionMFASetup {
		if st.NewSession, res.Token, res.CSRF, err = s.fullSession(c, afterMFA(c.User, pol, st.Now), st.Now); err != nil {
			return MFAResult{}, err
		}
		res.Caller.Session = *st.NewSession
	}
	rec := s.entry(c.actor(), c.SourceIP, "auth.mfa_enabled", userObject(c.User.ID), audit.ResultSuccess,
		map[string]any{"recovery_codes": len(codes), "state": string(res.Caller.Session.State)})
	if err := s.store.MFAStep(ctx, st, rec); err != nil {
		return MFAResult{}, err
	}
	return res, nil
}

// VerifyMFA — второй шаг входа: код TOTP или код восстановления (ровно
// одно из двух). Неверный код считается неудачей входа (ИАФ.4). Сессия
// mfa_pending заменяется полной с новыми токенами.
func (s *Service) VerifyMFA(ctx context.Context, c Caller, code, recovery string) (MFAResult, error) {
	if c.Session.State != SessionMFAPending {
		return MFAResult{}, ErrSessionState
	}
	if s.box == nil {
		return MFAResult{}, ErrMFAUnavailable
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return MFAResult{}, err
	}
	st := MFAStep{Kind: MFAStepVerify, Now: s.clock()}
	action, kind := "auth.mfa_verified", "totp"
	if recovery != "" {
		// Неразборчивый код — тоже неудача: хеш остаётся nil.
		st.RecoveryHash, _ = s.recoveryHash(recovery)
		action, kind = "auth.recovery_code_used", "recovery_code"
	} else {
		st.Check = s.totpCheck(code, st.Now)
	}
	if err := s.prepare(ctx, &st, c, pol, kind); err != nil {
		return MFAResult{}, err
	}
	res := MFAResult{Caller: c}
	if st.NewSession, res.Token, res.CSRF, err = s.fullSession(c, afterMFA(c.User, pol, st.Now), st.Now); err != nil {
		return MFAResult{}, err
	}
	res.Caller.Session = *st.NewSession
	rec := s.entry(c.actor(), c.SourceIP, action, sessionObject(st.NewSession.ID), audit.ResultSuccess,
		map[string]any{"state": string(st.NewSession.State), "previous_session": c.Session.ID})
	if err := s.store.MFAStep(ctx, st, rec); err != nil {
		return MFAResult{}, err
	}
	return res, nil
}

// RegenerateRecoveryCodes выпускает новые коды восстановления по текущему
// коду TOTP; прежние неиспользованные коды гасятся.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, c Caller, code string) ([]string, error) {
	if c.Session.State != SessionActive {
		return nil, ErrSessionState
	}
	if s.box == nil {
		return nil, ErrMFAUnavailable
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	codes, hashes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	st := MFAStep{Kind: MFAStepRegenerate, Now: s.clock(), RecoveryHashes: hashes}
	st.Check = s.totpCheck(code, st.Now)
	if err := s.prepare(ctx, &st, c, pol, "totp"); err != nil {
		return nil, err
	}
	rec := s.entry(c.actor(), c.SourceIP, "auth.recovery_codes_regenerated", userObject(c.User.ID), audit.ResultSuccess,
		map[string]any{"recovery_codes": len(codes)})
	if err := s.store.MFAStep(ctx, st, rec); err != nil {
		return nil, err
	}
	return codes, nil
}

// ResetMFA сбрасывает второй фактор другого пользователя (ИАФ.5): секрет и
// коды восстановления уничтожаются, сессии пользователя завершаются; при
// следующем входе фактор подключается заново (если обязателен — сразу).
func (s *Service) ResetMFA(ctx context.Context, by Caller, userID string) error {
	if by.User.ID == userID {
		return ErrSelf
	}
	// Сброс фактора открыл бы учётной записи IdP путь к локальному входу (ADR-0025, 1.6).
	if err := requireLocal(by); err != nil {
		return err
	}
	u, err := s.store.UserByID(ctx, s.orgID, userID)
	if err != nil {
		return err
	}
	// Фактор более сильной учётной записи не сбрасывает (УПД.2, задача 2.9).
	if err := s.canManage(ctx, by, u.Role, "auth.mfa_reset", userObject(userID)); err != nil {
		return err
	}
	return s.resetMFA(ctx, by.actor(), by.SourceIP, userID)
}

// resetMFA — общая часть сброса фактора администратором и aisec-cli.
func (s *Service) resetMFA(ctx context.Context, actor audit.Actor, ip netip.Addr, userID string) error {
	rec := s.entry(actor, ip, "auth.mfa_reset", userObject(userID), audit.ResultSuccess, nil)
	return s.store.ResetMFA(ctx, userID, s.clock(), rec)
}

// newRecoveryCodes — коды восстановления для показа (XXXX-XXXX-XXXX-XXXX) и их хеши.
func (s *Service) newRecoveryCodes() ([]string, [][]byte, error) {
	codes := make([]string, 0, RecoveryCodeCount)
	hashes := make([][]byte, 0, RecoveryCodeCount)
	for range RecoveryCodeCount {
		b, err := aisecCrypto.RandomBytes(s.random, recoveryCodeBytes)
		if err != nil {
			return nil, nil, err
		}
		raw := base32NoPad.EncodeToString(b)
		codes = append(codes, raw[0:4]+"-"+raw[4:8]+"-"+raw[8:12]+"-"+raw[12:16])
		hashes = append(hashes, s.hasher.Sum([]byte(raw)))
	}
	return codes, hashes, nil
}

// recoveryHash разбирает введённый код восстановления (дефисы и пробелы
// игнорируются, регистр не важен) и возвращает его хеш.
func (s *Service) recoveryHash(in string) ([]byte, bool) {
	raw, ok := NormalizeRecoveryCode(in)
	if !ok {
		return nil, false
	}
	return s.hasher.Sum([]byte(raw)), true
}

// maxRecoveryInput — предел введённого кода восстановления до разбора.
const maxRecoveryInput = 64

// NormalizeRecoveryCode приводит код восстановления к каноническому виду:
// 16 символов base32 в верхнем регистре, без дефисов и пробелов.
func NormalizeRecoveryCode(in string) (string, bool) {
	if len(in) > maxRecoveryInput {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(in); i++ {
		switch c := in[i]; {
		case c == '-' || c == ' ':
		case c >= 'a' && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		case (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7'):
			b.WriteByte(c)
		default:
			return "", false
		}
	}
	raw := b.String()
	if len(raw) != recoveryCodeLen {
		return "", false
	}
	dec, err := base32NoPad.DecodeString(raw)
	if err != nil || len(dec) != recoveryCodeBytes {
		return "", false
	}
	return raw, true
}
