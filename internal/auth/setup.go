package auth

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// setupTokenPrefix — префикс токена первичной настройки, который выдаёт
// aisec-cli init (ЗИ.4).
const setupTokenPrefix = "aisec_setup_"

// SetupInput — первичная настройка: одноразовый токен из aisec-cli init и
// первая учётная запись администратора безопасности.
type SetupInput struct {
	Token       string
	Login       string
	DisplayName string
	Password    string
	// Timezone — часовой пояс показа времени (ВРМ.2), имя IANA; пусто —
	// DefaultTimezone.
	Timezone string
	// RetentionMode — режим хранения содержимого по умолчанию для новых
	// приложений (ТЗ 5.5): none, masked или full; пусто — DefaultRetentionMode.
	RetentionMode string
	SourceIP      netip.Addr
}

// Умолчания первичной настройки (ТЗ 6.4, решение H-Р4).
const (
	DefaultTimezone      = "Europe/Moscow"
	DefaultRetentionMode = RetentionMasked
	maxTimezoneLen       = 64
)

// InstallSettings — настройки установки, которые администратор выбирает при
// первичной настройке; позже их меняют в «Администрировании».
type InstallSettings struct {
	Timezone      string
	RetentionMode string
}

// retentionModes — допустимые режимы хранения содержимого (ТЗ 5.5).
// RetentionMasked — режим хранения по умолчанию: содержимое с маскированием.
const RetentionMasked = "masked"

var retentionModes = map[string]bool{"none": true, RetentionMasked: true, "full": true}

// installSettings проверяет и дополняет умолчаниями выбор администратора.
func installSettings(in SetupInput) (InstallSettings, error) {
	return InstallSettings{Timezone: in.Timezone, RetentionMode: in.RetentionMode}.Normalize()
}

// Normalize проверяет настройки и дополняет пустые поля умолчаниями.
// Неверное поле — InputError с именем поля API.
func (cfg InstallSettings) Normalize() (InstallSettings, error) {
	if cfg.Timezone == "" {
		cfg.Timezone = DefaultTimezone
	}
	if cfg.RetentionMode == "" {
		cfg.RetentionMode = DefaultRetentionMode
	}
	// «Local» и пустое имя LoadLocation принимает, но это не имя IANA; без
	// «/» из базы IANA годится только UTC — posixrules, localtime, Factory
	// и подобные отклоняются (Н43 ревью 2.r4).
	if len(cfg.Timezone) > maxTimezoneLen || !utf8.ValidString(cfg.Timezone) ||
		cfg.Timezone != "UTC" && !strings.Contains(cfg.Timezone, "/") {
		return InstallSettings{}, &InputError{"timezone", timezoneRule}
	}
	if _, err := time.LoadLocation(cfg.Timezone); err != nil {
		return InstallSettings{}, &InputError{"timezone", timezoneRule}
	}
	if !retentionModes[cfg.RetentionMode] {
		return InstallSettings{}, &InputError{"retention_mode", retentionModeRule}
	}
	return cfg, nil
}

const (
	timezoneRule      = "Укажите имя часового пояса IANA, например Europe/Moscow или UTC."
	retentionModeRule = "Допустимы значения none, masked и full."
)

// SetupRequired — нужна ли первичная настройка (в организации нет учётных записей).
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	has, err := s.store.HasUsers(ctx, s.orgID)
	return !has, err
}

// Setup гасит токен первичной настройки и создаёт первого администратора
// безопасности (ЗИ.4, ИАФ.1). Пароль задаёт сам администратор и он должен
// соответствовать политике. Неверный, истёкший или погашенный токен, а
// также уже выполненная настройка — ErrSetupUnavailable; отказ пишется в
// аудит без токена. Временного пароля нет: токен уже одноразовый секрет.
func (s *Service) Setup(ctx context.Context, in SetupInput) (User, error) {
	now := s.clock()
	system := audit.Actor{Type: audit.ActorSystem, ID: "setup", Name: "Первичная настройка"}
	// После настройки отказ — до проверки пароля и хеширования: открытый
	// эндпоинт не должен тратить Argon2id впустую. Окончательная проверка —
	// в транзакции хранилища.
	has, err := s.store.HasUsers(ctx, s.orgID)
	if err != nil {
		return User{}, err
	}
	if has {
		return User{}, s.setupFailed(ctx, system, in.SourceIP, "unavailable")
	}
	cfg, err := installSettings(in)
	if err != nil {
		return User{}, err
	}
	login, ok := NormalizeLogin(in.Login)
	if !ok {
		return User{}, &InputError{"login", loginRule}
	}
	name, ok := CleanDisplayName(in.DisplayName)
	if !ok {
		return User{}, &InputError{"display_name", displayNameRule}
	}
	pol, err := s.store.Policy(ctx, s.orgID)
	if err != nil {
		return User{}, err
	}
	if err := pol.CheckPassword(in.Password, login); err != nil {
		return User{}, err
	}
	tokenHash, ok := s.setupTokenHash(in.Token)
	if !ok {
		return User{}, s.setupFailed(ctx, system, in.SourceIP, "bad_token")
	}
	h, err := s.pw.Hash(ctx, []byte(in.Password))
	if err != nil {
		return User{}, err
	}
	id, err := store.NewUUIDv7(now, s.random)
	if err != nil {
		return User{}, err
	}
	u := User{
		ID: string(id), OrgID: s.orgID, Login: login, DisplayName: name, Role: RoleSecurityAdmin,
		Status: StatusActive, PasswordHash: h, PasswordChangedAt: now, CreatedAt: now, CreatedBy: system.ID,
	}
	rec := s.entry(system, in.SourceIP, "setup.completed", userObject(u.ID), audit.ResultSuccess,
		map[string]any{"login": login, "role": string(RoleSecurityAdmin),
			"timezone": cfg.Timezone, "retention_mode": cfg.RetentionMode,
			// Хранение содержимого целиком или отказ от хранения — ослабление
			// относительно masked, как у приложений (Н42 ревью 2.r4, DM-40).
			"weakening": cfg.RetentionMode != RetentionMasked})
	err = s.store.SetupFirstUser(ctx, tokenHash, s.hasher.Name(), u, cfg, rec)
	if errors.Is(err, ErrSetupUnavailable) {
		return User{}, s.setupFailed(ctx, system, in.SourceIP, "unavailable")
	}
	if err != nil {
		return User{}, err
	}
	return u, nil
}

// setupTokenHash строго разбирает токен (префикс и канонический base64url)
// и возвращает его хеш в том виде, в каком его сохранил aisec-cli init.
func (s *Service) setupTokenHash(token string) ([]byte, bool) {
	rest, ok := strings.CutPrefix(token, setupTokenPrefix)
	if !ok {
		return nil, false
	}
	if _, err := parseToken(rest); err != nil {
		return nil, false
	}
	return s.hasher.Sum([]byte(token)), true
}

func (s *Service) setupFailed(ctx context.Context, by audit.Actor, ip netip.Addr, reason string) error {
	rec := s.entry(by, ip, "setup.completed", audit.Object{}, audit.ResultFailure, map[string]any{"reason": reason})
	if err := s.audit.Record(ctx, rec); err != nil {
		return err
	}
	return ErrSetupUnavailable
}
