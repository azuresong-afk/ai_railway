package auth

import (
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Policy — настройки входа организации: парольная политика (ИАФ.2),
// блокировка (ИАФ.4), сессии (УПД.4), временный пароль (ИАФ.3).
type Policy struct {
	PasswordMinLength  int `json:"password_min_length"`
	PasswordMinClasses int `json:"password_min_classes"`
	PasswordHistory    int `json:"password_history"`
	PasswordMaxAgeDays int `json:"password_max_age_days"` // 0 — бессрочно
	PasswordWarnDays   int `json:"password_warn_days"`
	LockoutThreshold   int `json:"lockout_threshold"`
	LockoutMinutes     int `json:"lockout_minutes"` // 0 — до разблокировки администратором
	SessionIdleMinutes int `json:"session_idle_minutes"`
	SessionMaxPerUser  int `json:"session_max_per_user"`
	TempPasswordHours  int `json:"temp_password_hours"`
}

// DefaultPolicy — значения по умолчанию (ТЗ: длина 12, бездействие 15 минут).
func DefaultPolicy() Policy {
	return Policy{
		PasswordMinLength: 12, PasswordMinClasses: 3, PasswordHistory: 5,
		PasswordMaxAgeDays: 90, PasswordWarnDays: 14,
		LockoutThreshold: 5, LockoutMinutes: 15,
		SessionIdleMinutes: 15, SessionMaxPerUser: 5,
		TempPasswordHours: 72,
	}
}

// Границы настроек; те же — в CHECK таблицы auth_settings.
const (
	minPasswordLength = 8
	maxPasswordLength = 64
	// MaxPasswordRunes — предел длины пароля в символах; в байтах действует
	// ещё и crypto.MaxPasswordLen.
	MaxPasswordRunes = 256
	maxHistory       = 24
	maxAgeDays       = 365
	maxWarnDays      = 60
	minLockout       = 3
	maxLockout       = 20
	maxLockoutMin    = 1440
	minIdleMinutes   = 1
	maxIdleMinutes   = 240
	maxSessions      = 20
	maxTempHours     = 168
)

// Validate проверяет границы настроек.
func (p Policy) Validate() error {
	check := []struct {
		v, lo, hi int
		name      string
	}{
		{p.PasswordMinLength, minPasswordLength, maxPasswordLength, "минимальная длина пароля"},
		{p.PasswordMinClasses, 1, 4, "число классов символов"},
		{p.PasswordHistory, 0, maxHistory, "глубина истории паролей"},
		{p.PasswordMaxAgeDays, 0, maxAgeDays, "срок действия пароля"},
		{p.PasswordWarnDays, 0, maxWarnDays, "срок предупреждения о смене пароля"},
		{p.LockoutThreshold, minLockout, maxLockout, "число неудачных попыток до блокировки"},
		{p.LockoutMinutes, 0, maxLockoutMin, "длительность блокировки"},
		{p.SessionIdleMinutes, minIdleMinutes, maxIdleMinutes, "время бездействия сессии"},
		{p.SessionMaxPerUser, 1, maxSessions, "лимит сессий пользователя"},
		{p.TempPasswordHours, 1, maxTempHours, "срок временного пароля"},
	}
	for _, c := range check {
		if c.v < c.lo || c.v > c.hi {
			return fmt.Errorf("%s: от %d до %d", c.name, c.lo, c.hi)
		}
	}
	if p.PasswordMaxAgeDays > 0 && p.PasswordWarnDays >= p.PasswordMaxAgeDays {
		return errors.New("предупреждение о смене пароля должно быть раньше его истечения")
	}
	return nil
}

// PasswordError — пароль не соответствует политике; текст — для пользователя.
type PasswordError struct{ Reason string }

func (e *PasswordError) Error() string { return e.Reason }

// CheckPassword проверяет новый пароль по политике (ИАФ.2): длина в
// символах, число классов (строчные, прописные — в том числе кириллица,
// цифры, прочие), отсутствие управляющих символов, логин не входит в
// пароль. История проверяется отдельно — по хешам.
func (p Policy) CheckPassword(password, login string) error {
	if !utf8.ValidString(password) {
		return &PasswordError{"Пароль содержит недопустимые символы."}
	}
	n := utf8.RuneCountInString(password)
	if n < p.PasswordMinLength {
		return &PasswordError{fmt.Sprintf("Пароль должен быть не короче %d символов.", p.PasswordMinLength)}
	}
	if n > MaxPasswordRunes || len(password) > aisecCrypto.MaxPasswordLen {
		return &PasswordError{fmt.Sprintf("Пароль должен быть не длиннее %d символов.", MaxPasswordRunes)}
	}
	var lower, upper, digit, other bool
	for _, r := range password {
		switch {
		case unicode.IsControl(r):
			return &PasswordError{"Пароль содержит недопустимые символы."}
		case unicode.IsLower(r):
			lower = true
		case unicode.IsUpper(r):
			upper = true
		case unicode.IsDigit(r):
			digit = true
		default:
			other = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit, other} {
		if b {
			classes++
		}
	}
	if classes < p.PasswordMinClasses {
		return &PasswordError{fmt.Sprintf(
			"Пароль должен содержать символы не менее %d разных типов: строчные и прописные буквы, цифры, другие символы.",
			p.PasswordMinClasses)}
	}
	if len(login) >= 3 && strings.Contains(strings.ToLower(password), login) {
		return &PasswordError{"Пароль не должен содержать логин."}
	}
	return nil
}

// Алфавит временного пароля: без похожих символов (0/O, 1/l/I).
const (
	tempLower  = "abcdefghijkmnopqrstuvwxyz"
	tempUpper  = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	tempDigits = "23456789"
	tempOther  = "-_.!@#%+="
	// tempMinLen — длина временного пароля, если политика не требует больше.
	tempMinLen = 20
)

// GenerateTempPassword создаёт временный пароль (ИАФ.3) из источника
// криптопрофиля: длина — max(20, минимум политики), по символу каждого
// класса, остальное — из общего алфавита.
func GenerateTempPassword(r aisecCrypto.Random, p Policy) (string, error) {
	n := max(tempMinLen, p.PasswordMinLength)
	all := tempLower + tempUpper + tempDigits + tempOther
	out := make([]byte, n)
	for i, alphabet := range []string{tempLower, tempUpper, tempDigits, tempOther} {
		c, err := pick(r, alphabet)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	for i := 4; i < n; i++ {
		c, err := pick(r, all)
		if err != nil {
			return "", err
		}
		out[i] = c
	}
	// Перемешивание Фишера — Йетса, чтобы обязательные классы не стояли в начале.
	for i := n - 1; i > 0; i-- {
		j, err := uniform(r, i+1)
		if err != nil {
			return "", err
		}
		out[i], out[j] = out[j], out[i]
	}
	return string(out), nil
}

func pick(r aisecCrypto.Random, alphabet string) (byte, error) {
	i, err := uniform(r, len(alphabet))
	if err != nil {
		return 0, err
	}
	return alphabet[i], nil
}

// uniform — равномерное число из [0, n), n ≤ 256: выборка с отбрасыванием,
// без смещения остатка от деления.
func uniform(r aisecCrypto.Random, n int) (int, error) {
	limit := 256 - 256%n
	var b [1]byte
	for {
		if err := r.Read(b[:]); err != nil {
			return 0, err
		}
		if int(b[0]) < limit {
			return int(b[0]) % n, nil
		}
	}
}
