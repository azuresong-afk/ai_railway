// Пакет license — лицензия продукта (ТЗ 5.15, ЗИ.2; задачи 4.26, 4.27
// этапа 4, ADR-0026): разбор содержимого, проверка подписи офлайн через
// internal/crypto, состояние срока (льготный период, запрет изменений),
// пределы шлюзов и приложений, модули, хранение и загрузка.
package license

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// PayloadFormat — метка формата содержимого лицензии.
const PayloadFormat = "aisec-license-data-v1"

// Типы лицензии (на ограничения не влияют).
const (
	TypePilot      = "pilot"
	TypeCommercial = "commercial"
)

// Модули (ADR-0026, п. 3). Базовая защита модулем не является.
const (
	ModuleAgents     = "agents"
	ModuleShadowAI   = "shadow_ai"
	ModuleCompliance = "compliance"
	ModuleML         = "ml"
)

// Modules — все модули в порядке показа.
var Modules = []string{ModuleAgents, ModuleShadowAI, ModuleCompliance, ModuleML}

// ModuleTitle — название модуля для сообщений и консоли.
func ModuleTitle(m string) string {
	switch m {
	case ModuleAgents:
		return "Агенты и MCP"
	case ModuleShadowAI:
		return "Теневой ИИ"
	case ModuleCompliance:
		return "Соответствие требованиям"
	case ModuleML:
		return "ML-детекторы"
	}
	return m
}

// Пределы содержимого.
const (
	maxNumber       = 1<<53 - 1
	maxOrganization = 200
	// MaxLimit — наибольший предел шлюзов или приложений; 0 — без ограничения.
	MaxLimit = 1_000_000
	// MaxPilotTerm и MaxCommercialTerm — наибольший срок лицензии.
	MaxPilotTerm      = 92 * 24 * time.Hour
	MaxCommercialTerm = 1827 * 24 * time.Hour
)

// ErrPayload — содержимое лицензии не по формату. Причина — в тексте
// обёртки, без значений полей.
var ErrPayload = errors.New("лицензия: неверное содержимое")

// Licensee — владелец лицензии.
type Licensee struct {
	Organization string `json:"organization"`
	INN          string `json:"inn"`
}

// Limits — пределы; 0 — без ограничения.
type Limits struct {
	Gateways     int `json:"gateways"`
	Applications int `json:"applications"`
}

// License — содержимое лицензии.
type License struct {
	Number     uint64
	Licensee   Licensee
	IssuedAt   time.Time
	ValidFrom  time.Time
	ValidUntil time.Time
	Type       string
	Limits     Limits
	// Modules — включённые модули в порядке Modules.
	Modules []string
}

// HasModule — модуль включён.
func (l *License) HasModule(m string) bool { return slices.Contains(l.Modules, m) }

type payloadJSON struct {
	Format     string   `json:"format"`
	Number     uint64   `json:"number"`
	Licensee   Licensee `json:"licensee"`
	IssuedAt   string   `json:"issued_at"`
	ValidFrom  string   `json:"valid_from"`
	ValidUntil string   `json:"valid_until"`
	Type       string   `json:"type"`
	Limits     Limits   `json:"limits"`
	Modules    []string `json:"modules"`
}

const timeLayout = time.RFC3339

func payloadErr(msg string) error { return fmt.Errorf("%w: %s", ErrPayload, msg) }

// fields — объект с ровно этими ключами (точное сравнение, без учёта
// регистра encoding/json для структур). Повторы ключей уже исключены
// aisecCrypto.CheckLicensePayload.
func fields(raw json.RawMessage, names ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, errors.New("не объект")
	}
	if len(m) != len(names) {
		return nil, errors.New("лишние или недостающие поля")
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return nil, fmt.Errorf("нет поля %s", n)
		}
	}
	return m, nil
}

// Parse строго разбирает содержимое лицензии (ADR-0026, п. 3). Вызывается
// после проверки подписи (Verify) или инструментом подписи до неё.
func Parse(data []byte) (*License, error) {
	if err := aisecCrypto.CheckLicensePayload(data); err != nil {
		return nil, payloadErr("не объект JSON без повторяющихся ключей или больше 8 КиБ")
	}
	top, err := fields(data, "format", "number", "licensee", "issued_at", "valid_from", "valid_until", "type", "limits", "modules")
	if err != nil {
		return nil, payloadErr(err.Error())
	}
	if _, err := fields(top["licensee"], "organization", "inn"); err != nil {
		return nil, payloadErr("licensee: " + err.Error())
	}
	if _, err := fields(top["limits"], "gateways", "applications"); err != nil {
		return nil, payloadErr("limits: " + err.Error())
	}
	var j payloadJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, payloadErr("неверный тип поля")
	}
	// Номер — целое без дробной части и экспоненты.
	if raw := strings.TrimSpace(string(top["number"])); raw != strconv.FormatUint(j.Number, 10) {
		return nil, payloadErr("number — целое число")
	}
	for _, f := range []string{"gateways", "applications"} {
		var lm map[string]json.RawMessage
		_ = json.Unmarshal(top["limits"], &lm) //nolint:gosec // G104: объект уже разобран выше
		var n int
		if err := json.Unmarshal(lm[f], &n); err != nil || strings.TrimSpace(string(lm[f])) != strconv.Itoa(n) {
			return nil, payloadErr("limits." + f + " — целое число")
		}
	}
	if j.Format != PayloadFormat {
		return nil, payloadErr("format — " + PayloadFormat)
	}
	l := &License{Number: j.Number, Licensee: j.Licensee, Type: j.Type, Limits: j.Limits}
	if l.IssuedAt, err = parseTime(j.IssuedAt); err != nil {
		return nil, payloadErr("issued_at: " + err.Error())
	}
	if l.ValidFrom, err = parseTime(j.ValidFrom); err != nil {
		return nil, payloadErr("valid_from: " + err.Error())
	}
	if l.ValidUntil, err = parseTime(j.ValidUntil); err != nil {
		return nil, payloadErr("valid_until: " + err.Error())
	}
	if j.Modules == nil {
		return nil, payloadErr("modules — массив")
	}
	for _, m := range j.Modules {
		if !slices.Contains(Modules, m) || slices.Contains(l.Modules, m) {
			return nil, payloadErr("modules — без повторов из agents, shadow_ai, compliance, ml")
		}
		l.Modules = append(l.Modules, m)
	}
	l.Modules = ordered(l.Modules)
	if err := l.check(); err != nil {
		return nil, payloadErr(err.Error())
	}
	return l, nil
}

// ordered — модули в порядке Modules.
func ordered(in []string) []string {
	out := []string{}
	for _, m := range Modules {
		if slices.Contains(in, m) {
			out = append(out, m)
		}
	}
	return out
}

// parseTime — только UTC с суффиксом Z и точностью до секунды.
func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil || t.Location() != time.UTC || t.Format(timeLayout) != s {
		return time.Time{}, errors.New("время в формате ГГГГ-ММ-ДДTЧЧ:ММ:ССZ")
	}
	return t, nil
}

// check — правила полей (ADR-0026, п. 3).
func (l *License) check() error {
	org := l.Licensee.Organization
	switch {
	case l.Number == 0 || l.Number > maxNumber:
		return fmt.Errorf("number — от 1 до %d", uint64(maxNumber))
	case org == "" || !utf8.ValidString(org) || utf8.RuneCountInString(org) > maxOrganization || hasControl(org) ||
		org != trimSpace(org):
		return fmt.Errorf("licensee.organization — от 1 до %d символов без управляющих и пробелов по краям", maxOrganization)
	case !ValidINN(l.Licensee.INN):
		return errors.New("licensee.inn — ИНН из 10 или 12 цифр с верной контрольной суммой")
	case !l.ValidFrom.Before(l.ValidUntil):
		return errors.New("valid_from раньше valid_until")
	case l.IssuedAt.After(l.ValidUntil):
		return errors.New("issued_at не позже valid_until")
	case l.Type != TypePilot && l.Type != TypeCommercial:
		return errors.New("type — pilot или commercial")
	case l.Type == TypePilot && l.ValidUntil.Sub(l.ValidFrom) > MaxPilotTerm:
		return errors.New("срок пилотной лицензии — не больше 92 суток")
	case l.ValidUntil.Sub(l.ValidFrom) > MaxCommercialTerm:
		return errors.New("срок лицензии — не больше 5 лет")
	case l.Limits.Gateways < 0 || l.Limits.Gateways > MaxLimit || l.Limits.Applications < 0 || l.Limits.Applications > MaxLimit:
		return fmt.Errorf("пределы — от 0 (без ограничения) до %d", MaxLimit)
	}
	for i, m := range l.Modules {
		if !slices.Contains(Modules, m) || slices.Contains(l.Modules[:i], m) {
			return errors.New("modules — без повторов из agents, shadow_ai, compliance, ml")
		}
	}
	return nil
}

func hasControl(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && s[start] == ' ' {
		start++
	}
	for end > start && s[end-1] == ' ' {
		end--
	}
	return s[start:end]
}

// ValidINN — ИНН юридического лица (10 цифр) или индивидуального
// предпринимателя (12 цифр) с верными контрольными цифрами.
func ValidINN(s string) bool {
	d := make([]int, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
		d[i] = int(s[i] - '0')
	}
	sum := func(w []int) int {
		n := 0
		for i, k := range w {
			n += d[i] * k
		}
		return n % 11 % 10
	}
	switch len(s) {
	case 10:
		return sum([]int{2, 4, 10, 3, 5, 9, 4, 6, 8}) == d[9]
	case 12:
		return sum([]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == d[10] && sum([]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == d[11]
	}
	return false
}

// Encode — каноническое содержимое лицензии (инструмент подписи и тесты).
func Encode(l *License) ([]byte, error) {
	c := *l
	c.IssuedAt, c.ValidFrom, c.ValidUntil = c.IssuedAt.UTC().Truncate(time.Second), c.ValidFrom.UTC().Truncate(time.Second),
		c.ValidUntil.UTC().Truncate(time.Second)
	if err := c.check(); err != nil {
		return nil, payloadErr(err.Error())
	}
	data, err := json.Marshal(payloadJSON{Format: PayloadFormat, Number: c.Number, Licensee: c.Licensee,
		IssuedAt: c.IssuedAt.Format(timeLayout), ValidFrom: c.ValidFrom.Format(timeLayout), ValidUntil: c.ValidUntil.Format(timeLayout),
		Type: c.Type, Limits: c.Limits, Modules: ordered(c.Modules)})
	if err != nil {
		return nil, err
	}
	if _, err := Parse(data); err != nil {
		return nil, err
	}
	return data, nil
}
