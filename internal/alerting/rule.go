package alerting

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Виды правил (ТЗ 5.6).
const (
	KindThreshold = "threshold" // порог по событиям
	KindNew       = "new"       // впервые встреченное значение
	KindFrequency = "frequency" // N событий за M минут (задача 3.12)
	KindAnomaly   = "anomaly"   // отклонение от базовой линии (3.12)
	KindBudget    = "budget"    // 80 % и 100 % бюджета (3.12)
	KindSystem    = "system"    // системные (3.11), не отключаются
	KindSecurity  = "security"  // безопасность конфигурации и доступа, не отключаются
)

// Kinds — все виды правил.
func Kinds() []string {
	return []string{KindThreshold, KindNew, KindFrequency, KindAnomaly, KindBudget, KindSystem, KindSecurity}
}

// Locked — правило этого вида нельзя отключить (ТЗ 5.6).
func Locked(kind string) bool { return kind == KindSystem || kind == KindSecurity }

// Серьёзность — шкала ТЗ 6.2, та же, что у правил политики.
var severities = []string{"info", "low", "medium", "high", "critical"}

// Severities — значения серьёзности по возрастанию.
func Severities() []string { return slices.Clone(severities) }

// severityRank — место в шкале с 1; 0 — нет значения или неизвестное.
func severityRank(s string) int { return slices.Index(severities, s) + 1 }

// Поля условия «новое» (ТЗ 5.6: модель, провайдер, пользователь; приложение
// — для установок с самостоятельной регистрацией приложений).
var newFields = []string{"model", "provider", "user", "app"}

// groupFields — поля группировки правила «порог»: однозначные столбцы
// событий. Многозначные (угрозы, детекторы) ключом не годятся.
var groupFields = []string{"type", "app", "env", "user", "provider", "model", "source", "gateway", "action", "rule",
	"severity", "policy_mode"}

// GroupFields — допустимые поля группировки правила «порог».
func GroupFields() []string { return slices.Clone(groupFields) }

// NewFields — допустимые поля правила «новое».
func NewFields() []string { return slices.Clone(newFields) }

// Пределы (ADR-0020, п. 10).
const (
	MaxRules           = 200 // правил администратора в организации
	MaxName            = 200
	MaxDescription     = 2000
	MaxComment         = 2000
	MaxGroupBy         = 4
	MaxRecipientRoles  = 10
	MaxRecipientUsers  = 50
	MaxSuppressMinutes = 7 * 24 * 60
	MaxGroupMinutes    = 24 * 60
	// MaxAlertEvents — ссылок на события в одном оповещении; дальше растёт
	// только счётчик.
	MaxAlertEvents = 100
	// MaxDetailItems — элементов списка изменений в подробностях
	// сгруппированного оповещения (DM-40).
	MaxDetailItems = 50
	// MaxTitle — длина заголовка оповещения, символов.
	MaxTitle = 300
	// DefaultSuppressMinutes — окно подавления после закрытия по умолчанию.
	DefaultSuppressMinutes = 60
	// MaxRuleBody — предел тела запроса правила.
	MaxRuleBody = 64 << 10
	// maxConditionJSON — предел условия в JSON (ограничение столбца condition).
	maxConditionJSON = 8192
)

// Condition — условие правила «порог» или «новое». Filter — фильтр
// событий языка ADR-0015 в канонической записи.
type Condition struct {
	Filter      string `json:"filter,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	// Field — поле правила «новое»: model, provider, user или app.
	Field string `json:"field,omitempty"`
}

// Recipients — получатели правила сверх обязательных (п. 8 ADR-0020).
type Recipients struct {
	Roles []string `json:"roles"`
	Users []string `json:"users"`
}

// AlwaysRoles — роли, которые всегда получают оповещения (ТЗ 5.6, Р3).
func AlwaysRoles() []string {
	return []string{string(auth.RoleSecurityAdmin), string(auth.RoleAuditor)}
}

// EffectiveRoles — роли-получатели с обязательными, по алфавиту.
func (r Recipients) EffectiveRoles() []string {
	out := append(AlwaysRoles(), r.Roles...)
	slices.Sort(out)
	return slices.Compact(out)
}

func (r Recipients) equal(o Recipients) bool {
	return slices.Equal(r.Roles, o.Roles) && slices.Equal(r.Users, o.Users)
}

// removedFrom — в r нет какого-то получателя из old.
func (r Recipients) removedFrom(old Recipients) bool {
	for _, x := range old.Roles {
		if !slices.Contains(r.Roles, x) {
			return true
		}
	}
	for _, x := range old.Users {
		if !slices.Contains(r.Users, x) {
			return true
		}
	}
	return false
}

// Rule — правило оповещения.
type Rule struct {
	ID    string
	OrgID string
	// BuiltinKey — ключ встроенного правила; пусто — правило администратора.
	BuiltinKey      string
	Kind            string
	Name            string
	Description     string
	Enabled         bool
	Severity        string
	Condition       Condition
	GroupBy         []string
	SuppressMinutes int
	GroupMinutes    int
	Recipients      Recipients
	Version         int
	CreatedAt       time.Time
	CreatedBy       string
	UpdatedAt       time.Time
	UpdatedBy       string
}

// Builtin — правило встроенное (создаёт код сервера).
func (r *Rule) Builtin() bool { return r.BuiltinKey != "" }

func (r *Rule) clone() Rule {
	c := *r
	c.GroupBy = slices.Clone(r.GroupBy)
	c.Recipients = Recipients{Roles: slices.Clone(r.Recipients.Roles), Users: slices.Clone(r.Recipients.Users)}
	return c
}

// compiled — правило, готовое к проверке событий.
type compiled struct {
	rule    Rule
	filter  events.Filter
	minRank int
}

// compile разбирает условие правила, сохранённого в БД.
func compile(r Rule) (compiled, error) {
	f, err := events.ParseFilter(r.Condition.Filter)
	if err != nil {
		return compiled{}, fmt.Errorf("правило %s: условие: %w", r.ID, err)
	}
	return compiled{rule: r, filter: f, minRank: severityRank(r.Condition.MinSeverity)}, nil
}

// matches — событие подходит под условие правила.
func (c *compiled) matches(rec *events.Record) bool {
	if c.minRank > 0 && severityRank(rec.Severity) < c.minRank {
		return false
	}
	return c.filter.Match(rec)
}

// fieldValue — значение однозначного поля события для группировки и
// правила «новое».
func fieldValue(rec *events.Record, field string) string {
	switch field {
	case "type":
		return rec.Type
	case "app":
		return rec.App
	case "env":
		return rec.Env
	case "user":
		return rec.User
	case "provider":
		return rec.Provider
	case "model":
		return rec.Model
	case "source":
		return rec.Source
	case "gateway":
		return rec.GatewayID
	case "action":
		return rec.Action
	case "rule":
		return rec.Rule
	case "severity":
		return rec.Severity
	case "policy_mode":
		return rec.PolicyMode
	}
	return ""
}

// keySep — разделитель частей ключа дедупликации (U+001F): в значениях
// столбцов событий управляющих символов нет.
const keySep = "\x1f"

// GroupKey — ключ дедупликации по значениям полей группировки в порядке
// fields: «поле=значение», разделитель U+001F (ADR-0020, п. 3).
func GroupKey(fields []string, values map[string]string) string {
	parts := make([]string, len(fields))
	for i, f := range fields {
		parts[i] = f + "=" + values[f]
	}
	return strings.Join(parts, keySep)
}

// InputError — неверные данные правила или запроса; текст показывается
// пользователю и начинается с имени поля.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

// RuleInput — правило из запроса API (создание и полная замена).
type RuleInput struct {
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Enabled     *bool     `json:"enabled"`
	Severity    string    `json:"severity"`
	Condition   Condition `json:"condition"`
	GroupBy     []string  `json:"group_by"`
	// SuppressMinutes — окно подавления после закрытия; nil — 60 минут.
	SuppressMinutes *int       `json:"suppress_minutes"`
	Recipients      Recipients `json:"recipients"`
	// Version — версия, которую меняет запрос (только при изменении).
	Version int `json:"version"`
}

func textField(errs *[]error, field, v string, lo, hi int) {
	n := utf8.RuneCountInString(v)
	if !utf8.ValidString(v) || n < lo || n > hi {
		*errs = append(*errs, fmt.Errorf("%s: от %d до %d символов", field, lo, hi))
		return
	}
	for _, c := range v {
		if c < 0x20 && c != '\n' && c != '\t' || c == 0x7f {
			*errs = append(*errs, fmt.Errorf("%s: управляющие символы недопустимы", field))
			return
		}
	}
}

// ParseRuleInput проверяет правило из запроса и приводит его к
// канонической форме. kind — вид изменяемого правила (при создании —
// из запроса). Существование ролей и пользователей проверяет сервис.
func ParseRuleInput(in RuleInput, kind string) (Rule, error) {
	var errs []error
	if kind == "" {
		kind = in.Kind
	}
	switch {
	case in.Kind != "" && in.Kind != kind:
		errs = append(errs, errors.New("kind: вид правила не меняется"))
	case kind != KindThreshold && kind != KindNew:
		errs = append(errs, errors.New("kind: через API создаются правила «порог» (threshold) и «новое» (new)"))
	}
	r := Rule{Kind: kind, Name: strings.TrimSpace(in.Name), Description: strings.TrimSpace(in.Description), Enabled: true,
		Severity: in.Severity, SuppressMinutes: DefaultSuppressMinutes}
	textField(&errs, "name", r.Name, 1, MaxName)
	textField(&errs, "description", r.Description, 0, MaxDescription)
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	}
	if r.Severity == "" {
		r.Severity = "high"
		if kind == KindNew {
			r.Severity = "medium"
		}
	}
	if severityRank(r.Severity) == 0 {
		errs = append(errs, fmt.Errorf("severity: одно из %s", strings.Join(severities, ", ")))
	}
	if in.SuppressMinutes != nil {
		r.SuppressMinutes = *in.SuppressMinutes
	}
	if r.SuppressMinutes < 0 || r.SuppressMinutes > MaxSuppressMinutes {
		errs = append(errs, fmt.Errorf("suppress_minutes: от 0 до %d", MaxSuppressMinutes))
	}
	errs = append(errs, r.parseCondition(in.Condition, in.GroupBy)...)
	if b, err := json.Marshal(r.Condition); err != nil || len(b) > maxConditionJSON {
		errs = append(errs, fmt.Errorf("condition: больше %d байт в JSON", maxConditionJSON))
	}
	rc, rerrs := parseRecipients(in.Recipients)
	r.Recipients = rc
	errs = append(errs, rerrs...)
	if len(errs) > 0 {
		return Rule{}, &InputError{Errs: errs}
	}
	return r, nil
}

// parseCondition проверяет условие и группировку по виду правила.
func (r *Rule) parseCondition(c Condition, groupBy []string) []error {
	var errs []error
	if c.Filter != "" {
		f, err := events.ParseFilter(c.Filter)
		if err != nil {
			errs = append(errs, fmt.Errorf("condition.filter: %w", err))
		} else {
			r.Condition.Filter = f.String()
		}
	}
	if c.MinSeverity != "" {
		if severityRank(c.MinSeverity) == 0 {
			errs = append(errs, fmt.Errorf("condition.min_severity: одно из %s", strings.Join(severities, ", ")))
		}
		r.Condition.MinSeverity = c.MinSeverity
	}
	switch r.Kind {
	case KindThreshold:
		if c.Field != "" {
			errs = append(errs, errors.New("condition.field: только у правила «новое»"))
		}
		if c.Filter == "" && c.MinSeverity == "" {
			errs = append(errs, errors.New("condition: задайте фильтр или наименьшую серьёзность — иначе оповещением станет каждое событие"))
		}
		if len(groupBy) > MaxGroupBy {
			errs = append(errs, fmt.Errorf("group_by: не больше %d полей", MaxGroupBy))
			break
		}
		r.GroupBy = []string{}
		for _, g := range groupBy {
			switch {
			case !slices.Contains(groupFields, g):
				errs = append(errs, fmt.Errorf("group_by: поле %q не годится для группировки; допустимы: %s", short(g), strings.Join(groupFields, ", ")))
			case slices.Contains(r.GroupBy, g):
				errs = append(errs, fmt.Errorf("group_by: поле %s указано дважды", g))
			default:
				r.GroupBy = append(r.GroupBy, g)
			}
		}
	case KindNew:
		if !slices.Contains(newFields, c.Field) {
			errs = append(errs, fmt.Errorf("condition.field: одно из %s", strings.Join(newFields, ", ")))
		}
		r.Condition.Field = c.Field
		if len(groupBy) > 0 {
			errs = append(errs, errors.New("group_by: у правила «новое» ключ — значение поля condition.field"))
		}
		r.GroupBy = []string{c.Field}
	}
	return errs
}

// short — значение из ввода для сообщения об ошибке: не длиннее 64 байт.
func short(s string) string {
	if len(s) <= 64 {
		return s
	}
	for i := 64; i > 0; i-- {
		if utf8.RuneStart(s[i]) {
			return s[:i] + "…"
		}
	}
	return "…"
}

// parseRecipients проверяет получателей и приводит их к канонической
// форме: по алфавиту, без повторов и без обязательных ролей.
func parseRecipients(in Recipients) (Recipients, []error) {
	var errs []error
	out := Recipients{Roles: []string{}, Users: []string{}}
	if len(in.Roles) > MaxRecipientRoles {
		errs = append(errs, fmt.Errorf("recipients.roles: не больше %d ролей", MaxRecipientRoles))
	} else {
		for _, r := range in.Roles {
			switch {
			case !auth.Role(r).Valid():
				errs = append(errs, fmt.Errorf("recipients.roles: %q — не ID роли", short(r)))
			case slices.Contains(AlwaysRoles(), r):
				// Обязательные роли получают оповещения всегда: в списке не хранятся.
			default:
				out.Roles = append(out.Roles, r)
			}
		}
	}
	if len(in.Users) > MaxRecipientUsers {
		errs = append(errs, fmt.Errorf("recipients.users: не больше %d пользователей", MaxRecipientUsers))
	} else {
		for _, u := range in.Users {
			id, err := store.ParseUUID(u)
			if err != nil {
				errs = append(errs, fmt.Errorf("recipients.users: %q — не ID пользователя", short(u)))
				continue
			}
			out.Users = append(out.Users, string(id))
		}
	}
	slices.Sort(out.Roles)
	out.Roles = slices.Compact(out.Roles)
	slices.Sort(out.Users)
	out.Users = slices.Compact(out.Users)
	return out, errs
}

// Причины ослабления правила (DM-40, ADR-0020, п. 7).
const (
	WeakDisabled          = "disabled"
	WeakConditionChanged  = "condition_changed"
	WeakMinSeverityRaised = "min_severity_raised"
	WeakGroupByChanged    = "group_by_changed"
	WeakSeverityLowered   = "severity_lowered"
	WeakSuppressIncreased = "suppress_increased"
	WeakGroupIncreased    = "group_window_increased"
	WeakRecipientRemoved  = "recipient_removed"
)

// Weakening — чем изменение правила before → after ослабляет оповещения.
// Изменения выключенного правила ослаблением не считаются.
func Weakening(before, after *Rule) []string {
	if !before.Enabled {
		return nil
	}
	var out []string
	if !after.Enabled {
		out = append(out, WeakDisabled)
	}
	if before.Condition.Filter != after.Condition.Filter || before.Condition.Field != after.Condition.Field {
		out = append(out, WeakConditionChanged)
	}
	if severityRank(after.Condition.MinSeverity) > severityRank(before.Condition.MinSeverity) {
		out = append(out, WeakMinSeverityRaised)
	}
	if !slices.Equal(before.GroupBy, after.GroupBy) {
		out = append(out, WeakGroupByChanged)
	}
	if severityRank(after.Severity) < severityRank(before.Severity) {
		out = append(out, WeakSeverityLowered)
	}
	if after.SuppressMinutes > before.SuppressMinutes {
		out = append(out, WeakSuppressIncreased)
	}
	if after.GroupMinutes > before.GroupMinutes {
		out = append(out, WeakGroupIncreased)
	}
	if after.Recipients.removedFrom(before.Recipients) {
		out = append(out, WeakRecipientRemoved)
	}
	return out
}

// sameSettings — у правил одинаковы все настройки, кроме получателей.
func sameSettings(a, b *Rule) bool {
	return a.Name == b.Name && a.Description == b.Description && a.Enabled == b.Enabled && a.Severity == b.Severity &&
		a.Condition == b.Condition && slices.Equal(a.GroupBy, b.GroupBy) && a.SuppressMinutes == b.SuppressMinutes &&
		a.GroupMinutes == b.GroupMinutes
}
