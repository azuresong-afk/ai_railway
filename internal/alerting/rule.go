package alerting

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
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

// APIKind — правило этого вида создаётся и меняется через API.
func APIKind(kind string) bool {
	return kind == KindThreshold || kind == KindNew || kind == KindFrequency || kind == KindAnomaly || kind == KindBudget
}

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
	// MaxDetailsBytes — предел подробностей оповещения в JSON: столбец
	// details ограничен 16 КиБ в текстовой форме jsonb (миграция 0028),
	// запас — на пробелы этой формы (3В16 ревью 3.r2). Элемент, с которым
	// подробности переходят предел, не добавляется (items_truncated).
	MaxDetailsBytes = 12 << 10
	// MaxItemReasons — причин ослабления в одном элементе DM-40; общее
	// число — в reasons_total (3В16 ревью 3.r2).
	MaxItemReasons = 10
	// MaxTitle — длина заголовка оповещения, символов.
	MaxTitle = 300
	// DefaultSuppressMinutes — окно подавления после закрытия по умолчанию.
	DefaultSuppressMinutes = 60
	// MaxRuleBody — предел тела запроса правила.
	MaxRuleBody = 64 << 10
	// maxConditionJSON — предел условия в JSON (ограничение столбца condition).
	maxConditionJSON = 8192
)

// Пределы параметров правил «частота», «аномалия» и «бюджет» (задача 3.12).
const (
	MinFrequencyCount    = 2
	MaxFrequencyCount    = 100_000
	MaxWindowMinutes     = 24 * 60
	MinAnomalyFactor     = 1.5
	MaxAnomalyFactor     = 100
	DefaultAnomalyFactor = 3
	MaxMinVolume         = 1_000_000_000_000
	MinWarnPercent       = 50
	MaxWarnPercent       = 99
	DefaultWarnPercent   = 80
)

// Метрики правила «аномалия»: по агрегатам событий без содержимого.
const (
	MetricRequests         = "requests"          // запросы через шлюз и Check API
	MetricTokens           = "tokens"            // токены входа и выхода
	MetricCompletionTokens = "completion_tokens" // токены ответов модели (DM-17)
)

// metricMinVolume — наименьший объём за час по умолчанию: ниже него рост
// не считается аномалией (шум малых приложений).
var metricMinVolume = map[string]int64{MetricRequests: 100, MetricTokens: 200_000, MetricCompletionTokens: 100_000}

// Metrics — метрики правила «аномалия».
func Metrics() []string { return []string{MetricRequests, MetricTokens, MetricCompletionTokens} }

// anomalyGroupFields — поля группировки «аномалии»: измерение агрегатов.
var anomalyGroupFields = []string{"app"}

// Condition — условие правила. Filter — фильтр событий языка ADR-0015 в
// канонической записи («порог», «новое», «частота»). Поля сравнимы через ==:
// без срезов и отображений.
type Condition struct {
	Filter      string `json:"filter,omitempty"`
	MinSeverity string `json:"min_severity,omitempty"`
	// Field — поле правила «новое»: model, provider, user или app.
	Field string `json:"field,omitempty"`
	// Count и WindowMinutes — «частота»: Count подходящих событий за
	// WindowMinutes минут по ключу group_by (задача 3.12).
	Count         int `json:"count,omitempty"`
	WindowMinutes int `json:"window_minutes,omitempty"`
	// Metric, Factor и MinVolume — «аномалия»: объём за последний час не
	// меньше MinVolume и не меньше Factor медиан базовой линии того же часа
	// недели (задача 3.12).
	Metric    string  `json:"metric,omitempty"`
	Factor    float64 `json:"factor,omitempty"`
	MinVolume int64   `json:"min_volume,omitempty"`
	// WarnPercent — «бюджет»: порог предупреждения в процентах месячного
	// бюджета; второй порог — 100 % (ТЗ 5.6).
	WarnPercent int `json:"warn_percent,omitempty"`
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
	case !APIKind(kind):
		errs = append(errs, errors.New("kind: через API создаются правила threshold, new, frequency, anomaly и budget; "+
			"системные правила и правила безопасности создаёт сервер"))
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
		if kind == KindNew || kind == KindAnomaly {
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
	if r.Kind != KindFrequency && (c.Count != 0 || c.WindowMinutes != 0) {
		errs = append(errs, errors.New("condition.count: только у правила «частота»"))
	}
	if r.Kind != KindAnomaly && (c.Metric != "" || c.Factor != 0 || c.MinVolume != 0) {
		errs = append(errs, errors.New("condition.metric: только у правила «аномалия»"))
	}
	if r.Kind != KindBudget && c.WarnPercent != 0 {
		errs = append(errs, errors.New("condition.warn_percent: только у правила «бюджет»"))
	}
	if (r.Kind == KindAnomaly || r.Kind == KindBudget) && (c.Filter != "" || c.MinSeverity != "" || c.Field != "") {
		errs = append(errs, errors.New("condition.filter: правила «аномалия» и «бюджет» считаются по агрегатам, фильтр событий к ним не применяется"))
	}
	switch r.Kind {
	case KindThreshold, KindFrequency:
		if c.Field != "" {
			errs = append(errs, errors.New("condition.field: только у правила «новое»"))
		}
		// Проверяется нормализованный фильтр: фильтр из одних пробелов
		// разбирается в пустой и иначе дал бы оповещение на каждое событие.
		if r.Condition.Filter == "" && c.MinSeverity == "" {
			errs = append(errs, errors.New("condition: задайте фильтр или наименьшую серьёзность — иначе оповещением станет каждое событие"))
		}
		if r.Kind == KindFrequency {
			errs = append(errs, r.parseFrequency(c)...)
		}
		errs = append(errs, r.parseGroupBy(groupBy, groupFields)...)
	case KindAnomaly:
		errs = append(errs, r.parseAnomaly(c)...)
		errs = append(errs, r.parseGroupBy(groupBy, anomalyGroupFields)...)
	case KindBudget:
		if c.WarnPercent == 0 {
			c.WarnPercent = DefaultWarnPercent
		}
		if c.WarnPercent < MinWarnPercent || c.WarnPercent > MaxWarnPercent {
			errs = append(errs, fmt.Errorf("condition.warn_percent: от %d до %d", MinWarnPercent, MaxWarnPercent))
		}
		r.Condition.WarnPercent = c.WarnPercent
		if len(groupBy) > 0 && !slices.Equal(groupBy, []string{"app"}) {
			errs = append(errs, errors.New("group_by: бюджет задаётся на приложение — ключ всегда app"))
		}
		r.GroupBy = []string{"app"}
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

// parseGroupBy проверяет поля группировки по списку допустимых.
func (r *Rule) parseGroupBy(groupBy, allowed []string) []error {
	var errs []error
	if len(groupBy) > MaxGroupBy {
		return []error{fmt.Errorf("group_by: не больше %d полей", MaxGroupBy)}
	}
	r.GroupBy = []string{}
	for _, g := range groupBy {
		switch {
		case !slices.Contains(allowed, g):
			errs = append(errs, fmt.Errorf("group_by: поле %q не годится для группировки; допустимы: %s", short(g), strings.Join(allowed, ", ")))
		case slices.Contains(r.GroupBy, g):
			errs = append(errs, fmt.Errorf("group_by: поле %s указано дважды", g))
		default:
			r.GroupBy = append(r.GroupBy, g)
		}
	}
	return errs
}

// parseFrequency проверяет порог и окно правила «частота».
func (r *Rule) parseFrequency(c Condition) []error {
	var errs []error
	if c.Count < MinFrequencyCount || c.Count > MaxFrequencyCount {
		errs = append(errs, fmt.Errorf("condition.count: от %d до %d событий", MinFrequencyCount, MaxFrequencyCount))
	}
	if c.WindowMinutes < 1 || c.WindowMinutes > MaxWindowMinutes {
		errs = append(errs, fmt.Errorf("condition.window_minutes: от 1 до %d минут", MaxWindowMinutes))
	}
	r.Condition.Count, r.Condition.WindowMinutes = c.Count, c.WindowMinutes
	return errs
}

// parseAnomaly проверяет метрику и порог правила «аномалия»; пустые
// множитель и наименьший объём — умолчания метрики.
func (r *Rule) parseAnomaly(c Condition) []error {
	var errs []error
	if !slices.Contains(Metrics(), c.Metric) {
		return []error{fmt.Errorf("condition.metric: одно из %s", strings.Join(Metrics(), ", "))}
	}
	if c.Factor == 0 {
		c.Factor = DefaultAnomalyFactor
	}
	if math.IsNaN(c.Factor) || c.Factor < MinAnomalyFactor || c.Factor > MaxAnomalyFactor {
		errs = append(errs, fmt.Errorf("condition.factor: от %g до %d — во сколько раз объём выше медианы базовой линии",
			MinAnomalyFactor, MaxAnomalyFactor))
	}
	if c.MinVolume == 0 {
		c.MinVolume = metricMinVolume[c.Metric]
	}
	if c.MinVolume < 1 || c.MinVolume > MaxMinVolume {
		errs = append(errs, fmt.Errorf("condition.min_volume: от 1 до %d за час", int64(MaxMinVolume)))
	}
	r.Condition.Metric, r.Condition.Factor, r.Condition.MinVolume = c.Metric, c.Factor, c.MinVolume
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
	// Пороги правил «частота», «аномалия» и «бюджет» (задача 3.12).
	WeakCountRaised     = "count_raised"
	WeakWindowShortened = "window_shortened"
	WeakFactorRaised    = "factor_raised"
	WeakMinVolumeRaised = "min_volume_raised"
	WeakWarnRaised      = "warn_percent_raised"
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
	bc, ac := &before.Condition, &after.Condition
	if bc.Filter != ac.Filter || bc.Field != ac.Field || bc.Metric != ac.Metric {
		out = append(out, WeakConditionChanged)
	}
	if ac.Count > bc.Count {
		out = append(out, WeakCountRaised)
	}
	if ac.WindowMinutes < bc.WindowMinutes {
		out = append(out, WeakWindowShortened)
	}
	if ac.Factor > bc.Factor {
		out = append(out, WeakFactorRaised)
	}
	if ac.MinVolume > bc.MinVolume {
		out = append(out, WeakMinVolumeRaised)
	}
	if ac.WarnPercent > bc.WarnPercent {
		out = append(out, WeakWarnRaised)
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
