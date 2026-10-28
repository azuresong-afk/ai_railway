package compliance

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"
)

// Status — статус пункта.
type Status string

// Статусы пункта (Р10): вычисленные проверками, выставленные вручную и
// «ждёт ручной отметки».
const (
	StatusMet           Status = "met"            // выполнено
	StatusPartial       Status = "partial"        // частично
	StatusNotMet        Status = "not_met"        // не выполнено
	StatusNotApplicable Status = "not_applicable" // не применимо
	StatusManual        Status = "manual"         // нужна ручная отметка
)

// StatusTitle — название статуса для интерфейса и отчётов.
func StatusTitle(s Status) string {
	switch s {
	case StatusMet:
		return "Выполнено"
	case StatusPartial:
		return "Частично"
	case StatusNotMet:
		return "Не выполнено"
	case StatusNotApplicable:
		return "Не применимо"
	case StatusManual:
		return "Нужна ручная отметка"
	}
	return string(s)
}

// ValidMarkStatus — статус, который вправе поставить человек.
func ValidMarkStatus(s Status) bool {
	return s == StatusMet || s == StatusPartial || s == StatusNotMet || s == StatusNotApplicable
}

// CheckResult — итог одной автоматической проверки.
type CheckResult struct {
	Name   string `json:"name"`
	Title  string `json:"title"`
	Status Status `json:"status"`
	// Detail — результат словами, например «Фильтрация входа включена для 5
	// из 7 приложений промышленной среды». Без содержимого запросов.
	Detail string `json:"detail"`
}

// paramDef — допустимые значения параметра проверки: перечень или целое
// в границах. Произвольных строк и выражений нет.
type paramDef struct {
	values   []string
	min, max int
	numeric  bool
	def      string
}

func (p paramDef) valid(v string) bool {
	if p.numeric {
		n, err := strconv.Atoi(v)
		return err == nil && strconv.Itoa(n) == v && n >= p.min && n <= p.max
	}
	return slices.Contains(p.values, v)
}

type checkDef struct {
	title  string
	params map[string]paramDef
	// groups — группы снимка, без которых проверка не выполняется.
	groups []string
	fn     func(s *Snapshot, param func(string) string) (Status, string)
}

var envParam = paramDef{values: []string{"prod", "test", "any"}, def: "prod"}

// checkRegistry — именованные проверки. YAML базы ссылается на них по
// имени с параметрами из этого реестра; добавить проверку можно только
// кодом (вместе с тестом), а не файлом базы.
var checkRegistry = map[string]checkDef{
	"filter_enforced": {
		title:  "Фильтрация входа или выхода включена в режиме enforce",
		params: map[string]paramDef{"direction": {values: []string{"input", "output"}, def: "input"}, "env": envParam},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			dir := param("direction")
			n, total := countApps(s, param("env"), func(a AppFact) bool {
				rules := a.InputRules
				if dir == "output" {
					rules = a.OutputRules
				}
				return a.PolicyMode == "enforce" && rules > 0
			})
			what := "Фильтрация входа включена"
			if dir == "output" {
				what = "Фильтрация выхода включена"
			}
			return ratioStatus(n, total, what, appsOf(param("env")))
		},
	},
	"pii_protection_external": {
		title:  "ПДн маскируются до отправки внешнему провайдеру",
		params: map[string]paramDef{"env": envParam},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			env := param("env")
			total, n := 0, 0
			for _, a := range s.Apps {
				if !envMatches(a.Env, env) || !a.ExternalProvider {
					continue
				}
				total++
				if a.PIIRules > 0 {
					n++
				}
			}
			return ratioStatus(n, total, "Защита ПДн от отправки внешнему провайдеру настроена", "приложений с внешним провайдером ("+envLabel(env)+")")
		},
	},
	"content_storage": {
		title:  "Запросы и ответы регистрируются (режим хранения не none)",
		params: map[string]paramDef{"env": envParam},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			n, total := countApps(s, param("env"), func(a AppFact) bool { return a.Storage != "none" })
			return ratioStatus(n, total, "Регистрация содержимого запросов и ответов включена", appsOf(param("env")))
		},
	},
	"quota_configured": {
		title: "Квоты запросов и токенов заданы",
		params: map[string]paramDef{"env": envParam, "field": {def: "any", values: []string{"any", "requests_per_minute",
			"requests_per_minute_per_user", "requests_per_minute_per_key", "tokens_per_minute", "tokens_per_day", "max_messages", "max_tokens", "max_input_bytes"}}},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			field := param("field")
			n, total := countApps(s, param("env"), func(a AppFact) bool {
				if field == "any" {
					for _, v := range a.Quotas {
						if v > 0 {
							return true
						}
					}
					return false
				}
				return a.Quotas[field] > 0
			})
			what := "Квоты заданы"
			if field == "max_input_bytes" {
				what = "Предел объёма входных данных задан"
			}
			return ratioStatus(n, total, what, appsOf(param("env")))
		},
	},
	"model_list_restricted": {
		title:  "Список разрешённых моделей ограничен",
		params: map[string]paramDef{"env": envParam},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			n, total := countApps(s, param("env"), func(a AppFact) bool { return a.Models > 0 })
			return ratioStatus(n, total, "Разрешённые модели перечислены", appsOf(param("env")))
		},
	},
	"tool_policy_strict": {
		title:  "Политика блокирует неодобренные инструменты агентов",
		params: map[string]paramDef{"env": envParam},
		groups: []string{GroupApps},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			n, total := countApps(s, param("env"), func(a AppFact) bool { return a.ToolsBlockUnapproved })
			return ratioStatus(n, total, "Неодобренные инструменты блокируются", appsOf(param("env")))
		},
	},
	"mfa_privileged_roles": {
		title:  "Второй фактор обязателен для ролей управления безопасностью",
		groups: []string{GroupRoles},
		fn: func(s *Snapshot, _ func(string) string) (Status, string) {
			total, n := 0, 0
			for _, r := range s.PrivilegedRoles {
				if r.Users == 0 {
					continue
				}
				total++
				if r.MFA || s.MFARequiredAll {
					n++
				}
			}
			return ratioStatus(n, total, "Второй фактор обязателен", "ролей с правами управления безопасностью, у которых есть пользователи")
		},
	},
	"audit_chain_verified": {
		title:  "Цепочка журнала аудита проверена и цела",
		params: map[string]paramDef{"max_age_hours": {numeric: true, min: 1, max: 720, def: "48"}},
		groups: []string{GroupAuditChain},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			if s.AuditChain == nil {
				return StatusNotMet, "Проверок цепочки журнала аудита ещё не было"
			}
			if !s.AuditChain.OK {
				return StatusNotMet, "Последняя проверка нашла нарушение цепочки журнала аудита"
			}
			hours, _ := strconv.Atoi(param("max_age_hours")) //nolint:gosec // G104: значение проверено по реестру при загрузке базы
			age := s.Now.Sub(s.AuditChain.CheckedAt)
			if age > time.Duration(hours)*time.Hour {
				return StatusPartial, fmt.Sprintf("Цепочка цела, но последняя проверка старше %d ч", hours)
			}
			return StatusMet, "Цепочка журнала аудита проверена и цела"
		},
	},
	"integrity_verified": {
		title:  "Самотест и контроль целостности успешны",
		groups: []string{GroupIntegrity},
		fn: func(s *Snapshot, _ func(string) string) (Status, string) {
			if s.Integrity == nil {
				return StatusNotMet, "Итогов самотеста и контроля целостности ещё нет"
			}
			if !s.Integrity.ServerOK {
				return StatusNotMet, "Самотест или контроль целостности сервера не пройдены"
			}
			if s.Integrity.GatewaysOK < s.Integrity.Gateways {
				return StatusPartial, fmt.Sprintf("Сервер в порядке; проверки шлюзов успешны у %d из %d", s.Integrity.GatewaysOK, s.Integrity.Gateways)
			}
			return StatusMet, fmt.Sprintf("Проверки успешны у сервера и у шлюзов (%d)", s.Integrity.Gateways)
		},
	},
	"alert_rules_enabled": {
		title:  "Правила оповещений включены",
		params: map[string]paramDef{"min": {numeric: true, min: 1, max: 1000, def: "1"}},
		groups: []string{GroupAlerts},
		fn: func(s *Snapshot, param func(string) string) (Status, string) {
			min, _ := strconv.Atoi(param("min")) //nolint:gosec // G104: значение проверено по реестру при загрузке базы
			detail := fmt.Sprintf("Включено правил оповещений: %d (нужно не меньше %d)", s.AlertRulesEnabled, min)
			switch {
			case s.AlertRulesEnabled >= min:
				return StatusMet, detail
			case s.AlertRulesEnabled > 0:
				return StatusPartial, detail
			}
			return StatusNotMet, detail
		},
	},
	"notification_channel": {
		title:  "Канал уведомлений включён",
		groups: []string{GroupChannels},
		fn: func(s *Snapshot, _ func(string) string) (Status, string) {
			if s.ChannelsEnabled > 0 {
				return StatusMet, fmt.Sprintf("Включено каналов уведомлений: %d", s.ChannelsEnabled)
			}
			return StatusNotMet, "Ни один канал уведомлений не включён: оповещения видны только в консоли"
		},
	},
}

// CheckNames — имена проверок реестра по алфавиту.
func CheckNames() []string {
	out := make([]string, 0, len(checkRegistry))
	for n := range checkRegistry {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// CheckTitle — название проверки.
func CheckTitle(name string) string { return checkRegistry[name].title }

// RunCheck выполняет проверку по снимку. Параметры должны быть проверены
// при загрузке базы; пропущенные берутся из значений по умолчанию.
func RunCheck(s *Snapshot, ref CheckRef) CheckResult {
	def, ok := checkRegistry[ref.Name]
	if !ok {
		return CheckResult{Name: ref.Name, Status: StatusNotMet, Detail: "Проверка неизвестна этой версии продукта"}
	}
	res := CheckResult{Name: ref.Name, Title: def.title}
	for _, g := range def.groups {
		if !s.has(g) {
			res.Status, res.Detail = StatusNotMet, "Нет данных: источник сведений временно недоступен"
			return res
		}
	}
	param := func(name string) string {
		if v, ok := ref.Params[name]; ok {
			return v
		}
		return def.params[name].def
	}
	res.Status, res.Detail = def.fn(s, param)
	return res
}

func envMatches(env, want string) bool { return want == "any" || env == want }

func countApps(s *Snapshot, env string, ok func(AppFact) bool) (n, total int) {
	for _, a := range s.Apps {
		if !envMatches(a.Env, env) {
			continue
		}
		total++
		if ok(a) {
			n++
		}
	}
	return n, total
}

func envLabel(env string) string {
	switch env {
	case "prod":
		return "промышленной среды"
	case "test":
		return "тестовой среды"
	}
	return "всех сред"
}

func appsOf(env string) string { return "приложений " + envLabel(env) }

// ratioStatus — статус по доле: всё — выполнено, часть — частично, ничего —
// не выполнено, объектов нет — не применимо (граничный случай «0 приложений»).
func ratioStatus(n, total int, what, objects string) (Status, string) {
	if total == 0 {
		return StatusNotApplicable, "Нет " + objects + ": проверять нечего"
	}
	detail := fmt.Sprintf("%s для %d из %d %s", what, n, total, objects)
	switch n {
	case total:
		return StatusMet, detail
	case 0:
		return StatusNotMet, detail
	}
	return StatusPartial, detail
}
