package alerting

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Встроенные системные правила и правила безопасности (ТЗ 5.6, 5.16:
// DM-38–DM-44; раздел 7: ИАФ.4, ИАФ.5, УПД.6, РСБ.4, РСБ.5, ОЦЛ.5, ВРМ.1;
// задача 3.11 этапа 3). Не отключаются: у них меняются только получатели.
// Срабатывают по записям журнала аудита в транзакции записи (OnAudit) и по
// событиям auth_failure в транзакции приёма (DM-38).
const (
	BuiltinGatewayAuth    = "security.gateway_auth"       // DM-38
	BuiltinConsoleBrute   = "security.console_bruteforce" // DM-39, ИАФ.4
	BuiltinAccessDenied   = "security.access_denied"      // DM-39, УПД.6
	BuiltinWeakening      = "security.weakening"          // DM-40, ИАФ.5
	BuiltinContentAccess  = "security.content_access"     // DM-41
	BuiltinIntegrity      = "system.integrity"            // DM-42, ОЦЛ.5
	BuiltinAuditChain     = "system.audit_chain"          // DM-43, РСБ.4
	BuiltinEventsDropped  = "system.events_dropped"       // DM-44
	BuiltinGatewayOffline = "system.gateway_offline"      // DM-44
	BuiltinTimeSync       = "system.time_sync"            // DM-44, ВРМ.1
	BuiltinAuditStorage   = "system.audit_storage"        // DM-44, РСБ.5
	BuiltinCertExpiry     = "system.cert_expiry"          // DM-44
	BuiltinReportsStale   = "system.reports_stale"        // DM-44, Н29
	BuiltinConfigBundle   = "system.config_bundle"        // ОЦЛ.3
	BuiltinNotifyFailed   = "system.notify_failed"        // DM-44: уведомление не доставлено
)

// Пороги правил безопасности (обоснование — ADR-0020, раздел «Пороги
// системных правил и правил безопасности»).
const (
	// ConsoleFailThreshold неудачных попыток входа в консоль, второго
	// фактора и токенов API с одного адреса за ConsoleFailWindow — перебор
	// (DM-39). Блокировка одной учётной записи (5 попыток, ИАФ.4) даёт
	// оповещение сразу; порог по адресу ловит перебор по многим записям.
	ConsoleFailThreshold = 10
	ConsoleFailWindow    = 10 * time.Minute
	// DeniedThreshold отказов в доступе к функциям управления одному
	// субъекту за DeniedWindow (УПД.6, DM-39). Консоль скрывает недоступные
	// действия, поэтому серия отказов — попытка, а не случайность.
	DeniedThreshold = 3
	DeniedWindow    = 10 * time.Minute
	// ContentReadThreshold просмотров содержимого событий одним субъектом
	// за ContentReadWindow — массовый просмотр (DM-41).
	ContentReadThreshold = 20
	ContentReadWindow    = 10 * time.Minute
	// LargeExportRows — выгрузка событий от этого числа строк крупная
	// (DM-41); ExportThreshold выгрузок одного субъекта за ExportWindow —
	// тоже.
	LargeExportRows = 10000
	ExportThreshold = 5
	ExportWindow    = time.Hour
	// WeakeningGroupMinutes — окно группировки DM-40 (ТЗ 5.6).
	WeakeningGroupMinutes = 10
	// maxSystemDetails — предел подробностей system.alert в оповещении:
	// больше — только код условия и требование (столбец details до 16 КиБ).
	maxSystemDetails = 4096
)

// securityRules — встроенные правила задачи 3.11.
func securityRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	rule := func(key, kind, name, desc, sev string, group []string) Rule {
		return Rule{BuiltinKey: key, Kind: kind, Name: name, Description: desc, Enabled: true, Severity: sev,
			GroupBy: group, SuppressMinutes: DefaultSuppressMinutes, Recipients: none}
	}
	weak := rule(BuiltinWeakening, KindSecurity, "Ослабление защиты",
		"DM-40: перевод политики в monitor, отключение или ослабление правила, понижение действия, режим хранения none или full, "+
			"сокращение сроков хранения, снятие признака «внешний», сброс второго фактора, отключение канала уведомлений. "+
			"Изменения одного пользователя за 10 минут — одно оповещение со списком изменений.", "high", []string{"actor"})
	weak.GroupMinutes = WeakeningGroupMinutes
	return []Rule{
		rule(BuiltinGatewayAuth, KindSecurity, "Перебор или отозванный ключ на шлюзе",
			"DM-38: шлюз заблокировал адрес после серии неудачных попыток, запрос с отозванным ключом "+
				"или ключ вне разрешённых адресов. Ключ — только префикс.", "high", []string{"remote_addr", "key_prefix"}),
		rule(BuiltinConsoleBrute, KindSecurity, "Перебор паролей к консоли",
			"DM-39, ИАФ.4: учётная запись заблокирована после неудачных попыток или с одного адреса "+
				strconv.Itoa(ConsoleFailThreshold)+" и более неудачных входов, кодов второго фактора и токенов API за 10 минут.",
			"high", []string{"source_ip", "account"}),
		rule(BuiltinAccessDenied, KindSecurity, "Отказы в доступе к управлению",
			"DM-39, УПД.6: "+strconv.Itoa(DeniedThreshold)+" и более отказов в доступе к функциям управления одному субъекту за 10 минут.",
			"medium", []string{"actor"}),
		weak,
		rule(BuiltinContentAccess, KindSecurity, "Массовый просмотр содержимого или крупная выгрузка",
			"DM-41: "+strconv.Itoa(ContentReadThreshold)+" и более просмотров содержимого событий одним субъектом за 10 минут, "+
				"выгрузка от "+strconv.Itoa(LargeExportRows)+" строк или "+strconv.Itoa(ExportThreshold)+" выгрузок за час.",
			"high", []string{"actor"}),
		rule(BuiltinIntegrity, KindSystem, "Нарушена целостность компонента",
			"DM-42, ОЦЛ.5: провал контроля целостности или самотеста, откат выпуска, чужой ключ пакетов, отклонённый шлюзом пакет, "+
				"сборка не для поставки.", "critical", []string{"component"}),
		rule(BuiltinAuditChain, KindSystem, "Нарушена цепочка журнала аудита",
			"DM-43, РСБ.4: проверка цепочки хешей журнала аудита нашла изменённые или удалённые записи.", "critical", []string{}),
		rule(BuiltinEventsDropped, KindSystem, "Шлюз отбрасывает события",
			"DM-44: счётчик отброшенных событий шлюза вырос — часть событий не дойдёт до сервера.", "high", []string{"gateway"}),
		rule(BuiltinGatewayOffline, KindSystem, "Шлюз недоступен",
			"DM-44: действующий шлюз не выходил на связь дольше трёх периодов heartbeat.", "high", []string{"gateway"}),
		rule(BuiltinTimeSync, KindSystem, "Время не синхронизировано",
			"DM-44, ВРМ.1: часы сервера не синхронизированы — время событий и аудита ненадёжно.", "medium", []string{}),
		rule(BuiltinAuditStorage, KindSystem, "Журнал аудита приближается к пределу хранилища",
			"DM-44, РСБ.5: заполнение хранилища журнала аудита достигло порога предупреждения.", "high", []string{}),
		rule(BuiltinCertExpiry, KindSystem, "Скоро истекает сертификат",
			"DM-44, ИАФ.10: сертификат шлюза истекает меньше чем через 14 суток (автоматический перевыпуск не сработал) "+
				"или корню внутреннего УЦ осталось 60 суток и меньше.",
			"medium", []string{"certificate"}),
		rule(BuiltinReportsStale, KindSystem, "Нет данных контроля целостности шлюза",
			"DM-44, Н29: шлюз на связи, но итог контроля целостности старше двух периодов проверки или не приходит.",
			"high", []string{"gateway"}),
		rule(BuiltinConfigBundle, KindSystem, "Пакет конфигурации шлюзов не применён",
			"ОЦЛ.3: пакет собран не полностью или шлюз работает на устаревшем пакете.", "medium", []string{"component"}),
		rule(BuiltinNotifyFailed, KindSystem, "Уведомление не доставлено",
			"DM-44: канал уведомлений не доставил сообщение после всех повторов.", "high", []string{"channel"}),
	}
}

// auditCount — выборка для подсчёта записей аудита в окне правила.
type auditCount struct {
	Actions []string
	// Since — начало окна по времени записей (часы сервера).
	Since time.Time
	// SourceIP — только записи с этого адреса; невалидный — любой.
	SourceIP netip.Addr
	// ActorType и ActorID — только записи этого субъекта; пусто — любого.
	ActorType string
	ActorID   string
}

// secOps — действия правил по журналу аудита в транзакции записи.
type secOps interface {
	txOps
	// countAudit — записей организации, подходящих под q, вместе с только
	// что вставленной.
	countAudit(ctx context.Context, orgID string, q auditCount) (int, error)
}

// auditRules — правила безопасности и системные правила по записи журнала
// аудита r в транзакции её записи.
func auditRules(ctx context.Context, ops secOps, r *audit.Record) error {
	raises, err := classifyAudit(ctx, ops, r)
	if err != nil || len(raises) == 0 {
		return err
	}
	return raiseBuiltin(ctx, ops, raises)
}

// recordDetails — подробности записи; неразборные — пустые (каноническая
// форма, записанная журналом, всегда разбирается).
func recordDetails(r *audit.Record) map[string]any {
	var d map[string]any
	if len(r.Details) > 0 {
		_ = json.Unmarshal(r.Details, &d) //nolint:gosec // G104: каноническая форма журнала; ошибка — без подробностей
	}
	if d == nil {
		d = map[string]any{}
	}
	return d
}

// actorName — субъект для заголовка оповещения: имя или ID.
func actorName(a audit.Actor) string {
	if a.Name != "" {
		return a.Name
	}
	return a.ID
}

// actorKey — устойчивый ключ субъекта: тип и ID.
func actorKey(a audit.Actor) string { return string(a.Type) + ":" + a.ID }

// item — элемент списка подробностей оповещения по записи аудита.
func item(r *audit.Record, extra map[string]any) map[string]any {
	it := map[string]any{"action": r.Action, "audit_id": r.ID, "at": r.TS.UTC().Format(time.RFC3339Nano)}
	if r.Object.Type != "" {
		it["object_type"] = r.Object.Type
	}
	if r.Object.ID != "" {
		it["object_id"] = r.Object.ID
	}
	for k, v := range extra {
		it[k] = v
	}
	return it
}

// raiseOf — срабатывание встроенного правила key: ключ дедупликации —
// поля keyFields из keyValues, заголовок — по values.
func raiseOf(key string, keyValues, values map[string]string, count int, details map[string]any) Raise {
	fields := make([]string, 0, len(keyValues))
	for f := range keyValues {
		fields = append(fields, f)
	}
	slices.Sort(fields)
	return Raise{Key: key, Trigger: Trigger{Key: GroupKey(fields, keyValues), Values: values, Count: int64(max(count, 1)),
		Details: details}}
}

// countFor — число записей в окне; при достижении порога ровно сейчас
// оповещение получает весь счёт, дальше каждая запись добавляет единицу.
func countFor(n, threshold int) int {
	if n == threshold {
		return n
	}
	return 1
}

// classifyAudit — срабатывания встроенных правил по записи r.
func classifyAudit(ctx context.Context, ops secOps, r *audit.Record) ([]Raise, error) {
	var raises []Raise
	var d map[string]any
	details := func() map[string]any {
		if d == nil {
			d = recordDetails(r)
		}
		return d
	}
	switch r.Action {
	case "auth.locked":
		// ИАФ.4: блокировка учётной записи — оповещение сразу.
		raises = append(raises, raiseOf(BuiltinConsoleBrute, map[string]string{"account": r.Object.ID},
			map[string]string{"account": actorName(r.Actor)}, 1,
			map[string]any{"items": []any{item(r, map[string]any{"source_ip": addrString(r.SourceIP)})}}))
	case "auth.login_failed", "auth.mfa_failed", "api_token.auth_failed":
		if !r.SourceIP.IsValid() {
			break
		}
		n, err := ops.countAudit(ctx, r.OrgID, auditCount{Actions: []string{"auth.login_failed", "auth.mfa_failed", "api_token.auth_failed"},
			Since: r.TS.Add(-ConsoleFailWindow), SourceIP: r.SourceIP})
		if err != nil {
			return nil, err
		}
		if n >= ConsoleFailThreshold {
			ip := addrString(r.SourceIP)
			raises = append(raises, raiseOf(BuiltinConsoleBrute, map[string]string{"source_ip": ip},
				map[string]string{"source_ip": ip}, countFor(n, ConsoleFailThreshold),
				map[string]any{"window_minutes": int(ConsoleFailWindow / time.Minute), "failures_in_window": n}))
		}
	case "access.denied":
		n, err := ops.countAudit(ctx, r.OrgID, auditCount{Actions: []string{"access.denied"}, Since: r.TS.Add(-DeniedWindow),
			ActorType: string(r.Actor.Type), ActorID: r.Actor.ID})
		if err != nil {
			return nil, err
		}
		if n >= DeniedThreshold {
			dd := details()
			raises = append(raises, raiseOf(BuiltinAccessDenied, map[string]string{"actor": actorKey(r.Actor)},
				map[string]string{"actor": actorName(r.Actor)}, countFor(n, DeniedThreshold),
				map[string]any{"denials_in_window": n, "items": []any{item(r, map[string]any{"path": dd["path"], "permission": dd["permission"]})}}))
		}
	case "events.content_read":
		n, err := ops.countAudit(ctx, r.OrgID, auditCount{Actions: []string{"events.content_read"},
			Since: r.TS.Add(-ContentReadWindow), ActorType: string(r.Actor.Type), ActorID: r.Actor.ID})
		if err != nil {
			return nil, err
		}
		if n >= ContentReadThreshold {
			raises = append(raises, raiseOf(BuiltinContentAccess, map[string]string{"actor": actorKey(r.Actor)},
				map[string]string{"actor": actorName(r.Actor)}, countFor(n, ContentReadThreshold),
				map[string]any{"content_reads_in_window": n}))
		}
	case "data.export":
		rows, _ := details()["rows"].(float64)
		n, err := ops.countAudit(ctx, r.OrgID, auditCount{Actions: []string{"data.export"}, Since: r.TS.Add(-ExportWindow),
			ActorType: string(r.Actor.Type), ActorID: r.Actor.ID})
		if err != nil {
			return nil, err
		}
		if rows >= LargeExportRows || n >= ExportThreshold {
			raises = append(raises, raiseOf(BuiltinContentAccess, map[string]string{"actor": actorKey(r.Actor)},
				map[string]string{"actor": actorName(r.Actor)}, 1,
				map[string]any{"items": []any{item(r, map[string]any{"rows": int64(rows), "exports_in_hour": n})}}))
		}
	case "system.alert":
		if x, ok := systemRaise(r, details()); ok {
			raises = append(raises, x)
		}
	case "audit.chain_broken":
		raises = append(raises, raiseOf(BuiltinAuditChain, map[string]string{"condition": "audit_chain"}, map[string]string{}, 1,
			map[string]any{"items": []any{item(r, map[string]any{"reason": details()["reason"], "broken_seq": details()["broken_seq"]})}}))
	case "bundle.rejected", "gateway.bundle_key_mismatch":
		// Шлюз отверг пакет (подпись, версия) или прислал чужой ключ
		// получателя: возможна подмена пакета (DM-42).
		comp := "gateway:" + r.Actor.ID
		if r.Actor.Type != audit.ActorGateway {
			comp = r.Object.Type + ":" + r.Object.ID
		}
		raises = append(raises, raiseOf(BuiltinIntegrity, map[string]string{"component": comp},
			map[string]string{"component": comp}, 1, map[string]any{"items": []any{item(r, map[string]any{"reason": details()["reason"]})}}))
	case "notify.delivery_failed":
		raises = append(raises, raiseOf(BuiltinNotifyFailed, map[string]string{"channel": r.Object.ID},
			map[string]string{"channel": str(details()["channel_name"], r.Object.ID)}, 1,
			map[string]any{"items": []any{item(r, map[string]any{"error": details()["error"], "attempts": details()["attempts"]})}}))
	}
	if reasons, ok := weakening(r, details); ok {
		raises = append(raises, raiseOf(BuiltinWeakening, map[string]string{"actor": actorKey(r.Actor)},
			map[string]string{"actor": actorName(r.Actor)}, 1,
			map[string]any{"items": []any{item(r, map[string]any{"reasons": reasons})}}))
	}
	return raises, nil
}

// str — строковое значение или замена.
func str(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}

func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// weakening — запись об ослаблении защиты (DM-40, ТЗ 5.16): признак
// weakening, который ставят сервисы (политики, приложения, провайдеры,
// вход, оповещения, каналы), сброс второго фактора (ИАФ.5), сокращение
// сроков хранения событий и журнала аудита, отключение событий аудита.
func weakening(r *audit.Record, details func() map[string]any) ([]any, bool) {
	if r.Result != audit.ResultSuccess {
		return nil, false
	}
	switch r.Action {
	case "auth.mfa_reset":
		return []any{"mfa_reset"}, true
	case "events.settings_changed":
		if b, _ := details()["reduced"].(bool); b {
			return []any{"retention_reduced"}, true
		}
		return nil, false
	case "audit.settings_changed":
		return auditSettingsWeakened(details())
	}
	d := details()
	if b, _ := d["weakening"].(bool); !b {
		return nil, false
	}
	reasons, _ := d["weakening_reasons"].([]any)
	if reasons == nil {
		reasons = []any{}
	}
	return reasons, true
}

// auditSettingsWeakened — сокращён срок хранения журнала аудита или
// отключены новые необязательные события (РСБ.3).
func auditSettingsWeakened(d map[string]any) ([]any, bool) {
	before, _ := d["before"].(map[string]any)
	after, _ := d["after"].(map[string]any)
	if before == nil || after == nil {
		return nil, false
	}
	var reasons []any
	if b, a := before["retention_days"], after["retention_days"]; numLess(a, b) {
		reasons = append(reasons, "retention_reduced")
	}
	was, _ := before["disabled_actions"].([]any)
	now, _ := after["disabled_actions"].([]any)
	for _, x := range now {
		if !slices.Contains(was, x) {
			reasons = append(reasons, "audit_event_disabled")
			break
		}
	}
	return reasons, len(reasons) > 0
}

func numLess(a, b any) bool {
	x, ok1 := a.(float64)
	y, ok2 := b.(float64)
	return ok1 && ok2 && x < y
}

// systemFamilies — семейство условия раздела 7 → встроенное правило.
var systemFamilies = map[string]string{
	"integrity":         BuiltinIntegrity,
	"test_build":        BuiltinIntegrity,
	"audit_chain":       BuiltinAuditChain,
	"time_sync":         BuiltinTimeSync,
	"audit_storage":     BuiltinAuditStorage,
	"config_bundle":     BuiltinConfigBundle,
	"config_bundle_lag": BuiltinConfigBundle,
	"events_dropped":    BuiltinEventsDropped,
	"gateway_offline":   BuiltinGatewayOffline,
	"cert_expiry":       BuiltinCertExpiry,
	"ca_expiry":         BuiltinCertExpiry,
	"reports_stale":     BuiltinReportsStale,
}

// systemRaise — оповещение по возникшему условию раздела 7 (запись
// system.alert с state = raised). Снятие условия оповещение не закрывает:
// его закрывает человек после разбора.
func systemRaise(r *audit.Record, d map[string]any) (Raise, bool) {
	if d["state"] != "raised" {
		return Raise{}, false
	}
	code := r.Object.ID
	fam, _, _ := strings.Cut(code, ":")
	key, ok := systemFamilies[fam]
	if !ok {
		return Raise{}, false
	}
	values := map[string]string{}
	switch key {
	case BuiltinIntegrity, BuiltinConfigBundle:
		comp := str(d["component"], code)
		if n := str(d["gateway_name"], ""); n != "" {
			comp += " (" + n + ")"
		}
		values["component"] = comp
	case BuiltinEventsDropped, BuiltinGatewayOffline, BuiltinReportsStale:
		values["gateway"] = str(d["gateway_name"], strings.TrimPrefix(code, fam+":"))
	case BuiltinCertExpiry:
		// Условие ca_expiry (корень внутреннего УЦ) ведёт sysstatus с задачи
		// 3В5; ca_expiry:critical — второе условие за 7 суток.
		values["certificate"] = "корень УЦ"
		if fam == "cert_expiry" {
			values["certificate"] = "шлюз " + str(d["gateway_name"], strings.TrimPrefix(code, fam+":"))
		}
	}
	det := map[string]any{"condition": code, "requirement": d["requirement"]}
	if raw, err := json.Marshal(d); err == nil && len(raw) <= maxSystemDetails {
		det = map[string]any{}
		for k, v := range d {
			if k != "state" {
				det[k] = v
			}
		}
	}
	det["audit_id"] = r.ID
	return raiseOf(key, map[string]string{"condition": code}, values, 1, det), true
}
