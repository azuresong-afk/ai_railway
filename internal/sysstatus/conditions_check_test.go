package sysstatus_test

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/servicedb/kinds"
	"github.com/azuresong-afk/ai_railway/internal/sysstatus"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Пример ID шлюза — UUID, как в реестре шлюзов.
const sampleGatewayID = "0192a000-0000-7000-8000-000000000001"

// dbKindNames — виды служебных баз выпуска (коды service_db_*:<вид>).
func dbKindNames() []string {
	var out []string
	for _, k := range kinds.All() {
		out = append(out, k.Name)
	}
	return out
}

// conditionCheck — ограничение system_alert_state_condition_check из
// последней миграции, которая его задаёт: список кодов IN и шаблоны ~.
type conditionCheck struct {
	file     string
	literals map[string]bool
	patterns []*regexp.Regexp
}

var (
	reInList  = regexp.MustCompile(`(?s)condition IN \(([^)]*)\)`)
	reQuoted  = regexp.MustCompile(`'([^']*)'`)
	rePattern = regexp.MustCompile(`condition ~ '([^']*)'`)
)

func loadConditionCheck(t *testing.T) conditionCheck {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(names)
	var cc conditionCheck
	for _, n := range names {
		b, err := fs.ReadFile(migrations.FS, n)
		if err != nil {
			t.Fatal(err)
		}
		const marker = "ADD CONSTRAINT system_alert_state_condition_check"
		i := strings.LastIndex(string(b), marker)
		if i < 0 {
			continue
		}
		stmt := string(b[i:])
		if j := strings.Index(stmt, ";"); j >= 0 {
			stmt = stmt[:j]
		}
		cc = conditionCheck{file: n, literals: map[string]bool{}}
		m := reInList.FindStringSubmatch(stmt)
		if m == nil {
			t.Fatalf("%s: в ограничении нет списка IN", n)
		}
		for _, q := range reQuoted.FindAllStringSubmatch(m[1], -1) {
			cc.literals[q[1]] = true
		}
		for _, p := range rePattern.FindAllStringSubmatch(stmt, -1) {
			cc.patterns = append(cc.patterns, regexp.MustCompile(p[1]))
		}
	}
	if cc.file == "" {
		t.Fatal("ни одна миграция не задаёт system_alert_state_condition_check")
	}
	return cc
}

func (cc conditionCheck) accepts(code string) bool {
	if len([]rune(code)) > 128 {
		return false
	}
	if cc.literals[code] {
		return true
	}
	for _, re := range cc.patterns {
		if re.MatchString(code) {
			return true
		}
	}
	return false
}

// 5В5 ревью 5.r4 этапа 5 (дефект 5.49-1): каждое условие, состояние
// которого сервер хранит, принимает ограничение последней миграции —
// иначе база отвергает запись и оповещение «Состояния системы» не живёт
// между проверками. Новое условие в коде без новой миграции этот тест
// останавливает (как сверка видов аудита).
func TestStoredConditionsMatchCheck(t *testing.T) {
	cc := loadConditionCheck(t)
	if len(cc.literals) == 0 || len(cc.patterns) == 0 {
		t.Fatalf("%s: ограничение не разобрано: %d кодов, %d шаблонов", cc.file, len(cc.literals), len(cc.patterns))
	}
	codes := sysstatus.StoredConditionSamples(sampleGatewayID, dbKindNames())
	for _, code := range codes {
		if !cc.accepts(code) {
			t.Errorf("условие %q не принимает ограничение из %s: нужна новая миграция", code, cc.file)
		}
	}
	// Условия этапов 4 и 5, которых не было в 0064, — явно.
	for _, code := range []string{"shadow_ai_storage", "shadow_ai_full", "gateway_limits:" + sampleGatewayID,
		"gateway_media_overloaded:" + sampleGatewayID, "gateway_media_unavailable:" + sampleGatewayID,
		"gateway_media_selftest:" + sampleGatewayID, "service_db_previous:redteam_scenarios",
		"service_db_unused:compliance_requirements"} {
		if !cc.accepts(code) {
			t.Errorf("условие %q не принято", code)
		}
	}
	// Отказы: семейства без компонента, чужие символы, неизвестное условие.
	for _, code := range []string{"bogus", "gateway_limits", "gateway_media_selftest:", "service_db_unused",
		"service_db_unused:Kind-1", "gateway_media_overloaded:G1'--", "shadow_ai_full:" + sampleGatewayID,
		"service_db_previous:" + strings.Repeat("a", 65)} {
		if cc.accepts(code) {
			t.Errorf("неверный код %q принят", code)
		}
	}
}
