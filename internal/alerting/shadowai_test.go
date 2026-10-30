package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// shadowRecords — записи аудита импорта синтетического журнала Squid в
// теневой ИИ (хранилище в памяти).
func shadowRecords(t *testing.T, logs ...string) []audit.Entry {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	mac, err := p.NewMAC(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	m := shadowai.NewMemory()
	svc, err := shadowai.New(shadowai.Options{Store: m, Provider: p, UserMAC: mac,
		Clock: func() time.Time { return time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	cat, err := os.ReadFile("../../testdata/shadowai/catalog-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	by := shadowai.By{Actor: tUser}
	if _, err := svc.UploadCatalog(context.Background(), by, cat); err != nil {
		t.Fatal(err)
	}
	for _, l := range logs {
		if _, err := svc.Import(context.Background(), by, shadowai.FormatSquid, strings.NewReader(l)); err != nil {
			t.Fatal(err)
		}
	}
	var out []audit.Entry
	for _, r := range m.Records() {
		if r.Action == "shadow_ai.new_service" {
			out = append(out, r)
		}
	}
	return out
}

// TestDM37_NewServiceAlert — сервис каталога, которого не было в сводках
// теневого ИИ за 30 суток, даёт оповещение встроенного правила «новое»
// shadow_ai.new_service: одно на сервис, в заголовке — название сервиса и
// число пользователей, в подробностях нет логинов и псевдонимов; правило
// можно отключить. Покрывает: DM-37.
func TestDM37_NewServiceAlert(t *testing.T) {
	e := newEnv(t)
	log, err := os.ReadFile("../../testdata/shadowai/access-squid.log")
	if err != nil {
		t.Fatal(err)
	}
	recs := shadowRecords(t, string(log))
	if len(recs) < 2 {
		t.Fatalf("записей о новых сервисах %d", len(recs))
	}
	for _, r := range recs {
		e.audit(t, e.rec(t, r.Actor, "", r.Action, r.Object, r.Result, r.Details))
	}
	// Повтор той же записи (две партии одновременно — исключено блокировкой,
	// но ключ дедупликации — ID сервиса) не даёт второго оповещения.
	e.audit(t, e.rec(t, recs[0].Actor, "", recs[0].Action, recs[0].Object, recs[0].Result, recs[0].Details))
	got := e.alerts(t, BuiltinShadowNewService)
	if len(got) != len(recs) {
		t.Fatalf("оповещений %d, сервисов %d: %+v", len(got), len(recs), got)
	}
	var chatgpt *Alert
	for i := range got {
		a := &got[i]
		if a.Kind != KindNew || a.Severity != "medium" {
			t.Fatalf("оповещение: %+v", a)
		}
		if strings.Contains(a.Title, "ChatGPT") {
			chatgpt = a
		}
		for _, bad := range []string{"ivanov", "petrova", "10.0.12"} {
			if strings.Contains(a.Title+detailsText(t, a.Details), bad) {
				t.Fatalf("в оповещении %q: %+v", bad, a)
			}
		}
	}
	if chatgpt == nil || !strings.Contains(chatgpt.Title, "пользователей: 1") {
		t.Fatalf("оповещение о ChatGPT: %+v", got)
	}
	// Неуспешная запись оповещения не даёт.
	e.audit(t, e.rec(t, tUser, "", "shadow_ai.new_service", audit.Object{Type: "shadow_ai_service", ID: "poe"}, audit.ResultFailure,
		map[string]any{"service": "poe", "users": 3}))
	if n := len(e.alerts(t, BuiltinShadowNewService)); n != len(recs) {
		t.Fatalf("неуспешная запись дала оповещение: %d", n)
	}
	r := e.rule(t, BuiltinShadowNewService)
	if Locked(r.Kind) || r.Condition.Field != ShadowServiceField {
		t.Fatalf("правило: %+v", r)
	}
	off := false
	in := RuleInput{Name: r.Name, Description: r.Description, Enabled: &off, Severity: r.Severity, Condition: r.Condition,
		SuppressMinutes: &r.SuppressMinutes, Recipients: r.Recipients, Version: r.Version}
	if _, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, in); err != nil {
		t.Fatalf("отключение правила: %v", err)
	}
}

// Поле shadow_ai_service — только у встроенного правила.
func TestShadowServiceFieldOnlyBuiltin(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var ie *InputError
	if _, err := e.svc.CreateRule(ctx, e.admin, RuleInput{Kind: KindNew, Name: "Свои сервисы",
		Condition: Condition{Field: ShadowServiceField}}); !errors.As(err, &ie) {
		t.Fatalf("создание по shadow_ai_service: %v", err)
	}
	r := e.rule(t, BuiltinShadowNewService)
	in := RuleInput{Name: r.Name, Description: r.Description, Severity: r.Severity, Condition: Condition{Field: "model"},
		SuppressMinutes: &r.SuppressMinutes, Recipients: r.Recipients, Version: r.Version}
	if _, err := e.svc.UpdateRule(ctx, e.admin, r.ID, in); !errors.As(err, &ie) {
		t.Fatalf("смена поля встроенного: %v", err)
	}
}

func detailsText(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 4В27: импорт журнала, добавивший больше ShadowAliasProbeThreshold новых
// псевдонимов от одного субъекта за импорт или за сутки, — оповещение
// безопасности security.shadow_ai_alias_probe (правило не отключается);
// импорт до порога — нет. Покрывает: DM-37.
func TestDM37_AliasProbeAlert(t *testing.T) {
	e := newEnv(t)
	imp := func(details map[string]any) {
		e.audit(t, e.rec(t, tUser, "", "shadow_ai.import", audit.Object{Type: "shadow_ai_import", ID: "i"}, audit.ResultSuccess, details))
	}
	imp(map[string]any{"users": 300, "new_users": ShadowAliasProbeThreshold, "new_users_day": ShadowAliasProbeThreshold})
	if got := e.alerts(t, BuiltinShadowAliasProbe); len(got) != 0 {
		t.Fatalf("до порога: %+v", got)
	}
	// За сутки набралось больше порога, хотя в импорте — немного.
	imp(map[string]any{"users": 10, "new_users": 10, "new_users_day": ShadowAliasProbeThreshold + 10})
	got := e.alerts(t, BuiltinShadowAliasProbe)
	if len(got) != 1 || got[0].Kind != KindSecurity || got[0].Severity != "high" {
		t.Fatalf("перебор за сутки: %+v", got)
	}
	if !strings.Contains(detailsText(t, got[0].Details), `"new_users_day":510`) {
		t.Fatalf("подробности: %s", detailsText(t, got[0].Details))
	}
	if r := e.rule(t, BuiltinShadowAliasProbe); !Locked(r.Kind) {
		t.Fatalf("правило отключаемо: %+v", r)
	}
}

// 4В28: исходный состав (первый импорт с пользователями) не освобождается
// от правила: при пустых сводках — свежая установка или очистка по сроку —
// первый импорт перебором строил бы таблицу без оповещения. Покрывает: DM-37.
func TestDM37_AliasProbeBaselineAlert(t *testing.T) {
	e := newEnv(t)
	e.audit(t, e.rec(t, tUser, "", "shadow_ai.import", audit.Object{Type: "shadow_ai_import", ID: "i"}, audit.ResultSuccess,
		map[string]any{"users": 4000, "new_users": 4000, "new_users_day": 4000, "baseline": true}))
	got := e.alerts(t, BuiltinShadowAliasProbe)
	if len(got) != 1 || !strings.Contains(detailsText(t, got[0].Details), `"baseline":true`) {
		t.Fatalf("исходный состав: %+v", got)
	}
}
