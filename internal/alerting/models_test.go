package alerting

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Правила сканера моделей (задачи 5.21 и 5.22 этапа 5, ADR-0029,
// дополнение 1): подмена файлов и запрет по отчёту сканера.

const testModelID = "01900000-0000-7000-8000-000000000b01"

func modelObj() audit.Object { return audit.Object{Type: "inventory_model", ID: testModelID} }

// DM-29 (этап 5), ТЗ 5.12: расхождение файлов весов или адаптеров модели с
// эталонными хешами реестра (запись models.hash_mismatch) — критическое
// оповещение по модели; правило не отключается; хешей в оповещении нет,
// только виды расхождений и пути. Повтор по той же модели — то же
// оповещение, другая модель — новое.
//
// Покрывает: DM-29
func TestDM29_HashMismatchAlert(t *testing.T) {
	e := newEnv(t)
	r := e.rule(t, BuiltinModelsHashMismatch)
	if !Locked(r.Kind) || !r.Enabled || r.Severity != "critical" {
		t.Fatalf("правило: %+v", r)
	}
	off := false
	if _, err := e.svc.UpdateRule(context.Background(), e.admin, r.ID, RuleInput{Enabled: &off, Version: r.Version,
		Recipients: Recipients{Roles: []string{}, Users: []string{}}}); !errors.Is(err, ErrLocked) {
		t.Fatalf("отключение: %v", err)
	}
	details := map[string]any{"provider": "vllm", "name": "llama-ft", "report": "rep-1", "host": "gpu-01", "kind": "verify",
		"changed": 1, "missing": 0, "extra": 1, "not_hashed": 0, "total": 2, "paths": []string{"model.safetensors", "lora.safetensors"}}
	e.audit(t, e.rec(t, tUser, "", "models.hash_mismatch", modelObj(), audit.ResultSuccess, details))
	got := e.alerts(t, BuiltinModelsHashMismatch)
	if len(got) != 1 {
		t.Fatalf("оповещений %d: %+v", len(got), got)
	}
	a := got[0]
	if a.Severity != "critical" || a.Kind != KindSecurity || a.Status != StatusNew || !strings.Contains(a.Title, "vllm/llama-ft") {
		t.Fatalf("оповещение: %+v", a)
	}
	items, _ := a.Details["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("подробности: %+v", a.Details)
	}
	it, _ := items[0].(map[string]any)
	if it["host"] != "gpu-01" || it["changed"] != float64(1) || it["extra"] != float64(1) || it["model_id"] != testModelID {
		t.Fatalf("элемент: %+v", it)
	}
	// Повтор по той же модели — то же оповещение.
	e.audit(t, e.rec(t, tUser, "", "models.hash_mismatch", modelObj(), audit.ResultSuccess, details))
	if got := e.alerts(t, BuiltinModelsHashMismatch); len(got) != 1 || got[0].Count != 2 {
		t.Fatalf("повтор: %+v", got)
	}
	// Запрет по отчёту из-за хешей не поднимает правило сканера.
	e.audit(t, e.rec(t, tUser, "", "models.scan_reported", modelObj(), audit.ResultSuccess,
		map[string]any{"name": "llama-ft", "provider": "vllm", "verdict": "block", "block_reasons": []string{"hash_mismatch"}}))
	if got := e.alerts(t, BuiltinModelsScanBlocked); len(got) != 0 {
		t.Fatalf("правило сканера по расхождению хешей: %+v", got)
	}
	// Неуспешная запись не поднимает правило.
	other := audit.Object{Type: "inventory_model", ID: "01900000-0000-7000-8000-000000000b02"}
	e.audit(t, e.rec(t, tUser, "", "models.hash_mismatch", other, audit.ResultFailure, details))
	if got := e.alerts(t, BuiltinModelsHashMismatch); len(got) != 1 {
		t.Fatalf("неуспешная запись: %+v", got)
	}
}

// DM-27, DM-28 (этап 5): отчёт сканера, запретивший модель по находке с
// запретом или по шаблону чата, поднимает правило models.scan_blocked;
// отчёт без запрета — нет.
func TestModelsScanBlockedAlert(t *testing.T) {
	e := newEnv(t)
	r := e.rule(t, BuiltinModelsScanBlocked)
	if !Locked(r.Kind) || !r.Enabled || r.Severity != "high" {
		t.Fatalf("правило: %+v", r)
	}
	e.audit(t, e.rec(t, tUser, "", "models.scan_reported", modelObj(), audit.ResultSuccess,
		map[string]any{"name": "llama-ft", "verdict": "warn", "templates": "changed"}))
	if got := e.alerts(t, BuiltinModelsScanBlocked); len(got) != 0 {
		t.Fatalf("без запрета: %+v", got)
	}
	e.audit(t, e.rec(t, tUser, "", "models.scan_reported", modelObj(), audit.ResultSuccess,
		map[string]any{"name": "llama-ft", "verdict": "block", "templates": "injection", "findings": 2,
			"block_reasons": []string{"scan", "chat_template", "hash_mismatch"}}))
	got := e.alerts(t, BuiltinModelsScanBlocked)
	if len(got) != 1 || got[0].Severity != "high" || !strings.Contains(got[0].Title, "llama-ft") {
		t.Fatalf("оповещение: %+v", got)
	}
	items, _ := got[0].Details["items"].([]any)
	it, _ := items[0].(map[string]any)
	reasons, _ := it["reasons"].([]any)
	if len(reasons) != 2 || reasons[0] != "scan" || reasons[1] != "chat_template" {
		t.Fatalf("причины: %+v", it)
	}
	// Снятие запрета (models.unblocked) — ослабление защиты (DM-40).
	e.audit(t, e.rec(t, tUser, "", "models.unblocked", modelObj(), audit.ResultSuccess,
		map[string]any{"name": "llama-ft", "weakening": true, "weakening_reasons": []string{"model_unblocked"}}))
	if got := e.alerts(t, BuiltinWeakening); len(got) != 1 {
		t.Fatalf("ослабление: %+v", got)
	}
}
