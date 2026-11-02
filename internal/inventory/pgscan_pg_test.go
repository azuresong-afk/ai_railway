package inventory

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// Отчёты сканера и запрет модели на живой БД (задачи 5.21 и 5.22, миграция
// 0072): отчёт, состояние blocked и записи аудита — одной транзакцией;
// запрет и снятие меняют ревизию конфигурации (пакет шлюзов); хранятся
// последние MaxReportsPerModel отчётов; CHECK состояния и итогов.

func (e *pgEnv) revision(t *testing.T) int {
	t.Helper()
	return e.count(t, `SELECT COALESCE(max(revision), 0)::int FROM config_revisions`)
}

func TestPGInventoryScanReports(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	in, err := ParseModelInput([]byte(`{"kind":"provider","provider":"gigachat","name":"GigaChat-Pro","files":[` +
		fileJSON("model.safetensors") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	m, err := e.svc.CreateModel(ctx, e.by, in)
	if err != nil {
		t.Fatal(err)
	}
	rev := e.revision(t)
	ok := ReportInput{Kind: ReportVerify, Host: "gpu-01", ScannerVersion: "1.5.0",
		Files: []ReportFile{{Path: "model.safetensors", Size: 1024, SHA256: testHash}}}
	r, got, err := e.svc.SubmitReport(ctx, e.by, m.ID, ok)
	if err != nil || r.Verdict != VerdictOK || got.Status != StatusActive {
		t.Fatalf("совпадение: %+v %v", r, err)
	}
	if e.revision(t) != rev {
		t.Fatal("отчёт без запрета изменил ревизию конфигурации")
	}
	// Подмена весов: запрет, три записи аудита, ревизия конфигурации растёт.
	bad := ok
	bad.Files = []ReportFile{{Path: "model.safetensors", Size: 1024, SHA256: otherHash}}
	r, got, err = e.svc.SubmitReport(ctx, e.by, m.ID, bad)
	if err != nil || !r.Blocked || got.Status != StatusBlocked {
		t.Fatalf("подмена: %+v %v", r, err)
	}
	if e.revision(t) <= rev {
		t.Fatal("запрет не изменил ревизию конфигурации")
	}
	for _, a := range []string{ActionScanReported, ActionHashMismatch, ActionBlocked} {
		if want := map[string]int{ActionScanReported: 2}[a]; e.audits(t, a) != max(want, 1) {
			t.Fatalf("%s: %d записей", a, e.audits(t, a))
		}
	}
	if n := e.count(t, `SELECT count(*) FROM inventory_models WHERE id = $1 AND status = 'blocked'`, m.ID); n != 1 {
		t.Fatal("состояние в БД")
	}
	bm, err := e.svc.Blocked(ctx)
	if err != nil || len(bm) != 1 || bm[0] != (BlockedModel{Provider: "gigachat", Name: "GigaChat-Pro"}) {
		t.Fatalf("запрещённые: %+v %v", bm, err)
	}
	list, err := e.svc.Reports(ctx, m.ID)
	if err != nil || len(list) != 2 || list[0].ID != r.ID || list[0].Detail.MismatchTotal != 1 ||
		list[0].Detail.Mismatches[0].Problem != MismatchChanged || list[0].ReceivedBy == "" {
		t.Fatalf("отчёты: %+v %v", list, err)
	}
	if err := e.svc.DeleteModel(ctx, e.by, m.ID); !errors.Is(err, ErrBlocked) {
		t.Fatalf("удаление запрещённой: %v", err)
	}
	// Снятие запрета: повторная проверка, аудит, ревизия растёт.
	rev = e.revision(t)
	if _, err := e.svc.Unblock(ctx, e.by, m.ID); !errors.Is(err, ErrConfirmNeeded) {
		t.Fatalf("без проверки: %v", err)
	}
	by := e.by
	by.Confirm = func(context.Context) error { return nil }
	if got, err = e.svc.Unblock(ctx, by, m.ID); err != nil || got.Status != StatusActive {
		t.Fatalf("снятие: %+v %v", got, err)
	}
	if e.audits(t, ActionUnblocked) != 1 || e.revision(t) <= rev {
		t.Fatal("снятие: аудит или ревизия")
	}
	if bm, _ := e.svc.Blocked(ctx); len(bm) != 0 { //nolint:gosec // G104: ошибка даёт пустой список — проверка ниже
		t.Fatalf("после снятия: %+v", bm)
	}
	// Хранятся последние отчёты.
	for i := range MaxReportsPerModel + 3 {
		e.clock.t = e.clock.t.Add(1)
		in := ok
		in.Host = fmt.Sprintf("gpu-%02d", i)
		if _, _, err := e.svc.SubmitReport(ctx, e.by, m.ID, in); err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM inventory_scan_reports WHERE model_id = $1`, m.ID); n != MaxReportsPerModel {
		t.Fatalf("отчётов в БД: %d", n)
	}
	list, _ = e.svc.Reports(ctx, m.ID) //nolint:gosec // G104: ошибку покажет проверка списка ниже
	if list[0].Host != fmt.Sprintf("gpu-%02d", MaxReportsPerModel+2) {
		t.Fatalf("первым — последний: %s", list[0].Host)
	}
	// CHECK: состояние и итоги.
	if _, err := e.owner.Exec(ctx, `UPDATE inventory_models SET status = 'deleted' WHERE id = $1`, m.ID); err == nil {
		t.Fatal("CHECK состояния")
	}
	if _, err := e.owner.Exec(ctx, `UPDATE inventory_scan_reports SET verdict = 'maybe' WHERE model_id = $1`, m.ID); err == nil {
		t.Fatal("CHECK итога")
	}
	// Удаление модели удаляет её отчёты.
	if err := e.svc.DeleteModel(ctx, e.by, m.ID); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM inventory_scan_reports WHERE model_id = $1`, m.ID); n != 0 {
		t.Fatalf("отчёты удалённой модели: %d", n)
	}
	if _, _, err := e.svc.SubmitReport(ctx, e.by, m.ID, ok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("отчёт по удалённой: %v", err)
	}
}
