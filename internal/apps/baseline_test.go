package apps_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
)

const promptText = "Ты — помощник отдела продаж.\nОтвечай только о тарифах."

func ptr(s string) *string { return &s }

// Покрывает: DM-26
// Эталон системного промпта: текст только шифротекстом, хеш — как в шлюзе,
// смена режима без текста, понижение режима и снятие — ослабление с
// повторной проверкой и weakening в аудите (DM-40).
func TestDM26_PromptBaselineLifecycle(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a := e.app(t, "sales", e.provider(t, "llm").ID, ownerA)
	if _, err := e.svc.PromptBaseline(ctx, a.ID); !errors.Is(err, apps.ErrNoPromptBaseline) {
		t.Fatalf("без эталона: %v", err)
	}
	if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Mode: apps.PromptBlock}); err == nil {
		t.Fatal("режим без текста принят")
	}
	b, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Text: ptr(promptText), Mode: apps.PromptBlock})
	if err != nil {
		t.Fatal(err)
	}
	if b.Hash != session.PromptHash(e.h, "Ты — помощник отдела продаж. Отвечай только о тарифах.") || b.Size != len(promptText) {
		t.Fatalf("хеш или размер: %+v", b)
	}
	if strings.Contains(string(b.Text.Data), "помощник") {
		t.Fatal("текст эталона хранится открыто")
	}
	if text, err := e.svc.OpenPromptText(ctx, b); err != nil || text != promptText {
		t.Fatalf("текст: %q %v", text, err)
	}
	if rec := e.last(t, "application.prompt_baseline_set"); strings.Contains(recText(t, rec), "помощник") {
		t.Fatal("текст эталона в журнале аудита")
	}
	// Повтор без изменений — без записи аудита.
	n := len(e.mem.Records())
	if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Text: ptr(" " + promptText + " "), Mode: apps.PromptBlock}); err != nil {
		t.Fatal(err)
	}
	if len(e.mem.Records()) != n {
		t.Fatal("запись аудита без изменений")
	}
	// Понижение режима без повторной проверки — отказ, с ней — weakening.
	noConfirm := e.by
	noConfirm.Confirm = nil
	if _, err := e.svc.SetPromptBaseline(ctx, noConfirm, a.ID, apps.PromptBaselineInput{Mode: apps.PromptAlert}); !errors.Is(err, apps.ErrConfirmRequired) {
		t.Fatalf("понижение без проверки: %v", err)
	}
	if got, err := e.svc.PromptBaseline(ctx, a.ID); err != nil || got.Mode != apps.PromptBlock {
		t.Fatalf("режим изменён без повторной проверки: %v", err)
	}
	if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Mode: apps.PromptAlert}); err != nil {
		t.Fatal(err)
	}
	if d := details(t, e.last(t, "application.prompt_baseline_set")); d["weakening"] != true {
		t.Fatalf("понижение режима без weakening: %v", d)
	}
	// Новый текст при том же режиме — не ослабление.
	if _, err := e.svc.SetPromptBaseline(ctx, noConfirm, a.ID, apps.PromptBaselineInput{Text: ptr("Новый промпт"), Mode: apps.PromptBlock}); err != nil {
		t.Fatal(err)
	}
	if d := details(t, e.last(t, "application.prompt_baseline_set")); d["weakening"] != false {
		t.Fatalf("повышение режима — ослабление: %v", d)
	}
	// Снятие действующего эталона — ослабление.
	if _, err := e.svc.DeletePromptBaseline(ctx, noConfirm, a.ID); !errors.Is(err, apps.ErrConfirmRequired) {
		t.Fatalf("снятие без проверки: %v", err)
	}
	if _, err := e.svc.DeletePromptBaseline(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	if d := details(t, e.last(t, "application.prompt_baseline_removed")); d["weakening"] != true {
		t.Fatalf("снятие без weakening: %v", d)
	}
	if _, err := e.svc.DeletePromptBaseline(ctx, e.by, a.ID); !errors.Is(err, apps.ErrNoPromptBaseline) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if _, err := e.svc.PromptBaseline(ctx, "01900000-0000-7000-8000-0000000000ff"); !errors.Is(err, apps.ErrNotFound) {
		t.Fatalf("чужое приложение: %v", err)
	}
}

// Граничные значения текста эталона.
func TestPromptBaselineValidation(t *testing.T) {
	e := newEnv(t, true)
	ctx := context.Background()
	a := e.app(t, "sales", e.provider(t, "llm").ID, ownerA)
	for name, in := range map[string]apps.PromptBaselineInput{
		"режим":           {Text: ptr("x"), Mode: "strict"},
		"пустой":          {Text: ptr(""), Mode: apps.PromptAlert},
		"пробелы":         {Text: ptr(" \n\t "), Mode: apps.PromptAlert},
		"слишком длинный": {Text: ptr(strings.Repeat("я", session.MaxPrompt/2+1)), Mode: apps.PromptAlert},
		"не UTF-8":        {Text: ptr("a\xffb"), Mode: apps.PromptAlert},
		"управляющий":     {Text: ptr("a\x00b"), Mode: apps.PromptAlert},
		"ESC":             {Text: ptr("a\x1b[31mb"), Mode: apps.PromptAlert},
	} {
		var ie *apps.InputError
		if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, in); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Text: ptr(strings.Repeat("a", session.MaxPrompt)), Mode: apps.PromptOff}); err != nil {
		t.Fatalf("промпт на пределе: %v", err)
	}
	// Без ключа данных текст не задать.
	e2 := newEnv(t, false)
	a2 := e2.app(t, "sales", e2.provider(t, "llm").ID, ownerA)
	if _, err := e2.svc.SetPromptBaseline(ctx, e2.by, a2.ID, apps.PromptBaselineInput{Text: ptr("x"), Mode: apps.PromptAlert}); !errors.Is(err, apps.ErrNoDataKey) {
		t.Fatalf("без ключа данных: %v", err)
	}
}

func details(t *testing.T, rec audit.Entry) map[string]any {
	t.Helper()
	d, ok := rec.Details.(map[string]any)
	if !ok {
		t.Fatalf("подробности записи %s: %T", rec.Action, rec.Details)
	}
	return d
}

func recText(t *testing.T, rec audit.Entry) string {
	t.Helper()
	b, err := json.Marshal(rec.Details)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
