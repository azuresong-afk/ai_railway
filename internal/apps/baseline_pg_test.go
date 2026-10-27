package apps_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
)

// Эталон системного промпта на живой БД (задача 4.14, миграция 0051):
// текст только шифротекстом ключа данных с AAD места хранения, счётчик
// изменений конфигурации растёт от режима и хеша, но не от
// перешифрования, аудит без текста, снятие.
func TestPGPromptBaselineStorage(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	_, a := e.fixture(t)
	revision := func() int64 {
		var r int64
		if err := e.owner.QueryRow(ctx, `SELECT coalesce(max(revision), 0) FROM config_revisions`).Scan(&r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rev0 := revision()
	b, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Text: ptr(promptText), Mode: apps.PromptBlock})
	if err != nil {
		t.Fatal(err)
	}
	if revision() <= rev0 {
		t.Fatal("счётчик изменений конфигурации не вырос")
	}
	var sealed []byte
	if err := e.owner.QueryRow(ctx, `SELECT text_sealed FROM prompt_baselines WHERE app_id = $1`, a.ID).Scan(&sealed); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("помощник")) {
		t.Fatal("текст эталона хранится открыто")
	}
	got, err := e.svc.PromptBaseline(ctx, a.ID)
	if err != nil || got.Hash != b.Hash || got.Mode != apps.PromptBlock || got.Size != len(promptText) {
		t.Fatalf("прочитано: %+v %v", got, err)
	}
	if text, err := e.svc.OpenPromptText(ctx, got); err != nil || text != promptText {
		t.Fatalf("текст: %v", err)
	}
	moved := got
	moved.AppID = "01900000-0000-7000-8000-0000000000ff"
	if _, err := e.svc.OpenPromptText(ctx, moved); err == nil {
		t.Fatal("шифротекст расшифрован с чужим AAD")
	}
	if _, err := e.app.Exec(ctx, `UPDATE prompt_baselines SET created_by = 'x'`); sqlState(err) != "42501" {
		t.Fatalf("изменение created_by ролью сервера: %v", err)
	}
	if _, err := e.app.Exec(ctx, `UPDATE prompt_baselines SET mode = 'strict'`); sqlState(err) != "23514" {
		t.Fatalf("неизвестный режим: %v", err)
	}
	all, err := e.svc.PromptBaselines(ctx)
	if err != nil || len(all) != 1 || all[0].AppID != a.ID {
		t.Fatalf("эталоны организации: %+v %v", all, err)
	}

	// Перешифрование при ротации ключа данных — без нового пакета.
	ownerLog, err := audit.New(e.owner, mustProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	actor := audit.Actor{Type: audit.ActorCLI, ID: "uid:0", Name: "root"}
	if _, err := keyring.RotateData(ctx, e.owner, ownerLog, mustProfile(t), e.dir, audit.DefaultOrgID, actor, time.Now()); err != nil {
		t.Fatal(err)
	}
	full, err := keyring.Load(ctx, e.owner, mustProfile(t), e.dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	rev1 := revision()
	n, err := keyring.Rewrap(ctx, e.owner, full, keyring.RewrapOptions{ContentPurpose: "event-content"})
	if err != nil || n.Prompts != 1 {
		t.Fatalf("перешифрование: %+v %v", n, err)
	}
	if revision() != rev1 {
		t.Fatal("перешифрование текста изменило счётчик конфигурации")
	}
	if res, err := keyring.DestroyRetired(ctx, e.owner, ownerLog, audit.DefaultOrgID, actor); err != nil || len(res.Destroyed) != 1 {
		t.Fatalf("вывод прежней версии: %+v %v", res, err)
	}
	if err := e.box.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	got, err = e.svc.PromptBaseline(ctx, a.ID)
	if err != nil || got.Text.KeyID == e.keyID {
		t.Fatalf("после ротации: %+v %v", got, err)
	}
	if text, err := e.svc.OpenPromptText(ctx, got); err != nil || text != promptText {
		t.Fatalf("текст после ротации: %v", err)
	}

	// Понижение режима и снятие.
	if _, err := e.svc.SetPromptBaseline(ctx, e.by, a.ID, apps.PromptBaselineInput{Mode: apps.PromptOff}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.DeletePromptBaseline(ctx, e.by, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PromptBaseline(ctx, a.ID); !errors.Is(err, apps.ErrNoPromptBaseline) {
		t.Fatalf("после снятия: %v", err)
	}
	acts := e.actions(t)
	if acts["application.prompt_baseline_set"] != 2 || acts["application.prompt_baseline_removed"] != 1 {
		t.Fatalf("аудит: %v", acts)
	}
	var details string
	if err := e.owner.QueryRow(ctx, "SELECT string_agg(details::text, ' ') FROM audit_log").Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "помощник") {
		t.Fatal("текст эталона попал в журнал аудита")
	}
}
