package shadowai

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Исключения и новые сервисы на живой БД: сводки исключённого удаляются
// при добавлении, отсеиваются при записи (даже если партия собрана до
// исключения); записи shadow_ai.new_service — по одной на сервис, в том
// числе при одновременной записи двух партий.
func TestPGShadowAIExclusionsAndNewServices(t *testing.T) {
	e := setupPG(t)
	ctx := pgTestCtx(t)
	s := e.service(t)
	if _, err := s.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	squid := readFile(t, "../../testdata/shadowai/access-squid.log")
	imp, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(squid))
	if err != nil {
		t.Fatal(err)
	}
	newServices := func() int {
		return e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.new_service'`)
	}
	if n := newServices(); n != imp.Services || n < 2 {
		t.Fatalf("записей о новых сервисах %d, сервисов %d", n, imp.Services)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.new_service'
		AND details->>'service' = 'chatgpt' AND (details->>'users')::int = 1 AND details->>'source' = 'import'
		AND details::text NOT LIKE '%ivanov%'`); n != 1 {
		t.Fatalf("запись о ChatGPT: %d", n)
	}
	// Повтор тех же сервисов другим файлом — новых записей нет.
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(append(append([]byte{}, squid...), '\n'))); err != nil {
		t.Fatal(err)
	}
	before := newServices()
	if before != imp.Services {
		t.Fatalf("повтор дал записи: %d", before)
	}

	alias := pseudonym(testMAC(t), "ivanov.ia")
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_hour WHERE user_alias = $1`, alias); n == 0 {
		t.Fatal("нет сводок пользователя до исключения")
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeUser, Login: "ivanov.ia", Comment: "шлюз"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeUser, Alias: alias}); !errors.Is(err, ErrExclusionExists) {
		t.Fatalf("повтор псевдонимом: %v", err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_hour WHERE user_alias = $1`, alias); n != 0 {
		t.Fatalf("сводки исключённого не удалены: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.exclusion_added'
		AND (details->>'weakening')::boolean AND (details->>'deleted_rows')::int > 0 AND details::text NOT LIKE '%ivanov%'`); n != 1 {
		t.Fatalf("аудит исключения: %d", n)
	}
	list, err := s.ListExclusions(ctx)
	if err != nil || len(list) != 1 || list[0].Value != alias || list[0].Comment != "шлюз" {
		t.Fatalf("исключения: %+v %v", list, err)
	}

	// Партия, собранная до исключения сервиса, всё равно отсеивается запросом.
	hour := testNow.Truncate(time.Hour).Add(-2 * time.Hour)
	batch := SyslogBatch{Aggregates: []Aggregate{
		{Bucket: hour, Service: "chatgpt", UserAlias: alias, UserKind: UserKindUser, Requests: 3, Bytes: 10},
		{Bucket: hour, Service: "poe", UserAlias: "", UserKind: UserKindNone, Requests: 1, Bytes: 1},
		{Bucket: hour, Service: "kimi", UserAlias: "", UserKind: UserKindNone, Requests: 2, Bytes: 2},
	}, ServiceNames: map[string]string{"chatgpt": "ChatGPT", "poe": "Poe", "kimi": "Kimi"}}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "poe"}); err != nil {
		t.Fatal(err)
	}
	if err := e.st.SaveSyslog(ctx, audit.DefaultOrgID, batch); err != nil {
		t.Fatal(err)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_hour WHERE user_alias = $1 OR service = 'poe'`, alias); n != 0 {
		t.Fatalf("исключённые записаны: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM shadow_ai_hour WHERE service = 'kimi'`); n != 1 {
		t.Fatalf("сводка kimi: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.new_service' AND details->>'service' = 'kimi'
		AND actor_type = 'system' AND details->>'source' = 'syslog'`); n != 1 || newServices() != before+1 {
		t.Fatalf("новый сервис по syslog: %d, всего %d", n, newServices())
	}

	// Две партии одновременно с одним новым сервисом — одна запись.
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- e.st.SaveSyslog(ctx, audit.DefaultOrgID, SyslogBatch{Aggregates: []Aggregate{
				{Bucket: hour, Service: "mistral", UserKind: UserKindNone, Requests: 1}}})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM audit_log WHERE action = 'shadow_ai.new_service' AND details->>'service' = 'mistral'`); n != 1 {
		t.Fatalf("одновременные партии: записей %d", n)
	}

	// Снятие исключения; журнал импорта хранит число исключённых строк.
	if err := s.RemoveExclusion(ctx, testBy, ExcludeService, "poe"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveExclusion(ctx, testBy, ExcludeService, "poe"); !errors.Is(err, ErrExclusionNotFound) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, bytes.NewReader(append(append([]byte{}, squid...), '\n', '\n'))); err != nil {
		t.Fatal(err)
	}
	imps, err := s.Imports(ctx)
	if err != nil || len(imps) != 3 || imps[0].Excluded == 0 {
		t.Fatalf("журнал импорта: %+v %v", imps, err)
	}
}
