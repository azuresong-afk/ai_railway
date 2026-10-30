package shadowai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

func confirmed() By {
	by := testBy
	by.Confirm = func(context.Context) error { return nil }
	return by
}

func loadedService(t *testing.T, mac bool) (*Service, *Memory) {
	t.Helper()
	m := NewMemory()
	s := newTestService(t, m, mac)
	if _, err := s.UploadCatalog(context.Background(), testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	return s, m
}

// Исключённый пользователь (по логину) и исключённый сервис не попадают в
// сводки импорта; накопленные сводки удаляются при добавлении исключения;
// логина нет ни в хранилище, ни в аудите.
func TestExclusionsInImport(t *testing.T) {
	ctx := context.Background()
	s, m := loadedService(t, true)
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(string(readFile(t, "../../testdata/shadowai/access-squid.log")))); err != nil {
		t.Fatal(err)
	}
	alias := pseudonym(testMAC(t), "ivanov.ia")
	has := func(f func(Aggregate) bool) bool {
		for _, a := range m.Aggregates() {
			if f(a) {
				return true
			}
		}
		return false
	}
	if !has(func(a Aggregate) bool { return a.UserAlias == alias }) || !has(func(a Aggregate) bool { return a.Service == "deepseek" }) {
		t.Fatalf("до исключений: %v", m.Aggregates())
	}
	// Без повторной проверки — отказ.
	if _, err := s.AddExclusion(ctx, testBy, ExclusionInput{Kind: ExcludeUser, Login: "ivanov.ia"}); !errors.Is(err, ErrConfirmNeeded) {
		t.Fatalf("без проверки: %v", err)
	}
	ex, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeUser, Login: " ivanov.ia ", Comment: "учётка шлюза"})
	if err != nil || ex.Value != alias || ex.Kind != ExcludeUser {
		t.Fatalf("исключение пользователя: %+v %v", ex, err)
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "deepseek"}); err != nil {
		t.Fatal(err)
	}
	if has(func(a Aggregate) bool { return a.UserAlias == alias || a.Service == "deepseek" }) {
		t.Fatalf("сводки исключённых не удалены: %v", m.Aggregates())
	}
	rec, n := lastRecord(m, "shadow_ai.exclusion_added")
	d, _ := rec.Details.(map[string]any)
	if n != 2 || d["weakening"] != true || d["deleted_rows"] == int64(0) {
		t.Fatalf("аудит: %+v", rec)
	}
	for _, r := range m.Records() {
		if strings.Contains(fmt.Sprint(r.Details), "ivanov") {
			t.Fatalf("логин в аудите: %+v", r)
		}
	}
	// Повторный импорт (другой файл с теми же строками): исключённые — в
	// счётчике, не в сводках.
	data := string(readFile(t, "../../testdata/shadowai/access-squid.log")) + "\n"
	imp, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if imp.Excluded == 0 || has(func(a Aggregate) bool { return a.UserAlias == alias || a.Service == "deepseek" }) {
		t.Fatalf("импорт с исключениями: %+v", imp.ImportResult)
	}
	// Снятие: следующие строки снова учитываются.
	if err := s.RemoveExclusion(ctx, testBy, ExcludeService, "deepseek"); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveExclusion(ctx, testBy, ExcludeService, "deepseek"); !errors.Is(err, ErrExclusionNotFound) {
		t.Fatalf("повторное снятие: %v", err)
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(data+"\n")); err != nil {
		t.Fatal(err)
	}
	if !has(func(a Aggregate) bool { return a.Service == "deepseek" }) || has(func(a Aggregate) bool { return a.UserAlias == alias }) {
		t.Fatalf("после снятия: %v", m.Aggregates())
	}
	list, err := s.ListExclusions(ctx)
	if err != nil || len(list) != 1 || list[0].Comment != "учётка шлюза" {
		t.Fatalf("список: %+v %v", list, err)
	}
}

// Проверка ввода исключения.
func TestExclusionInput(t *testing.T) {
	ctx := context.Background()
	s, _ := loadedService(t, true)
	bad := map[string]ExclusionInput{
		"нет вида":              {Login: "a"},
		"логин и псевдоним":     {Kind: ExcludeUser, Login: "a", Alias: strings.Repeat("a", 32)},
		"ни логина, ни псевдон": {Kind: ExcludeUser},
		"псевдоним не hex":      {Kind: ExcludeUser, Alias: strings.Repeat("z", 32)},
		"логин с управляющим":   {Kind: ExcludeUser, Login: "a\x00b"},
		"логин длинный":         {Kind: ExcludeUser, Login: strings.Repeat("a", 300)},
		"сервис не ID":          {Kind: ExcludeService, Service: "Chat GPT"},
		"сервис и логин":        {Kind: ExcludeService, Service: "chatgpt", Login: "a"},
		"длинный комментарий":   {Kind: ExcludeService, Service: "chatgpt", Comment: strings.Repeat("я", 201)},
	}
	for name, in := range bad {
		var qe *QueryError
		if _, err := s.AddExclusion(ctx, confirmed(), in); !errors.As(err, &qe) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "chatgpt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "chatgpt"}); !errors.Is(err, ErrExclusionExists) {
		t.Fatalf("повтор: %v", err)
	}
	if err := s.RemoveExclusion(ctx, testBy, "group", "x"); !errors.Is(err, ErrExclusionNotFound) {
		t.Fatalf("чужой вид: %v", err)
	}
	// Без ключа псевдонимов пользователей исключать некого.
	s2, _ := loadedService(t, false)
	if _, err := s2.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeUser, Login: "a"}); !errors.Is(err, ErrNoUserKey) {
		t.Fatalf("без ключа: %v", err)
	}
}

// Предел числа исключений.
func TestExclusionsLimit(t *testing.T) {
	ctx := context.Background()
	s, _ := loadedService(t, true)
	for i := range MaxExclusions {
		if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: fmt.Sprintf("svc-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "one-more"}); !errors.Is(err, ErrTooManyExclusions) {
		t.Fatalf("сверх предела: %v", err)
	}
}

// DM-37: новый сервис — сервис каталога, которого не было в сводках за 30
// суток до его первого часа в партии и после него. Одна запись аудита на
// сервис; в ней число пользователей, без псевдонимов и логинов; повторное
// появление сервиса записи не даёт, после 30 суток тишины — даёт снова.
func TestDM37_NewServiceAudit(t *testing.T) {
	ctx := context.Background()
	s, m := loadedService(t, true)
	imp, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(string(readFile(t, "../../testdata/shadowai/access-squid.log"))))
	if err != nil {
		t.Fatal(err)
	}
	news := func() map[string]map[string]any {
		out := map[string]map[string]any{}
		for _, r := range m.Records() {
			if r.Action == "shadow_ai.new_service" {
				d, _ := r.Details.(map[string]any)
				out[r.Object.ID] = d
			}
		}
		return out
	}
	got := news()
	if len(got) != imp.Services || got["chatgpt"] == nil {
		t.Fatalf("новые сервисы: %v (сервисов в импорте %d)", got, imp.Services)
	}
	if d := got["chatgpt"]; d["service_name"] != "ChatGPT" || d["users"] != 1 || d["source"] != SourceImport {
		t.Fatalf("запись о ChatGPT: %v", d)
	}
	alias := pseudonym(testMAC(t), "ivanov.ia")
	for _, r := range m.Records() {
		if r.Action == "shadow_ai.new_service" && (strings.Contains(fmt.Sprint(r.Details), alias) ||
			strings.Contains(fmt.Sprint(r.Details), "ivanov")) {
			t.Fatalf("псевдоним или логин в записи: %+v", r)
		}
		if r.Action == "shadow_ai.new_service" && r.Actor != testBy.Actor {
			t.Fatalf("субъект записи: %+v", r.Actor)
		}
	}
	// Те же сервисы через сутки — не новые.
	line := func(at time.Time, host, user string) string {
		return fmt.Sprintf("%d.000 10 10.0.0.1 TCP_TUNNEL/200 100 CONNECT %s:443 %s HIER_DIRECT/203.0.113.1 -\n", at.Unix(), host, user)
	}
	day := time.Date(2026, 10, 28, 9, 0, 0, 0, time.UTC)
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(line(day, "chatgpt.com", "a")+line(day, "claude.ai", "b")+
		line(day, "claude.ai", "c"))); err != nil {
		t.Fatal(err)
	}
	after := news()
	if len(after) != len(got)+1 || after["claude"] == nil || after["claude"]["users"] != 2 {
		t.Fatalf("после второго импорта: %v", after)
	}
	// Сервис, которого не было 30 суток, снова новый: сводки старого периода
	// не мешают (каталог проверяет только окно перед первым часом партии).
	m2 := NewMemory()
	s2 := newTestService(t, m2, true)
	if _, err := s2.UploadCatalog(ctx, testBy, readFile(t, testCatalogSigned)); err != nil {
		t.Fatal(err)
	}
	old := testNow.AddDate(0, 0, -45)
	if _, err := s2.Import(ctx, testBy, FormatSquid, strings.NewReader(line(old, "perplexity.ai", "a"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Import(ctx, testBy, FormatSquid, strings.NewReader(line(day, "perplexity.ai", "a"))); err != nil {
		t.Fatal(err)
	}
	if _, n := lastRecord(m2, "shadow_ai.new_service"); n != 2 {
		t.Fatalf("после 30 суток тишины записей %d, ждали 2", n)
	}
	// Импорт старого журнала после свежего: сервис уже есть позже — не новый.
	if _, err := s2.Import(ctx, testBy, FormatSquid, strings.NewReader(line(old.Add(time.Hour), "perplexity.ai", "b"))); err != nil {
		t.Fatal(err)
	}
	if _, n := lastRecord(m2, "shadow_ai.new_service"); n != 2 {
		t.Fatalf("старый журнал после свежего дал запись: %d", n)
	}
	// Исключённый сервис новым не считается.
	if _, err := s2.AddExclusion(ctx, confirmed(), ExclusionInput{Kind: ExcludeService, Service: "chatgpt"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s2.Import(ctx, testBy, FormatSquid, strings.NewReader(line(day, "chatgpt.com", "a")+"\n")); err != nil {
		t.Fatal(err)
	}
	for _, r := range m2.Records() {
		if r.Action == "shadow_ai.new_service" && r.Object.ID == "chatgpt" {
			t.Fatalf("исключённый сервис дал запись: %+v", r)
		}
	}
}

// 4В27: импорт журнала, где каждому подобранному логину отведён свой час, —
// оракул псевдонимов. Число разных и новых для организации псевдонимов
// импорта и сумма новых от того же субъекта за сутки пишутся в аудит
// shadow_ai.import; первый импорт с пользователями — исходный состав.
// Логины синтетические. Покрывает: DM-37.
func TestDM37_ImportCountsNewAliases(t *testing.T) {
	ctx := context.Background()
	s, m := loadedService(t, true)
	at := time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)
	probe := func(prefix string, n int) string {
		var b strings.Builder
		for i := range n {
			// Каждому логину — свой час: по сводке часа виден его псевдоним.
			fmt.Fprintf(&b, "%d.000 10 10.0.0.1 TCP_TUNNEL/200 100 CONNECT chatgpt.com:443 %s%04d HIER_DIRECT/203.0.113.1 -\n",
				at.Add(time.Duration(i%24)*time.Hour).Unix(), prefix, i)
		}
		return b.String()
	}
	details := func() map[string]any {
		r, _ := lastRecord(m, "shadow_ai.import")
		d, _ := r.Details.(map[string]any)
		return d
	}
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(probe("staff.", 30))); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["users"] != int64(30) || d["new_users"] != int64(0) || d["baseline"] != true || d["new_users_day"] != int64(0) {
		t.Fatalf("исходный состав: %v", d)
	}
	// 20 новых логинов и 10 известных.
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(probe("probe.", 20)+probe("staff.", 10))); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["users"] != int64(30) || d["new_users"] != int64(20) || d["baseline"] != nil || d["new_users_day"] != int64(20) {
		t.Fatalf("второй импорт: %v", d)
	}
	// Сумма за сутки — по субъекту: другой субъект её не продолжает.
	if _, err := s.Import(ctx, testBy, FormatSquid, strings.NewReader(probe("more.", 5))); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["new_users"] != int64(5) || d["new_users_day"] != int64(25) {
		t.Fatalf("третий импорт: %v", d)
	}
	other := By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u-other"}}
	if _, err := s.Import(ctx, other, FormatSquid, strings.NewReader(probe("other.", 3))); err != nil {
		t.Fatal(err)
	}
	if d := details(); d["new_users"] != int64(3) || d["new_users_day"] != int64(3) {
		t.Fatalf("другой субъект: %v", d)
	}
	for _, r := range m.Records() {
		if r.Action == "shadow_ai.import" && strings.Contains(fmt.Sprint(r.Details), "probe.") {
			t.Fatalf("логин в аудите: %+v", r)
		}
	}
}
