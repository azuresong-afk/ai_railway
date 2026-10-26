package versions_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/versions"
)

// Исключения в версиях политик (задача 3.22 этапа 3).

func (e *env) createStrict(t testing.TB) {
	t.Helper()
	if _, err := e.svc.Create(context.Background(), e.by, spec("p", policy.Enforce, ruleInjection, rulePII), versions.SourceAPI, "",
		versions.ConsoleDefaults); err != nil {
		t.Fatal(err)
	}
}

var excInput = versions.ExceptionInput{Detector: "injection.heuristic", Pattern: "persona_removal", App: "support",
	Reason: "ложное срабатывание на скрипте оператора"}

// Новое и продлённое исключение — ослабление защиты (DM-40): без повторной
// проверки версия не создаётся, в аудите — weakening и причина.
func TestDM40_ExceptionAddIsWeakening(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createStrict(t)
	if _, _, err := e.svc.AddException(ctx, e.by, "p", 1, excInput, ""); !errors.Is(err, versions.ErrConfirmRequired) {
		t.Fatalf("исключение без повторной проверки: %v", err)
	}
	d, exc, err := e.svc.AddException(ctx, e.confirmed(), "p", 1, excInput, "по событию")
	if err != nil {
		t.Fatal(err)
	}
	if d.Version.Version != 2 || len(d.Spec.Exceptions) != 1 || !strings.HasPrefix(exc.ID, "exc-") ||
		exc.Author != "user:"+e.by.Actor.ID || !exc.CreatedAt.Equal(e.now) || !exc.ExpiresAt.Equal(e.now.Add(policy.DefaultExceptionTTL)) {
		t.Fatalf("исключение: %+v, версия %d", exc, d.Version.Version)
	}
	det := e.last(t, versions.ActionExceptionAdd).Details.(map[string]any)
	if det["weakening"] != true || det["exception"] != exc.ID || !slices.ContainsFunc(det["weakening_reasons"].([]map[string]string),
		func(r map[string]string) bool { return r["kind"] == "exception_added" && r["exception"] == exc.ID }) {
		t.Fatalf("аудит: %v", det)
	}
	// Продление — ослабление; сокращение срока — нет.
	if _, _, err := e.svc.ExtendException(ctx, e.by, "p", 2, exc.ID, 60, nil, "", ""); !errors.Is(err, versions.ErrConfirmRequired) {
		t.Fatalf("продление без проверки: %v", err)
	}
	e.now = e.now.Add(time.Hour)
	d, ext, err := e.svc.ExtendException(ctx, e.confirmed(), "p", 2, exc.ID, 60, nil, "", "")
	if err != nil || !ext.ExpiresAt.Equal(e.now.Add(60*24*time.Hour)) || ext.Reason != excInput.Reason {
		t.Fatalf("продление: %+v %v", ext, err)
	}
	if det := e.last(t, versions.ActionExceptionExtend).Details.(map[string]any); det["weakening"] != true {
		t.Fatalf("аудит продления: %v", det)
	}
	if _, short, err := e.svc.ExtendException(ctx, e.by, "p", d.Version.Version, exc.ID, 1, nil, "сокращаем", ""); err != nil ||
		short.Reason != "сокращаем" {
		t.Fatalf("сокращение срока: %+v %v", short, err)
	}
	// Удаление — усиление, без проверки.
	d, err = e.svc.DeleteException(ctx, e.by, "p", 4, exc.ID, "")
	if err != nil || len(d.Spec.Exceptions) != 0 || d.Version.Version != 5 {
		t.Fatalf("удаление: %+v %v", d.Version, err)
	}
	if det := e.last(t, versions.ActionExceptionDelete).Details.(map[string]any); det["weakening"] == true {
		t.Fatalf("удаление помечено ослаблением: %v", det)
	}
	if _, err := e.svc.DeleteException(ctx, e.by, "p", 5, exc.ID, ""); !errors.Is(err, versions.ErrExceptionNotFound) {
		t.Fatalf("удаление отсутствующего: %v", err)
	}
	// Старая версия неизменна: исключение в ней осталось.
	old, err := e.svc.Get(ctx, "p", 2)
	if err != nil || len(old.Spec.Exceptions) != 1 {
		t.Fatalf("версия 2: %v", err)
	}
}

// Новое исключение через полную спецификацию, загрузку YAML и откат — тоже
// ослабление: без повторной проверки версия не создаётся (DM-40).
func TestDM40_ExceptionWeakeningOtherPaths(t *testing.T) {
	ctx := context.Background()
	newExc := policy.ExceptionSpec{ID: "exc-manual", Detector: "injection.heuristic", App: "support", Reason: "вручную"}
	withExc := func() *policy.Spec {
		s := spec("p", policy.Enforce, ruleInjection, rulePII)
		s.Exceptions = []policy.ExceptionSpec{newExc}
		return s
	}
	cases := map[string]func(t *testing.T, e *env, by versions.By) (versions.Doc, string, error){
		"полная спецификация": func(t *testing.T, e *env, by versions.By) (versions.Doc, string, error) {
			d, err := e.svc.Update(ctx, by, "p", 1, withExc(), versions.SourceAPI, "", versions.ConsoleDefaults)
			return d, "policy.update", err
		},
		"загрузка YAML": func(t *testing.T, e *env, by versions.By) (versions.Doc, string, error) {
			s := withExc()
			s.Version = 2
			s.Exceptions[0].Author = "user:x"
			s.Exceptions[0].CreatedAt = e.now
			s.Exceptions[0].ExpiresAt = e.now.Add(time.Hour)
			y, err := policy.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			d, _, err := e.svc.Import(ctx, by, bytes.NewReader(y), 1, "")
			return d, "policy.import", err
		},
		"откат к версии с исключением": func(t *testing.T, e *env, by versions.By) (versions.Doc, string, error) {
			if _, _, err := e.svc.AddException(ctx, e.confirmed(), "p", 1, excInput, ""); err != nil {
				t.Fatal(err)
			}
			d, err := e.svc.Get(ctx, "p", 2)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.DeleteException(ctx, e.by, "p", 2, d.Spec.Exceptions[0].ID, ""); err != nil {
				t.Fatal(err)
			}
			d, err = e.svc.Rollback(ctx, by, "p", 2, 3, "")
			return d, "policy.rollback", err
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			e.createStrict(t)
			if _, _, err := run(t, e, e.by); !errors.Is(err, versions.ErrConfirmRequired) {
				t.Fatalf("без повторной проверки: %v", err)
			}
			e = newEnv(t)
			e.createStrict(t)
			d, action, err := run(t, e, e.confirmed())
			if err != nil || len(d.Spec.Exceptions) != 1 {
				t.Fatalf("с проверкой: %+v %v", d.Spec, err)
			}
			det := e.last(t, action).Details.(map[string]any)
			if det["weakening"] != true || !slices.ContainsFunc(det["weakening_reasons"].([]map[string]string),
				func(r map[string]string) bool { return r["kind"] == "exception_added" }) {
				t.Fatalf("аудит: %v", det)
			}
		})
	}
}

func TestExceptionRejects(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createStrict(t)
	by := e.confirmed()
	broad := versions.ExceptionInput{Detector: "injection.heuristic", Reason: "весь детектор"}
	_, _, err := e.svc.AddException(ctx, by, "p", 1, broad, "")
	inputErr(t, err, "слишком широкое")
	unknown := excInput
	unknown.Detector = "judge.llm"
	_, _, err = e.svc.AddException(ctx, by, "p", 1, unknown, "")
	inputErr(t, err, "judge.llm")
	long := excInput
	long.ExpiresInDays = 366
	_, _, err = e.svc.AddException(ctx, by, "p", 1, long, "")
	inputErr(t, err, "365")
	past := excInput
	at := e.now.Add(-time.Second)
	past.ExpiresAt = &at
	_, _, err = e.svc.AddException(ctx, by, "p", 1, past, "")
	inputErr(t, err, "expires_at")
	if _, _, err := e.svc.AddException(ctx, by, "p", 7, excInput, ""); !errors.Is(err, versions.ErrConflict) {
		t.Fatalf("устаревшая base_version: %v", err)
	}
	if _, _, err := e.svc.AddException(ctx, by, policy.TemplateBase, 1, excInput, ""); !errors.Is(err, versions.ErrTemplate) {
		t.Fatalf("исключение в шаблоне: %v", err)
	}
	if _, _, err := e.svc.ExtendException(ctx, by, "p", 1, "exc-000000000000", 10, nil, "", ""); !errors.Is(err, versions.ErrExceptionNotFound) {
		t.Fatalf("продление отсутствующего: %v", err)
	}
	if d, err := e.svc.Get(ctx, "p", 0); err != nil || d.Version.Version != 1 {
		t.Fatalf("после отказов появилась версия: %+v %v", d.Version, err)
	}
}

// Автора, created_at и срок исключения из YAML или полной спецификации
// ставит сервер: подставить чужого автора или старую дату создания нельзя.
// Неизменённые исключения переносятся как есть; откат возвращает
// сохранённые сервером значения.
func TestExceptionStampedByServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createStrict(t)
	d, exc, err := e.svc.AddException(ctx, e.confirmed(), "p", 1, excInput, "")
	if err != nil {
		t.Fatal(err)
	}
	// Полная спецификация без списка исключений (KeepExceptions) — исключения
	// сохраняются, ослабления нет.
	keep := versions.ConsoleDefaults
	keep.KeepExceptions = true
	s := spec("p", policy.Enforce, ruleInjection, rulePII)
	d, err = e.svc.Update(ctx, e.by, "p", d.Version.Version, s, versions.SourceAPI, "", keep)
	if err != nil || len(d.Spec.Exceptions) != 1 || d.Spec.Exceptions[0] != exc {
		t.Fatalf("перенос исключений: %+v %v", d.Spec.Exceptions, err)
	}
	if s.Exceptions != nil {
		t.Fatal("спецификация вызывающего изменена")
	}
	// Подмена автора и дат: сервер ставит свои.
	e.now = e.now.Add(24 * time.Hour)
	forged := exc
	forged.ID, forged.Author = "exc-forged", "user:someone-else"
	forged.CreatedAt = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	forged.ExpiresAt = forged.CreatedAt.Add(policy.MaxExceptionTTL)
	s = spec("p", policy.Enforce, ruleInjection, rulePII)
	s.Exceptions = []policy.ExceptionSpec{exc, forged}
	d, err = e.svc.Update(ctx, e.confirmed(), "p", d.Version.Version, s, versions.SourceAPI, "", versions.ConsoleDefaults)
	if err != nil {
		t.Fatal(err)
	}
	got := d.Spec.Exceptions[1]
	if got.Author != "user:"+e.by.Actor.ID || !got.CreatedAt.Equal(e.now) || got.ExpiresAt.Sub(got.CreatedAt) > policy.MaxExceptionTTL {
		t.Fatalf("подменённое исключение: %+v", got)
	}
	if d.Spec.Exceptions[0] != exc {
		t.Fatalf("неизменённое исключение переписано: %+v", d.Spec.Exceptions[0])
	}
	// Загрузка YAML с истёкшим сроком — отказ.
	y, err := policy.Marshal(d.Spec)
	if err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(400 * 24 * time.Hour)
	y = bytes.Replace(y, []byte("id: exc-forged"), []byte("id: exc-forged-2"), 1)
	if _, _, err := e.svc.Import(ctx, e.confirmed(), bytes.NewReader(y), d.Version.Version, ""); err == nil {
		t.Fatal("загружено исключение с истёкшим сроком")
	}
	// Откат к версии 2 возвращает исключение как было сохранено.
	r, err := e.svc.Rollback(ctx, e.confirmed(), "p", 2, d.Version.Version, "")
	if err != nil || len(r.Spec.Exceptions) != 1 || r.Spec.Exceptions[0] != exc {
		t.Fatalf("откат: %+v %v", r.Spec.Exceptions, err)
	}
}

func TestExceptionsStatus(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createStrict(t)
	short := excInput
	short.ExpiresInDays = 1
	if _, _, err := e.svc.AddException(ctx, e.confirmed(), "p", 1, short, ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.AddException(ctx, e.confirmed(), "p", 2, excInput, ""); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(48 * time.Hour)
	d, list, err := e.svc.Exceptions(ctx, "p", 0)
	if err != nil || d.Version.Version != 3 || len(list) != 2 || !list[0].Expired || list[1].Expired {
		t.Fatalf("состояние: %+v %v", list, err)
	}
	if _, _, err := e.svc.Exceptions(ctx, "missing", 0); !errors.Is(err, versions.ErrNotFound) {
		t.Fatalf("нет политики: %v", err)
	}
}

// decodeInput — условие из JSON, как его разбирает API (неизвестные поля —
// ошибка), и проверка Check.
func decodeInput(data []byte) (versions.ExceptionInput, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var in versions.ExceptionInput
	if err := dec.Decode(&in); err != nil {
		return in, err
	}
	return in, in.Check()
}

func TestExceptionInputCheck(t *testing.T) {
	in, err := decodeInput([]byte(`{"detector":"pii.ru","category":"pii.card","app":"crm",` +
		`"reason":"тестовые карты","expires_in_days":7,"event_id":"01900000-0000-7000-8000-000000000001"}`))
	if err != nil || in.ExpiresInDays != 7 || in.App != "crm" {
		t.Fatalf("разбор: %+v %v", in, err)
	}
	for name, body := range map[string]string{
		"широкое":       `{"detector":"pii.ru","category":"pii.card","reason":"r"}`,
		"без причины":   `{"detector":"pii.ru","app":"crm"}`,
		"оба срока":     `{"detector":"pii.ru","app":"crm","reason":"r","expires_in_days":1,"expires_at":"2026-11-01T00:00:00Z"}`,
		"отрицательный": `{"detector":"pii.ru","app":"crm","reason":"r","expires_in_days":-1}`,
		"больше года":   `{"detector":"pii.ru","app":"crm","reason":"r","expires_in_days":366}`,
		"длинная":       `{"detector":"pii.ru","app":"crm","reason":"` + strings.Repeat("я", policy.MaxExceptionReason+1) + `"}`,
		"событие":       `{"detector":"pii.ru","app":"crm","reason":"r","event_id":"x"}`,
	} {
		if _, err := decodeInput([]byte(body)); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// FuzzExceptionInputCheck: принятое Check условие полно, срок допустим, а
// AddException с ним создаёт исключение, проходящее проверку политики.
func FuzzExceptionInputCheck(f *testing.F) {
	f.Add([]byte(`{"detector":"injection.heuristic","pattern":"persona_removal","app":"support","reason":"r"}`))
	f.Add([]byte(`{"detector":"pii.ru","fragment":"abababababababababababababababab","reason":"r","expires_at":"2026-11-01T00:00:00Z"}`))
	f.Add([]byte(`{"detector":"pii.ru","user":"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd","source":"rag","reason":"r","expires_in_days":365}`))
	f.Add([]byte(`{"detector":"x","reason":""}`))
	e := newEnv(f)
	e.createStrict(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := decodeInput(data)
		if err != nil {
			return
		}
		if in.Detector == "" || strings.TrimSpace(in.Reason) == "" ||
			in.Pattern == "" && in.Fragment == "" && in.App == "" && in.User == "" {
			t.Fatalf("принято неполное условие: %+v", in)
		}
		if in.ExpiresInDays < 0 || in.ExpiresInDays > 365 || in.ExpiresInDays != 0 && in.ExpiresAt != nil {
			t.Fatalf("принят неверный срок: %+v", in)
		}
		cur, err := e.svc.Get(context.Background(), "p", 0)
		if err != nil {
			t.Fatal(err)
		}
		d, exc, err := e.svc.AddException(context.Background(), e.confirmed(), "p", cur.Version.Version, in, "")
		if err != nil {
			return // неизвестный детектор, срок вне окна от сохранения
		}
		if exc.ExpiresAt.Sub(exc.CreatedAt) > policy.MaxExceptionTTL || !exc.Narrowed() || d.Spec.Validate() != nil {
			t.Fatalf("исключение: %+v", exc)
		}
	})
}

func hasKind(d versions.Diff, kind string) bool {
	return slices.ContainsFunc(d.Weakening, func(w versions.Weakening) bool { return w.Kind == kind })
}

// Различие версий: добавление, изменение условия, продление и удаление.
func TestCompareExceptions(t *testing.T) {
	created := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	exc := policy.ExceptionSpec{ID: "exc-1", Detector: "pii.ru", App: "crm", Reason: "r", Author: "user:u1",
		CreatedAt: created, ExpiresAt: created.Add(policy.DefaultExceptionTTL)}
	a := spec("p", policy.Enforce, rulePII)
	b := spec("p", policy.Enforce, rulePII)
	b.Exceptions = []policy.ExceptionSpec{exc}
	if d := versions.Compare(a, b); !d.Weakened() || len(d.ExceptionsAdded) != 1 || !hasKind(d, "exception_added") {
		t.Fatalf("добавление: %+v", d)
	}
	if d := versions.Compare(b, a); d.Weakened() || len(d.ExceptionsRemoved) != 1 {
		t.Fatalf("удаление: %+v", d)
	}
	c := spec("p", policy.Enforce, rulePII)
	ext := exc
	ext.ExpiresAt = ext.ExpiresAt.Add(time.Hour)
	c.Exceptions = []policy.ExceptionSpec{ext}
	if d := versions.Compare(b, c); !d.Weakened() || !hasKind(d, "exception_extended") {
		t.Fatalf("продление: %+v", d)
	}
	if d := versions.Compare(c, b); d.Weakened() || len(d.ExceptionsChanged) != 1 {
		t.Fatalf("сокращение: %+v", d)
	}
	wide := exc
	wide.App, wide.Pattern = "", "x"
	c.Exceptions = []policy.ExceptionSpec{wide}
	if d := versions.Compare(b, c); !d.Weakened() || !hasKind(d, "exception_changed") {
		t.Fatalf("изменение условия: %+v", d)
	}
}

// 3В26 ревью 3.r3: версию с сотнями исключений (ID по 63 символа) можно
// сохранить и откатить — подробности аудита не больше 16 КиБ: списки ID
// ограничены, рядом — их число, причины ослабления исключениями — одна
// каждого вида.
func TestVersionManyExceptionsAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.createStrict(t)
	s := spec("p", policy.Enforce, ruleInjection, rulePII)
	for i := range policy.MaxExceptions {
		id := fmt.Sprintf("exc-%059d", i)
		s.Exceptions = append(s.Exceptions, policy.ExceptionSpec{ID: id, Detector: "injection.heuristic", Pattern: "persona_removal",
			App: fmt.Sprintf("app-%058d", i), Reason: excInput.Reason, Author: "user:" + e.by.Actor.ID,
			CreatedAt: e.now, ExpiresAt: e.now.Add(policy.DefaultExceptionTTL)})
	}
	if len(s.Exceptions[0].ID) != 63 {
		t.Fatalf("длина ID: %d", len(s.Exceptions[0].ID))
	}
	d, err := e.svc.Update(ctx, e.confirmed(), "p", 1, s, versions.SourceAPI, "", versions.ConsoleDefaults)
	if err != nil {
		t.Fatalf("версия с %d исключениями: %v", policy.MaxExceptions, err)
	}
	det := e.last(t, "policy.update").Details.(map[string]any)
	if det["exceptions_added_count"] != policy.MaxExceptions || len(det["exceptions_added"].([]string)) != 50 || det["weakening"] != true {
		t.Fatalf("подробности: added %v, count %v", len(det["exceptions_added"].([]string)), det["exceptions_added_count"])
	}
	// Откат к версии без исключений: снять все разом.
	if _, err := e.svc.Rollback(ctx, e.by, "p", 1, d.Version.Version, "снять исключения"); err != nil {
		t.Fatalf("откат: %v", err)
	}
	det = e.last(t, "policy.rollback").Details.(map[string]any)
	if det["exceptions_removed_count"] != policy.MaxExceptions {
		t.Fatalf("откат: %v", det["exceptions_removed_count"])
	}
	for _, a := range []string{"policy.update", "policy.rollback"} {
		raw, err := json.Marshal(e.last(t, a).Details)
		if err != nil || len(raw) > 16<<10 {
			t.Fatalf("%s: %d байт %v", a, len(raw), err)
		}
	}
}
