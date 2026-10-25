package audit

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

func provider(t testing.TB) crypto.Provider {
	t.Helper()
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hasher(t testing.TB) crypto.Hasher {
	t.Helper()
	h, err := provider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// goldenRecord — запись с фиксированными полями для эталонного вектора.
func goldenRecord(h crypto.Hasher) Record {
	return Record{
		Seq:      1,
		ID:       "0192f3a0-0000-7000-8000-000000000001",
		OrgID:    DefaultOrgID,
		TS:       time.Date(2026, 10, 20, 19, 30, 0, 123456000, time.UTC),
		Actor:    Actor{Type: ActorUser, ID: "u-1", Name: "Иванов <admin>"},
		SourceIP: netip.MustParseAddr("192.0.2.10"),
		Action:   "auth.login",
		Object:   Object{Type: "session", ID: "s-1"},
		Result:   ResultSuccess,
		Details:  json.RawMessage(`{"method":"password+totp"}`),
		HashAlg:  h.Name(),
		PrevHash: genesis(h),
	}
}

// Эталон канонической формы: менять только вместе с formatVersion, иначе
// записи, сохранённые раньше, перестанут проверяться.
func TestCanonicalGolden(t *testing.T) {
	h := hasher(t)
	r := goldenRecord(h)
	c, err := r.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"seq":1,"id":"0192f3a0-0000-7000-8000-000000000001","org_id":"00000000-0000-7000-8000-000000000001",` +
		`"ts":"2026-10-20T19:30:00.123456Z","actor":{"type":"user","id":"u-1","name":"Иванов \u003cadmin\u003e"},` +
		`"ip":"192.0.2.10","action":"auth.login","object":{"type":"session","id":"s-1"},"result":"success",` +
		`"details":{"method":"password+totp"},"alg":"SHA-256","prev":"` + strings.Repeat("0", 64) + `"}`
	if string(c) != want {
		t.Fatalf("каноническая форма изменилась:\n%s\n%s", c, want)
	}
	sum, err := r.ComputeHash(h)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sum); got != hex.EncodeToString(h.Sum([]byte(want))) {
		t.Fatalf("хеш не от канонической формы: %s", got)
	}
}

func TestCanonicalTimeZoneIndependent(t *testing.T) {
	h := hasher(t)
	a := goldenRecord(h)
	b := a
	b.TS = a.TS.In(time.FixedZone("MSK", 3*3600))
	ca, errA := a.Canonical()
	cb, errB := b.Canonical()
	if errA != nil || errB != nil || string(ca) != string(cb) {
		t.Fatal("каноническая форма зависит от часового пояса")
	}
}

func TestCanonicalDetails(t *testing.T) {
	got, err := CanonicalDetails(map[string]any{"b": 1, "a": map[string]any{"z": true, "y": []any{0.5, "x"}}})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"a":{"y":[0.5,"x"],"z":true},"b":1}`; string(got) != want {
		t.Fatalf("%s != %s", got, want)
	}
	if got, err := CanonicalDetails(nil); err != nil || string(got) != "{}" {
		t.Fatalf("nil → %s, %v", got, err)
	}
	// Числа не пересчитываются через float64.
	got, err = CanonicalJSON([]byte(`{ "n" : 12345678901234567890, "f": 1.10 }`))
	if err != nil || string(got) != `{"f":1.10,"n":12345678901234567890}` {
		t.Fatalf("%s, %v", got, err)
	}
}

func TestCanonicalJSONRejects(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxDetailsDepth+1) + "1" + strings.Repeat("}", maxDetailsDepth+1)
	cases := map[string]string{ //nolint:gosec // G101: синтетические строки для проверки фильтра секретов, не настоящие учётные данные
		"не объект":       `[1,2]`,
		"строка":          `"x"`,
		"неверный JSON":   `{"a":`,
		"хвост":           `{"a":1} {"b":2}`,
		"глубина":         deep,
		"размер":          `{"a":"` + strings.Repeat("x", maxDetailsSize) + `"}`,
		"пароль":          `{"new_password":"x"}`,
		"секрет вложенно": `{"after":{"provider":{"api_key":"x"}}}`,
		"токен в массиве": `{"list":[{"Session-Token":"x"}]}`,
		"TOTP":            `{"totp":"123456"}`,
		"ключ":            `{"key":"x"}`,
		"Authorization":   `{"Authorization":"Bearer x"}`,
		"secret_key":      `{"secret_key":"x"}`,
		"access_key":      `{"AccessKey":"x"}`,
		"хеш пароля":      `{"password_hash":"x"}`,
		"pwd":             `{"pwd":"x"}`,
		"dsn":             `{"dsn":"x"}`,
		"сессия":          `{"session":"x"}`,
	}
	for name, in := range cases {
		if _, err := CanonicalJSON([]byte(in)); err == nil {
			t.Errorf("%s: принято %.60s", name, in)
		}
	}
	// Похожие, но безопасные ключи проходят.
	for _, k := range []string{"key_prefix", "token_id", "api_token_id", "keyring_size", "public_key", "key_id", "requests_per_minute_per_key"} {
		if _, err := CanonicalJSON([]byte(`{"` + k + `":"x"}`)); err != nil {
			t.Errorf("%s отклонён: %v", k, err)
		}
	}
	for _, v := range []string{"https://example.com/a@b", "mailto:a@b", "user@example.com", "https://u@h/x"} {
		got, err := CanonicalJSON([]byte(`{"v":"` + v + `"}`))
		if err != nil || string(got) != `{"v":"`+v+`"}` {
			t.Errorf("%s: %s, %v", v, got, err)
		}
	}
}

// В4 ревью 2.r1: значение, похожее на секрет, маскируется, а запись не
// отклоняется — обязательное событие (причина просмотра содержимого)
// пишется, секрет в журнал не попадает.
func TestCanonicalJSONMasksSecretValues(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: синтетические строки для проверки фильтра секретов, не настоящие учётные данные
		`Bearer abc`:      `Bearer [скрыто]`,
		`bearer  abc def`: `bearer  [скрыто] def`,
		`Bearer-токен утёк, разбор`:                  `Bearer-токен утёк, разбор`,
		`Bearer abc утёк, разбор`:                    `Bearer [скрыто] утёк, разбор`,
		`утёк токен: BEARER eyJ.x.y, и Basic dXNlcg`: `утёк токен: BEARER [скрыто] и Basic [скрыто]`,
		`подбор basic`:                               `подбор basic`,
		`Bearer [скрыто]`:                            `Bearer [скрыто]`,
		`Обычный bearerish текст`:                    `Обычный bearerish текст`,
		`postgres://aisec:pass@db:5432/aisec`:        `postgres://aisec:[скрыто]@db:5432/aisec`,
		`см. https://u:p@h/x и ftp://a:b@c`:          `см. https://u:[скрыто]@h/x и ftp://a:[скрыто]@c`,
		`postgres://aisec:[скрыто]@db/aisec`:         `postgres://aisec:[скрыто]@db/aisec`,
	}
	for in, want := range cases {
		got, err := CanonicalDetails(map[string]any{"reason": in, "list": []any{in}})
		if err != nil {
			t.Errorf("%q: отклонено: %v", in, err)
			continue
		}
		wantJSON, err := json.Marshal(map[string]any{"list": []string{want}, "reason": want})
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(wantJSON) {
			t.Errorf("%q: %s, ожидалось %s", in, got, wantJSON)
		}
		// Повторное применение (проверка канонической формы) не меняет запись.
		again, err := CanonicalJSON(got)
		if err != nil || string(again) != string(got) {
			t.Errorf("%q: повторно %s, %v", in, again, err)
		}
	}
}

func validEntry() Entry {
	return Entry{
		Actor:    Actor{Type: ActorUser, ID: "u-1", Name: "admin"},
		SourceIP: netip.MustParseAddr("192.0.2.1"),
		Action:   "auth.login",
		Result:   ResultSuccess,
	}
}

func TestEntryValidate(t *testing.T) {
	if _, err := (&Entry{}).normalize(); err == nil {
		t.Fatal("пустая запись принята")
	}
	e := validEntry()
	if ev, err := e.normalize(); err != nil || !ev.Mandatory {
		t.Fatalf("%v, %v", ev, err)
	}
	// Отклоняются только ошибки программиста.
	bad := map[string]func(*Entry){
		"код вне перечня": func(e *Entry) { e.Action = "auth.unknown" },
		"тип субъекта":    func(e *Entry) { e.Actor.Type = "root" },
		"без ID субъекта": func(e *Entry) { e.Actor.ID = "" },
		"результат":       func(e *Entry) { e.Result = "ok" },
		"ID организации":  func(e *Entry) { e.OrgID = "not-a-uuid" },
	}
	for name, mut := range bad {
		e := validEntry()
		mut(&e)
		if _, err := e.normalize(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

// РСБ.2: поля, которые задаёт нарушитель (логин при неудачном входе, адрес),
// не мешают записать обязательное событие — они нормализуются.
func TestEntryNormalizesUntrustedFields(t *testing.T) {
	e := validEntry()
	e.Action = "auth.login_failed"
	e.Result = ResultFailure
	e.Actor.ID = strings.Repeat("a", maxActorID+50)
	e.Actor.Name = "adm\x00in\xff"
	e.Object.ID = strings.Repeat("я", maxObjectID+1)
	e.SourceIP = netip.MustParseAddr("fe80::1%eth0")
	if _, err := e.normalize(); err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(e.Actor.ID); n != maxActorID || !strings.HasSuffix(e.Actor.ID, "…") {
		t.Errorf("ID не обрезан: %d", n)
	}
	if e.Actor.Name != "adm\uFFFDin\uFFFD" {
		t.Errorf("имя: %q", e.Actor.Name)
	}
	if utf8.RuneCountInString(e.Object.ID) != maxObjectID {
		t.Error("ID объекта не обрезан")
	}
	if e.SourceIP.Zone() != "" || e.SourceIP.String() != "fe80::1" {
		t.Errorf("адрес: %s", e.SourceIP)
	}
	// Граница: ровно предел символов не меняется.
	e = validEntry()
	e.Actor.Name = strings.Repeat("я", maxActorName)
	if _, err := e.normalize(); err != nil || e.Actor.Name != strings.Repeat("я", maxActorName) {
		t.Errorf("имя на пределе изменено: %v", err)
	}
	e.SourceIP = netip.MustParseAddr("::ffff:192.0.2.7")
	if _, err := e.normalize(); err != nil || e.SourceIP.String() != "192.0.2.7" {
		t.Errorf("IPv4 в IPv6: %s", e.SourceIP)
	}
}

func TestCatalog(t *testing.T) {
	// События из РСБ.2 — обязательные.
	for _, a := range []string{
		"auth.login", "auth.logout", "auth.login_failed", "gateway.auth_failed",
		"component.start", "component.stop", "integrity.check", "system.error",
		"update.install", "backup.create", "backup.restore", "system.restored", "data.export", "events.content_read",
	} {
		ev, ok := Lookup(a)
		if !ok || !ev.Mandatory {
			t.Errorf("%s: нет в перечне или не обязательное", a)
		}
	}
	all := Catalog()
	if len(all) != len(catalog) {
		t.Fatal("Catalog теряет события")
	}
	for i, ev := range all {
		if i > 0 && all[i-1].Action >= ev.Action {
			t.Fatal("Catalog не отсортирован")
		}
		if ev.Title == "" {
			t.Errorf("%s без описания", ev.Action)
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	ok := Settings{DisabledActions: []string{"events.list"}, RetentionDays: DefaultRetentionDays}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]Settings{
		"обязательное": {DisabledActions: []string{"auth.login"}, RetentionDays: 365},
		"вне перечня":  {DisabledActions: []string{"x.y"}, RetentionDays: 365},
		"повтор":       {DisabledActions: []string{"events.list", "events.list"}, RetentionDays: 365},
		"срок мал":     {RetentionDays: MinRetentionDays - 1},
		"срок велик":   {RetentionDays: MaxRetentionDays + 1},
	} {
		if err := s.Validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	for _, d := range []int{MinRetentionDays, MaxRetentionDays} {
		if err := (Settings{RetentionDays: d}).Validate(); err != nil {
			t.Errorf("срок %d отклонён", d)
		}
	}
}

func TestTechEntryValidate(t *testing.T) {
	good := TechEntry{Component: "server", Kind: TechStart, Level: LevelInfo, Message: "запущен"}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]func(*TechEntry){
		"компонент":         func(e *TechEntry) { e.Component = "Server!" },
		"вид":               func(e *TechEntry) { e.Kind = "boot" },
		"важность":          func(e *TechEntry) { e.Level = "debug" },
		"ошибка без класса": func(e *TechEntry) { e.Kind = TechError },
		"класс":             func(e *TechEntry) { e.Class = "disk" },
		"пустое сообщение":  func(e *TechEntry) { e.Message = "" },
	}
	for name, mut := range bad {
		e := good
		mut(&e)
		if err := e.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}
