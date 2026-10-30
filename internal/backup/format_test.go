package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

const testPhrase = "синтетическая фраза копии 2026"

func provider(t testing.TB) crypto.Provider {
	t.Helper()
	p, err := crypto.New(crypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

var testTime = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// sampleSnapshot — непротиворечивая копия с объектами всех видов
// (синтетические данные).
func sampleSnapshot(t testing.TB, p crypto.Provider, keys *Keys) *Snapshot {
	t.Helper()
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	const (
		org   = "00000000-0000-7000-8000-000000000001"
		user1 = "0192a000-0000-7000-8000-000000000001"
		prov1 = "0192a000-0000-7000-8000-000000000101"
		app1  = "0192a000-0000-7000-8000-000000000201"
		key1  = "0192a000-0000-7000-8000-000000000301"
		key2  = "0192a000-0000-7000-8000-000000000302"
		pol1  = "0192a000-0000-7000-8000-000000000401"
		tok1  = "0192a000-0000-7000-8000-000000000501"
	)
	totp, err := keys.SealSecret(bytes.Repeat([]byte{1}, crypto.TOTPSecretSize), secretMFA, user1)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := keys.SealSecret([]byte("synthetic-credential"), secretProviderCredential, prov1)
	if err != nil {
		t.Fatal(err)
	}
	spec := "id: corp\nname: Синтетическая\nmode: monitor\n"
	from := key1
	s := &Snapshot{
		Version: FormatVersion, OrgID: org, OrgName: "Синтетическая организация", SchemaVersion: 18, TakenAt: testTime,
		Settings: Settings{Events: &EventSettings{MetadataDays: 365, ContentDays: 90, UpdatedAt: testTime}},
		Roles: []Role{{ID: "duty_analyst", DisplayName: "Дежурный", CreatedAt: testTime, CreatedBy: "user:x", UpdatedAt: testTime,
			Permissions: []RolePermission{{Permission: "events.read", Scope: "all"}}}},
		Users: []User{{ID: user1, Login: "admin", DisplayName: "Админ", Role: "security_admin", Status: "active",
			PasswordHash:      "$argon2id$v=19$m=65536,t=3,p=2$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U",
			PasswordChangedAt: testTime, CreatedAt: testTime, CreatedBy: "setup",
			MFA: &MFA{State: "enabled", Secret: totp, Alg: "AES-256-GCM", CreatedAt: testTime, EnabledAt: &testTime}}},
		APITokens: []APIToken{{ID: tok1, UserID: user1, Name: "ci", Prefix: "aisec_pat_abcdefgh", TokenHash: make([]byte, 32),
			HashAlg: "SHA-256", Permissions: []string{"events.read:all"}, ExpiresAt: testTime.Add(time.Hour), CreatedAt: testTime}},
		Providers: []Provider{{ID: prov1, Slug: "mock", Name: "Мок", Type: "openai", BaseURL: "https://llm.example",
			CAPEM: "-----", Credential: cred, CredentialSetAt: &testTime, CreatedAt: testTime, CreatedBy: "x", UpdatedAt: testTime, UpdatedBy: "x"}},
		Applications: []Application{{ID: app1, Slug: "bot", Name: "Бот", OwnerID: user1, Env: "test", ProviderID: prov1,
			Models: []string{"m"}, Aliases: json.RawMessage(`{}`), Policy: "corp", PolicyMode: "monitor", Storage: "masked",
			FailMode: "fail_open", UserFrom: "none", Quotas: json.RawMessage(`{}`), Lists: json.RawMessage(`[]`),
			CreatedAt: testTime, CreatedBy: "x", UpdatedAt: testTime, UpdatedBy: "x",
			Keys: []AppKey{
				{ID: key2, Name: "новый", Prefix: "aisec_bbbbbbbb", KeyHash: make([]byte, 32), HashAlg: "SHA-256",
					ExpiresAt: testTime.Add(time.Hour), CreatedAt: testTime, CreatedBy: "x", RotatedFrom: &from},
				{ID: key1, Name: "старый", Prefix: "aisec_aaaaaaaa", KeyHash: make([]byte, 32), HashAlg: "SHA-256",
					ExpiresAt: testTime.Add(time.Hour), CreatedAt: testTime, CreatedBy: "x"},
			}}},
		Policies: []Policy{{ID: pol1, Slug: "corp", Name: "Синтетическая", Mode: "monitor", CurrentVersion: 1,
			CreatedAt: testTime, CreatedBy: "x", UpdatedAt: testTime, UpdatedBy: "x",
			Versions: []PolicyVersion{{Version: 1, SpecYAML: spec, SpecHash: h.Sum([]byte(spec)), HashAlg: h.Name(),
				Source: "api", CreatedAt: testTime, CreatedBy: "x"}}}},
	}
	if err := s.SetUserHMACKey(keys, bytes.Repeat([]byte{9}, 32)); err != nil {
		t.Fatal(err)
	}
	return s
}

func sealSample(t *testing.T, p crypto.Provider) ([]byte, *Snapshot) {
	t.Helper()
	w, err := NewWriter(context.Background(), p, []byte(testPhrase), testTime)
	if err != nil {
		t.Fatal(err)
	}
	s := sampleSnapshot(t, p, w.Keys())
	data, err := w.Seal(s)
	if err != nil {
		t.Fatal(err)
	}
	return data, s
}

// Круговой тест формата: копия открывается той же фразой, содержимое и
// секреты совпадают, секреты в файле не видны.
func TestSealOpenRoundTrip(t *testing.T) {
	p := provider(t)
	data, want := sealSample(t, p)
	if !bytes.HasPrefix(data, []byte(`{"format":"aisec-config-backup","version":1,"profile":"standard","kdf":"Argon2id","kdf_params":"m=65536,t=3,p=2"`)) {
		t.Fatalf("заголовок: %.200s", data)
	}
	for _, leak := range []string{"synthetic-credential", "Синтетическая", "admin", "argon2id$"} {
		if bytes.Contains(data, []byte(leak)) {
			t.Errorf("в файле открытым текстом: %q", leak)
		}
	}
	a, err := Open(context.Background(), p, []byte(testPhrase), data)
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.Marshal(a.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	exp, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, exp) {
		t.Fatalf("содержимое отличается:\n%s\n%s", got, exp)
	}
	if !a.CreatedAt.Equal(testTime) {
		t.Errorf("время копии %v", a.CreatedAt)
	}
	cred, err := a.Keys().OpenSecret(a.Snapshot.Providers[0].Credential, secretProviderCredential, a.Snapshot.Providers[0].ID)
	if err != nil || string(cred) != "synthetic-credential" {
		t.Fatalf("учётные данные: %q %v", cred, err)
	}
	key, err := a.UserHMACKey()
	if err != nil || !bytes.Equal(key, bytes.Repeat([]byte{9}, 32)) {
		t.Fatalf("ключ HMAC: %v", err)
	}
	// Секрет не переносится на другой объект: AAD — вид и ID.
	if _, err := a.Keys().OpenSecret(a.Snapshot.Providers[0].Credential, secretMFA, a.Snapshot.Providers[0].ID); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("секрет открыт с чужим видом: %v", err)
	}
}

// Неверная фраза и подменённый байт в любой части файла — один и тот же
// отказ ErrDecrypt (или ErrFormat для испорченного заголовка), без
// подробностей.
func TestOpenRejectsWrongPassphraseAndTampering(t *testing.T) {
	p := provider(t)
	data, _ := sealSample(t, p)
	ctx := context.Background()
	if _, err := Open(ctx, p, []byte(testPhrase+"!"), data); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("неверная фраза: %v", err)
	}
	headerEnd := bytes.IndexByte(data, '\n')
	saltAt := bytes.Index(data, []byte(`"salt":"`)) + len(`"salt":"`)
	for name, i := range map[string]int{
		"соль":          saltAt + 2,
		"время":         bytes.Index(data, []byte(`"created_at":"2026`)) + len(`"created_at":"2026`) - 1,
		"начало тела":   headerEnd + 1,
		"середина тела": headerEnd + (len(data)-headerEnd)/2,
		"тег":           len(data) - 1,
	} {
		bad := bytes.Clone(data)
		bad[i] ^= 0x01
		_, err := Open(ctx, p, []byte(testPhrase), bad)
		if !errors.Is(err, ErrDecrypt) && !errors.Is(err, ErrFormat) {
			t.Errorf("%s (байт %d): %v", name, i, err)
		}
	}
	if _, err := Open(ctx, p, []byte(testPhrase), data[:len(data)-1]); !errors.Is(err, ErrDecrypt) {
		t.Errorf("обрезанный файл: %v", err)
	}
	// Версия в заголовке подменена: AAD не сходится — отказ до разбора.
	bad := bytes.Replace(data, []byte(`"version":1`), []byte(`"version":2`), 1)
	if _, err := Open(ctx, p, []byte(testPhrase), bad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("подменённая версия: %v", err)
	}
}

// sealRaw шифрует произвольное содержимое с заголовком версии version —
// как это сделал бы другой выпуск.
func sealRaw(t *testing.T, p crypto.Provider, version int, payload []byte) []byte {
	t.Helper()
	w, err := NewWriter(context.Background(), p, []byte(testPhrase), testTime)
	if err != nil {
		t.Fatal(err)
	}
	var h header
	if err := json.Unmarshal(bytes.TrimSuffix(w.header, []byte("\n")), &h); err != nil {
		t.Fatal(err)
	}
	h.Version = version
	line, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	line = append(line, '\n')
	sealed, err := w.keys.payload.Seal(payload, payloadAAD(line))
	if err != nil {
		t.Fatal(err)
	}
	return append(line, sealed...)
}

// Порядок проверок: AEAD → версия → схема. Подлинный файл другой версии —
// ErrVersion; подлинный файл с лишним полем или нарушенной схемой — ErrFormat.
func TestOpenVersionThenSchema(t *testing.T) {
	p := provider(t)
	ctx := context.Background()
	payload := []byte(`{"version":2,"something_new":true}`)
	if _, err := Open(ctx, p, []byte(testPhrase), sealRaw(t, p, 2, payload)); !errors.Is(err, ErrVersion) {
		t.Fatalf("версия 2: %v", err)
	}
	w, err := NewWriter(ctx, p, []byte(testPhrase), testTime)
	if err != nil {
		t.Fatal(err)
	}
	good, err := json.Marshal(sampleSnapshot(t, p, w.Keys()))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"лишнее поле": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`{"version":1,`), []byte(`{"version":1,"extra":1,`), 1)
		},
		"данные после":       func(b []byte) []byte { return append(b, []byte(` {}`)...) },
		"версия содержимого": func(b []byte) []byte { return bytes.Replace(b, []byte(`{"version":1,`), []byte(`{"version":3,`), 1) },
		"неверный ID": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"0192a000-0000-7000-8000-000000000101"`), []byte(`"x"`), 1)
		},
		"хеш политики": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`mode: monitor\n`), []byte(`mode: enforce\n`), 1)
		},
		"не JSON": func([]byte) []byte { return []byte("not json") },
	} {
		_, err := Open(ctx, p, []byte(testPhrase), sealRaw(t, p, 1, mutate(bytes.Clone(good))))
		if !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Open(ctx, p, []byte(testPhrase), sealRaw(t, p, 1, good)); err != nil {
		t.Fatalf("подлинная копия через sealRaw: %v", err)
	}
}

func TestOpenRejectsMalformedHeader(t *testing.T) {
	p := provider(t)
	ctx := context.Background()
	for name, data := range map[string][]byte{
		"пусто":          nil,
		"без перевода":   []byte(`{"format":"aisec-config-backup"}`),
		"длинный":        append(bytes.Repeat([]byte(" "), maxHeader+1), '\n'),
		"чужой формат":   []byte(`{"format":"x","version":1,"profile":"standard","kdf":"Argon2id","kdf_params":"m=65536,t=3,p=2","salt":"AAAAAAAAAAAAAAAAAAAAAA==","aead":"AES-256-GCM","created_at":"2026-10-22T00:00:00Z"}` + "\nxx"),
		"лишнее поле":    []byte(`{"format":"aisec-config-backup","x":1}` + "\n"),
		"короткая соль":  []byte(`{"format":"aisec-config-backup","version":1,"profile":"standard","kdf":"Argon2id","kdf_params":"m=65536,t=3,p=2","salt":"AAAA","aead":"AES-256-GCM","created_at":"2026-10-22T00:00:00Z"}` + "\nxx"),
		"память выше":    []byte(`{"format":"aisec-config-backup","version":1,"profile":"standard","kdf":"Argon2id","kdf_params":"m=1048576,t=3,p=2","salt":"AAAAAAAAAAAAAAAAAAAAAA==","aead":"AES-256-GCM","created_at":"2026-10-22T00:00:00Z"}` + "\nxx"),
		"чужой профиль":  []byte(`{"format":"aisec-config-backup","version":1,"profile":"gost","kdf":"Argon2id","kdf_params":"m=65536,t=3,p=2","salt":"AAAAAAAAAAAAAAAAAAAAAA==","aead":"AES-256-GCM","created_at":"2026-10-22T00:00:00Z"}` + "\nxx"),
		"два объекта":    []byte(`{"format":"aisec-config-backup"} {}` + "\n"),
		"больше предела": make([]byte, MaxFileSize+1),
	} {
		if _, err := Open(ctx, p, []byte(testPhrase), data); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCheckPassphrase(t *testing.T) {
	for p, ok := range map[string]bool{
		"":                       false,
		"пятнадцать симв":        false, // 15 символов
		"шестнадцать симв":       true,  // 16 символов (32 байта)
		"0123456789abcdef":       true,
		strings.Repeat("я", 512): true,
		strings.Repeat("я", 513): false, // 1026 байт
		"0123456789abcde\xff":    false,
	} {
		if err := CheckPassphrase([]byte(p)); (err == nil) != ok {
			t.Errorf("%q: %v", p, err)
		}
	}
	if _, err := NewWriter(context.Background(), provider(t), []byte("короткая"), testTime); err == nil {
		t.Fatal("короткая фраза принята")
	}
}

// Н41 ревью 2.r4: фраза новой копии — не только по длине.
func TestCheckNewPassphrase(t *testing.T) {
	for p, ok := range map[string]bool{
		testPhrase: true,
		"конь лампа ветер окно": true,
		"aaaaaaaaaaaaaaaa":      false, // один символ
		"abababababababab":      false, // два разных
		"1234567890123456":      false, // последовательность с переходом 9→0
		"6543210987654321":      false,
		"abcdefghijklmnop":      false,
		"qwerty12qwerty12":      false, // повтор фрагмента
		"пароль1 пароль1 ":      false,
		"пятнадцать симв":       false, // короче 16
		"ООО Синтетика Плюс":    false, // название организации
		"  synthetic-admin-01 ": false, // имя пользователя ОС
	} {
		err := CheckNewPassphrase([]byte(p), "synthetic-admin-01", "ооо синтетика плюс")
		if (err == nil) != ok {
			t.Errorf("%q: %v", p, err)
		}
		if err != nil && !ok && utf8.RuneCountInString(p) >= MinPassphraseChars && !strings.Contains(err.Error(), "случайных слов") {
			t.Errorf("%q: нет подсказки: %v", p, err)
		}
	}
	if _, err := NewWriter(context.Background(), provider(t), []byte("1234567890123456"), testTime); err == nil {
		t.Fatal("последовательность принята для новой копии")
	}
}

// Ссылки внутри копии проверяются до записи в БД.
func TestValidateReferences(t *testing.T) {
	p := provider(t)
	w, err := NewWriter(context.Background(), p, []byte(testPhrase), testTime)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*Snapshot){
		"роль пользователя":    func(s *Snapshot) { s.Users[0].Role = "nobody" },
		"предустановленная":    func(s *Snapshot) { s.Roles[0].ID = "auditor" },
		"владелец приложения":  func(s *Snapshot) { s.Applications[0].OwnerID = "0192a000-0000-7000-8000-00000000ffff" },
		"провайдер приложения": func(s *Snapshot) { s.Applications[0].ProviderID = "0192a000-0000-7000-8000-00000000ffff" },
		"владелец токена":      func(s *Snapshot) { s.APITokens[0].UserID = "0192a000-0000-7000-8000-00000000ffff" },
		"повтор логина":        func(s *Snapshot) { s.Users = append(s.Users, s.Users[0]) },
		"версии не подряд":     func(s *Snapshot) { s.Policies[0].Versions[0].Version = 2 },
		"текущая версия":       func(s *Snapshot) { s.Policies[0].CurrentVersion = 2 },
		"ротация вне приложения": func(s *Snapshot) {
			x := "0192a000-0000-7000-8000-00000000ffff"
			s.Applications[0].Keys[0].RotatedFrom = &x
		},
		"учётные данные без времени": func(s *Snapshot) { s.Providers[0].CredentialSetAt = nil },
		"фактор без секрета":         func(s *Snapshot) { s.Users[0].MFA.Secret = nil },
		"нет схемы":                  func(s *Snapshot) { s.SchemaVersion = 0 },
	} {
		s := sampleSnapshot(t, p, w.Keys())
		mutate(s)
		if err := s.validate(); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	if err := sampleSnapshot(t, p, w.Keys()).validate(); err != nil {
		t.Fatal(err)
	}
}

// Ключ-предшественник вставляется раньше преемника.
func TestKeyOrder(t *testing.T) {
	id := func(s string) *string { return &s }
	keys := []AppKey{{ID: "c", RotatedFrom: id("b")}, {ID: "b", RotatedFrom: id("a")}, {ID: "a"}, {ID: "d"}}
	var got []string
	for _, k := range keyOrder(keys) {
		got = append(got, k.ID)
	}
	if strings.Join(got, "") != "adbc" {
		t.Fatalf("порядок %v", got)
	}
	cyc := []AppKey{{ID: "x", RotatedFrom: id("y")}, {ID: "y", RotatedFrom: id("x")}}
	if len(keyOrder(cyc)) != 2 {
		t.Fatal("цикл потерял ключи")
	}
}

// 4В38 ревью 4.r4: действующий ключ агента восстанавливается отозванным
// не раньше выпуска; отозванный и обычный ключи — как в копии, исходный
// срез не меняется.
func TestRevokeAgentKeys(t *testing.T) {
	gone := testTime.Add(-time.Hour)
	by := "user:x"
	keys := []AppKey{
		{ID: "plain", CreatedAt: testTime.Add(-48 * time.Hour)},
		{ID: "agent", AgentBound: true, CreatedAt: testTime.Add(-48 * time.Hour)},
		{ID: "agent-revoked", AgentBound: true, CreatedAt: testTime.Add(-48 * time.Hour), RevokedAt: &gone, RevokedBy: &by},
		{ID: "agent-future", AgentBound: true, CreatedAt: testTime.Add(time.Hour)},
	}
	out, n := revokeAgentKeys(keys, testTime)
	if n != 2 {
		t.Fatalf("отозвано %d, ожидалось 2", n)
	}
	if out[0].RevokedAt != nil {
		t.Fatal("обычный ключ отозван")
	}
	if k := out[1]; k.RevokedAt == nil || !k.RevokedAt.Equal(testTime) || *k.RevokedBy != keyRevokedByRestore {
		t.Fatalf("ключ агента: %+v", k)
	}
	if k := out[2]; !k.RevokedAt.Equal(gone) || *k.RevokedBy != by {
		t.Fatalf("отозванный ключ изменён: %+v", k)
	}
	if k := out[3]; k.RevokedAt == nil || !k.RevokedAt.Equal(k.CreatedAt) {
		t.Fatalf("отзыв раньше выпуска: %+v", k)
	}
	if keys[1].RevokedAt != nil {
		t.Fatal("изменён исходный срез")
	}
}

// Fuzz открытого заголовка: единственная часть файла, которая разбирается
// до проверки AEAD.
func FuzzParseHeader(f *testing.F) {
	p := provider(f)
	w, err := NewWriter(context.Background(), p, []byte(testPhrase), testTime)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(bytes.Clone(w.header), 1, 2, 3))
	f.Add([]byte("{}\n"))
	f.Add([]byte(`{"format":"aisec-config-backup","salt":"AAAAAAAAAAAAAAAAAAAAAA=="}` + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		h, line, rest, err := parseHeader(data)
		if err != nil {
			return
		}
		if len(line) > maxHeader || len(line)+len(rest) != len(data) || line[len(line)-1] != '\n' {
			t.Fatalf("границы заголовка: %d %d %d", len(line), len(rest), len(data))
		}
		if h.Format != FormatName || len(h.Salt) < crypto.PassphraseSaltSize {
			t.Fatalf("принят заголовок %+v", h)
		}
	})
}

// Fuzz строгого разбора содержимого (после расшифрования).
func FuzzDecodeSnapshot(f *testing.F) {
	p := provider(f)
	w, err := NewWriter(context.Background(), p, []byte(testPhrase), testTime)
	if err != nil {
		f.Fatal(err)
	}
	good, err := json.Marshal(sampleSnapshot(f, p, w.Keys()))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"version":1}`))
	f.Add([]byte(`{"version":1,"org_id":"00000000-0000-7000-8000-000000000001","schema_version":1}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		s, err := decodeSnapshot(data)
		if err != nil {
			if !errors.Is(err, ErrFormat) {
				t.Fatalf("ошибка без ErrFormat: %v", err)
			}
			return
		}
		if s.Version != FormatVersion || !uuidRe.MatchString(s.OrgID) {
			t.Fatalf("принята копия %+v", s)
		}
		if err := s.validate(); err != nil {
			t.Fatalf("принятая копия не проходит проверку: %v", err)
		}
	})
}
