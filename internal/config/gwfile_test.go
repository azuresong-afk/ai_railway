package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func readFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/fixtures/config/gateway.yaml")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseGatewayFileFixture(t *testing.T) {
	f, err := ParseGatewayFile(strings.NewReader(readFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Providers) != 3 || len(f.Applications) != 1 {
		t.Fatalf("разбор: %+v", f)
	}
	p := f.Providers[0]
	if !p.IsExternal() || time.Duration(p.ConnectTimeout) != 5*time.Second {
		t.Fatalf("провайдер: %+v", p)
	}
	if !f.Providers[1].IsExternal() {
		t.Fatal("провайдер без признака external должен считаться внешним (ТЗ, 5.4)")
	}
	a := f.Applications[0]
	if a.Aliases["default"] != "mock-echo" || a.Quotas.MaxTokens != 4096 || a.Keys[0].Prefix != "aisec_abcd1234" {
		t.Fatalf("приложение: %+v", a)
	}
}

func TestParseGatewayFileErrors(t *testing.T) {
	base := readFixture(t)
	cases := map[string][2]string{
		"неизвестное поле":     {"policy: base\n", "policy: base\n    debug: true\n"},
		"схема":                {"schema_version: 1", "schema_version: 2"},
		"http":                 {"https://mock-llm:9443", "http://mock-llm:9443"},
		"учётные данные в URL": {"https://mock-llm:9443", "https://u:p@mock-llm:9443"},
		"нет доверия":          {"    ca_file: /keys/ca.pem\n", ""},
		"system_roots":         {"    ca_file: /keys/ca.pem\n", "    ca_file: /keys/ca.pem\n    system_roots: true\n"},
		"тип провайдера":       {"type: openai", "type: claude"},
		"нет провайдера":       {"provider: mock", "provider: nope"},
		"нет моделей":          {"models: [mock-echo, mock-stream-slow]", "models: []"},
		"псевдоним":            {"default: mock-echo", "default: other"},
		"full":                 {"storage: masked", "storage: full"},
		"режим":                {"policy_mode: monitor", "policy_mode: audit"},
		"fail mode":            {"fail_mode: fail_closed", "fail_mode: ignore"},
		"user_from":            {"user_from: header", "user_from: cookie"},
		"префикс":              {"prefix: aisec_abcd1234", "prefix: sk-1234"},
		"хеш":                  {"sha256: 0000000000000000000000000000000000000000000000000000000000000000", "sha256: plain-secret"},
		"срок":                 {"expires: 2027-01-01", "expires: 01.01.2027"},
		"подсеть":              {"10.0.0.0/8", "10.0.0.0/33"},
		"подсеть IPv4-in-IPv6": {"10.0.0.0/8", "::ffff:10.0.0.0/104"},
		"биты узла в подсети":  {"10.0.0.0/8", "10.1.2.3/8"},
		"нет events_file":      {"  events_file: /var/lib/aisec/events.jsonl\n", ""},
		"квота":                {"max_tokens: 4096", "max_tokens: -1"},
		"таймаут":              {"connect_timeout: 5s", "connect_timeout: 1h"},
		"длительность":         {"connect_timeout: 5s", "connect_timeout: 5"},
		"gigachat без scope":   {"    scope: GIGACHAT_API_CORP\n", ""},
		"gigachat scope":       {"scope: GIGACHAT_API_CORP", "scope: GIGACHAT_API_ALL"},
		"yandex folder_id":     {"folder_id: b1gexamplefolder0000", "folder_id: B1G/../x"},
		"yandex без folder_id": {"    folder_id: b1gexamplefolder0000\n", ""},
		"id":                   {"id: support-bot", "id: Support Bot"},
		"два документа":        {"schema_version: 1", "schema_version: 1\n---\nx: 1\n---"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(base, c[0]) {
				t.Fatalf("фикстура не содержит %q", c[0])
			}
			doc := strings.Replace(base, c[0], c[1], 1)
			if _, err := ParseGatewayFile(strings.NewReader(doc)); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
	// Тот же блок приложения дважды: повтор id и префикса ключа.
	app := base[strings.Index(base, "  - id: support-bot"):]
	_, err := ParseGatewayFile(strings.NewReader(base + app))
	if err == nil || !strings.Contains(err.Error(), "указано дважды") || !strings.Contains(err.Error(), "уже используется") {
		t.Fatalf("повтор приложения и префикса ключа должен отвергаться: %v", err)
	}
	if _, err := ParseGatewayFile(strings.NewReader(strings.Repeat("#", MaxGatewayFile+1))); err == nil {
		t.Fatal("слишком большой файл должен отвергаться")
	}
}

func TestLoadGatewayFilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/gateway.yaml"
	if err := os.WriteFile(path, []byte(readFixture(t)), 0o600); err != nil {
		t.Fatal(err)
	}
	// Чтение группой и остальными допустимо: секретов в файле нет.
	if err := os.Chmod(path, 0o644); err != nil { //nolint:gosec // G302: тест проверяет, что конфигурация с правами 0644 принимается
		t.Fatal(err)
	}
	if _, err := LoadGatewayFile(path); err != nil {
		t.Fatalf("файл 0644: %v", err)
	}
	// Файл, который может изменить группа или любой пользователь, не принимается.
	for _, perm := range []os.FileMode{0o664, 0o646} {
		if err := os.Chmod(path, perm); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadGatewayFile(path); err == nil {
			t.Errorf("права %o: ожидалась ошибка", perm)
		}
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Каталог, в который может писать любой, — подмена файла переименованием.
	if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // G302: тест проверяет отказ при каталоге с записью для всех
		t.Fatal(err)
	}
	if _, err := LoadGatewayFile(path); err == nil {
		t.Error("каталог 0777: ожидалась ошибка")
	}
	// С битом sticky чужой файл не переименовать и не удалить — допустимо.
	if err := os.Chmod(dir, 0o777|os.ModeSticky); err != nil { //nolint:gosec // G302: тест проверяет каталог с битом sticky
		t.Fatal(err)
	}
	if _, err := LoadGatewayFile(path); err != nil {
		t.Errorf("каталог с битом sticky: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: каталогу нужен бит x; 0700 — только владелец
		t.Fatal(err)
	}
	if _, err := LoadGatewayFile(dir); err == nil {
		t.Error("каталог вместо файла: ожидалась ошибка")
	}
	if _, err := LoadGatewayFile(dir + "/нет.yaml"); err == nil {
		t.Error("нет файла: ожидалась ошибка")
	}
}

func FuzzParseGatewayFile(f *testing.F) {
	f.Add([]byte("schema_version: 1\napplications: []\n"))
	f.Add([]byte("{"))
	if b, err := os.ReadFile("../../testdata/fixtures/config/gateway.yaml"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseGatewayFile(strings.NewReader(string(data)))
		if err != nil {
			return
		}
		for _, a := range cfg.Applications {
			if a.Storage == "full" || len(a.Keys) == 0 {
				t.Fatalf("принята недопустимая конфигурация: %+v", a)
			}
		}
	})
}
