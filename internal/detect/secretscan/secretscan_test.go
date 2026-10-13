package secretscan

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Синтетические секреты для тестов: случайные строки, никогда не выданные
// поставщиками. Префиксы собираются из частей (j), чтобы сканеры секретов
// (push protection, gitleaks) не принимали исходники тестов за утечку.

const (
	b62    = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64url = b62 + "-_"
	b64std = b62 + "+/"
	lowDig = "abcdefghijklmnopqrstuvwxyz0123456789"
	upDig  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	digits = "0123456789"
)

func mix(n uint64) uint64 {
	n += 0x9e3779b97f4a7c15
	n = (n ^ (n >> 30)) * 0xbf58476d1ce4e5b9
	n = (n ^ (n >> 27)) * 0x94d049bb133111eb
	return n ^ (n >> 31)
}

// rnd — k символов алфавита, детерминированно из n (не источник случайности
// для безопасности: только разнообразие тестовых данных).
func rnd(n uint64, alphabet string, k int) string {
	b := make([]byte, k)
	for i := range b {
		b[i] = alphabet[mix(n*1000003+uint64(i))%uint64(len(alphabet))]
	}
	return string(b)
}

func j(parts ...string) string { return strings.Join(parts, "") }

// pw — синтетический пароль: прописная, строчные, цифры и знак.
func pw(n uint64) string { return "Q" + rnd(n, lowDig, 10) + "7!" }

func pem(kind string, n uint64) string {
	var b strings.Builder
	b.WriteString(j("-----BEG", "IN ", kind, "-----\n"))
	for i := range uint64(4) {
		b.WriteString(rnd(n+i, b64std, 64) + "\n")
	}
	b.WriteString(j("-----EN", "D ", kind, "-----"))
	return b.String()
}

func jwt(n uint64) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + enc([]byte(`{"sub":"user-0001","exp":1900000000}`)) + "." + rnd(n, b64url, 43)
}

func find(t testing.TB, text string, dir detect.Direction) []detect.Finding {
	t.Helper()
	fs, err := New().Detect(context.Background(), detect.Text{Text: text, Direction: dir})
	if err != nil {
		t.Fatal(err)
	}
	prev := -1
	for _, f := range fs {
		if err := detect.ValidateFinding(f, New(), text); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if f.Start < prev {
			t.Fatalf("%q: находки пересекаются или не по порядку: %+v", text, fs)
		}
		prev = f.End
	}
	return fs
}

// above — находки с оценкой от порога по умолчанию 0,5.
func above(fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	for _, f := range fs {
		if f.Score >= 0.5 {
			out = append(out, f)
		}
	}
	return out
}

type secretCase struct{ text, cat, value string }

func positives() []secretCase {
	rsa := pem("RSA PRIVATE KEY", 1)
	ossh := pem("OPENSSH PRIVATE KEY", 2)
	truncated := strings.SplitN(pem("PRIVATE KEY", 3), "\n-----EN", 2)[0]
	app := j("aisec", "_") + rnd(4, lowDig, 8) + "_" + rnd(5, b64url, 43)
	gh := j("gh", "p_") + rnd(6, b62, 36)
	ghPat := j("github", "_pat_") + rnd(7, b62+"_", 82)
	gl := j("gl", "pat-") + rnd(8, b62, 20)
	slack := j("xo", "xb-") + rnd(9, digits, 12) + "-" + rnd(10, digits, 12) + "-" + rnd(11, b62, 24)
	aws := j("AK", "IA") + rnd(12, upDig, 16)
	google := j("AI", "za") + rnd(13, b64url, 35)
	openai := j("sk", "-proj-") + rnd(14, b64url, 48)
	anthropic := j("sk", "-ant-api03-") + rnd(15, b64url, 93)
	stripe := j("sk", "_live_") + rnd(16, b62, 24)
	yc := j("AQ", "VN") + rnd(17, b64url, 35)
	iam := j("t", "1.") + rnd(18, b64url, 16) + "." + rnd(19, b64url, 86)
	yoauth := j("y0", "_") + rnd(20, b64url, 50)
	npm := j("np", "m_") + rnd(21, b62, 36)
	tg := "5" + rnd(22, digits, 9) + ":" + "AA" + rnd(23, b62, 33)
	token := jwt(24)
	conn := pw(25)
	p1, p2, p3, p4, p5 := pw(26), pw(27), pw(28), pw(29), pw(30)
	key1, key2, key3, key4 := rnd(31, b62, 32), rnd(32, b62, 40), rnd(33, b62, 32), rnd(34, b62, 32)
	bearer := rnd(35, b64url, 40)
	basic := base64.StdEncoding.EncodeToString([]byte("svc-user:" + pw(36)))
	ent := rnd(37, b62, 40)
	return []secretCase{
		{"Вот ключ сервера:\n" + rsa + "\nпроверь доступ", CatPrivateKey, rsa},
		{ossh, CatPrivateKey, ossh},
		{"обрывок ключа: " + truncated, CatPrivateKey, truncated},
		{"Ключ приложения " + app, CatAPIKey, app},
		{"export GH_TOKEN=" + gh, CatAPIKey, gh},
		{"token: " + ghPat, CatAPIKey, ghPat},
		{gl + " — токен для CI", CatAPIKey, gl},
		{"SLACK_BOT=" + slack, CatAPIKey, slack},
		{"aws_access_key_id = " + aws, CatAPIKey, aws},
		{"https://maps.example.test/api?key=" + google, CatAPIKey, google},
		{"OPENAI_API_KEY=" + openai, CatAPIKey, openai},
		{"Используй ключ " + anthropic + " для запросов", CatAPIKey, anthropic},
		{"stripe: " + stripe, CatAPIKey, stripe},
		{"Yandex Cloud API key: " + yc, CatAPIKey, yc},
		{"IAM-токен " + iam, CatAPIKey, iam},
		{"OAuth " + yoauth, CatAPIKey, yoauth},
		{"//registry.npmjs.org/:_authToken=" + npm, CatAPIKey, npm},
		{"Бот: " + tg, CatAPIKey, tg},
		{"Authorization: Bearer " + token, CatJWT, token},
		{"cookie session=" + token + "; path=/", CatJWT, token},
		{"DATABASE_URL=postgres://app:" + conn + "@db.internal:5432/app", CatConnString, conn},
		{"mongodb+srv://svc:" + conn + "@cluster0.example.test/db?retryWrites=true", CatConnString, conn},
		{"Пароль от почты: " + p1, CatPassword, p1},
		{"DB_PASSWORD=" + p2, CatPassword, p2},
		{`{"user": "admin", "password": "` + p3 + `"}`, CatPassword, p3},
		{"my password is " + p4 + ", не говори никому", CatPassword, p4},
		{"Логин ivan, пароль " + p5, CatPassword, p5},
		{"dbPassword: '" + p1 + "'", CatPassword, p1},
		{"Пароль: 4821", CatPassword, "4821"},
		{"api_key: " + key1, CatAPIKey, key1},
		{"client_secret=" + key2, CatToken, key2},
		{"x-api-key: " + key3, CatAPIKey, key3},
		{"API-ключ: " + key4, CatAPIKey, key4},
		{"Authorization: Bearer " + bearer, CatToken, bearer},
		{"Authorization: Basic " + basic, CatToken, basic},
		{"Ключ доступа " + ent + " действует до пятницы", CatToken, ent},
	}
}

// TestDM32_SecretsInRequest: секреты в запросе к модели (DM-32). Позиции
// охватывают само значение — по ним маскирование.
func TestDM32_SecretsInRequest(t *testing.T) {
	for _, c := range positives() {
		fs := above(find(t, c.text, detect.Input))
		if len(fs) != 1 || fs[0].Category != c.cat || c.text[fs[0].Start:fs[0].End] != c.value || fs[0].Threat != "DM-32" {
			t.Errorf("%q: %+v, ожидалось %s на %q", c.text, fs, c.cat, c.value)
		}
	}
}

// TestDM10_SecretsInResponse: те же секреты в ответе модели — DM-10.
func TestDM10_SecretsInResponse(t *testing.T) {
	text := "Вот конфигурация:\nDB_PASSWORD=" + pw(40) + "\nAuthorization: Bearer " + jwt(41)
	fs := above(find(t, text, detect.Output))
	if len(fs) != 2 || fs[0].Category != CatPassword || fs[1].Category != CatJWT {
		t.Fatalf("%+v", fs)
	}
	for _, f := range fs {
		if f.Threat != "DM-10" || f.Detector != ID || f.Version != Version {
			t.Fatalf("%+v", f)
		}
	}
}

// Ложные срабатывания дороже пропусков (ТЗ, 1.6): тексты о паролях и
// ключах, заглушки из документации, обращения к переменным, хеши, UUID,
// публичные ключи и сертификаты, идентификаторы в ссылках.
func TestNoFalsePositives(t *testing.T) {
	pub := pem("PUBLIC KEY", 50)
	cert := pem("CERTIFICATE", 51)
	for _, text := range []string{
		"Пароль должен содержать не менее 8 символов, буквы и цифры",
		"Забыли пароль? Нажмите «Восстановить пароль».",
		"password: ${DB_PASSWORD}",
		"DB_PASSWORD=",
		`password = os.Getenv("DB_PASSWORD")`,
		"password: process.env.DB_PASSWORD",
		"password: string (required)",
		`"password": {"type": "string", "minLength": 8}`,
		`password: ""`,
		"token_type: bearer",
		"max_tokens: 4096",
		"password_min_length: 12",
		"if password == expected {",
		"Секретный ингредиент — корица",
		"Ключ к успеху — регулярность",
		"токен — минимальная единица текста для модели",
		"basic knowledge of SQL",
		"Bearer tokens are described in RFC 6750",
		"Authorization: Bearer <token>",
		"Authorization: Bearer YOUR_API_KEY",
		"Bearer ${TOKEN}",
		"postgres://user:password@localhost:5432/db",
		"Подключение: postgres://localhost:5432/app",
		"https://example.test/docs?page=2&lang=ru",
		"commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
		"sha256: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		"request 550e8400-e29b-41d4-a716-446655440000",
		"Пример из документации AWS: " + j("AK", "IAIOSFODNN7EXAMPLE"),
		"ssh-keygen -t ed25519 -C ci@example.test",
		"Публичный ключ:\n" + pub,
		"Публичный ключ: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + rnd(57, b62, 43),
		"Сертификат:\n" + cert,
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI" + rnd(53, b62, 43) + " ci@example.test",
		"Ссылка https://docs.example.test/document/d/" + rnd(54, b62, 44) + "/edit",
		"data:image/png;base64," + rnd(55, b64std, 200),
		"sk-learn — библиотека машинного обучения",
		"requestId " + rnd(56, b62, 40),
		j("-----BEG", "IN PRIVATE KEY-----\n...\n-----EN", "D PRIVATE KEY-----"),
		"",
	} {
		if fs := above(find(t, text, detect.Input)); len(fs) > 0 {
			t.Errorf("%q: ложное срабатывание %+v", text, fs)
		}
	}
}

// fold приводит к нижнему регистру латиницу и кириллицу без изменения длины;
// остальные символы не трогает.
func TestFold(t *testing.T) {
	in := "ПАРОЛЬ Ёлка PASSWORD Straße İ ΣΑ 😀 \xff"
	got, err := fold(context.Background(), in)
	if err != nil || len(got) != len(in) {
		t.Fatalf("%q, %v", got, err)
	}
	if want := "пароль ёлка password straße İ ΣΑ 😀 \xff"; got != want {
		t.Fatalf("%q, ожидалось %q", got, want)
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, detect.Text{Text: "DB_PASSWORD=" + pw(1), Direction: detect.Input}); err == nil {
		t.Fatal("отменённый контекст не учтён")
	}
}

// Детектор соблюдает срок и на больших текстах худшего вида.
func TestDeadline(t *testing.T) {
	text := strings.Repeat("password=a: ", 32<<20/12) // 32 МиБ — предел тела запроса шлюза
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := New().Detect(ctx, detect.Text{Text: text, Direction: detect.Input})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка %v", err)
	}
	el := time.Since(start)
	t.Logf("остановился через %v", el)
	if el > time.Second {
		t.Fatalf("остановился через %v", el)
	}
}

// Детектор — цель фаззинга (ТЗ, 5.2, 8.5): без паники, находки корректны
// (проверка реестра, границы символов), не пересекаются и идут по порядку.
func FuzzDetect(f *testing.F) {
	for _, c := range positives()[:12] {
		f.Add(c.text)
	}
	f.Add("password=\"" + pw(60) + "\" token: " + rnd(61, b62, 40))
	f.Add("-----BEGIN PRIVATE KEY-----")
	f.Add("eyJ.eyJ.")
	f.Add("postgres://:@")
	f.Fuzz(func(t *testing.T, text string) {
		for _, fd := range find(t, text, detect.Input) {
			if !detect.OnRuneBoundary(text, fd.Start) || !detect.OnRuneBoundary(text, fd.End) {
				t.Fatalf("позиции [%d, %d) не на границах символов", fd.Start, fd.End)
			}
		}
	})
}

// Промпт 8 КБ с несколькими секретами (цель ТЗ 5.1 — p95 ≤ 30 мс на все
// правила).
func BenchmarkDetect8KB(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 8<<10 {
		sb.WriteString("Помоги настроить сервис: конфигурация ниже, ошибка при подключении к базе. ")
		sb.WriteString("DB_PASSWORD=" + pw(70) + "\nAuthorization: Bearer " + jwt(71) + "\n")
	}
	text := detect.Text{Text: sb.String(), Direction: detect.Input}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}

// Худший случай: 1 МБ ключевых слов, разделителей и случайных строк.
func BenchmarkDetectWorst(b *testing.B) {
	text := detect.Text{Text: strings.Repeat("password=a: token="+rnd(80, b62, 40)+" eyJ ", 1<<20/72), Direction: detect.Input}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}
