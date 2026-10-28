package shadowai

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func testMAC(t testing.TB) aisecCrypto.MAC {
	t.Helper()
	m, err := provider(t).NewMAC(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func testInput(t testing.TB, format string) importInput {
	t.Helper()
	h, err := provider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	msk, err := time.LoadLocation("Europe/Moscow")
	if err != nil {
		msk = time.FixedZone("MSK", 3*3600)
	}
	return importInput{format: format, catalog: sourceCatalog(t), mac: testMAC(t), hasher: h, loc: msk, now: testNow,
		cutoff: testNow.Truncate(time.Hour).AddDate(0, 0, -DefaultRetentionDays)}
}

func runFile(t *testing.T, format, path string) ImportResult {
	t.Helper()
	res, err := aggregate(context.Background(), bytes.NewReader(readFile(t, path)), testInput(t, format))
	if err != nil {
		t.Fatal(err)
	}
	return res
}

type counts struct{ lines, matched, unmatched, errors int64 }

func (r ImportResult) counts() counts { return counts{r.Lines, r.Matched, r.Unmatched, r.Errors} }

func services(r ImportResult) []string {
	var out []string
	for _, a := range r.Aggregates {
		if !slices.Contains(out, a.Service) {
			out = append(out, a.Service)
		}
	}
	slices.Sort(out)
	return out
}

// Синтетические журналы testdata/shadowai: сопоставленные строки — в
// агрегатах по сервису, псевдониму и часу; строки вне каталога и ошибочные
// только считаются, номера ошибочных — без содержимого.
func TestImportSquid(t *testing.T) {
	res := runFile(t, FormatSquid, "../../testdata/shadowai/access-squid.log")
	if res.counts() != (counts{9, 5, 2, 2}) || !slices.Equal(res.ErrorLines, []int64{7, 8}) {
		t.Fatalf("счётчики: %+v, ошибки в строках %v", res.counts(), res.ErrorLines)
	}
	if got := services(res); !slices.Equal(got, []string{"chatgpt", "deepseek", "gigachat", "yandexgpt-alice"}) {
		t.Fatalf("сервисы: %v", got)
	}
	ivanov := pseudonym(testMAC(t), "ivanov.ia")
	var chat, giga Aggregate
	for _, a := range res.Aggregates {
		switch a.Service {
		case "chatgpt":
			chat = a
		case "gigachat":
			giga = a
		}
	}
	if chat.UserAlias != ivanov || chat.UserKind != UserKindUser || chat.Requests != 2 || chat.Bytes != 7168 ||
		!chat.Bucket.Equal(time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("chatgpt: %+v", chat)
	}
	// Пользователя нет («-») — псевдоним адреса клиента.
	if giga.UserKind != UserKindAddress || giga.UserAlias != pseudonym(testMAC(t), "10.0.12.35") {
		t.Fatalf("gigachat: %+v", giga)
	}
	if len(res.SHA256) != 64 || res.From == nil || !res.UsersPseudonymized || res.Services != 4 {
		t.Fatalf("итог: %+v", res)
	}
}

func TestImportCSV(t *testing.T) {
	res := runFile(t, FormatCSV, "../../testdata/shadowai/access.csv")
	if res.counts() != (counts{6, 4, 1, 1}) || !slices.Equal(res.ErrorLines, []int64{7}) {
		t.Fatalf("счётчики: %+v, ошибки в строках %v", res.counts(), res.ErrorLines)
	}
	if got := services(res); !slices.Equal(got, []string{"chatgpt", "gemini", "huggingface", "perplexity"}) {
		t.Fatalf("сервисы: %v", got)
	}
	for _, a := range res.Aggregates {
		// Время без зоны — в часовом поясе установки (МСК): 10:15 → 07:00 UTC.
		if a.Service == "chatgpt" && !a.Bucket.Equal(time.Date(2026, 10, 27, 7, 0, 0, 0, time.UTC)) {
			t.Fatalf("время без зоны: %s", a.Bucket)
		}
		if a.Service == "perplexity" && !a.Bucket.Equal(time.Date(2026, 10, 27, 8, 0, 0, 0, time.UTC)) {
			t.Fatalf("время с зоной: %s", a.Bucket)
		}
		if a.Service == "huggingface" && a.UserAlias != pseudonym(testMAC(t), "kuznetsov.av") {
			t.Fatalf("пользователь в кавычках: %+v", a)
		}
	}
}

// Журнал UserGate в формате CEF (по открытой документации UserGate
// выгружает журналы в SIEM в CEF и JSON; ADR-0027, п. 5).
func TestImportCEF(t *testing.T) {
	res := runFile(t, FormatCEF, "../../testdata/shadowai/usergate-cef.log")
	if res.counts() != (counts{4, 2, 1, 1}) || !slices.Equal(res.ErrorLines, []int64{4}) {
		t.Fatalf("счётчики: %+v, ошибки в строках %v", res.counts(), res.ErrorLines)
	}
	for _, a := range res.Aggregates {
		switch a.Service {
		case "chatgpt":
			if a.Bytes != 12288 || a.UserKind != UserKindUser {
				t.Fatalf("chatgpt: %+v", a)
			}
		case "microsoft-copilot":
			if a.UserKind != UserKindAddress || !a.Bucket.Equal(time.Date(2026, 10, 27, 7, 0, 0, 0, time.UTC)) {
				t.Fatalf("copilot: %+v", a)
			}
		default:
			t.Fatalf("лишний сервис: %+v", a)
		}
	}
}

// Без ключа псевдонимов пользователи не сохраняются вовсе (ADR-0027, п. 6).
func TestImportWithoutUserKey(t *testing.T) {
	in := testInput(t, FormatSquid)
	in.mac = nil
	res, err := aggregate(context.Background(), bytes.NewReader(readFile(t, "../../testdata/shadowai/access-squid.log")), in)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range res.Aggregates {
		if a.UserAlias != "" || a.UserKind != UserKindNone {
			t.Fatalf("пользователь без ключа: %+v", a)
		}
	}
	if res.UsersPseudonymized {
		t.Fatal("признак псевдонимов")
	}
}

func TestImportLimits(t *testing.T) {
	ctx := context.Background()
	line := "1793095200.000 1 10.0.0.1 TCP_TUNNEL/200 10 CONNECT chatgpt.com:443 u HIER_DIRECT/203.0.113.1 -\n"
	run := func(in importInput, data string) (ImportResult, error) {
		return aggregate(ctx, strings.NewReader(data), in)
	}
	in := testInput(t, FormatSquid)
	// Строка сверх предела — ошибка строки, остаток пропускается.
	in.limits.MaxLine = 200
	res, err := run(in, line+strings.Repeat("x", 1000)+"\n"+line)
	if err != nil || res.counts() != (counts{3, 2, 0, 1}) || !slices.Equal(res.ErrorLines, []int64{2}) {
		t.Fatalf("длинная строка: %+v %v %v", res.counts(), res.ErrorLines, err)
	}
	// Длинная последняя строка без перевода строки.
	if res, err = run(in, line+strings.Repeat("x", 1000)); err != nil || res.Errors != 1 {
		t.Fatalf("длинный хвост: %+v %v", res.counts(), err)
	}
	in = testInput(t, FormatSquid)
	in.limits.MaxLines = 2
	if _, err := run(in, strings.Repeat(line, 3)); !errors.Is(err, ErrTooManyLines) {
		t.Fatalf("строк сверх предела: %v", err)
	}
	in = testInput(t, FormatSquid)
	in.limits.MaxDecompressed = int64(len(line) * 2)
	if _, err := run(in, strings.Repeat(line, 3)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("файл сверх предела: %v", err)
	}
	in = testInput(t, FormatSquid)
	in.limits.MaxKeys = 1
	two := line + strings.Replace(line, " u ", " v ", 1)
	if _, err := run(in, two); !errors.Is(err, ErrTooManyKeys) {
		t.Fatalf("ключей сверх предела: %v", err)
	}
	if _, err := run(testInput(t, FormatSquid), ""); !errors.Is(err, ErrEmpty) {
		t.Fatalf("пустой файл: %v", err)
	}
	if _, err := run(testInput(t, "json"), line); !errors.Is(err, ErrBadFormat) {
		t.Fatalf("формат: %v", err)
	}
	if _, err := run(testInput(t, FormatCSV), "a,b,c\n1,2,3\n"); !errors.Is(err, ErrHeader) {
		t.Fatalf("CSV без заголовка: %v", err)
	}
	// Отмена контекста прерывает разбор.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := aggregate(cctx, strings.NewReader(strings.Repeat(line, ctxCheckEvery+1)), testInput(t, FormatSquid)); !errors.Is(err, context.Canceled) {
		t.Fatalf("отмена: %v", err)
	}
	// Бинарный мусор — ошибки строк, без паники и без агрегатов.
	garbage := bytes.Repeat([]byte{0x00, 0xff, 0x1b, '\n', 0x80, '|'}, 300)
	for _, f := range Formats() {
		res, err := aggregate(ctx, bytes.NewReader(garbage), testInput(t, f))
		if f == FormatCSV {
			if !errors.Is(err, ErrHeader) {
				t.Fatalf("CSV из мусора: %v", err)
			}
			continue
		}
		if err != nil || res.Matched != 0 || res.Errors == 0 || len(res.ErrorLines) != MaxErrorLines {
			t.Fatalf("%s из мусора: %+v %v", f, res.counts(), err)
		}
	}
	// Записи старше срока хранения не сохраняются, но считаются.
	in = testInput(t, FormatSquid)
	in.cutoff = testNow
	if res, err := run(in, line); err != nil || res.Outdated != 1 || res.Matched != 0 || len(res.Aggregates) != 0 {
		t.Fatalf("старше срока: %+v %v", res, err)
	}
	// Время в будущем дальше суток — ошибка строки.
	future := strings.Replace(line, "1793095200", "1893095200", 1)
	if res, err := run(testInput(t, FormatSquid), future); err != nil || res.Errors != 1 {
		t.Fatalf("будущее: %+v %v", res.counts(), err)
	}
}

func TestSplitCSV(t *testing.T) {
	for in, want := range map[string][]string{
		`a,b,c`:         {"a", "b", "c"},
		`"a,1","b""c",`: {"a,1", `b"c`, ""},
		`,`:             {"", ""},
		`"x"`:           {"x"},
		`плюс,"минус"`:  {"плюс", "минус"},
	} {
		got, err := splitCSV([]byte(in), ',')
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{`"a`, `"a"b`, strings.Repeat("a,", maxCSVFields+1)} {
		if _, err := splitCSV([]byte(in), ','); err == nil {
			t.Errorf("%q принято", in)
		}
	}
}

func TestCEFPairs(t *testing.T) {
	kv, ok := cefPairs([]byte(`rt=1 suser=Иван Петров request=https://a.example/?q\=1 msg=a\\b\nc`))
	if !ok || kv["suser"] != "Иван Петров" || kv["request"] != "https://a.example/?q=1" || kv["msg"] != "a\\b\nc" {
		t.Fatalf("%q %v", kv, ok)
	}
	for _, in := range []string{`текст rt=1`, `rt=1 rt=2`, `rt=a\x`, `rt=a\`} {
		if _, ok := cefPairs([]byte(in)); ok {
			t.Errorf("%q принято", in)
		}
	}
}

func TestParseCEFTime(t *testing.T) {
	msk := time.FixedZone("MSK", 3*3600)
	for in, want := range map[string]time.Time{
		"1793095200000":                  time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC),
		"Oct 27 2026 13:00:00":           time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC),
		"Oct 27 2026 10:00:00 UTC":       time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC),
		"Oct 27 2026 12:00:00.250 +0200": time.Date(2026, 10, 27, 10, 0, 0, 250e6, time.UTC),
	} {
		got, ok := parseCEFTime(in, msk)
		if !ok || !got.Equal(want) {
			t.Errorf("%q: %s %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "Oct 27 10:00:00", "1793095200.5", "Oct 27 2026 10:00:00 MSK", "вчера"} {
		if _, ok := parseCEFTime(in, msk); ok {
			t.Errorf("%q принято", in)
		}
	}
}

func fuzzParser(f *testing.F, format string, seeds ...string) {
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	b := timeBounds{loc: time.UTC, max: testNow.Add(24 * time.Hour)}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := newParser(format, b)
		if err != nil {
			t.Fatal(err)
		}
		lr := newLineReader(bytes.NewReader(data), 512)
		for {
			line, long, err := lr.next()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if long {
				continue
			}
			if len(line) > 512 {
				t.Fatalf("строка длиннее предела: %d", len(line))
			}
			rec, skip, err := p.parse(line)
			if err != nil || skip {
				continue
			}
			if !b.ok(rec.time) || rec.bytes < 0 || rec.bytes > maxLineBytes || len(rec.user) > maxUserLen ||
				(rec.userKind == UserKindNone) != (rec.user == "") {
				t.Fatalf("запись вне правил: %+v", rec)
			}
			if h, ok := NormalizeHost(rec.host); ok && !strings.EqualFold(strings.TrimSuffix(h, "."), h) {
				t.Fatalf("узел: %q", h)
			}
		}
	})
}

func FuzzParseSquid(f *testing.F) {
	fuzzParser(f, FormatSquid, string(readFile(f, "../../testdata/shadowai/access-squid.log")),
		"1793095200.1 1 a b/1 1 GET http://u:p@x.example/ - - -\n")
}

func FuzzParseCSV(f *testing.F) {
	fuzzParser(f, FormatCSV, string(readFile(f, "../../testdata/shadowai/access.csv")),
		"time,domain\n2026-10-27T10:00:00Z,\"a,b\"\n", "\xef\xbb\xbfvремя;url\n")
}

func FuzzParseCEF(f *testing.F) {
	fuzzParser(f, FormatCEF, string(readFile(f, "../../testdata/shadowai/usergate-cef.log")),
		"CEF:0|a\\|b|c|d|e|f|g|rt=Oct 27 2026 10:00:00 +0300 dhost=x.example in=1\n")
}
