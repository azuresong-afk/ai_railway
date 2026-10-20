package exfil

import "strings"

// MaxWindowBack — насколько раньше нужной позиции Window может начать окно:
// длинный абзац, пункт списка или строка в блоке кода сверх этого
// проверяются без учёта кода (strict).
const MaxWindowBack = 8 << 10

// Window — проверка растущего текста ответа окнами (поток, режим
// incremental). Окно, начатое с середины текста, не знает, открыт ли в его
// начале блок кода: закрывающую ограду оно примет за открывающую и сочтёт
// кодом всё после неё, и изображение там не станет находкой (ревью
// 1.22–1.24, п. 1). Window разбирает строки текста по мере роста тем же
// разбором, что и Detect, и говорит, откуда начать окно и что поставить
// перед ним, чтобы код в окне был тем же, что во всём тексте.
//
// Окно начинается:
//   - внутри блока кода верхнего уровня — с начала строки, перед ним —
//     открывающая ограда того же вида;
//   - внутри пункта списка (или блока кода в нём) — с начала последнего
//     пункта верхнего уровня;
//   - иначе — с начала абзаца или последнего блока: встроенный код не
//     выходит за абзац.
//
// Если такое начало дальше MaxWindowBack, окно начинается с нужной позиции
// и strict = true: проверять его с detect.Text.NoCode — кода в окне нет.
// Ошибка в эту сторону даёт лишнюю находку, а не пропуск.
//
// Нулевое значение готово к работе. Текст только растёт, его начало не
// меняется. Не для одновременного вызова.
type Window struct {
	b blockScan
	// done — строки до этой позиции разобраны; scan — от done до scan
	// перевода строки нет.
	done, scan int
}

// Next — окно для text, покрывающее всё с позиции p (p не убывает от
// вызова к вызову). Позиция i в окне — позиция start + i - shift в text;
// i < shift — служебный префикс. strict — окно проверять без учёта кода.
func (w *Window) Next(text string, p int) (window string, start, shift int, strict bool) {
	p = min(max(p, 0), len(text))
	if p < w.done {
		return text[p:], p, 0, true
	}
	w.advance(text, p)
	b := &w.b
	switch {
	case b.inFence && b.fenceBase == 0:
		if p-w.done <= MaxWindowBack {
			prefix := strings.Repeat(string(b.fenceChar), b.fenceLen) + "\n"
			return prefix + text[w.done:], w.done, len(prefix), false
		}
	case b.inFence || b.lists.n > 0:
		if p-b.reset <= MaxWindowBack {
			return text[b.reset:], b.reset, 0, false
		}
	default:
		if s := max(b.para, b.reset); p-s <= MaxWindowBack {
			return text[s:], s, 0, false
		}
	}
	return text[p:], p, 0, true
}

// advance разбирает строки, которые целиком лежат до строки с позицией p.
func (w *Window) advance(text string, p int) {
	for {
		i := strings.IndexByte(text[w.scan:p], '\n')
		if i < 0 {
			w.scan = p
			return
		}
		le := w.scan + i
		w.b.line(text, w.done, le, le+1)
		w.done, w.scan = le+1, le+1
	}
}
