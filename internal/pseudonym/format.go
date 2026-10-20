package pseudonym

import (
	"strconv"
	"strings"
)

// Пределы формата псевдонима [[ТИП_N]] (ADR-0005).
const (
	// MaxTypeLen — длина ТИП.
	MaxTypeLen = 16
	// MaxNumber — наибольший номер N (пять цифр).
	MaxNumber    = 99999
	maxNumDigits = 5
	// maxSpaces — пробелы у скобок, которые допускает обратная подстановка.
	maxSpaces = 2
	// MaxTokenLen — наибольшая длина псевдонима с допустимыми искажениями:
	// две экранированные скобки, пробелы, тип, экранированный разделитель,
	// номер, пробелы, две экранированные скобки. Столько байт может ждать
	// в буфере потоковой подстановки.
	MaxTokenLen = 4 + maxSpaces + MaxTypeLen + 2 + maxNumDigits + maxSpaces + 4
)

// defaultType — тип, если из категории его не получить.
const defaultType = "DATA"

// TypeOf — ТИП псевдонима по категории находки: последняя часть категории
// латиницей в верхнем регистре без знаков, не длиннее MaxTypeLen
// (pii.phone → PHONE, secret.private_key → PRIVATEKEY).
func TypeOf(category string) string {
	if i := strings.LastIndexByte(category, '.'); i >= 0 {
		category = category[i+1:]
	}
	var b strings.Builder
	for i := 0; i < len(category) && b.Len() < MaxTypeLen; i++ {
		c := category[i]
		switch {
		case 'a' <= c && c <= 'z':
			b.WriteByte(c - 'a' + 'A')
		case 'A' <= c && c <= 'Z', b.Len() > 0 && '0' <= c && c <= '9':
			b.WriteByte(c)
		}
	}
	if b.Len() == 0 {
		return defaultType
	}
	return b.String()
}

// formatToken — псевдоним в каноническом виде.
func formatToken(typ string, n int) string {
	return "[[" + typ + "_" + strconv.Itoa(n) + "]]"
}

// redactMarker — замена фрагмента при необратимом маскировании: [[ТИП]].
// Без номера, поэтому обратная подстановка её не трогает.
func redactMarker(typ string) string {
	return "[[" + typ + "]]"
}

// scanResult — исход разбора псевдонима с позиции.
type scanResult int

const (
	scanNo    scanResult = iota // с этой позиции псевдонима нет
	scanMatch                   // псевдоним найден
	scanMore                    // текст кончился посреди возможного псевдонима
)

// token — разобранный псевдоним: тип в верхнем регистре, номер и конец.
type token struct {
	typ string
	n   int
	end int
}

// parseToken разбирает псевдоним в s с позиции i. final — после s текста не
// будет; esc — принимать экранирование markdown «\» (в JSON «\[» и «\_» —
// не экранирование, а ошибка). Грамматика (ADR-0005), с допустимыми
// искажениями модели:
//
//	открытие   — «[» или «[[», при esc каждая скобка может быть
//	             экранирована «\»;
//	пробелы    — до двух;
//	тип        — латинская буква, затем буквы и цифры, до MaxTypeLen,
//	             в любом регистре;
//	разделитель — «_», «\_» (при esc), «-» или пробел;
//	номер      — 1–99999 без ведущего нуля;
//	пробелы    — до двух;
//	закрытие   — «]» или «]]», при esc скобка может быть экранирована.
//
// Решение зависит только от s[i:i+MaxTokenLen]. scanMore возвращается,
// только когда s кончилась раньше, чем решение стало однозначным, и только
// при final = false: с дописанным текстом разбор даст тот же исход, что на
// всём тексте. На этом держится равенство потоковой и обычной подстановки.
func parseToken(s string, i int, final, esc bool) (token, scanResult) {
	more := func() (token, scanResult) {
		if final {
			return token{}, scanNo
		}
		return token{}, scanMore
	}
	j, ok, need := bracket(s, i, '[', esc)
	switch {
	case need:
		return more()
	case !ok:
		return token{}, scanNo
	}
	k, ok, need := bracket(s, j, '[', esc)
	switch {
	case need:
		return more()
	case ok:
		j = k
	}
	j, need = spaces(s, j)
	if need {
		return more()
	}
	if j >= len(s) {
		return more()
	}
	if !isLetter(s[j]) {
		return token{}, scanNo
	}
	start := j
	for j < len(s) && (isLetter(s[j]) || isDigit(s[j])) {
		j++
		if j-start > MaxTypeLen {
			return token{}, scanNo
		}
	}
	if j >= len(s) {
		return more()
	}
	typ := strings.ToUpper(s[start:j])
	switch s[j] {
	case '_', '-', ' ':
		j++
	case '\\':
		if !esc {
			return token{}, scanNo
		}
		if j+1 >= len(s) {
			return more()
		}
		if s[j+1] != '_' {
			return token{}, scanNo
		}
		j += 2
	default:
		return token{}, scanNo
	}
	if j >= len(s) {
		return more()
	}
	if s[j] < '1' || s[j] > '9' {
		return token{}, scanNo
	}
	n := 0
	digits := 0
	for j < len(s) && isDigit(s[j]) {
		digits++
		if digits > maxNumDigits {
			return token{}, scanNo
		}
		n = n*10 + int(s[j]-'0')
		j++
	}
	if j >= len(s) {
		return more()
	}
	j, need = spaces(s, j)
	if need {
		return more()
	}
	j, ok, need = bracket(s, j, ']', esc)
	switch {
	case need:
		return more()
	case !ok:
		return token{}, scanNo
	}
	// Вторая закрывающая скобка необязательна: модель иногда теряет одну.
	k, ok, need = bracket(s, j, ']', esc)
	switch {
	case need && !final:
		return token{}, scanMore
	case ok:
		j = k
	}
	return token{typ: typ, n: n, end: j}, scanMatch
}

// bracket — скобка b в позиции i, при esc — возможно экранированная «\».
// need — текст кончился раньше, чем это стало ясно.
func bracket(s string, i int, b byte, esc bool) (next int, ok, need bool) {
	switch {
	case i >= len(s):
		return i, false, true
	case s[i] == b:
		return i + 1, true, false
	case !esc || s[i] != '\\':
		return i, false, false
	case i+1 >= len(s):
		return i, false, true
	case s[i+1] == b:
		return i + 2, true, false
	}
	return i, false, false
}

// spaces пропускает до maxSpaces пробелов; need — текст кончился на них.
// Больше maxSpaces пробелов подряд — не псевдоним: позиция остаётся на
// лишнем пробеле, и следующий шаг грамматики его не примет.
func spaces(s string, i int) (next int, need bool) {
	for k := 0; k < maxSpaces && i < len(s) && s[i] == ' '; k++ {
		i++
	}
	return i, i >= len(s)
}

func isLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }
