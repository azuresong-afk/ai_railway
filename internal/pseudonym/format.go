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
	// MaxPending — сколько байт может ждать в буфере потоковой подстановки:
	// псевдоним с переведённым типом, который считается в метрике неудачных
	// подстановок (2 скобки, до 40 байт типа, «_», номер, следующий символ),
	// или псевдоним с искажениями и afterLen байт за ним, по которым правило
	// мест решает, не продолжается ли за ним адрес.
	MaxPending = max(2+maxLooseType+1+maxNumDigits+1, MaxTokenLen+afterLen)
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
//	открытие   — «[» или «[[»; при esc — «\[» или «\[\[»;
//	пробелы    — до двух;
//	тип        — латинская буква, затем буквы и цифры, до MaxTypeLen,
//	             в любом регистре;
//	разделитель — «_», «\_» (при esc), «-» или пробел;
//	номер      — 1–99999 без ведущего нуля;
//	пробелы    — до двух;
//	закрытие   — «]» или «]]», экранированные так же, как открытие.
//
// Экранирование скобок должно быть одинаковым у всего псевдонима: иначе
// «C:\» перед псевдонимом [[…]] потеряло бы обратную косую.
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
	first := bracketPlain
	if esc {
		first = bracketAny
	}
	j, mode, need := bracket(s, i, '[', first)
	switch {
	case need:
		return more()
	case mode == bracketNone:
		return token{}, scanNo
	}
	k, m, need := bracket(s, j, '[', mode)
	switch {
	case need:
		return more()
	case m != bracketNone:
		j = k
	}
	j, need = spaces(s, j)
	if need {
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
	n, j, res := number(s, j)
	if res != scanMatch {
		if res == scanMore {
			return more()
		}
		return token{}, scanNo
	}
	j, need = spaces(s, j)
	if need {
		return more()
	}
	j, m, need = bracket(s, j, ']', mode)
	switch {
	case need:
		return more()
	case m == bracketNone:
		return token{}, scanNo
	}
	// Вторая закрывающая скобка необязательна: модель иногда теряет одну.
	k, m, need = bracket(s, j, ']', mode)
	switch {
	case need && !final:
		return token{}, scanMore
	case m != bracketNone:
		j = k
	}
	return token{typ: typ, n: n, end: j}, scanMatch
}

// number — номер псевдонима 1–99999 без ведущего нуля с позиции j; scanMore —
// текст кончился на номере или до него (за номером должен идти ещё символ).
func number(s string, j int) (n, end int, res scanResult) {
	if j >= len(s) {
		return 0, j, scanMore
	}
	if s[j] < '1' || s[j] > '9' {
		return 0, j, scanNo
	}
	for digits := 0; j < len(s) && isDigit(s[j]); j++ {
		if digits++; digits > maxNumDigits {
			return 0, j, scanNo
		}
		n = n*10 + int(s[j]-'0')
	}
	if j >= len(s) {
		return n, j, scanMore
	}
	return n, j, scanMatch
}

// Виды скобки псевдонима.
const (
	bracketNone    = iota // скобки нет
	bracketPlain          // «[» или «]»
	bracketEscaped        // «\[» или «\]»
	bracketAny            // для поиска: любая из двух
)

// bracket — скобка b вида want в позиции i; возвращает найденный вид.
// need — текст кончился раньше, чем это стало ясно.
func bracket(s string, i int, b byte, want int) (next, got int, need bool) {
	switch {
	case i >= len(s):
		return i, bracketNone, true
	case s[i] == b && want != bracketEscaped:
		return i + 1, bracketPlain, false
	case s[i] != '\\' || want == bracketPlain:
		return i, bracketNone, false
	case i+1 >= len(s):
		return i, bracketNone, true
	case s[i+1] == b:
		return i + 2, bracketEscaped, false
	}
	return i, bracketNone, false
}

// maxLooseType — длина «типа» в байтах у псевдонима с переведённым типом.
const maxLooseType = 40

// parseLoose — псевдоним с переведённым на другой язык типом
// ([[ТЕЛЕФОН_1]]): скобки, буквы с хотя бы одним символом вне ASCII,
// «_», номер, «]». Такой псевдоним не восстанавливается, только считается
// в метрике неудачных подстановок. Решение — по s[i:i+MaxPending].
func parseLoose(s string, i int, final bool) (end int, res scanResult) {
	more := func() (int, scanResult) {
		if final {
			return 0, scanNo
		}
		return 0, scanMore
	}
	j := i
	for k := 0; k < 2 && j < len(s) && s[j] == '['; k++ {
		j++
	}
	if j == i {
		return 0, scanNo
	}
	start, wide := j, false
	for j < len(s) && (isLetter(s[j]) || s[j] >= 0x80) {
		wide = wide || s[j] >= 0x80
		if j++; j-start > maxLooseType {
			return 0, scanNo
		}
	}
	if j >= len(s) {
		return more()
	}
	if j == start || !wide || s[j] != '_' {
		return 0, scanNo
	}
	_, j, r := number(s, j+1)
	switch {
	case r == scanMore:
		return more()
	case r == scanNo || s[j] != ']':
		return 0, scanNo
	}
	return j + 1, scanMatch
}

// parseBare — псевдоним без скобок «ТИП_N» или «ТИП-N» с выданным типом
// (точно в верхнем регистре) с начала слова в позиции i: модель потеряла
// скобки или переоформила их (<PHONE_1>). Не восстанавливается, только
// считается. prefix — может ли незаконченное слово стать выданным типом:
// только тогда хвост части задерживается.
func parseBare(s string, i int, final bool, issued, prefix func(string) bool) (end int, res scanResult) {
	more := func() (int, scanResult) {
		if final {
			return 0, scanNo
		}
		return 0, scanMore
	}
	j := i
	for j < len(s) && (isUpper(s[j]) || isDigit(s[j])) {
		if j++; j-i > MaxTypeLen {
			return 0, scanNo
		}
	}
	if j >= len(s) {
		if prefix(s[i:j]) {
			return more()
		}
		return 0, scanNo
	}
	if !issued(s[i:j]) || s[j] != '_' && s[j] != '-' {
		return 0, scanNo
	}
	n, j, r := number(s, j+1)
	switch {
	case r == scanMore && final && n > 0:
		return j, scanMatch // «PHONE_1» в самом конце текста
	case r == scanMore:
		return more()
	case r == scanNo || isWord(s[j]):
		return 0, scanNo
	}
	return j, scanMatch
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
func isUpper(c byte) bool  { return 'A' <= c && c <= 'Z' }
func isDigit(c byte) bool  { return '0' <= c && c <= '9' }

// isWord — символ слова ASCII: буква, цифра или «_».
func isWord(c byte) bool { return isLetter(c) || isDigit(c) || c == '_' }
