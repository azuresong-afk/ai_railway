package events

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"
)

// Подгонка содержимого full под предел хранения (В10 ревью 2.r3a). Шифротекст
// ограничен столбцом event_content.sealed (256 КиБ), а открытый текст — JSON
// {request, response}, в котором управляющие символы занимают до 6 байт.
// Поэтому 2 × 64 КиБ текста могут не поместиться; тогда сервер обрезает
// текст, а не отвергает событие (и тем более пакет): находки и решение
// сохраняются, у события ставится отметка content_truncated.

const (
	// MaxSealedBytes — предел шифротекста содержимого (CHECK event_content.sealed).
	MaxSealedBytes = 256 << 10
	// sealedReserve — запас на накладные расходы шифрования (nonce, тег,
	// заголовок) любого криптопрофиля.
	sealedReserve = 1 << 10
	// MaxSealedPlain — предел открытого текста содержимого full.
	MaxSealedPlain = MaxSealedBytes - sealedReserve
	// truncMark — отметка обрезки в конце текста.
	truncMark = "…"
)

// MarshalContent — открытый текст содержимого full: JSON без HTML-экранирования
// (иначе «<», «>», «&» занимали бы по 6 байт). json.Unmarshal читает и
// прежнюю запись с экранированием.
func MarshalContent(c Content) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// encodedLen — длина строки s в JSON без HTML-экранирования, с кавычками.
func encodedLen(s string) int {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// Строка кодируется всегда; на всякий случай — худший случай.
		return 6*len(s) + 2
	}
	defer clear(b.Bytes())
	return b.Len() - 1
}

// FitContent возвращает содержимое, открытый текст которого (MarshalContent)
// не длиннее limit байт, и признак обрезки. Запрос и ответ делят предел
// поровну; часть, которая короче своей доли, отдаёт остаток другой.
// Обрезка — по границе символа, в конце ставится «…».
func FitContent(c Content, limit int) (Content, bool) {
	req, resp := encodedLen(c.Request), encodedLen(c.Response)
	// Ключи, скобки и запятая: всё, кроме самих строк в кавычках.
	fixed := len(`{"request":,"response":}`)
	if fixed+req+resp <= limit {
		return c, false
	}
	budget := limit - fixed
	half := budget / 2
	lreq, lresp := half, budget-half
	switch {
	case req <= half:
		lreq, lresp = req, budget-req
	case resp <= budget-half:
		lreq, lresp = budget-resp, resp
	}
	return Content{Request: truncateEncoded(c.Request, lreq), Response: truncateEncoded(c.Response, lresp)}, true
}

// truncateEncoded обрезает s так, чтобы длина в JSON (с отметкой обрезки) была
// не больше n. Длина кодирования префикса монотонна, поэтому ищется
// двоичным поиском по байтовой позиции с выравниванием на начало символа.
func truncateEncoded(s string, n int) string {
	if encodedLen(s) <= n {
		return s
	}
	if n < encodedLen(truncMark) {
		return ""
	}
	lo, hi := 0, len(s) // lo подходит всегда, hi — нет
	for hi-lo > 1 {
		mid := runeStart(s, (lo+hi)/2)
		if mid <= lo {
			// Между lo и hi один символ: следующая граница — за ним.
			_, size := utf8.DecodeRuneInString(s[lo:])
			if mid = lo + size; mid >= hi {
				break
			}
		}
		if encodedLen(s[:mid]+truncMark) <= n {
			lo = mid
		} else {
			hi = mid
		}
	}
	return s[:lo] + truncMark
}

// runeStart — ближайшее начало символа не правее i.
func runeStart(s string, i int) int {
	if i >= len(s) {
		return len(s)
	}
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return i
}
