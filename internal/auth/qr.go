package auth

import (
	"errors"
	"strings"

	"rsc.io/qr"
)

// maxQRText — предел текста QR-кода: ссылка otpauth с логином до 64 символов
// заметно короче; длиннее — ошибка вызывающего.
const maxQRText = 512

// qrMatrix кодирует text в QR-код (уровень коррекции M) и возвращает матрицу
// модулей: строка на ряд, «1» — тёмный модуль. Картинку рисует консоль
// (SVG из прямоугольников), сервер изображений не формирует.
func qrMatrix(text string) ([]string, error) {
	if text == "" || len(text) > maxQRText {
		return nil, errors.New("QR-код: недопустимая длина текста")
	}
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	rows := make([]string, c.Size)
	var b strings.Builder
	for y := range c.Size {
		b.Reset()
		for x := range c.Size {
			if c.Black(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[y] = b.String()
	}
	return rows, nil
}
