package notify

import (
	"context"
	"encoding/base64"
	"mime"
	"strings"
	"time"
)

// Письмо с отчётом по расписанию (задача 3.25 этапа 3): текст и вложение
// HTML или XLSX. Отправка — тем же каналом почты и тем же транспортом, что
// и уведомления; повторы и журнал доставки ведёт планировщик отчётов
// (таблица report_runs), потому что у отчёта нет оповещения.

// MaxReportAttachment — наибольший размер вложения, байт.
const MaxReportAttachment = 8 << 20

// ReportMail — письмо с отчётом.
type ReportMail struct {
	// ID — идентификатор запуска: Message-ID письма.
	ID      string
	Subject string
	Body    string
	// Filename — имя вложения: латиница, цифры и «._-».
	Filename    string
	ContentType string
	Data        []byte
}

// SendReport отправляет отчёт через почтовый канал channelID. Отключённый
// или не почтовый канал — ошибка доставки с кодом, повторять нечего.
func (s *Service) SendReport(ctx context.Context, channelID string, m ReportMail) error {
	c, err := s.store.Channel(ctx, channelID)
	if err != nil {
		return err
	}
	if c.Type != TypeEmail {
		return failed(ErrCodeConfig)
	}
	if !c.Enabled {
		return failed(ErrCodeDisabled)
	}
	if len(m.Data) > MaxReportAttachment {
		return failed(ErrCodeConfig)
	}
	sec, err := s.secrets(ctx, c)
	if err != nil {
		return failed(ErrCodeConfig)
	}
	return s.transport.SendRaw(ctx, c, sec, reportMessage(m, c.Settings.From, c.Settings.To, s.now()))
}

// wrap64 разбивает base64 на строки по 76 знаков (RFC 2045).
func wrap64(b *strings.Builder, data []byte) {
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
}

// safeFilename оставляет в имени вложения безопасные знаки.
func safeFilename(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, s)
	if out == "" {
		return "report"
	}
	return out
}

// reportMessage — письмо multipart/mixed: текст UTF-8 и вложение в base64.
// Граница не встречается в base64 (знак «=» там только в конце строки).
func reportMessage(m ReportMail, from string, to []string, now time.Time) []byte {
	boundary := "=_aisec_" + safeFilename(m.ID)
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", strings.Join(to, ", "))
	h("Subject", mime.BEncoding.Encode("utf-8", clean(m.Subject)))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+safeFilename(m.ID)+"@aisec>")
	h("MIME-Version", "1.0")
	h("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n--" + boundary + "\r\n")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "base64")
	b.WriteString("\r\n")
	wrap64(&b, []byte(strings.ReplaceAll(m.Body, "\n", "\r\n")+"\r\n"))
	name := safeFilename(m.Filename)
	b.WriteString("--" + boundary + "\r\n")
	h("Content-Type", m.ContentType+`; name="`+name+`"`)
	h("Content-Transfer-Encoding", "base64")
	h("Content-Disposition", `attachment; filename="`+name+`"`)
	b.WriteString("\r\n")
	wrap64(&b, m.Data)
	b.WriteString("--" + boundary + "--\r\n")
	return []byte(b.String())
}
