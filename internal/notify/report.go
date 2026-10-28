package notify

import (
	"context"
	"encoding/base64"
	"mime"
	"slices"
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
	// ExtraTo — адреса пользователей консоли (учётные записи, задача 4.6):
	// получатели в дополнение к адресам канала. Неверные адреса и повторы
	// отбрасываются; всего получателей не больше MaxReportRecipients.
	ExtraTo []string
	// Before — вызывается после чтения канала и до отправки с адресами
	// получателей канала (3Н47 ревью 3.r4: data.export рассылки фиксирует,
	// кому ушёл отчёт, ровно по адресам этой отправки). Ошибка — письмо не
	// отправляется, SendReport возвращает её как есть.
	Before func(to []string) error
	// Rejected — вызывается после отправки с числом адресов пользователей
	// (ExtraTo), которые сервер SMTP отклонил в RCPT: письмо ушло остальным
	// (ревью 4.r1, 4В13). nil — не вызывается.
	Rejected func(n int)
}

// MaxReportRecipients — наибольшее число получателей письма с отчётом:
// адреса канала и адреса пользователей расписания.
const MaxReportRecipients = 2 * MaxRecipients

// MergeRecipients объединяет адреса канала и дополнительные адреса: повторы
// (без учёта регистра) и неверные адреса отбрасываются, порядок сохраняется,
// адреса канала идут первыми.
func MergeRecipients(channel, extra []string) []string {
	out := slices.Clone(channel)
	seen := make(map[string]bool, len(channel)+len(extra))
	for _, a := range channel {
		seen[strings.ToLower(a)] = true
	}
	for _, a := range extra {
		k := strings.ToLower(a)
		if len(out) >= MaxReportRecipients || seen[k] || !validAddress(a) {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
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
	// Адреса получателей этой отправки: канал и пользователи расписания.
	// В заголовке To — только адреса канала: адреса пользователей идут
	// лишь в конверте (RCPT) и не видны другим получателям, в том числе
	// внешним адресам канала (ревью 4.r1, 4Н10).
	header := slices.Clone(c.Settings.To)
	c.Settings.To = MergeRecipients(c.Settings.To, m.ExtraTo)
	users := c.Settings.To[len(header):]
	if m.Before != nil {
		if err := m.Before(slices.Clone(c.Settings.To)); err != nil {
			return err
		}
	}
	n, err := s.transport.SendRawSoft(ctx, c, sec, reportMessage(m, c.Settings.From, header, s.now()), users)
	if err == nil && n > 0 && m.Rejected != nil {
		m.Rejected(n)
	}
	return err
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
