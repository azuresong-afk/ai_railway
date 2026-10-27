package notify

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"
	"time"
)

// Письмо с отчётом: multipart/mixed, текст и вложение читаются
// стандартным разбором, заголовки не поддаются внедрению через тему и имя файла.
func TestReportMessage(t *testing.T) {
	data := bytes.Repeat([]byte("PK\x03\x04binary\x00data"), 500)
	raw := reportMessage(ReportMail{ID: "01900000-0000-7000-8000-000000000001", Subject: "Отчёт\r\nBcc: evil@example.org",
		Body: "Отчёт во вложении.\n.Строка с точкой", Filename: "../aisec report\r\n.xlsx", ContentType: "application/vnd.test", Data: data},
		"aisec@example.org", []string{"a@example.org", "b@example.org"}, time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC))
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Header.Get("Bcc") != "" || msg.Header.Get("To") != "a@example.org, b@example.org" || msg.Header.Get("Auto-Submitted") != "auto-generated" {
		t.Errorf("заголовки: %v", msg.Header)
	}
	subj, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || strings.ContainsAny(subj, "\r\n") {
		t.Errorf("тема: %q %v", subj, err)
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/mixed" {
		t.Fatalf("тип: %q %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts int
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		enc, err := io.ReadAll(p)
		if err != nil {
			t.Fatal(err)
		}
		if p.Header.Get("Content-Transfer-Encoding") != "base64" {
			t.Fatalf("кодирование части: %q", p.Header.Get("Content-Transfer-Encoding"))
		}
		body, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(string(enc)))
		if err != nil {
			t.Fatal(err)
		}
		parts++
		switch parts {
		case 1:
			if !strings.Contains(string(body), "Отчёт во вложении.") {
				t.Errorf("текст: %q", body)
			}
		case 2:
			if !bytes.Equal(body, data) {
				t.Errorf("вложение повреждено: %d байт", len(body))
			}
			if _, p2, err := mime.ParseMediaType(p.Header.Get("Content-Disposition")); err != nil || strings.ContainsAny(p2["filename"], "/\\\r\n ") {
				t.Errorf("имя файла: %q %v", p2["filename"], err)
			}
		}
	}
	if parts != 2 {
		t.Errorf("частей %d", parts)
	}
	for _, l := range strings.Split(string(raw), "\r\n") {
		if len(l) > 998 {
			t.Errorf("строка длиннее 998 знаков: %d", len(l))
		}
	}
}

// 3Н47 ревью 3.r4: Before получает адреса канала до отправки; его ошибка
// останавливает письмо и возвращается как есть.
func TestSendReportBefore(t *testing.T) {
	e := newEnv(t)
	srv := newSMTPServer(t, e.tp, e.cert, e.key, true)
	c, err := e.svc.CreateChannel(testCtx(t), e.by, e.emailInput(srv.addr, ""))
	if err != nil {
		t.Fatal(err)
	}
	m := ReportMail{ID: "01900000-0000-7000-8000-000000000002", Subject: "Отчёт", Body: "Во вложении.", Filename: "r.csv",
		ContentType: "text/csv", Data: []byte("a,b\r\n")}
	stop := errors.New("запись аудита не сделана")
	m.Before = func([]string) error { return stop }
	if err := e.svc.SendReport(testCtx(t), c.ID, m); !errors.Is(err, stop) {
		t.Fatalf("ошибка Before: %v", err)
	}
	srv.mu.Lock()
	sent := len(srv.data)
	srv.mu.Unlock()
	if sent != 0 {
		t.Fatalf("письмо ушло после ошибки Before: %d", sent)
	}
	var got []string
	m.Before = func(to []string) error { got = to; return nil }
	if err := e.svc.SendReport(testCtx(t), c.ID, m); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if strings.Join(got, ",") != "soc@example.ru,duty@example.ru" || len(srv.data) != 1 {
		t.Fatalf("получатели %v, писем %d", got, len(srv.data))
	}
}
