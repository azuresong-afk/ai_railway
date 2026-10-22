package notify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Виды уведомления.
const (
	KindAlert = "alert"
	KindTest  = "test"
)

// Message — уведомление об оповещении: только метаданные оповещения, без
// содержимого запросов и ответов (ADR-0020 п. 9; ТЗ 5.5).
type Message struct {
	Kind string
	// ID — оповещение (KindAlert) или строка журнала доставки (KindTest).
	ID       string
	Rule     string // ключ встроенного правила или ID правила
	RuleName string
	// AlertKind — тип правила: threshold, new, system, security…
	AlertKind string
	Severity  string
	Title     string
	Count     int64
	Group     map[string]string
	CreatedAt time.Time
}

// testMessage — уведомление тестовой отправки.
func testMessage(id string, now time.Time) Message {
	return Message{Kind: KindTest, ID: id, Rule: "test", RuleName: "Тестовая отправка", AlertKind: "test",
		Severity: "info", Title: "Тестовое уведомление AISec: канал настроен", Count: 1, Group: map[string]string{},
		CreatedAt: now}
}

// payload — тело общего формата JSON (webhook и syslog).
type payload struct {
	Product   string            `json:"product"`
	Version   string            `json:"version"`
	Type      string            `json:"type"`
	ID        string            `json:"id"`
	Rule      string            `json:"rule"`
	RuleName  string            `json:"rule_name"`
	Kind      string            `json:"kind"`
	Severity  string            `json:"severity"`
	Title     string            `json:"title"`
	Count     int64             `json:"count"`
	Group     map[string]string `json:"group"`
	CreatedAt string            `json:"created_at"`
}

func jsonBody(m Message, version string) ([]byte, error) {
	g := m.Group
	if g == nil {
		g = map[string]string{}
	}
	return json.Marshal(payload{Product: "AISec", Version: version, Type: m.Kind, ID: m.ID, Rule: m.Rule, RuleName: m.RuleName,
		Kind: m.AlertKind, Severity: m.Severity, Title: m.Title, Count: m.Count, Group: g,
		CreatedAt: m.CreatedAt.UTC().Format(time.RFC3339)})
}

// severityRu — серьёзность в тексте для человека.
var severityRu = map[string]string{"info": "информация", "low": "низкая", "medium": "средняя", "high": "высокая",
	"critical": "критическая"}

// lines — текст уведомления для человека (письмо, Mattermost).
func lines(m Message) []string {
	out := []string{
		m.Title,
		"",
		"Серьёзность: " + severityRu[m.Severity],
		"Правило: " + m.RuleName,
		"Срабатываний: " + strconv.FormatInt(m.Count, 10),
		"Время (UTC): " + m.CreatedAt.UTC().Format("2006-01-02 15:04:05"),
		"ID: " + m.ID,
	}
	for _, k := range slices.Sorted(maps.Keys(m.Group)) {
		out = append(out, k+": "+m.Group[k])
	}
	return append(out, "", "Подробности — в консоли AISec, раздел «Оповещения».")
}

// clean убирает управляющие символы из значений, которые мог задать
// нарушитель (логин при переборе, имя шлюза).
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
}

// mdEscaper — разметка Markdown Mattermost/Rocket.Chat: значения выводятся
// как текст, упоминания @channel и @all не срабатывают.
var mdEscaper = strings.NewReplacer(`\`, `\\`, "*", `\*`, "_", `\_`, "`", "\\`", "~", `\~`, "[", `\[`, "]", `\]`,
	"(", `\(`, ")", `\)`, "<", `\<`, ">", `\>`, "#", `\#`, "|", `\|`, "!", `\!`, "@", "@\u200b")

func mattermostBody(m Message) ([]byte, error) {
	ls := lines(m)
	for i := range ls {
		ls[i] = mdEscaper.Replace(clean(ls[i]))
	}
	ls[0] = "**" + ls[0] + "**"
	return json.Marshal(map[string]string{"text": strings.Join(ls, "\n"), "username": "AISec"})
}

// emailMessage — письмо RFC 5322: тема по RFC 2047, текст UTF-8 в base64.
// Адреса проверены при сохранении канала (без CR/LF).
func emailMessage(m Message, from string, to []string, msgID string, now time.Time) []byte {
	ls := lines(m)
	for i := range ls {
		ls[i] = clean(ls[i])
	}
	subject := "[AISec] " + severityRu[m.Severity] + ": " + clean(m.Title)
	var b strings.Builder
	h := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	h("From", from)
	h("To", strings.Join(to, ", "))
	h("Subject", mime.BEncoding.Encode("utf-8", subject))
	h("Date", now.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+msgID+"@aisec>")
	h("MIME-Version", "1.0")
	h("Content-Type", `text/plain; charset="utf-8"`)
	h("Content-Transfer-Encoding", "base64")
	h("Auto-Submitted", "auto-generated")
	b.WriteString("\r\n")
	enc := base64.StdEncoding.EncodeToString([]byte(strings.Join(ls, "\r\n") + "\r\n"))
	for len(enc) > 76 {
		b.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	b.WriteString(enc + "\r\n")
	return []byte(b.String())
}

// Серьёзность syslog (RFC 5424, 6.2.1) и CEF (0–10).
var (
	syslogSeverity = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}
	cefSeverity    = map[string]int{"critical": 10, "high": 8, "medium": 5, "low": 3, "info": 1}
)

// cefHeader экранирует поле заголовка CEF: обратная косая и вертикальная черта.
var cefHeader = strings.NewReplacer(`\`, `\\`, "|", `\|`, "\r", " ", "\n", " ")

// cefValue экранирует значение расширения CEF: обратная косая, «=» и переводы строк.
var cefValue = strings.NewReplacer(`\`, `\\`, "=", `\=`, "\r", `\r`, "\n", `\n`)

// cefBody — запись CEF 0 (ArcSight Common Event Format, ревизия 25).
func cefBody(m Message, version string) []byte {
	h := func(s string) string { return cefHeader.Replace(clean(s)) }
	v := func(s string) string { return cefValue.Replace(s) }
	ext := []string{
		"rt=" + strconv.FormatInt(m.CreatedAt.UnixMilli(), 10),
		"cat=" + v(m.AlertKind),
		"cnt=" + strconv.FormatInt(m.Count, 10),
		"externalId=" + v(m.ID),
		"cs1Label=rule",
		"cs1=" + v(m.RuleName),
		"cs2Label=type",
		"cs2=" + v(m.Kind),
	}
	if len(m.Group) > 0 {
		var g []string
		for _, k := range slices.Sorted(maps.Keys(m.Group)) {
			g = append(g, k+": "+m.Group[k])
		}
		ext = append(ext, "msg="+v(strings.Join(g, "; ")))
	}
	return fmt.Appendf(nil, "CEF:0|AISec|AISec|%s|%s|%s|%d|%s", h(version), h(m.Rule), h(m.Title),
		cefSeverity[m.Severity], strings.Join(ext, " "))
}

// syslogRecord — запись RFC 5424 с фреймингом RFC 6587 (octet counting):
// «длина SP запись». STRUCTURED-DATA нет, MSG — UTF-8 без BOM (6.4).
func syslogRecord(m Message, s Settings, version string) ([]byte, error) {
	var msg []byte
	if s.Format == FormatCEF {
		msg = cefBody(m, version)
	} else {
		var err error
		if msg, err = jsonBody(m, version); err != nil {
			return nil, err
		}
	}
	facility := DefaultFacility
	if s.Facility != nil {
		facility = *s.Facility
	}
	sev, ok := syslogSeverity[m.Severity]
	if !ok {
		sev = 6
	}
	host := s.Hostname
	if !syslogName(host, 255) {
		host = DefaultHostname
	}
	msgID := "alert"
	if m.Kind == KindTest {
		msgID = "test"
	}
	rec := fmt.Appendf(nil, "<%d>1 %s %s aisec - %s - ", facility*8+sev,
		m.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000Z07:00"), host, msgID)
	rec = append(rec, msg...)
	return append(fmt.Appendf(nil, "%d ", len(rec)), rec...), nil
}
