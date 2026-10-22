package notify

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Типы каналов (Р4, ADR-0020 п. 9).
const (
	TypeEmail   = "email"
	TypeWebhook = "webhook"
	TypeSyslog  = "syslog"
)

// Форматы тела: webhook — общий JSON или входящий webhook Mattermost и
// Rocket.Chat; syslog — JSON или CEF 0.
const (
	FormatGeneric    = "generic"
	FormatMattermost = "mattermost"
	FormatJSON       = "json"
	FormatCEF        = "cef"
)

// Секреты канала: шифруются ключом данных одним шифротекстом (ЗИ.1,
// ADR-0007); в ответах API — только признак «задан».
const (
	SecretPassword   = "password"
	SecretURL        = "url"
	SecretSigningKey = "signing_key"
)

// Пределы ввода.
const (
	// MaxChannelBody — тело запроса канала: корневые сертификаты и остальное.
	MaxChannelBody = 320 << 10
	MaxCAPEM       = 256 << 10
	MaxName        = 200
	MaxRecipients  = 20
	maxHost        = 253
	maxAddress     = 254
	maxUsername    = 256
	maxPassword    = 1024
	maxURL         = 2048
	// MinSigningKey — ключ подписи webhook не короче 256 бит.
	MinSigningKey = 32
	maxSigningKey = 512
	// Порты по умолчанию: отправка почты (RFC 6409) и syslog по TLS (RFC 5425).
	DefaultSMTPPort   = 587
	DefaultSyslogPort = 6514
	// DefaultFacility — authpriv: сообщения безопасности (RFC 5424, 6.2.1).
	DefaultFacility = 10
	// DefaultHostname — HOSTNAME записи syslog, если не задан.
	DefaultHostname = "aisec-server"
	// MaxChannels — каналов в организации.
	MaxChannels = 50
)

// severities — шкала серьёзности по возрастанию (как у оповещений).
var severities = []string{"info", "low", "medium", "high", "critical"}

// SeverityRank — место в шкале с 1; 0 — неизвестное значение.
func SeverityRank(s string) int { return slices.Index(severities, s) + 1 }

// Settings — настройки канала без секретов (хранятся в jsonb). Набор полей
// зависит от типа; чужие для типа поля отклоняются.
type Settings struct {
	Host  string `json:"host,omitempty"`
	Port  int    `json:"port,omitempty"`
	CAPEM string `json:"ca_pem,omitempty"`
	// Почта.
	Username string   `json:"username,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// Webhook и syslog.
	Format string `json:"format,omitempty"`
	// Syslog.
	Facility *int   `json:"facility,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	// URLOrigin — схема, узел и порт адреса webhook для показа; сам адрес
	// (в пути бывает токен Mattermost) — секрет. Заполняет сервер.
	URLOrigin string `json:"url_origin,omitempty"`
}

// Secrets — секреты канала в открытом виде (только в памяти сервера).
type Secrets struct {
	Password   string `json:"password,omitempty"`
	URL        string `json:"url,omitempty"`
	SigningKey string `json:"signing_key,omitempty"`
}

// fields — имена заданных секретов по алфавиту.
func (s Secrets) fields() []string {
	out := []string{}
	if s.Password != "" {
		out = append(out, SecretPassword)
	}
	if s.SigningKey != "" {
		out = append(out, SecretSigningKey)
	}
	if s.URL != "" {
		out = append(out, SecretURL)
	}
	return out
}

// SecretsInput — секреты из запроса: поле не передано — прежнее значение,
// пустая строка — удалить (если секрет не обязателен).
type SecretsInput struct {
	Password   *string `json:"password"`
	URL        *string `json:"url"`
	SigningKey *string `json:"signing_key"`
}

// ChannelInput — канал из запроса API (создание и полная замена настроек).
type ChannelInput struct {
	Name        string       `json:"name"`
	Type        string       `json:"type"`
	Enabled     *bool        `json:"enabled"`
	MinSeverity string       `json:"min_severity"`
	Settings    Settings     `json:"settings"`
	Secrets     SecretsInput `json:"secrets"`
	// Version — для изменения: версия, которую видел администратор.
	Version int `json:"version"`
}

// Channel — канал уведомлений.
type Channel struct {
	ID          string
	OrgID       string
	Name        string
	Type        string
	Enabled     bool
	MinSeverity string
	Settings    Settings
	// SecretFields — какие секреты заданы (без значений).
	SecretFields []string
	// Secret и SecretKeyID — шифротекст секретов и версия ключа данных.
	Secret      []byte
	SecretKeyID string
	Version     int
	CreatedAt   time.Time
	CreatedBy   string
	UpdatedAt   time.Time
	UpdatedBy   string
}

// InputError — ошибки проверки ввода; каждая начинается с имени поля.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func invalidf(format string, a ...any) error {
	return &InputError{Errs: []error{fmt.Errorf(format, a...)}}
}

// DecodeInput разбирает тело запроса канала: неизвестные поля и данные
// после объекта отклоняются.
func DecodeInput(data []byte) (ChannelInput, error) {
	var in ChannelInput
	if len(data) > MaxChannelBody {
		return in, invalidf("тело запроса — не больше %d КиБ", MaxChannelBody>>10)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, invalidf("тело запроса — некорректный JSON")
	}
	if dec.More() {
		return in, invalidf("тело запроса — данные после объекта")
	}
	return in, nil
}

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// validHost — имя узла или IP-адрес без схемы и порта.
func validHost(h string) bool {
	if h == "" || len(h) > maxHost {
		return false
	}
	if ip := net.ParseIP(h); ip != nil {
		return true
	}
	return hostRe.MatchString(h)
}

// plainText — печатная строка без управляющих символов (в том числе CR/LF:
// значения идут в заголовки писем и записи syslog).
func plainText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return false
		}
	}
	return true
}

// validAddress — адрес почты без отображаемого имени.
func validAddress(s string) bool {
	if s == "" || len(s) > maxAddress || !plainText(s) {
		return false
	}
	a, err := mail.ParseAddress(s)
	return err == nil && a.Name == "" && a.Address == s && strings.Count(s, "@") == 1
}

// parseWebhookURL — адрес webhook: только https, без учётных данных в
// адресе и фрагмента (адреса задаёт администратор, ЗИ.3).
func parseWebhookURL(s string) (*url.URL, error) {
	if s == "" || len(s) > maxURL || !plainText(s) {
		return nil, errors.New("адрес https:// не длиннее 2048 символов")
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.Fragment != "" || u.RawFragment != "" {
		return nil, errors.New("адрес https:// без имени пользователя и фрагмента")
	}
	if !validHost(u.Hostname()) {
		return nil, errors.New("в адресе нет корректного имени узла")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return nil, errors.New("порт в адресе — от 1 до 65535")
		}
	}
	return u, nil
}

// origin — схема, узел и порт адреса для показа.
func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// normalize проверяет канал и подставляет значения по умолчанию. prev —
// прежние секреты (при изменении) или пустые; возвращает итоговые секреты.
// tls проверяет корневые сертификаты.
func normalize(in *ChannelInput, prev Secrets, tlsp aisecCrypto.TLSProvider) (Secrets, error) {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	in.Name = strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(in.Name); n == 0 || n > MaxName || !plainText(in.Name) {
		bad("name — от 1 до %d символов без управляющих", MaxName)
	}
	if in.MinSeverity == "" {
		in.MinSeverity = "info"
	}
	if SeverityRank(in.MinSeverity) == 0 {
		bad("min_severity — одно из значений: info, low, medium, high, critical")
	}
	if in.Enabled == nil {
		t := true
		in.Enabled = &t
	}
	sec := prev
	apply := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	apply(&sec.Password, in.Secrets.Password)
	apply(&sec.URL, in.Secrets.URL)
	apply(&sec.SigningKey, in.Secrets.SigningKey)

	s := &in.Settings
	s.URLOrigin = ""
	switch in.Type {
	case TypeEmail:
		if s.Format != "" || s.Facility != nil || s.Hostname != "" {
			bad("settings — у почты нет полей format, facility, hostname")
		}
		if sec.URL != "" || sec.SigningKey != "" {
			bad("secrets — у почты есть только password")
		}
		if s.Port == 0 {
			s.Port = DefaultSMTPPort
		}
		if !plainText(s.Username) || len(s.Username) > maxUsername {
			bad("settings.username — не длиннее %d байт без управляющих символов", maxUsername)
		}
		switch {
		case s.Username != "" && sec.Password == "":
			bad("secrets.password — обязателен, если задано имя пользователя SMTP")
		case s.Username == "" && sec.Password != "":
			bad("settings.username — задан пароль SMTP без имени пользователя")
		case len(sec.Password) > maxPassword || strings.ContainsAny(sec.Password, "\x00\r\n"):
			bad("secrets.password — не длиннее %d байт, без NUL и перевода строки", maxPassword)
		}
		if !validAddress(s.From) {
			bad("settings.from — адрес отправителя вида soc@example.ru")
		}
		if len(s.To) == 0 || len(s.To) > MaxRecipients {
			bad("settings.to — от 1 до %d адресов получателей", MaxRecipients)
		}
		for i, a := range s.To {
			if !validAddress(a) {
				bad("settings.to[%d] — адрес вида soc@example.ru", i)
			}
		}
		if len(s.To) > 0 {
			sorted := slices.Clone(s.To)
			slices.Sort(sorted)
			if len(slices.Compact(sorted)) != len(s.To) {
				bad("settings.to — адреса повторяются")
			}
		}
	case TypeWebhook:
		if s.Host != "" || s.Port != 0 || s.Username != "" || s.From != "" || len(s.To) > 0 || s.Facility != nil || s.Hostname != "" {
			bad("settings — у webhook есть только format и ca_pem; адрес — в secrets.url")
		}
		if sec.Password != "" {
			bad("secrets — у webhook есть только url и signing_key")
		}
		if s.Format == "" {
			s.Format = FormatGeneric
		}
		if s.Format != FormatGeneric && s.Format != FormatMattermost {
			bad("settings.format — generic или mattermost")
		}
		if u, err := parseWebhookURL(sec.URL); err != nil {
			bad("secrets.url — %v", err)
		} else {
			s.URLOrigin = origin(u)
		}
		if n := len(sec.SigningKey); n < MinSigningKey || n > maxSigningKey || !plainText(sec.SigningKey) {
			bad("secrets.signing_key — ключ подписи от %d до %d байт без управляющих символов", MinSigningKey, maxSigningKey)
		}
	case TypeSyslog:
		if s.Username != "" || s.From != "" || len(s.To) > 0 {
			bad("settings — у syslog нет полей username, from, to")
		}
		if sec != (Secrets{}) {
			bad("secrets — у syslog секретов нет")
		}
		if s.Port == 0 {
			s.Port = DefaultSyslogPort
		}
		if s.Format == "" {
			s.Format = FormatJSON
		}
		if s.Format != FormatJSON && s.Format != FormatCEF {
			bad("settings.format — json или cef")
		}
		if s.Facility == nil {
			f := DefaultFacility
			s.Facility = &f
		}
		if *s.Facility < 0 || *s.Facility > 23 {
			bad("settings.facility — от 0 до 23 (RFC 5424)")
		}
		if s.Hostname == "" {
			s.Hostname = DefaultHostname
		}
		if !syslogName(s.Hostname, 255) {
			bad("settings.hostname — от 1 до 255 печатных символов ASCII без пробелов")
		}
	default:
		bad("type — одно из значений: email, webhook, syslog")
	}
	if in.Type == TypeEmail || in.Type == TypeSyslog {
		if !validHost(s.Host) {
			bad("settings.host — имя узла или IP-адрес без схемы и порта")
		}
		if s.Port < 1 || s.Port > 65535 {
			bad("settings.port — от 1 до 65535")
		}
	}
	switch {
	case s.CAPEM == "":
		bad("ca_pem — корневые сертификаты получателя в PEM обязательны: соединение только по TLS")
	case len(s.CAPEM) > MaxCAPEM:
		bad("ca_pem — не больше %d КиБ", MaxCAPEM>>10)
	default:
		if _, err := tlsp.ClientConfig([]byte(s.CAPEM)); err != nil {
			bad("ca_pem — не найдено ни одного корректного сертификата PEM")
		}
	}
	if len(errs) > 0 {
		return Secrets{}, &InputError{Errs: errs}
	}
	return sec, nil
}

// syslogName — PRINTUSASCII (RFC 5424, 6.2.4–6.2.7) длиной от 1 до max.
func syslogName(s string, maxLen int) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 33 || s[i] > 126 {
			return false
		}
	}
	return true
}
