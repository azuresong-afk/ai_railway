// Пакет ldap — клиент каталога LDAP для входа в консоль (ТЗ 5.14, ИАФ.7;
// ADR-0025, раздел 2): поиск пользователя сервисной учётной записью,
// проверка пароля отдельным simple bind и группы пользователя. Ходит только
// к каталогу, который настроил администратор безопасности; пакет — в
// NET_CLIENT_ALLOWED. Библиотека github.com/go-ldap/ldap/v3 импортируется
// только здесь. TLS — ClientConfig криптопрофиля с корнями каталога;
// соединение без TLS не используется (только LDAPS или StartTLS).
package ldap

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пределы обмена с каталогом (ADR-0025, 2.3).
const (
	// DefaultTimeout — срок всей проверки входа (оба соединения).
	DefaultTimeout = 10 * time.Second
	// MaxRead — предел байт, прочитанных с одного соединения.
	MaxRead = 1 << 20
	// MaxGroups — предел групп пользователя.
	MaxGroups = 1000
	// MaxConcurrent — одновременных проверок входа; остальные ждут в
	// пределах срока запроса.
	MaxConcurrent = 16
	// LoginPlaceholder — место логина в шаблоне фильтра поиска.
	LoginPlaceholder = "{login}"
	// Пределы настроек.
	maxURL       = 512
	maxDN        = 1024
	maxFilter    = 512
	maxAttrName  = 64
	maxIDValue   = 255
	maxDisplay   = 1024
	timeLimitSec = 10
)

// Способы получения групп (ADR-0025, 2.4).
const (
	// GroupsMemberOf — атрибут memberOf записи пользователя (FreeIPA, ALD Pro, AD).
	GroupsMemberOf = "member_of"
	// GroupsMember — поиск групп с member или uniqueMember, равным DN пользователя.
	GroupsMember = "member"
	// GroupsADNested — вложенные группы AD: правило 1.2.840.113556.1.4.1941.
	GroupsADNested = "ad_nested"
)

// IDAttributes — атрибуты с неизменяемым идентификатором записи.
var IDAttributes = []string{"entryUUID", "ipaUniqueID", "nsUniqueId", "objectGUID"}

// GroupModes — допустимые способы получения групп.
var GroupModes = []string{GroupsMemberOf, GroupsMember, GroupsADNested}

func init() {
	// Разборщик BER библиотеки по умолчанию принимает пакеты до 2 ГиБ.
	// Ответ каталога для входа укладывается в MaxRead; предел соединения
	// (limitedConn) срабатывает раньше и даёт код too_large, этот — запасной.
	ber.MaxPacketLengthBytes = 2 * MaxRead
}

// Коды ошибок клиента для журнала аудита (наружу не выдаются).
const (
	CodeConfig      = "config"       // настройка неверна: адрес, корни, DN, фильтр
	CodeBlocked     = "blocked"      // адрес каталога запрещён (loopback, метаданные облака)
	CodeNetwork     = "network"      // соединение не установлено или прервано
	CodeTimeout     = "timeout"      // истёк срок проверки
	CodeBusy        = "busy"         // очередь проверок не освободилась в срок
	CodeTLS         = "tls"          // сертификат каталога не прошёл проверку, StartTLS отклонён
	CodeServiceBind = "service_bind" // сервисная учётная запись не прошла bind
	CodeCredentials = "credentials"  // неверный пароль пользователя
	CodeNotFound    = "not_found"    // пользователь не найден
	CodeAmbiguous   = "ambiguous"    // фильтру соответствуют несколько записей
	CodeIdentity    = "identity"     // нет или неверен атрибут идентификатора
	CodeTooLarge    = "too_large"    // групп больше MaxGroups или ответ больше MaxRead
	CodeResponse    = "response"     // каталог вернул ошибку операции
	CodeOther       = "internal"
)

// Error — отказ при обмене с каталогом. Code — один из Code*, Detail —
// короткое уточнение без данных каталога и без пароля.
type Error struct {
	Code   string
	Detail string
	err    error
}

func (e *Error) Error() string {
	s := "LDAP: " + e.Code
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	return s
}

func (e *Error) Unwrap() error { return e.err }

func fail(code, detail string) error { return &Error{Code: code, Detail: detail} }

func failErr(code, detail string, err error) error {
	return &Error{Code: code, Detail: detail, err: err}
}

// ErrorCode — код ошибки клиента; CodeOther — ошибка не *Error.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return CodeOther
}

// Detail — уточнение ошибки клиента без данных каталога.
func Detail(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Detail
	}
	return ""
}

// Config — настройки каталога из БД (пароль сервисной учётной записи уже
// расшифрован).
type Config struct {
	// URL — ldaps://узел[:порт] или ldap://узел[:порт]; у ldap:// StartTLS
	// обязателен и выполняется до bind.
	URL string
	// RootsPEM — корневые сертификаты каталога; системное хранилище не используется.
	RootsPEM     []byte
	BindDN       string
	BindPassword string
	UserBaseDN   string
	// UserFilter — шаблон фильтра поиска с LoginPlaceholder; логин
	// подставляется экранированным (RFC 4515).
	UserFilter       string
	IDAttribute      string
	DisplayAttribute string
	GroupMode        string
	// GroupBaseDN — ветка групп для GroupsMember и GroupsADNested.
	GroupBaseDN string
}

// Identity — проверенный пользователь каталога.
type Identity struct {
	DN string
	// ID — неизменяемый идентификатор записи (атрибут IDAttribute; у
	// objectGUID — 32 шестнадцатеричных символа).
	ID          string
	DisplayName string
	// Groups — DN групп пользователя в форме каталога.
	Groups []string
}

// ConfigError — неверная настройка каталога: поле и причина для администратора.
type ConfigError struct {
	Field  string
	Reason string
	err    error
}

func (e *ConfigError) Error() string { return "LDAP: " + e.Field + ": " + e.Reason }

func (e *ConfigError) Unwrap() error { return e.err }

// endpoint — разобранный адрес каталога.
type endpoint struct {
	host  string
	port  uint16
	ldaps bool
}

// parseURL — адрес каталога: ldaps:// или ldap:// (тогда StartTLS), узел,
// необязательный порт; без пути, параметров и учётных данных.
func parseURL(s string) (endpoint, error) {
	if s == "" || len(s) > maxURL {
		return endpoint{}, errors.New("адрес пуст или длиннее 512 символов")
	}
	u, err := url.Parse(s)
	if err != nil {
		return endpoint{}, errors.New("адрес не разобран")
	}
	var ep endpoint
	switch u.Scheme {
	case "ldaps":
		ep.ldaps, ep.port = true, 636
	case "ldap":
		ep.port = 389
	default:
		return endpoint{}, errors.New("адрес должен начинаться с ldaps:// или ldap:// (со StartTLS)")
	}
	switch {
	case u.Hostname() == "":
		return endpoint{}, errors.New("в адресе нет имени узла")
	case u.User != nil:
		return endpoint{}, errors.New("адрес не должен содержать имя пользователя или пароль")
	case u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return endpoint{}, errors.New("адрес — только узел и порт, без DN и параметров")
	}
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 {
			return endpoint{}, errors.New("неверный порт")
		}
		ep.port = uint16(n) //nolint:gosec // G115: ParseUint с разрядностью 16
	}
	ep.host = u.Hostname()
	return ep, nil
}

// ValidDN — строка разбирается как DN (RFC 4514) и не пуста.
func ValidDN(s string) bool {
	if s == "" || len(s) > maxDN || !utf8.ValidString(s) {
		return false
	}
	dn, err := goldap.ParseDN(s)
	return err == nil && len(dn.RDNs) > 0
}

// SameDN — a и b — один и тот же DN без учёта регистра и пробелов вокруг
// разделителей (сравнение групп из каталога с таблицей ролей).
func SameDN(a, b string) bool {
	if !ValidDN(a) || !ValidDN(b) {
		return false
	}
	da, err := goldap.ParseDN(a)
	if err != nil {
		return false
	}
	db, err := goldap.ParseDN(b)
	if err != nil {
		return false
	}
	return da.EqualFold(db)
}

// attrName — имя атрибута: буква, затем буквы, цифры и «-» (RFC 4512, 1.4).
func attrName(s string) bool {
	if s == "" || len(s) > maxAttrName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		if !alpha && (i == 0 || (!digit && c != '-')) {
			return false
		}
	}
	return true
}

// UserFilter подставляет экранированный логин в шаблон фильтра.
func UserFilter(tmpl, login string) string {
	return strings.ReplaceAll(tmpl, LoginPlaceholder, goldap.EscapeFilter(login))
}

// ErrLoginPlacement — {login} стоит не в значении условия: логин меняет
// структуру фильтра или атрибут условия (4В14). Текст — для администратора.
var ErrLoginPlacement = errors.New(LoginPlaceholder + " должен стоять в значении условия, например (uid=" +
	LoginPlaceholder + ")")

// loginProbes — пробы логина для проверки шаблона: обычные логины и логины с
// символами, которые EscapeFilter не экранирует, но которые вне значения
// меняют разбор условия (расширяемое сравнение, ~=, <=, >=, :dn:).
var loginProbes = []string{"x", "y", ":", "=", "~", "<", ">", "*", "(", ")", "\\", "&", "|", "!",
	":dn:", "x:=", "~=", "<=", ">=", "x:dn:1.2.3:=", "a\x00"}

// validFilter — шаблон фильтра: до 512 байт, с LoginPlaceholder только в
// значении (сразу после «=» или «*»: имя атрибута экранированием не
// защищается), и после подстановки — разбираемый фильтр LDAP.
// ErrLoginPlacement — логин стоит в имени атрибута или подстановка проб
// логина даёт фильтры разной структуры (то же свойство, что FuzzUserFilter).
func validFilter(tmpl string) error {
	if len(tmpl) > maxFilter || !utf8.ValidString(tmpl) || !strings.Contains(tmpl, LoginPlaceholder) {
		return errBadFilter
	}
	for i := 0; ; {
		j := strings.Index(tmpl[i:], LoginPlaceholder)
		if j < 0 {
			break
		}
		if k := i + j; k == 0 || (tmpl[k-1] != '=' && tmpl[k-1] != '*') {
			return ErrLoginPlacement
		}
		i += j + len(LoginPlaceholder)
	}
	want := ""
	for n, probe := range loginProbes {
		p, err := goldap.CompileFilter(UserFilter(tmpl, probe))
		if err != nil && n == 0 {
			return errBadFilter
		}
		if err != nil {
			return ErrLoginPlacement
		}
		got := filterShape(p)
		if n == 0 {
			want = got
		} else if got != want {
			return ErrLoginPlacement
		}
	}
	return nil
}

var errBadFilter = errors.New("фильтр не разобран или в нём нет " + LoginPlaceholder)

// filterShape — дерево фильтра без значений условий: теги, атрибуты и
// правила сравнения. Значения (равенство, порядок, подстроки, значение
// расширяемого сравнения) не учитываются: только туда попадает логин.
func filterShape(p *ber.Packet) string {
	var b strings.Builder
	writeShape(&b, p)
	return b.String()
}

func writeShape(b *strings.Builder, p *ber.Packet) {
	b.WriteString(strconv.Itoa(int(p.ClassType)) + "." + strconv.Itoa(int(p.Tag)) + "(")
	switch {
	case p.ClassType != ber.ClassContext:
	case p.Tag == goldap.FilterAnd || p.Tag == goldap.FilterOr || p.Tag == goldap.FilterNot:
		for _, c := range p.Children {
			writeShape(b, c)
		}
	case p.Tag == goldap.FilterPresent:
		b.WriteString(strconv.Quote(p.Data.String()))
	case p.Tag == goldap.FilterExtensibleMatch:
		for _, c := range p.Children {
			b.WriteString(strconv.Itoa(int(c.Tag)))
			if c.Tag != goldap.MatchingRuleAssertionMatchValue {
				b.WriteString(strconv.Quote(c.Data.String()))
			}
			b.WriteString(",")
		}
	default:
		// Равенство, подстроки, >=, <=, ~=: атрибут и виды частей подстроки.
		for i, c := range p.Children {
			switch {
			case i == 0:
				b.WriteString(strconv.Quote(c.Data.String()))
			case p.Tag == goldap.FilterSubstrings:
				for _, part := range c.Children {
					b.WriteString(strconv.Itoa(int(part.Tag)) + ",")
				}
			}
			b.WriteString(";")
		}
	}
	b.WriteString(")")
}

// ValidateConfig проверяет настройки без обращения к каталогу; пароль
// сервисной учётной записи не проверяется (он может быть «прежним»).
func ValidateConfig(cfg Config) error {
	if _, err := parseURL(cfg.URL); err != nil {
		return &ConfigError{Field: "url", Reason: err.Error()}
	}
	if !ValidDN(cfg.BindDN) {
		return &ConfigError{Field: "bind_dn", Reason: "DN сервисной учётной записи не разобран"}
	}
	if !ValidDN(cfg.UserBaseDN) {
		return &ConfigError{Field: "user_base_dn", Reason: "DN ветки пользователей не разобран"}
	}
	if err := validFilter(cfg.UserFilter); err != nil {
		return &ConfigError{Field: "user_filter", Reason: err.Error(), err: err}
	}
	if !slices.Contains(IDAttributes, cfg.IDAttribute) {
		return &ConfigError{Field: "id_attribute", Reason: "атрибут идентификатора — один из " + strings.Join(IDAttributes, ", ")}
	}
	if !attrName(cfg.DisplayAttribute) {
		return &ConfigError{Field: "display_attribute", Reason: "имя атрибута — латиница, цифры и «-», до 64 символов"}
	}
	if !slices.Contains(GroupModes, cfg.GroupMode) {
		return &ConfigError{Field: "group_mode", Reason: "способ получения групп — " + strings.Join(GroupModes, ", ")}
	}
	if cfg.GroupMode != GroupsMemberOf && !ValidDN(cfg.GroupBaseDN) {
		return &ConfigError{Field: "group_base_dn", Reason: "DN ветки групп не разобран"}
	}
	if cfg.GroupMode == GroupsMemberOf && cfg.GroupBaseDN != "" && !ValidDN(cfg.GroupBaseDN) {
		return &ConfigError{Field: "group_base_dn", Reason: "DN ветки групп не разобран"}
	}
	return nil
}

// Client — клиент каталога. Безопасен для одновременного использования.
type Client struct {
	tls     aisecCrypto.TLSProvider
	timeout time.Duration
	sem     chan struct{}

	mu      sync.Mutex
	allowed []netip.Prefix
}

// Option настраивает Client.
type Option func(*Client)

// WithTimeout задаёт срок проверки входа.
func WithTimeout(d time.Duration) Option { return func(c *Client) { c.timeout = d } }

// New создаёт клиент на криптопрофиле p. Без TLS в профиле (gost до
// этапа 6) — aisecCrypto.ErrNotImplemented.
func New(p aisecCrypto.Provider, opts ...Option) (*Client, error) {
	if p == nil {
		return nil, errors.New("LDAP: не задан криптопрофиль")
	}
	t, err := p.TLS()
	if err != nil {
		return nil, err
	}
	c := &Client{tls: t, timeout: DefaultTimeout, sem: make(chan struct{}, MaxConcurrent)}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// AllowNetworks разрешает сети, которые иначе запрещены (например, каталог
// на 127.0.0.1 в тестах). Вызывается до первого запроса.
func (c *Client) AllowNetworks(nets []netip.Prefix) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.allowed = slices.Clone(nets)
}

func (c *Client) allowedNets() []netip.Prefix {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.allowed
}

// acquire занимает место в очереди проверок с учётом срока ctx.
func (c *Client) acquire(ctx context.Context) error {
	select {
	case c.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return failErr(CodeBusy, "очередь проверок", ctx.Err())
	}
}

func (c *Client) release() { <-c.sem }

// session — соединение с каталогом и его ограничитель чтения.
type session struct {
	l    *goldap.Conn
	lim  *limitedConn
	stop func() bool
}

func (s *session) close() {
	s.stop()
	_ = s.l.Close() //nolint:gosec // G104: ошибка закрытия после обмена не важна
}

// connect — соединение с каталогом: TCP на проверенный адрес, затем LDAPS
// или StartTLS с проверкой сертификата и имени узла. Без TLS bind не
// выполняется никогда.
func (c *Client) connect(ctx context.Context, cfg Config) (*session, error) {
	ep, err := parseURL(cfg.URL)
	if err != nil {
		return nil, failErr(CodeConfig, "адрес", err)
	}
	tc, err := c.tls.ClientConfig(cfg.RootsPEM)
	if err != nil {
		return nil, failErr(CodeConfig, "корневые сертификаты", err)
	}
	tc.ServerName = ep.host
	raw, err := dial(ctx, c.allowedNets(), c.timeout, ep.host, ep.port)
	if errors.Is(err, errBlockedAddr) {
		return nil, failErr(CodeBlocked, "адрес", err)
	}
	if err != nil {
		return nil, netError(ctx, nil, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := raw.SetDeadline(dl); err != nil {
			_ = raw.Close() //nolint:gosec // G104: возвращается ошибка установки срока
			return nil, failErr(CodeNetwork, "срок соединения", err)
		}
	}
	// Отмена запроса (клиент ушёл) прерывает зависший обмен.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() }) //nolint:gosec // G104: соединение прерывается
	lim := newLimitedConn(raw, MaxRead)
	var conn net.Conn = lim
	if ep.ldaps {
		if conn, err = aisecCrypto.ClientTLS(ctx, lim, tc); err != nil {
			stop()
			return nil, tlsError(ctx, lim, err)
		}
	}
	l := goldap.NewConn(conn, ep.ldaps)
	l.Start()
	l.SetTimeout(c.timeout)
	s := &session{l: l, lim: lim, stop: stop}
	if !ep.ldaps {
		if err := l.StartTLS(tc); err != nil {
			s.close()
			return nil, tlsError(ctx, lim, err)
		}
	}
	return s, nil
}

// tlsError — отказ TLS или сети при установке защищённого соединения.
func tlsError(ctx context.Context, lim *limitedConn, err error) error {
	if aisecCrypto.IsTLSError(err) || goldap.IsErrorWithCode(err, goldap.LDAPResultProtocolError) ||
		goldap.IsErrorWithCode(err, goldap.LDAPResultUnavailable) || goldap.IsErrorWithCode(err, goldap.LDAPResultOperationsError) {
		return failErr(CodeTLS, "TLS", err)
	}
	if ne := netError(ctx, lim, err); ErrorCode(ne) != CodeNetwork {
		return ne
	}
	// Рукопожатие StartTLS библиотека сообщает как сетевую ошибку.
	return failErr(CodeTLS, "TLS", err)
}

// netError — код сетевой ошибки: срок, предел ответа или сеть.
func netError(ctx context.Context, lim *limitedConn, err error) error {
	switch {
	case lim != nil && lim.exceeded.Load():
		return failErr(CodeTooLarge, "ответ каталога", err)
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return failErr(CodeTimeout, "срок", err)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return failErr(CodeTimeout, "срок", err)
	}
	return failErr(CodeNetwork, "соединение", err)
}

// opError — ошибка операции LDAP: сетевая (код 200 библиотеки и
// таймаут запроса) или результат операции каталога.
func opError(ctx context.Context, s *session, code, detail string, err error) error {
	var le *goldap.Error
	if errors.As(err, &le) && le.ResultCode < goldap.ErrorNetwork {
		if le.ResultCode == goldap.LDAPResultSizeLimitExceeded {
			return failErr(CodeTooLarge, detail, err)
		}
		return failErr(code, detail+": код "+strconv.Itoa(int(le.ResultCode)), err)
	}
	return netError(ctx, s.lim, err)
}

// bindService — simple bind сервисной учётной записью.
func bindService(ctx context.Context, s *session, cfg Config) error {
	if cfg.BindPassword == "" {
		return fail(CodeConfig, "пустой пароль сервисной учётной записи")
	}
	if err := s.l.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return opError(ctx, s, CodeServiceBind, "bind сервисной учётной записи", err)
	}
	return nil
}

// withDeadline — срок проверки и место в очереди; done освобождает их.
func (c *Client) withDeadline(ctx context.Context) (context.Context, func(), error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	if err := c.acquire(ctx); err != nil {
		cancel()
		return nil, nil, err
	}
	return ctx, func() { c.release(); cancel() }, nil
}

// Check проверяет настройку: соединение с TLS, bind сервисной учётной
// записью и наличие веток пользователей и групп.
func (c *Client) Check(ctx context.Context, cfg Config) error {
	if err := ValidateConfig(cfg); err != nil {
		return failErr(CodeConfig, "настройка", err)
	}
	ctx, done, err := c.withDeadline(ctx)
	if err != nil {
		return err
	}
	defer done()
	s, err := c.connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.close()
	if err := bindService(ctx, s, cfg); err != nil {
		return err
	}
	bases := []string{cfg.UserBaseDN}
	if cfg.GroupMode != GroupsMemberOf {
		bases = append(bases, cfg.GroupBaseDN)
	}
	for _, base := range bases {
		_, err := s.l.Search(&goldap.SearchRequest{BaseDN: base, Scope: goldap.ScopeBaseObject,
			DerefAliases: goldap.NeverDerefAliases, SizeLimit: 1, TimeLimit: timeLimitSec,
			Filter: "(objectClass=*)", Attributes: []string{"1.1"}})
		if err != nil {
			return opError(ctx, s, CodeResponse, "ветка каталога", err)
		}
	}
	return nil
}

// Authenticate проверяет логин и пароль пользователя каталога: поиск
// записи сервисной учётной записью (не больше одной), simple bind
// пользователя на отдельном соединении, затем группы. Пустой пароль
// отклоняется до обращения к каталогу: иначе bind стал бы
// «неаутентифицированным» и прошёл бы (RFC 4513, 5.1.2).
func (c *Client) Authenticate(ctx context.Context, cfg Config, login, password string) (Identity, error) {
	if password == "" {
		return Identity{}, fail(CodeCredentials, "пустой пароль")
	}
	if login == "" {
		return Identity{}, fail(CodeNotFound, "пустой логин")
	}
	// Шаблон, сохранённый до проверки структуры (4В14): логин не
	// подставляется, отказ пишется в аудит входа с кодом config.
	if err := validFilter(cfg.UserFilter); err != nil {
		return Identity{}, failErr(CodeConfig, "шаблон фильтра: "+err.Error(), err)
	}
	ctx, done, err := c.withDeadline(ctx)
	if err != nil {
		return Identity{}, err
	}
	defer done()
	svc, err := c.connect(ctx, cfg)
	if err != nil {
		return Identity{}, err
	}
	defer svc.close()
	if err := bindService(ctx, svc, cfg); err != nil {
		return Identity{}, err
	}
	attrs := []string{cfg.IDAttribute, cfg.DisplayAttribute}
	if cfg.GroupMode == GroupsMemberOf {
		attrs = append(attrs, "memberOf")
	}
	res, err := svc.l.Search(&goldap.SearchRequest{BaseDN: cfg.UserBaseDN, Scope: goldap.ScopeWholeSubtree,
		DerefAliases: goldap.NeverDerefAliases, SizeLimit: 2, TimeLimit: timeLimitSec,
		Filter: UserFilter(cfg.UserFilter, login), Attributes: attrs})
	switch {
	case goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded):
		return Identity{}, fail(CodeAmbiguous, "несколько записей")
	case goldap.IsErrorWithCode(err, goldap.LDAPResultNoSuchObject):
		return Identity{}, fail(CodeNotFound, "нет ветки пользователей")
	case err != nil:
		return Identity{}, opError(ctx, svc, CodeResponse, "поиск пользователя", err)
	case len(res.Entries) == 0:
		return Identity{}, fail(CodeNotFound, "нет записи")
	case len(res.Entries) > 1:
		return Identity{}, fail(CodeAmbiguous, "несколько записей")
	}
	e := res.Entries[0]
	id, err := EntryID(cfg.IDAttribute, e.GetEqualFoldRawAttributeValues(cfg.IDAttribute))
	if err != nil {
		return Identity{}, err
	}
	if !ValidDN(e.DN) {
		return Identity{}, fail(CodeResponse, "DN записи не разобран")
	}
	if err := c.bindUser(ctx, cfg, e.DN, password); err != nil {
		return Identity{}, err
	}
	out := Identity{DN: e.DN, ID: id, DisplayName: displayValue(e.GetEqualFoldAttributeValues(cfg.DisplayAttribute))}
	if cfg.GroupMode == GroupsMemberOf {
		out.Groups = e.GetEqualFoldAttributeValues("memberOf")
		if len(out.Groups) > MaxGroups {
			return Identity{}, fail(CodeTooLarge, "групп больше предела")
		}
	} else if out.Groups, err = searchGroups(ctx, svc, cfg, e.DN); err != nil {
		return Identity{}, err
	}
	return out, nil
}

// bindUser — simple bind пользователя на отдельном соединении: сервисное
// соединение после него не меняет своей учётной записи.
func (c *Client) bindUser(ctx context.Context, cfg Config, dn, password string) error {
	s, err := c.connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.l.Bind(dn, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return failErr(CodeCredentials, "неверный пароль", err)
		}
		return opError(ctx, s, CodeResponse, "bind пользователя", err)
	}
	return nil
}

// GroupFilter — фильтр поиска групп пользователя с DN dn.
func GroupFilter(mode, dn string) string {
	v := goldap.EscapeFilter(dn)
	if mode == GroupsADNested {
		return "(member:1.2.840.113556.1.4.1941:=" + v + ")"
	}
	return "(|(member=" + v + ")(uniqueMember=" + v + "))"
}

// searchGroups — группы с членом dn в ветке групп; больше MaxGroups — отказ.
func searchGroups(ctx context.Context, s *session, cfg Config, dn string) ([]string, error) {
	res, err := s.l.Search(&goldap.SearchRequest{BaseDN: cfg.GroupBaseDN, Scope: goldap.ScopeWholeSubtree,
		DerefAliases: goldap.NeverDerefAliases, SizeLimit: MaxGroups, TimeLimit: timeLimitSec,
		Filter: GroupFilter(cfg.GroupMode, dn), Attributes: []string{"1.1"}, EnforceSizeLimit: true})
	if errors.Is(err, goldap.ErrSizeLimitExceeded) {
		return nil, fail(CodeTooLarge, "групп больше предела")
	}
	if err != nil {
		return nil, opError(ctx, s, CodeResponse, "поиск групп", err)
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, e.DN)
	}
	return out, nil
}

// EntryID — неизменяемый идентификатор записи из значений атрибута attr:
// ровно одно значение; objectGUID — 16 байт в шестнадцатеричной записи,
// остальные — 1–255 печатных символов ASCII.
func EntryID(attr string, values [][]byte) (string, error) {
	if len(values) != 1 {
		return "", fail(CodeIdentity, "атрибут идентификатора отсутствует или не один")
	}
	v := values[0]
	if attr == "objectGUID" {
		if len(v) != 16 {
			return "", fail(CodeIdentity, "objectGUID не 16 байт")
		}
		return hex.EncodeToString(v), nil
	}
	if len(v) == 0 || len(v) > maxIDValue {
		return "", fail(CodeIdentity, "длина идентификатора")
	}
	for _, b := range v {
		if b <= 0x20 || b > 0x7e {
			return "", fail(CodeIdentity, "символы идентификатора")
		}
	}
	return string(v), nil
}

// displayValue — первое значение атрибута отображаемого имени, если оно
// допустимо (дальнейшая очистка — в internal/auth).
func displayValue(v []string) string {
	if len(v) == 0 || len(v[0]) > maxDisplay || !utf8.ValidString(v[0]) {
		return ""
	}
	return v[0]
}
