package shadowai

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Разборщики журналов прокси и NGFW (ADR-0027, п. 5): CSV с заголовком,
// Squid access.log (native) и CEF (в том числе выгрузка UserGate). Вход
// недоверенный: строка ограничена по длине, разбор построчный, без
// регулярных выражений; каждый разборщик покрыт fuzz-тестом. Ошибка строки
// не прерывает импорт — строка считается ошибочной, её содержимое никуда
// не попадает.

// Форматы журналов.
const (
	FormatCSV   = "csv"
	FormatSquid = "squid"
	FormatCEF   = "cef"
)

// Formats — допустимые форматы.
func Formats() []string { return []string{FormatCSV, FormatSquid, FormatCEF} }

// Виды пользователя в агрегате.
const (
	UserKindUser    = "user"
	UserKindAddress = "address"
	UserKindNone    = "none"
)

// Пределы строки журнала.
const (
	// DefaultMaxLine — длина строки (без перевода строки).
	DefaultMaxLine = 16 << 10
	maxUserLen     = 256
	maxLineBytes   = 1 << 40
	maxCEFPairs    = 256
)

// record — сведения одной строки журнала.
type record struct {
	time     time.Time
	user     string
	userKind string
	host     string
	bytes    int64
}

// errLine — строка не разобрана; подробности не сохраняются (в них может
// быть содержимое строки).
var errLine = errors.New("строка журнала не разобрана")

// ErrHeader — у CSV нет заголовка с обязательными столбцами.
var ErrHeader = errors.New("CSV: в первой строке нужен заголовок со столбцами времени и домена (или URL)")

// lineParser разбирает строки одного файла. skip — строка без записи
// (заголовок CSV, пустая строка).
type lineParser interface {
	parse(line []byte) (rec record, skip bool, err error)
}

// timeBounds — допустимое время записи: от 2000 года до суток вперёд.
type timeBounds struct {
	loc *time.Location
	max time.Time
}

var minLogTime = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

func (b timeBounds) ok(t time.Time) bool { return !t.Before(minLogTime) && !t.After(b.max) }

func newParser(format string, b timeBounds) (lineParser, error) {
	switch format {
	case FormatCSV:
		return &csvParser{b: b}, nil
	case FormatSquid:
		return squidParser{b: b}, nil
	case FormatCEF:
		return cefParser{b: b}, nil
	}
	return nil, fmt.Errorf("формат журнала — %s", strings.Join(Formats(), ", "))
}

// lineReader читает строки не длиннее max байт. Длинная строка
// дочитывается до перевода строки без хранения и возвращается с long = true.
type lineReader struct {
	r   *bufio.Reader
	max int
}

func newLineReader(r io.Reader, max int) *lineReader {
	return &lineReader{r: bufio.NewReaderSize(r, max+2), max: max}
}

// next — следующая строка без «\n» и «\r» в конце; io.EOF — строк больше нет.
func (l *lineReader) next() (line []byte, long bool, err error) {
	line, err = l.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = l.r.ReadSlice('\n')
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, false, err
		}
		return nil, true, nil
	}
	if errors.Is(err, io.EOF) {
		if len(line) == 0 {
			return nil, false, io.EOF
		}
		err = nil
	}
	if err != nil {
		return nil, false, err
	}
	line = bytes.TrimSuffix(line, []byte("\n"))
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) > l.max {
		return nil, true, nil
	}
	return line, false, nil
}

// cleanUser проверяет идентификатор пользователя: «-» и пустой — нет
// пользователя; длинный, не UTF-8 или с управляющими символами — ошибка.
func cleanUser(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return "", nil
	}
	if len(s) > maxUserLen || !utf8.ValidString(s) {
		return "", errLine
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return "", errLine
		}
	}
	return s, nil
}

// withUser заполняет пользователя записи: имя, иначе адрес клиента.
func (r *record) withUser(user, addr string) error {
	u, err := cleanUser(user)
	if err != nil {
		return err
	}
	if u != "" {
		r.user, r.userKind = u, UserKindUser
		return nil
	}
	a, err := cleanUser(addr)
	if err != nil {
		return err
	}
	if a != "" {
		r.user, r.userKind = a, UserKindAddress
		return nil
	}
	r.userKind = UserKindNone
	return nil
}

// hostOf — имя узла из домена, «узел:порт» или URL. Пусто — узла нет.
// Схема — только [A-Za-z][A-Za-z0-9+.-]* перед первым «://», стоящим раньше
// «/?#» (4Н19): «chatgpt.com/c?next=https://ya.ru» — узел chatgpt.com.
func hostOf(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "://"); i > 0 && !strings.ContainsAny(s[:i], "/?#") && isScheme(s[:i]) {
		s = s[i+3:]
		if j := strings.IndexAny(s, "/?#"); j >= 0 {
			s = s[:j]
		}
		if j := strings.LastIndexByte(s, '@'); j >= 0 {
			s = s[j+1:]
		}
		return s
	}
	if j := strings.IndexAny(s, "/?#"); j >= 0 {
		s = s[:j]
	}
	return s
}

// isScheme — схема URL по RFC 3986: буква, затем буквы, цифры, «+», «-», «.».
func isScheme(s string) bool {
	for i, r := range s {
		ok := r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.')
		if !ok {
			return false
		}
	}
	return s != ""
}

// parseBytes — неотрицательное целое не больше maxLineBytes; «-» и пусто — 0.
func parseBytes(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "-" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 || n > maxLineBytes {
		return 0, errLine
	}
	return n, nil
}

// parseEpoch — секунды Unix с необязательной дробной частью (до 9 знаков)
// или, при ms = true, миллисекунды без дробной части.
func parseEpoch(s string, ms bool) (time.Time, bool) {
	intPart, frac, hasFrac := strings.Cut(s, ".")
	if intPart == "" || len(intPart) > 16 || (hasFrac && (ms || frac == "" || len(frac) > 9)) {
		return time.Time{}, false
	}
	for _, part := range []string{intPart, frac} {
		for i := 0; i < len(part); i++ {
			if part[i] < '0' || part[i] > '9' {
				return time.Time{}, false
			}
		}
	}
	n, err := strconv.ParseInt(intPart, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	if ms {
		return time.UnixMilli(n).UTC(), true
	}
	var nsec int64
	if hasFrac {
		f, err := strconv.ParseInt((frac + "000000000")[:9], 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		nsec = f
	}
	return time.Unix(n, nsec).UTC(), true
}

// --- CSV ---

// csvParser — CSV с заголовком (ADR-0027, п. 5): разделитель «,» или «;»
// по строке заголовка, кавычки по RFC 4180 без перевода строки в поле.
type csvParser struct {
	b      timeBounds
	header bool
	sep    byte
	cols   int
	// Номера столбцов; -1 — нет.
	time, user, host, bytes int
}

var csvColumns = map[string]string{
	"time": "time", "timestamp": "time", "время": "time", "datetime": "time", "date_time": "time",
	"user": "user", "username": "user", "login": "user", "пользователь": "user", "логин": "user",
	"domain": "host", "host": "host", "url": "host", "домен": "host", "адрес": "host", "узел": "host",
	"bytes": "bytes", "байты": "bytes", "size": "bytes", "размер": "bytes",
}

const maxCSVFields = 64

// splitCSV делит строку на поля. Поле в кавычках может содержать
// разделитель и «""»; после закрывающей кавычки — разделитель или конец.
func splitCSV(line []byte, sep byte) ([]string, error) {
	var out []string
	for i := 0; ; {
		if len(out) >= maxCSVFields {
			return nil, errLine
		}
		if i < len(line) && line[i] == '"' {
			var b strings.Builder
			i++
			for {
				if i >= len(line) {
					return nil, errLine // кавычка не закрыта
				}
				c := line[i]
				if c == '"' {
					if i+1 < len(line) && line[i+1] == '"' {
						b.WriteByte('"')
						i += 2
						continue
					}
					i++
					break
				}
				b.WriteByte(c)
				i++
			}
			out = append(out, b.String())
			if i == len(line) {
				return out, nil
			}
			if line[i] != sep {
				return nil, errLine
			}
			i++
			continue
		}
		j := bytes.IndexByte(line[i:], sep)
		if j < 0 {
			out = append(out, string(line[i:]))
			return out, nil
		}
		out = append(out, string(line[i:i+j]))
		i += j + 1
	}
}

func (p *csvParser) parse(line []byte) (record, bool, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return record{}, true, nil
	}
	if !p.header {
		return record{}, true, p.parseHeader(line)
	}
	fields, err := splitCSV(line, p.sep)
	if err != nil || len(fields) != p.cols {
		return record{}, false, errLine
	}
	var r record
	t, ok := parseCSVTime(strings.TrimSpace(fields[p.time]), p.b.loc)
	if !ok || !p.b.ok(t) {
		return record{}, false, errLine
	}
	r.time = t
	r.host = hostOf(fields[p.host])
	user := ""
	if p.user >= 0 {
		user = fields[p.user]
	}
	if err := r.withUser(user, ""); err != nil {
		return record{}, false, err
	}
	if p.bytes >= 0 {
		if r.bytes, err = parseBytes(fields[p.bytes]); err != nil {
			return record{}, false, err
		}
	}
	return r, false, nil
}

// parseHeader — первая непустая строка. Ошибка заголовка прерывает импорт:
// без него столбцы не определить.
func (p *csvParser) parseHeader(line []byte) error {
	line = bytes.TrimPrefix(line, []byte("\xef\xbb\xbf")) // BOM
	p.sep = ','
	if bytes.Count(line, []byte(";")) > bytes.Count(line, []byte(",")) {
		p.sep = ';'
	}
	fields, err := splitCSV(line, p.sep)
	if err != nil {
		return ErrHeader
	}
	p.time, p.user, p.host, p.bytes = -1, -1, -1, -1
	for i, f := range fields {
		var dst *int
		switch csvColumns[strings.ToLower(strings.TrimSpace(f))] {
		case "time":
			dst = &p.time
		case "user":
			dst = &p.user
		case "host":
			dst = &p.host
		case "bytes":
			dst = &p.bytes
		default:
			continue
		}
		if *dst >= 0 {
			return ErrHeader // столбец назван дважды
		}
		*dst = i
	}
	if p.time < 0 || p.host < 0 {
		return ErrHeader
	}
	p.cols, p.header = len(fields), true
	return nil
}

var csvTimeLayouts = []string{"2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999"}

// parseCSVTime — RFC 3339, местное время установки без зоны или секунды Unix.
func parseCSVTime(s string, loc *time.Location) (time.Time, bool) {
	if s == "" || len(s) > 40 {
		return time.Time{}, false
	}
	if s[0] >= '0' && s[0] <= '9' && !strings.ContainsAny(s, "-:") {
		return parseEpoch(s, false)
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC(), true
	}
	for _, l := range csvTimeLayouts {
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// --- Squid ---

// squidParser — Squid access.log, logformat squid (native):
// «время.мс длительность клиент код/статус байты метод URL пользователь
// иерархия тип». Пользователь «-» — адрес клиента; для CONNECT URL —
// «узел:порт».
type squidParser struct{ b timeBounds }

func (p squidParser) parse(line []byte) (record, bool, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return record{}, true, nil
	}
	f := strings.Fields(string(line))
	if len(f) < 7 || len(f) > 32 {
		return record{}, false, errLine
	}
	t, ok := parseEpoch(f[0], false)
	if !ok || !p.b.ok(t) {
		return record{}, false, errLine
	}
	if !strings.Contains(f[3], "/") {
		return record{}, false, errLine
	}
	r := record{time: t, host: hostOf(f[6])}
	var err error
	if r.bytes, err = parseBytes(f[4]); err != nil {
		return record{}, false, err
	}
	user := ""
	if len(f) > 7 {
		user = f[7]
	}
	if err := r.withUser(user, f[2]); err != nil {
		return record{}, false, err
	}
	return r, false, nil
}

// --- CEF ---

// cefParser — Common Event Format (ArcSight), в том числе журналы UserGate
// в формате CEF: «CEF:версия|производитель|продукт|версия|ID|имя|важность|
// расширение». Заголовок syslog перед «CEF:» допускается. Поля расширения:
// время — rt (мс Unix или «MMM dd yyyy HH:mm:ss[.SSS] [зона]»), иначе end,
// start; пользователь — suser, иначе src; узел — dhost, иначе из request;
// байты — in + out.
type cefParser struct{ b timeBounds }

func (p cefParser) parse(line []byte) (record, bool, error) {
	if len(bytes.TrimSpace(line)) == 0 {
		return record{}, true, nil
	}
	i := bytes.Index(line, []byte("CEF:"))
	if i < 0 {
		return record{}, false, errLine
	}
	ext, ok := cefExtension(line[i+4:])
	if !ok {
		return record{}, false, errLine
	}
	kv, ok := cefPairs(ext)
	if !ok {
		return record{}, false, errLine
	}
	var r record
	var t time.Time
	for _, k := range []string{"rt", "end", "start"} {
		if v, has := kv[k]; has {
			if t, ok = parseCEFTime(v, p.b.loc); !ok {
				return record{}, false, errLine
			}
			break
		}
	}
	if t.IsZero() || !p.b.ok(t) {
		return record{}, false, errLine
	}
	r.time = t
	r.host = kv["dhost"]
	if r.host == "" {
		r.host = hostOf(kv["request"])
	}
	if err := r.withUser(kv["suser"], kv["src"]); err != nil {
		return record{}, false, err
	}
	for _, k := range []string{"in", "out"} {
		n, err := parseBytes(kv[k])
		if err != nil {
			return record{}, false, err
		}
		r.bytes += n
	}
	return r, false, nil
}

// cefExtension пропускает 7 полей заголовка (разделитель — «|» без «\»
// перед ним) и возвращает расширение.
func cefExtension(s []byte) ([]byte, bool) {
	pipes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '|':
			pipes++
			if pipes == 7 {
				return s[i+1:], true
			}
		}
	}
	return nil, false
}

// cefKeyByte — символ ключа расширения.
func cefKeyByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '[' || c == ']'
}

// cefPairs разбирает «ключ=значение ключ=значение»: значение может
// содержать пробелы и тянется до следующего «пробел ключ=» (знак «=» в
// значении экранируется как «\=», неэкранированный — буквальный). Ключи — до maxCEFPairs. Повтор ключа —
// часть значения предыдущего ключа (4Н31 ревью 4.r3): источник без
// экранирования «=» в значении вида «x dhost=ya.ru» не подставляет чужой
// узел и не теряет строку.
func cefPairs(ext []byte) (map[string]string, bool) {
	// Начала ключей: позиции после пробела (или начало), с которых идёт
	// ключ и неэкранированный «=».
	type span struct{ k, v int }
	var starts []span
	for i := 0; i < len(ext); i++ {
		if i > 0 && ext[i-1] != ' ' {
			continue
		}
		j := i
		for j < len(ext) && cefKeyByte(ext[j]) {
			j++
		}
		if j == i || j >= len(ext) || ext[j] != '=' {
			continue
		}
		starts = append(starts, span{k: i, v: j + 1})
		if len(starts) > maxCEFPairs {
			return nil, false
		}
		i = j
	}
	if len(bytes.TrimSpace(ext)) > 0 && (len(starts) == 0 || len(bytes.TrimSpace(ext[:starts[0].k])) > 0) {
		return nil, false // текст до первого ключа
	}
	type pair struct {
		key    string
		v, end int
	}
	pairs := make([]pair, 0, len(starts))
	seen := make(map[string]bool, len(starts))
	for n, s := range starts {
		end := len(ext)
		if n+1 < len(starts) {
			end = starts[n+1].k
		}
		key := string(ext[s.k : s.v-1])
		if seen[key] {
			// Значения идут подряд: хвост вклеивается в предыдущее как есть.
			pairs[len(pairs)-1].end = end
			continue
		}
		seen[key] = true
		pairs = append(pairs, pair{key: key, v: s.v, end: end})
	}
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		v, ok := cefUnescape(bytes.TrimRight(ext[p.v:p.end], " "))
		if !ok {
			return nil, false
		}
		m[p.key] = v
	}
	return m, true
}

// cefUnescape: «\=», «\\», «\n», «\r»; неэкранированный «=» в значении —
// буквальный (4Н20): источник, не экранирующий «=» в URL или User-Agent, не
// теряет строку, и «curl -A 'a=b'» не прячет обращение.
func cefUnescape(v []byte) (string, bool) {
	if bytes.IndexByte(v, '\\') < 0 {
		return string(v), true
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c != '\\':
			b.WriteByte(c)
		case i+1 >= len(v):
			return "", false
		default:
			i++
			switch v[i] {
			case '=', '\\', '|':
				b.WriteByte(v[i])
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			default:
				return "", false
			}
		}
	}
	return b.String(), true
}

var cefTimeLayouts = []string{"Jan 2 2006 15:04:05", "Jan 2 2006 15:04:05.000"}

// parseCEFTime — миллисекунды Unix или «MMM dd yyyy HH:mm:ss[.SSS] [зона]»
// (зона — смещение ±ЧЧММ или UTC/GMT; без зоны — часовой пояс установки).
func parseCEFTime(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 40 {
		return time.Time{}, false
	}
	if s[0] >= '0' && s[0] <= '9' {
		return parseEpoch(s, true)
	}
	f := strings.Fields(s)
	if len(f) != 4 && len(f) != 5 {
		return time.Time{}, false
	}
	l := loc
	if len(f) == 5 {
		switch z := f[4]; {
		case z == "UTC" || z == "GMT" || z == "Z":
			l = time.UTC
		case len(z) == 5 && (z[0] == '+' || z[0] == '-'):
			off, err := time.Parse("-0700", z)
			if err != nil {
				return time.Time{}, false
			}
			_, sec := off.Zone()
			l = time.FixedZone(z, sec)
		default:
			return time.Time{}, false
		}
	}
	v := strings.Join(f[:4], " ")
	for _, layout := range cefTimeLayouts {
		if t, err := time.ParseInLocation(layout, v, l); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
