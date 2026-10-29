package events

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Язык фильтров событий (ТЗ 5.5, 6.5; задача 2.16): условия, соединённые
// «and», — как «чипы» над таблицей: каждое условие снимается отдельно.
// Скобок и «or» нет. Пример:
//
//	app = "crm-bot" and severity in ("high", "critical") and stream = true
//
// Поля и операторы — из белого списка filterFields. Значения — строки в
// двойных кавычках (экранируются только \" и \\), у логических полей —
// true или false без кавычек. В SQL условие превращается в готовый фрагмент
// из кода, значения передаются только параметрами.

// Лимиты разбора фильтра.
const (
	MaxFilterLen    = 2048 // байт во всей строке фильтра
	MaxFilterConds  = 20   // условий
	MaxFilterValues = 50   // значений в in (...)
	MaxFilterValue  = 256  // байт в одном значении (как у столбцов events)
)

// Операторы условий.
const (
	OpEq    = "="
	OpNe    = "!="
	OpIn    = "in"
	OpNotIn = "not in"
)

// Cond — условие фильтра. Values после разбора без повторов; у OpEq и OpNe
// одно значение, у OpIn и OpNotIn — не меньше двух (одно значение
// приводится к = или !=, чтобы у фильтра была одна каноническая запись).
type Cond struct {
	Field  string
	Op     string
	Values []string
}

// Filter — разобранный фильтр; пустой фильтр пропускает все события.
type Filter struct {
	Conds []Cond
}

// fieldKind — вид поля: определяет SQL-фрагмент и проверку значений.
type fieldKind int

const (
	kindText    fieldKind = iota // текстовый столбец events
	kindBool                     // логический столбец
	kindThreats                  // массив threats (ID строк матрицы)
	kindFinding                  // поле находки в details.findings (fieldDef.key)
	kindUUID                     // столбец uuid
	kindMark                     // отметка аналитика (event_marks)
	kindSession                  // псевдоним сессии details.session.id (задача 4.13) или details.agent.session (4.11)
	kindAgent                    // поле раздела details.agent (задача 4.11): агент, MCP-сервер, инструмент
)

// fieldDef — поле фильтра: столбец таблицы events (константа кода, не ввод
// пользователя) и проверка формы значения.
type fieldDef struct {
	column string
	kind   fieldKind
	valid  func(string) bool
	// key — поле находки для kindFinding (константа кода).
	key string
	// expr — выражение SQL вместо столбца e.<column> (константа кода).
	expr string
}

var (
	threatValueRe = regexp.MustCompile(`^DM-\d{2}$`)
	// detectorValueRe — имя детектора: латиница, цифры, «._-».
	detectorValueRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
)

func oneOf(vs ...string) func(string) bool {
	return func(s string) bool { return slices.Contains(vs, s) }
}

func anyText(string) bool { return true }

func uuidValue(s string) bool {
	_, err := store.ParseUUID(s)
	return err == nil
}

// filterFields — белый список полей фильтра.
var filterFields = map[string]fieldDef{
	"type": {column: "type", kind: kindText,
		valid: oneOf(TypeGatewayRequest, TypeCheck, TypeAuthFailure, TypeAgentToolCall, TypeAgentMCP)},
	"app":                {column: "app", kind: kindText, valid: anyText},
	"env":                {column: "env", kind: kindText, valid: anyText},
	"user":               {column: "user_alias", kind: kindText, valid: anyText},
	"provider":           {column: "provider", kind: kindText, valid: anyText},
	"model":              {column: "model", kind: kindText, valid: anyText},
	"source":             {column: "source", kind: kindText, valid: anyText},
	"policy_mode":        {column: "policy_mode", kind: kindText, valid: oneOf(ModeMonitor, ModeEnforce)},
	"action":             {column: "action", kind: kindText, valid: anyText},
	"rule":               {column: "rule", kind: kindText, valid: anyText},
	"severity":           {column: "severity", kind: kindText, valid: anyText},
	"storage":            {column: "storage", kind: kindText, valid: oneOf(StorageNone, StorageMasked, StorageFull)},
	"gateway":            {column: "gateway_id", kind: kindUUID, valid: uuidValue},
	"threat":             {column: "threats", kind: kindThreats, valid: threatValueRe.MatchString},
	"detector":           {column: "details", kind: kindFinding, valid: detectorValueRe.MatchString, key: "detector"},
	"stream":             {column: "stream", kind: kindBool, valid: oneOf("true", "false")},
	"non_text_unchecked": {column: "non_text_unchecked", kind: kindBool, valid: oneOf("true", "false")},
	"has_content":        {column: "has_content", kind: kindBool, valid: oneOf("true", "false")},
	// Задача 4.19 этапа 4: ML-детекторы политики не дали результата
	// (aisec-ml недоступен, ADR-0024) — признак решения в details.
	"ml_unavailable": {column: "details", kind: kindBool, valid: oneOf("true", "false"),
		expr: "COALESCE((e.details->'decision'->>'ml_unavailable')::boolean, false)"},
	// Задача 3.22: exception — находки, пропущенные по исключению с этим ID;
	// mark — отметка аналитика (false_positive, confirmed, none — нет отметки).
	"exception": {column: "details", kind: kindFinding, valid: exceptionRe.MatchString, key: "exception"},
	"mark":      {column: "id", kind: kindMark, valid: oneOf(MarkFalsePositive, MarkConfirmed, MarkNone)},
	// Задача 4.13 этапа 4: события одной сессии (псевдоним из карточки события).
	"session": {column: "details", kind: kindSession, valid: sessionIDRe.MatchString},
	// Задача 4.11 этапа 4: события агентов по агенту, MCP-серверу и
	// инструменту (хронология сессии агента, правило agents.tool_blocked).
	"agent":      {column: "details", kind: kindAgent, valid: agentSlugRe.MatchString, key: "agent"},
	"mcp_server": {column: "details", kind: kindAgent, valid: agentSlugRe.MatchString, key: "server"},
	"tool":       {column: "details", kind: kindAgent, valid: toolNameRe.MatchString, key: "tool"},
}

// FilterFields — имена полей фильтра по алфавиту (документация, подсказки).
func FilterFields() []string {
	out := make([]string, 0, len(filterFields))
	for k := range filterFields {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// FilterError — ошибка разбора фильтра. Pos — смещение в байтах, где
// обнаружена ошибка; текст — для пользователя, без повторения его ввода.
type FilterError struct {
	Pos int
	Msg string
}

func (e *FilterError) Error() string {
	return fmt.Sprintf("фильтр, позиция %d: %s", e.Pos, e.Msg)
}

// ErrFilterTooLong — строка фильтра длиннее MaxFilterLen.
var ErrFilterTooLong = errors.New("фильтр длиннее " + strconv.Itoa(MaxFilterLen) + " байт")

// Виды лексем.
type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokEq
	tokNe
	tokLParen
	tokRParen
	tokComma
)

type token struct {
	kind tokKind
	text string
	pos  int
}

type lexer struct {
	s   string
	pos int
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (l *lexer) next() (token, error) {
	for l.pos < len(l.s) && isSpace(l.s[l.pos]) {
		l.pos++
	}
	start := l.pos
	if l.pos >= len(l.s) {
		return token{kind: tokEOF, pos: start}, nil
	}
	switch c := l.s[l.pos]; {
	case c == '=':
		l.pos++
		return token{kind: tokEq, pos: start}, nil
	case c == '!':
		if l.pos+1 < len(l.s) && l.s[l.pos+1] == '=' {
			l.pos += 2
			return token{kind: tokNe, pos: start}, nil
		}
		return token{}, &FilterError{start, "ожидалось «!=»"}
	case c == '(':
		l.pos++
		return token{kind: tokLParen, pos: start}, nil
	case c == ')':
		l.pos++
		return token{kind: tokRParen, pos: start}, nil
	case c == ',':
		l.pos++
		return token{kind: tokComma, pos: start}, nil
	case c == '"':
		return l.str()
	case c >= 'a' && c <= 'z' || c == '_':
		for l.pos < len(l.s) && (l.s[l.pos] >= 'a' && l.s[l.pos] <= 'z' || l.s[l.pos] == '_') {
			l.pos++
		}
		return token{kind: tokIdent, text: l.s[start:l.pos], pos: start}, nil
	}
	return token{}, &FilterError{start, "недопустимый символ"}
}

// str читает строку в кавычках: экранируются только \" и \\, управляющие
// символы и неверный UTF-8 не допускаются.
func (l *lexer) str() (token, error) {
	start := l.pos
	l.pos++ // открывающая кавычка
	var b strings.Builder
	for {
		if l.pos >= len(l.s) {
			return token{}, &FilterError{start, "не закрыта кавычка"}
		}
		c := l.s[l.pos]
		switch {
		case c == '"':
			l.pos++
			return token{kind: tokString, text: b.String(), pos: start}, nil
		case c == '\\':
			if l.pos+1 >= len(l.s) || (l.s[l.pos+1] != '"' && l.s[l.pos+1] != '\\') {
				return token{}, &FilterError{l.pos, "в строке экранируются только \\\" и \\\\"}
			}
			b.WriteByte(l.s[l.pos+1])
			l.pos += 2
		case c < 0x20 || c == 0x7f:
			return token{}, &FilterError{l.pos, "управляющий символ в строке"}
		default:
			r, size := utf8.DecodeRuneInString(l.s[l.pos:])
			if r == utf8.RuneError && size <= 1 {
				return token{}, &FilterError{l.pos, "неверная кодировка UTF-8"}
			}
			b.WriteString(l.s[l.pos : l.pos+size])
			l.pos += size
		}
		if b.Len() > MaxFilterValue {
			return token{}, &FilterError{start, "значение длиннее " + strconv.Itoa(MaxFilterValue) + " байт"}
		}
	}
}

type parser struct {
	lx  lexer
	tok token
}

func (p *parser) advance() error {
	t, err := p.lx.next()
	if err != nil {
		return err
	}
	p.tok = t
	return nil
}

func (p *parser) keyword(kw string) bool { return p.tok.kind == tokIdent && p.tok.text == kw }

// ParseFilter разбирает фильтр. Пустая строка (или только пробелы) — пустой
// фильтр. Ошибка — *FilterError или ErrFilterTooLong.
func ParseFilter(s string) (Filter, error) {
	if len(s) > MaxFilterLen {
		return Filter{}, ErrFilterTooLong
	}
	p := &parser{lx: lexer{s: s}}
	if err := p.advance(); err != nil {
		return Filter{}, err
	}
	var f Filter
	if p.tok.kind == tokEOF {
		return f, nil
	}
	for {
		c, err := p.cond()
		if err != nil {
			return Filter{}, err
		}
		if len(f.Conds) == MaxFilterConds {
			return Filter{}, &FilterError{p.tok.pos, "больше " + strconv.Itoa(MaxFilterConds) + " условий"}
		}
		f.Conds = append(f.Conds, c)
		if p.tok.kind == tokEOF {
			return f, nil
		}
		if !p.keyword("and") {
			return Filter{}, &FilterError{p.tok.pos, "ожидалось «and» или конец фильтра"}
		}
		if err := p.advance(); err != nil {
			return Filter{}, err
		}
	}
}

func (p *parser) cond() (Cond, error) {
	if p.tok.kind != tokIdent {
		return Cond{}, &FilterError{p.tok.pos, "ожидалось имя поля"}
	}
	name, pos := p.tok.text, p.tok.pos
	def, ok := filterFields[name]
	if !ok {
		return Cond{}, &FilterError{pos, "неизвестное поле"}
	}
	if err := p.advance(); err != nil {
		return Cond{}, err
	}
	c := Cond{Field: name}
	opPos := p.tok.pos
	switch {
	case p.tok.kind == tokEq:
		c.Op = OpEq
	case p.tok.kind == tokNe:
		c.Op = OpNe
	case p.keyword("in"):
		c.Op = OpIn
	case p.keyword("not"):
		if err := p.advance(); err != nil {
			return Cond{}, err
		}
		if !p.keyword("in") {
			return Cond{}, &FilterError{p.tok.pos, "ожидалось «in» после «not»"}
		}
		c.Op = OpNotIn
	default:
		return Cond{}, &FilterError{opPos, "ожидался оператор: =, !=, in или not in"}
	}
	if def.kind == kindBool && c.Op != OpEq {
		return Cond{}, &FilterError{opPos, "у логического поля допустим только оператор ="}
	}
	if err := p.advance(); err != nil {
		return Cond{}, err
	}
	if c.Op == OpEq || c.Op == OpNe {
		v, err := p.value(def)
		if err != nil {
			return Cond{}, err
		}
		c.Values = []string{v}
		return c, nil
	}
	if p.tok.kind != tokLParen {
		return Cond{}, &FilterError{p.tok.pos, "ожидалась «(»"}
	}
	if err := p.advance(); err != nil {
		return Cond{}, err
	}
	for {
		vpos := p.tok.pos
		v, err := p.value(def)
		if err != nil {
			return Cond{}, err
		}
		if !slices.Contains(c.Values, v) {
			if len(c.Values) == MaxFilterValues {
				return Cond{}, &FilterError{vpos, "больше " + strconv.Itoa(MaxFilterValues) + " значений в списке"}
			}
			c.Values = append(c.Values, v)
		}
		if p.tok.kind == tokRParen {
			break
		}
		if p.tok.kind != tokComma {
			return Cond{}, &FilterError{p.tok.pos, "ожидалась «,» или «)»"}
		}
		if err := p.advance(); err != nil {
			return Cond{}, err
		}
	}
	if err := p.advance(); err != nil {
		return Cond{}, err
	}
	// Одно значение в списке — каноническая запись через = и !=.
	if len(c.Values) == 1 {
		c.Op = map[string]string{OpIn: OpEq, OpNotIn: OpNe}[c.Op]
	}
	return c, nil
}

func (p *parser) value(def fieldDef) (string, error) {
	pos := p.tok.pos
	var v string
	switch {
	case def.kind == kindBool && (p.keyword("true") || p.keyword("false")):
		v = p.tok.text
	case def.kind != kindBool && p.tok.kind == tokString:
		v = p.tok.text
	case def.kind == kindBool:
		return "", &FilterError{pos, "ожидалось true или false"}
	default:
		return "", &FilterError{pos, "ожидалось значение в двойных кавычках"}
	}
	if v == "" && def.kind != kindBool {
		return "", &FilterError{pos, "пустое значение"}
	}
	if !def.valid(v) {
		return "", &FilterError{pos, "недопустимое значение для этого поля"}
	}
	if err := p.advance(); err != nil {
		return "", err
	}
	return v, nil
}

// String — каноническая запись фильтра: ParseFilter(f.String()) даёт тот же
// фильтр. В таком виде фильтр сохраняется и пишется в журнал аудита.
func (f Filter) String() string {
	var b strings.Builder
	for i, c := range f.Conds {
		if i > 0 {
			b.WriteString(" and ")
		}
		b.WriteString(c.Field)
		b.WriteByte(' ')
		b.WriteString(c.Op)
		b.WriteByte(' ')
		def := filterFields[c.Field]
		if c.Op == OpIn || c.Op == OpNotIn {
			b.WriteByte('(')
		}
		for j, v := range c.Values {
			if j > 0 {
				b.WriteString(", ")
			}
			if def.kind == kindBool {
				b.WriteString(v)
				continue
			}
			b.WriteByte('"')
			b.WriteString(strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v))
			b.WriteByte('"')
		}
		if c.Op == OpIn || c.Op == OpNotIn {
			b.WriteByte(')')
		}
	}
	return b.String()
}

// sqlArgs — параметры запроса: add возвращает ссылку $N на значение.
type sqlArgs struct {
	args []any
}

func (a *sqlArgs) add(v any) string {
	a.args = append(a.args, v)
	return "$" + strconv.Itoa(len(a.args))
}

// appendSQL дописывает к b условия фильтра через « AND »: каждый фрагмент
// составлен из констант кода (имена столбцов из filterFields), значения —
// только параметрами a.
func (f Filter) appendSQL(b *strings.Builder, a *sqlArgs) {
	for _, c := range f.Conds {
		def := filterFields[c.Field]
		negate := c.Op == OpNe || c.Op == OpNotIn
		b.WriteString(" AND ")
		col := "e." + def.column
		if def.expr != "" {
			col = def.expr
		}
		switch def.kind {
		case kindBool:
			b.WriteString(col + " = " + a.add(c.Values[0] == "true"))
		case kindText, kindUUID:
			cast := "::text[]"
			if def.kind == kindUUID {
				cast = "::uuid[]"
			}
			ref := a.add(c.Values) + cast
			if negate {
				// NULL у необязательного поля тоже «не равно».
				b.WriteString("(" + col + " IS NULL OR " + col + " <> ALL(" + ref + "))")
			} else {
				b.WriteString(col + " = ANY(" + ref + ")")
			}
		case kindThreats:
			ref := a.add(c.Values) + "::text[]"
			if negate {
				b.WriteString("NOT (" + col + " && " + ref + ")")
			} else {
				b.WriteString(col + " && " + ref)
			}
		case kindFinding:
			ref := a.add(c.Values) + "::text[]"
			if negate {
				b.WriteString("NOT ")
			}
			b.WriteString("EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(" + col +
				"->'findings', '[]'::jsonb)) AS f WHERE f->>'" + def.key + "' = ANY(" + ref + "))")
		case kindSession:
			ref := a.add(c.Values) + "::text[]"
			sid := "COALESCE(" + col + "->'session'->>'id', " + col + "->'agent'->>'session')"
			if negate {
				b.WriteString("(" + sid + " IS NULL OR " + sid + " <> ALL(" + ref + "))")
			} else {
				b.WriteString(sid + " = ANY(" + ref + ")")
			}
		case kindAgent:
			ref := a.add(c.Values) + "::text[]"
			v := "(" + col + "->'agent'->>'" + def.key + "')"
			if negate {
				b.WriteString("(" + v + " IS NULL OR " + v + " <> ALL(" + ref + "))")
			} else {
				b.WriteString(v + " = ANY(" + ref + ")")
			}
		case kindMark:
			// «none» — нет отметки: значение отметки события, либо none.
			ref := a.add(c.Values) + "::text[]"
			if negate {
				b.WriteString("NOT ")
			}
			b.WriteString("(COALESCE((SELECT em.mark FROM event_marks em WHERE em.event_id = e.id AND em.event_ts = e.ts" +
				" AND em.org_id = e.org_id), '" + MarkNone + "') = ANY(" + ref + "))")
		}
	}
}

// Match — проверка фильтра на записи без PostgreSQL (хранилище Memory). Те
// же правила, что у SQL: «!=» и «not in» пропускают отсутствующее значение.
func (f Filter) Match(r *Record) bool {
	for _, c := range f.Conds {
		have := r.filterValues(c.Field)
		hit := false
		for _, v := range have {
			if slices.Contains(c.Values, v) {
				hit = true
				break
			}
		}
		if hit == (c.Op == OpNe || c.Op == OpNotIn) {
			return false
		}
	}
	return true
}

// filterValues — значения поля записи для Match; пустой срез — значения нет.
func (r *Record) filterValues(field string) []string {
	one := func(s string) []string {
		if s == "" {
			return nil
		}
		return []string{s}
	}
	switch field {
	case "type":
		return one(r.Type)
	case "app":
		return one(r.App)
	case "env":
		return one(r.Env)
	case "user":
		return one(r.User)
	case "provider":
		return one(r.Provider)
	case "model":
		return one(r.Model)
	case "source":
		return one(r.Source)
	case "policy_mode":
		return one(r.PolicyMode)
	case "action":
		return one(r.Action)
	case "rule":
		return one(r.Rule)
	case "severity":
		return one(r.Severity)
	case "storage":
		return one(r.Storage)
	case "gateway":
		return one(r.GatewayID)
	case "threat":
		return r.Threats
	case "detector":
		var out []string
		if r.Details != nil {
			for _, fd := range r.Details.Findings {
				out = append(out, fd.Detector)
			}
		}
		return out
	case "exception":
		var out []string
		if r.Details != nil {
			for _, fd := range r.Details.Findings {
				if fd.Exception != "" {
					out = append(out, fd.Exception)
				}
			}
		}
		return out
	case "session":
		if r.Details != nil && r.Details.Session != nil {
			return one(r.Details.Session.ID)
		}
		if r.Details != nil && r.Details.Agent != nil && r.Details.Agent.Session != "" {
			return one(r.Details.Agent.Session)
		}
		return nil
	case "agent", "mcp_server", "tool":
		if r.Details == nil || r.Details.Agent == nil {
			return nil
		}
		v := map[string]string{"agent": r.Details.Agent.Agent, "mcp_server": r.Details.Agent.Server, "tool": r.Details.Agent.Tool}[field]
		if v == "" {
			return nil
		}
		return one(v)
	case "mark":
		if r.Mark == nil {
			return []string{MarkNone}
		}
		return []string{r.Mark.Mark}
	case "stream":
		return []string{strconv.FormatBool(r.Stream)}
	case "non_text_unchecked":
		return []string{strconv.FormatBool(r.NonTextUnchecked)}
	case "has_content":
		return []string{strconv.FormatBool(r.HasContent)}
	case "ml_unavailable":
		return []string{strconv.FormatBool(r.Details != nil && r.Details.Decision != nil && r.Details.Decision.MLUnavailable)}
	}
	return nil
}
