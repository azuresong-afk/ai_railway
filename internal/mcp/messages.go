package mcp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
	"github.com/azuresong-afk/ai_railway/internal/policy/tooldesc"
)

// Методы клиента, которые пропускает прокси (ADR-0023, раздел 6).
// Остальные — -32601 от шлюза: completion/complete, logging/setLevel,
// tasks/*, ответы клиента на запросы сервера и прочее.
var (
	commonMethods = []string{"tools/list", "tools/call", "resources/list", "resources/templates/list", "resources/read",
		"prompts/list", "prompts/get"}
	methods20260728 = []string{"server/discover", "subscriptions/listen"}
	methods20251125 = []string{"initialize", "notifications/initialized", "ping", "notifications/cancelled"}
)

// MethodAllowed — метод клиента разрешён в ревизии version.
func MethodAllowed(method, version string) bool {
	if slices.Contains(commonMethods, method) {
		return true
	}
	switch version {
	case Version20260728:
		return slices.Contains(methods20260728, method)
	case Version20251125:
		return slices.Contains(methods20251125, method)
	}
	return false
}

// Пределы результатов (ADR-0023, раздел 6).
const (
	// MaxListItems — элементов на странице tools/list, resources/list,
	// prompts/list.
	MaxListItems = 256
	// MaxContentBlocks — блоков content в результате.
	MaxContentBlocks = 1024
	// MaxListTTL — ttlMs в ответе tools/list: отзыв одобрения доходит до
	// клиента не позже чем через минуту.
	MaxListTTL = 60000
)

// Text — строка результата или описания для детекторов: путь в документе
// и ссылка на значение (замена Ref.Str меняет документ — маскирование).
type Text struct {
	Path string
	Ref  *argschema.Value
}

// ListKey — поле со списком в результате метода списка; пусто — не список.
func ListKey(method string) string {
	switch method {
	case "tools/list":
		return "tools"
	case "resources/list":
		return "resources"
	case "resources/templates/list":
		return "resourceTemplates"
	case "prompts/list":
		return "prompts"
	}
	return ""
}

// Item — элемент списка: инструмент, ресурс, шаблон или промпт.
type Item struct {
	Value *argschema.Value
	// Text — строки описания через перевод строки: для встроенной проверки
	// описаний (DM-24) разбитая по полям инъекция видна целиком.
	Text string
	// Tool — разобранное описание инструмента (только tools/list); Raw —
	// его запись для tools:observe; Headers — аннотации x-mcp-header.
	Tool    tooldesc.Descriptor
	Raw     []byte
	Headers []ParamHeader
}

// List — результат метода списка.
type List struct {
	Key    string
	Result argschema.Value
	Items  []Item
	// Invalid — элементы, исключённые разбором: неверное описание
	// инструмента, повтор имени, неверный x-mcp-header, больше предела.
	Invalid int
}

// ParseList разбирает результат метода списка (копию result). Для
// tools/list каждое описание — до tooldesc.MaxSize байт, разбирается
// tooldesc.Parse (имя, пределы), повтор имени и неверные x-mcp-header
// исключают инструмент. Больше MaxListItems элементов — ошибка.
func ParseList(method string, result *argschema.Value) (*List, error) {
	key := ListKey(method)
	if key == "" {
		return nil, errors.New("не метод списка")
	}
	l := &List{Key: key, Result: Clone(*result)}
	arr, ok := l.Result.Get(key)
	if !ok {
		return nil, &ProtocolError{Code: CodeInternalError, Msg: "в результате нет поля " + key}
	}
	if arr.Kind != argschema.Array || len(arr.Arr) > MaxListItems {
		return nil, &ProtocolError{Code: CodeInternalError, Msg: fmt.Sprintf("%s — массив до %d элементов", key, MaxListItems)}
	}
	if c, ok := l.Result.Get("nextCursor"); ok && c.Kind != argschema.String {
		return nil, &ProtocolError{Code: CodeInternalError, Msg: "nextCursor — строка"}
	}
	if rt, ok := l.Result.Get("resultType"); ok && (rt.Kind != argschema.String || rt.Str != "complete") {
		return nil, &ProtocolError{Code: CodeInternalError, Msg: "resultType списка — complete"}
	}
	names := map[string]bool{}
	for i := range arr.Arr {
		v := &arr.Arr[i]
		if v.Kind != argschema.Object {
			l.Invalid++
			continue
		}
		it := Item{Value: v, Text: DescriptionText(v)}
		if key == "tools" {
			it.Raw = AppendJSON(nil, *v)
			if len(it.Raw) > tooldesc.MaxSize {
				l.Invalid++
				continue
			}
			d, err := tooldesc.Parse(it.Raw)
			if err != nil || names[d.Name] {
				l.Invalid++
				continue
			}
			schema, _ := GetObject(v, "inputSchema")
			hs, err := ParamHeaders(schema)
			if err != nil {
				l.Invalid++
				continue
			}
			names[d.Name] = true
			it.Tool, it.Headers = d, hs
		}
		l.Items = append(l.Items, it)
	}
	return l, nil
}

// listKeys — поля верхнего уровня результата списка по ревизиям
// (PaginatedResult; в 2026-07-28 ещё resultType, ttlMs и cacheScope), кроме
// самого списка; остальные, и _meta, шлюз клиенту не передаёт (ревью 4.r4,
// задача 5.10 этапа 5).
var listKeys = map[string][]string{
	Version20251125: {"nextCursor"},
	Version20260728: {"nextCursor", "resultType", "ttlMs", "cacheScope"},
}

// Rebuild собирает результат списка из элементов keep (по номерам Items):
// у каждого убираются icons и _meta (модель их не видит, внешние ссылки
// консоль не загружает). Поля верхнего уровня — только listKeys ревизии.
// Для ревизии 2026-07-28 ставятся cacheScope "private" и ttlMs не больше
// MaxListTTL: список зависит от агента, отзыв одобрения должен дойти до
// клиента за минуту. nextCursor — без изменений.
func (l *List) Rebuild(keep func(i int) bool, version string) argschema.Value {
	out := Clone(l.Result)
	Keep(&out, append([]string{l.Key}, listKeys[version]...)...)
	items := Array()
	items.Arr = []argschema.Value{}
	for i, it := range l.Items {
		if keep != nil && !keep(i) {
			continue
		}
		v := Clone(*it.Value)
		Delete(&v, "icons")
		Delete(&v, "_meta")
		items.Arr = append(items.Arr, v)
	}
	Set(&out, l.Key, items)
	if version == Version20260728 {
		ttl := int64(MaxListTTL)
		if t, ok := out.Get("ttlMs"); ok && t.Kind == argschema.Number && t.Num.IsInt() && t.Num.Num().IsInt64() {
			ttl = min(max(t.Num.Num().Int64(), 0), ttl)
		}
		Set(&out, "ttlMs", Int(ttl))
		Set(&out, "cacheScope", String("private"))
	}
	return out
}

// DescriptionText — строки описания элемента через перевод строки: все
// строковые значения и все имена ключей объектов на любой глубине, кроме
// name, icons и _meta верхнего уровня. Имя проверяется правилами имени, а
// не детекторами. Ключи пишутся все, а не только у properties: клиент
// получает схему целиком, и инструкция в ключе $defs, patternProperties
// или неизвестного поля доходит до модели (ревью 4.r1, 4В7).
func DescriptionText(v *argschema.Value) string {
	var b strings.Builder
	line := func(s string) {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s)
	}
	var walk func(v *argschema.Value, top bool)
	walk = func(v *argschema.Value, top bool) {
		switch v.Kind {
		case argschema.String:
			line(v.Str)
		case argschema.Array:
			for i := range v.Arr {
				walk(&v.Arr[i], false)
			}
		case argschema.Object:
			for i, k := range v.Keys {
				if top && (k == "name" || k == "icons" || k == "_meta") {
					continue
				}
				line(k)
				walk(&v.Vals[i], false)
			}
		}
	}
	walk(v, true)
	return b.String()
}

// CallParams — параметры tools/call (и prompts/get: name и arguments).
type CallParams struct {
	Name string
	// Args — аргументы (объект; нет — пустой объект).
	Args argschema.Value
	// ProgressToken — _meta.progressToken клиента; nil — нет.
	ProgressToken *argschema.Value
}

// ParseCallParams — name (строка) и arguments (объект). inputResponses и
// requestState (ответ на input_required, 2026-07-28) — отказ: результаты
// input_required шлюз клиенту не передаёт.
func ParseCallParams(params *argschema.Value) (*CallParams, error) {
	bad := func(msg string) error { return &ProtocolError{Code: CodeInvalidParams, Msg: msg} }
	if params == nil {
		return nil, bad("нет params")
	}
	name, ok := GetString(params, "name")
	if !ok || name == "" || len(name) > 1024 {
		return nil, bad("params.name — непустая строка")
	}
	for _, k := range []string{"inputResponses", "requestState"} {
		if _, ok := params.Get(k); ok {
			return nil, bad("params." + k + " не поддерживается шлюзом: запросы сервера к клиенту не передаются")
		}
	}
	cp := &CallParams{Name: name, Args: Object()}
	if a, ok := params.Get("arguments"); ok {
		if a.Kind != argschema.Object {
			return nil, bad("params.arguments — объект")
		}
		cp.Args = *a
	}
	if meta, ok := GetObject(params, "_meta"); ok {
		if t, ok := meta.Get(MetaProgressToken); ok && ValidProgressToken(t) {
			cp.ProgressToken = t
		}
	}
	return cp, nil
}

// ValidProgressToken — progressToken по спецификации (ProgressToken —
// строка или число; шлюз, как для id запроса, принимает строку до
// MaxIDLen байт или целое без дробной части и экспоненты): токен уходит
// вышестоящему серверу и возвращается клиенту в уведомлениях о ходе.
func ValidProgressToken(t *argschema.Value) bool { return t != nil && checkID(*t, false) == nil }

// CheckMeta проверяет params._meta запроса клиента: объект; progressToken —
// ValidProgressToken. Иначе — ошибка CodeInvalidParams: в UpstreamParams
// поле уходит серверу как есть (ревью 4.r4, задача 5.10 этапа 5).
func CheckMeta(params *argschema.Value) error {
	if params == nil {
		return nil
	}
	meta, ok := params.Get("_meta")
	if !ok {
		return nil
	}
	if meta.Kind != argschema.Object {
		return &ProtocolError{Code: CodeInvalidParams, Msg: "params._meta — объект"}
	}
	if t, ok := meta.Get(MetaProgressToken); ok && !ValidProgressToken(t) {
		return &ProtocolError{Code: CodeInvalidParams, Msg: fmt.Sprintf("params._meta.progressToken — строка до %d байт или целое", MaxIDLen)}
	}
	return nil
}

// handshakeKeys — поля верхнего уровня результата initialize (2025-11-25)
// и server/discover (2026-07-28) по спецификации.
var handshakeKeys = map[string][]string{
	"initialize":      {"protocolVersion", "capabilities", "serverInfo", "instructions"},
	"server/discover": {"resultType", "supportedVersions", "capabilities", "serverInfo", "instructions"},
}

// HandshakeResult оставляет в результате initialize или server/discover
// (копии) только поля спецификации: остальные, и _meta, клиенту не уходят
// — их не видела проверка описаний (ревью 4.r4, задача 5.10 этапа 5).
// Типы: protocolVersion и instructions — строки, capabilities и serverInfo
// — объекты, supportedVersions — массив строк, resultType — complete.
// Неверный тип — ошибка: instructions другого типа обошли бы проверку.
func HandshakeResult(method string, result *argschema.Value) error {
	keys, ok := handshakeKeys[method]
	if !ok {
		return errors.New("не метод установления соединения")
	}
	Keep(result, keys...)
	bad := func(msg string) error { return &ProtocolError{Code: CodeInternalError, Msg: msg} }
	for _, k := range []string{"protocolVersion", "instructions"} {
		if v, ok := result.Get(k); ok && v.Kind != argschema.String {
			return bad(k + " — строка")
		}
	}
	for _, k := range []string{"capabilities", "serverInfo"} {
		if v, ok := result.Get(k); ok && v.Kind != argschema.Object {
			return bad(k + " — объект")
		}
	}
	if v, ok := result.Get("supportedVersions"); ok {
		if v.Kind != argschema.Array || len(v.Arr) > MaxListItems {
			return bad("supportedVersions — массив строк")
		}
		for i := range v.Arr {
			if v.Arr[i].Kind != argschema.String {
				return bad("supportedVersions — массив строк")
			}
		}
	}
	if rt, ok := result.Get("resultType"); ok && (rt.Kind != argschema.String || rt.Str != "complete") {
		return bad("resultType — complete")
	}
	return nil
}

// Поля params, которые шлюз передаёт вышестоящему серверу, по методам;
// остальные (task, inputResponses, неизвестные) отбрасываются.
var paramKeys = map[string][]string{
	"tools/list":                {"cursor", "_meta"},
	"tools/call":                {"name", "arguments", "_meta"},
	"resources/list":            {"cursor", "_meta"},
	"resources/templates/list":  {"cursor", "_meta"},
	"resources/read":            {"uri", "_meta"},
	"prompts/list":              {"cursor", "_meta"},
	"prompts/get":               {"name", "arguments", "_meta"},
	"server/discover":           {"_meta"},
	"subscriptions/listen":      {"notifications", "_meta"},
	"initialize":                {"protocolVersion", "capabilities", "clientInfo", "_meta"},
	"notifications/initialized": {"_meta"},
	"ping":                      {"_meta"},
	"notifications/cancelled":   {"requestId", "reason"},
}

// metaKeys — поля _meta запроса, которые уходят серверу.
var metaKeys = []string{MetaProtocolVersion, MetaClientInfo, MetaClientCapabilities, MetaProgressToken}

// StrippedCapabilities — возможности клиента, которые шлюз вырезает
// (ADR-0023, раздел 6): каждой нужны свои проверки содержимого.
var StrippedCapabilities = []string{"sampling", "elicitation", "roots", "tasks", "extensions"}

// UpstreamParams — params для вышестоящего сервера, собранные из
// проверенного документа: только известные поля метода, в _meta — версия,
// сведения о клиенте, возможности и progressToken; из возможностей клиента
// (initialize.capabilities и _meta clientCapabilities) вырезаются
// StrippedCapabilities. Возвращает и имена вырезанных возможностей.
func UpstreamParams(method string, params *argschema.Value) (*argschema.Value, []string) {
	if params == nil {
		return nil, nil
	}
	out := Clone(*params)
	Keep(&out, paramKeys[method]...)
	var stripped []string
	if caps, ok := out.Get("capabilities"); ok && method == "initialize" && caps.Kind == argschema.Object {
		stripped = append(stripped, stripCaps(caps)...)
	}
	if meta, ok := out.Get("_meta"); ok {
		if meta.Kind != argschema.Object {
			Delete(&out, "_meta")
		} else {
			Keep(meta, metaKeys...)
			if caps, ok := meta.Get(MetaClientCapabilities); ok && caps.Kind == argschema.Object {
				stripped = append(stripped, stripCaps(caps)...)
			}
		}
	}
	slices.Sort(stripped)
	return &out, slices.Compact(stripped)
}

func stripCaps(caps *argschema.Value) []string {
	var out []string
	for _, c := range StrippedCapabilities {
		if Delete(caps, c) {
			out = append(out, c)
		}
	}
	return out
}

// ContentResult — строки и не текстовые части результата tools/call,
// resources/read или prompts/get для детекторов (DM-07).
type ContentResult struct {
	Result argschema.Value
	Texts  []Text
	// Media — не текстовые части: image, audio, blob (виды по порядку).
	Media []string
	// Links — блоки resource_link (URI — в Texts).
	Links   int
	IsError bool
}

// ErrInputRequired — результат input_required (2026-07-28, MRTR): запрос
// сервера к клиенту, шлюз его не передаёт.
var ErrInputRequired = errors.New("результат input_required: запросы сервера к клиенту шлюз не передаёт")

// ParseContentResult разбирает результат метода с содержимым (копию
// result). resultType, кроме complete, — ErrInputRequired или ошибка;
// неизвестный тип блока content — ошибка: такой результат не проверить.
// В результате остаются только поля спецификации (на уровне результата,
// блоков, ресурсов и сообщений): клиенту не уходит ничего, что не видели
// детекторы. Ключи объектов structuredContent детекторам не передаются.
func ParseContentResult(method string, result *argschema.Value) (*ContentResult, error) {
	cr := &ContentResult{Result: Clone(*result)}
	r := &cr.Result
	if rt, ok := r.Get("resultType"); ok {
		switch {
		case rt.Kind == argschema.String && rt.Str == "complete":
		case rt.Kind == argschema.String && rt.Str == "input_required":
			return nil, ErrInputRequired
		default:
			return nil, &ProtocolError{Code: CodeInternalError, Msg: "неизвестный resultType"}
		}
	}
	if _, ok := r.Get("inputRequests"); ok {
		return nil, ErrInputRequired
	}
	Delete(r, "_meta")
	switch method {
	case "tools/call":
		Keep(r, "resultType", "content", "structuredContent", "isError")
		if e, ok := r.Get("isError"); ok {
			if e.Kind != argschema.Bool {
				return nil, &ProtocolError{Code: CodeInternalError, Msg: "isError — логическое"}
			}
			cr.IsError = e.Bool
		}
		if c, ok := r.Get("content"); ok {
			if c.Kind != argschema.Array || len(c.Arr) > MaxContentBlocks {
				return nil, &ProtocolError{Code: CodeInternalError, Msg: "content — массив блоков"}
			}
			for i := range c.Arr {
				if err := cr.block(&c.Arr[i], "content["+strconv.Itoa(i)+"]"); err != nil {
					return nil, err
				}
			}
		}
		if s, ok := r.Get("structuredContent"); ok {
			cr.collect(s, "structuredContent")
		}
	case "resources/read":
		Keep(r, "resultType", "contents")
		c, ok := r.Get("contents")
		if !ok || c.Kind != argschema.Array || len(c.Arr) > MaxContentBlocks {
			return nil, &ProtocolError{Code: CodeInternalError, Msg: "contents — массив"}
		}
		for i := range c.Arr {
			if err := cr.resource(&c.Arr[i], "contents["+strconv.Itoa(i)+"]"); err != nil {
				return nil, err
			}
		}
	case "prompts/get":
		Keep(r, "resultType", "description", "messages")
		if d, ok := r.Get("description"); ok && d.Kind == argschema.String {
			cr.Texts = append(cr.Texts, Text{Path: "description", Ref: d})
		}
		msgs, ok := r.Get("messages")
		if !ok || msgs.Kind != argschema.Array || len(msgs.Arr) > MaxContentBlocks {
			return nil, &ProtocolError{Code: CodeInternalError, Msg: "messages — массив"}
		}
		for i := range msgs.Arr {
			at := "messages[" + strconv.Itoa(i) + "].content"
			if msgs.Arr[i].Kind != argschema.Object {
				return nil, &ProtocolError{Code: CodeInternalError, Msg: "messages[" + strconv.Itoa(i) + "] — объект"}
			}
			Keep(&msgs.Arr[i], "role", "content")
			if role, _ := GetString(&msgs.Arr[i], "role"); role != "user" && role != "assistant" {
				return nil, &ProtocolError{Code: CodeInternalError, Msg: "messages[" + strconv.Itoa(i) + "].role — user или assistant"}
			}
			c, ok := GetObject(&msgs.Arr[i], "content")
			if !ok {
				return nil, &ProtocolError{Code: CodeInternalError, Msg: at + " — объект"}
			}
			if err := cr.block(c, at); err != nil {
				return nil, err
			}
		}
	default:
		return nil, errors.New("метод без содержимого")
	}
	return cr, nil
}

// block — блок содержимого: text, image, audio, resource_link, resource.
func (cr *ContentResult) block(b *argschema.Value, at string) error {
	typ, ok := GetString(b, "type")
	if b.Kind != argschema.Object || !ok {
		return &ProtocolError{Code: CodeInternalError, Msg: at + ": блок без type"}
	}
	switch typ {
	case "text":
		Keep(b, "type", "text")
		t, ok := b.Get("text")
		if !ok || t.Kind != argschema.String {
			return &ProtocolError{Code: CodeInternalError, Msg: at + ".text — строка"}
		}
		cr.Texts = append(cr.Texts, Text{Path: at + ".text", Ref: t})
	case "image", "audio":
		Keep(b, "type", "data", "mimeType")
		cr.Media = append(cr.Media, typ)
		cr.strings(b, at, "mimeType")
	case "resource_link":
		Keep(b, "type", "uri", "name", "title", "description", "mimeType", "size")
		cr.Links++
		cr.strings(b, at, "uri", "name", "title", "description", "mimeType")
	case "resource":
		Keep(b, "type", "resource")
		res, ok := GetObject(b, "resource")
		if !ok {
			return &ProtocolError{Code: CodeInternalError, Msg: at + ".resource — объект"}
		}
		return cr.resource(res, at+".resource")
	default:
		return &ProtocolError{Code: CodeInternalError, Msg: at + ": неизвестный тип блока"}
	}
	return nil
}

// resource — содержимое ресурса: text или blob.
func (cr *ContentResult) resource(res *argschema.Value, at string) error {
	if res.Kind != argschema.Object {
		return &ProtocolError{Code: CodeInternalError, Msg: at + " — объект"}
	}
	Keep(res, "uri", "mimeType", "text", "blob")
	cr.strings(res, at, "uri", "mimeType")
	t, hasText := res.Get("text")
	_, hasBlob := res.Get("blob")
	switch {
	case hasText && t.Kind == argschema.String && !hasBlob:
		cr.Texts = append(cr.Texts, Text{Path: at + ".text", Ref: t})
	case hasBlob && !hasText:
		cr.Media = append(cr.Media, "blob")
	default:
		return &ProtocolError{Code: CodeInternalError, Msg: at + ": ровно одно из text и blob"}
	}
	return nil
}

// strings — строковые поля keys объекта obj для детекторов.
func (cr *ContentResult) strings(obj *argschema.Value, at string, keys ...string) {
	for _, k := range keys {
		if v, ok := obj.Get(k); ok && v.Kind == argschema.String {
			cr.Texts = append(cr.Texts, Text{Path: at + "." + k, Ref: v})
		}
	}
}

// collect — строковые значения structuredContent с путями.
func (cr *ContentResult) collect(v *argschema.Value, at string) {
	switch v.Kind {
	case argschema.String:
		cr.Texts = append(cr.Texts, Text{Path: at, Ref: v})
	case argschema.Array:
		for i := range v.Arr {
			cr.collect(&v.Arr[i], at+"["+strconv.Itoa(i)+"]")
		}
	case argschema.Object:
		for i, k := range v.Keys {
			cr.collect(&v.Vals[i], at+"."+k)
		}
	}
}

// ArgTexts — фрагменты аргументов вызова с путями для детекторов с
// источником tool_args: строковые значения, а также имена ключей и записи
// чисел (ревью 4.r1, 4В8: номер телефона числом или номер карты в имени
// ключа иначе уходили бы мимо pii и secrets). Фрагменты ключей и чисел —
// копии только для находок: аргументы не меняются.
func ArgTexts(args *argschema.Value) []Text {
	var out []Text
	var walk func(v *argschema.Value, at string)
	walk = func(v *argschema.Value, at string) {
		switch v.Kind {
		case argschema.String:
			out = append(out, Text{Path: at, Ref: v})
		case argschema.Number:
			out = append(out, Text{Path: at, Ref: &argschema.Value{Kind: argschema.String, Str: v.Raw}})
		case argschema.Array:
			for i := range v.Arr {
				walk(&v.Arr[i], at+"["+strconv.Itoa(i)+"]")
			}
		case argschema.Object:
			for i, k := range v.Keys {
				out = append(out, Text{Path: at + "." + k + "#key", Ref: &argschema.Value{Kind: argschema.String, Str: k}})
				walk(&v.Vals[i], at+"."+k)
			}
		}
	}
	walk(args, "arguments")
	return out
}

// MetaDecision — ключ _meta результата с решением шлюза (ADR-0023,
// раздел 5).
const MetaDecision = "ru.aisec/decision"

// ErrorResult — результат tools/call с isError: true и текстом msg: отказ
// политики, подтверждения или проверки результата. decision — объект
// решения для _meta (nil — без него).
func ErrorResult(msg, version string, decision *argschema.Value) argschema.Value {
	block := Object()
	Set(&block, "type", String("text"))
	Set(&block, "text", String(msg))
	out := Object()
	if version == Version20260728 {
		Set(&out, "resultType", String("complete"))
	}
	Set(&out, "content", Array(block))
	Set(&out, "isError", Bool(true))
	if decision != nil {
		meta := Object()
		Set(&meta, MetaDecision, *decision)
		Set(&out, "_meta", meta)
	}
	return out
}

// ServerMessageAllowed — сообщение вышестоящего сервера, кроме ответа на
// запрос, передаётся клиенту (ADR-0023, раздел 6): notifications/progress
// (не в потоке subscriptions/listen), notifications/*/list_changed и
// подтверждение подписки (только в потоке listen). Запросы сервера к
// клиенту (2025-11-25) и прочие уведомления — нет.
func ServerMessageAllowed(m *Message, listen bool) bool {
	if m.Kind != KindNotification {
		return false
	}
	switch {
	case m.Method == "notifications/progress":
		// progressToken другого вида (ValidProgressToken) клиенту не
		// передаётся: такой токен клиент серверу не давал.
		if m.Params == nil {
			return false
		}
		t, ok := m.Params.Get("progressToken")
		return !listen && ok && ValidProgressToken(t)
	case m.Method == "notifications/subscriptions/acknowledged":
		return listen
	case strings.HasPrefix(m.Method, "notifications/") && strings.HasSuffix(m.Method, "/list_changed"):
		return true
	}
	return false
}

// Sanitize — уведомление сервера в виде для клиента: у progress только
// progressToken, progress и total (текст message не проверяется и не
// передаётся), у list_changed и подтверждения подписки — без изменений
// содержимого, кроме _meta с subscriptionId.
func Sanitize(m *Message) *Message {
	out := &Message{Kind: KindNotification, Method: m.Method}
	if m.Params == nil {
		return out
	}
	p := Clone(*m.Params)
	switch m.Method {
	case "notifications/progress":
		Keep(&p, "progressToken", "progress", "total")
	case "notifications/subscriptions/acknowledged":
		Keep(&p, "notifications", "_meta")
	default:
		Keep(&p, "_meta")
	}
	if meta, ok := p.Get("_meta"); ok && meta.Kind == argschema.Object {
		Keep(meta, "io.modelcontextprotocol/subscriptionId")
	}
	out.Params = &p
	return out
}

// ProgressNotification — notifications/progress клиенту с текстом
// (ожидание подтверждения, ADR-0023, раздел 5).
func ProgressNotification(token argschema.Value, progress int64, message string) *Message {
	p := Object()
	Set(&p, "progressToken", token)
	Set(&p, "progress", Int(progress))
	Set(&p, "message", String(message))
	return &Message{Kind: KindNotification, Method: "notifications/progress", Params: &p}
}

// Instructions — поле instructions результата initialize (2025-11-25) или
// server/discover (2026-07-28): текст сервера для модели, его проверяет
// встроенная проверка описаний.
func Instructions(result *argschema.Value) (*argschema.Value, bool) {
	v, ok := result.Get("instructions")
	if !ok || v.Kind != argschema.String {
		return nil, false
	}
	return v, true
}
