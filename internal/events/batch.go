package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Пакет событий шлюза для POST /internal/v1/events:batch (ТЗ 5.5, задача
// 2.15). Пакет разбирается строго; ошибка структуры пакета отвергает его
// целиком, ошибка отдельного события — только это событие (Check), чтобы
// одно неверное событие не губило остальные.

// Пределы пакета. Шлюз отправляет не больше, сервер отвергает больше.
const (
	// MaxBatchBytes — предел тела пакета.
	MaxBatchBytes = 8 << 20
	// MaxBatchEvents — предел событий в пакете.
	MaxBatchEvents = 500
	// MaxContentBytes — предел текста запроса и ответа в событии: 64 КиБ
	// шлюза и многоточие после обрезки.
	MaxContentBytes = 64<<10 + 16
	// MaxEventAge — сервер принимает события не старше 7 суток: секции на
	// эти сутки существуют при любом сроке хранения.
	MaxEventAge = 7 * 24 * time.Hour
	// MaxClockSkew — допуск часов шлюза в будущее и расхождение времени
	// события с временем из его UUIDv7.
	MaxClockSkew = 5 * time.Minute
	// maxDetailsBytes — предел метаданных события без содержимого.
	maxDetailsBytes = 1 << 20

	maxShort     = 256
	maxNote      = 1024
	maxFindings  = 1024
	maxList      = 1024
	maxApplied   = 32
	maxThreats   = 64
	maxLatencies = 32
)

// Batch — тело пакета событий.
type Batch struct {
	Events []Event `json:"events"`
	// Stats — счётчики отправителя с его запуска (DM-44).
	Stats *SenderStats `json:"stats,omitempty"`
}

// SenderStats — счётчики отправителя шлюза: отброшенные из-за переполнения
// очереди или остановки и отклонённые сервером события.
type SenderStats struct {
	StartedAt time.Time `json:"started_at"`
	Dropped   uint64    `json:"dropped"`
	Rejected  uint64    `json:"rejected"`
}

// Коды отказа в отдельном событии (без текста: в нём могло бы оказаться
// содержимое).
const (
	RejectInvalid = "invalid" // схема события (Validate)
	RejectID      = "id"      // ID — не UUIDv7 в канонической записи
	RejectTime    = "time"    // время вне окна приёма или не совпадает с ID
	RejectLimits  = "limits"  // превышены пределы полей
	RejectNUL     = "nul"     // символ U+0000: PostgreSQL его не хранит
	// RejectStorage — СУБД отвергла событие при поштучной записи пакета:
	// проверка Check разошлась с ограничениями таблиц (В10 ревью 2.r3a).
	RejectStorage = "storage"
)

// Rejection — отказ в событии пакета.
type Rejection struct {
	Index int    `json:"index"`
	Code  string `json:"code"`
}

// BatchResult — итог приёма пакета.
type BatchResult struct {
	Accepted   int         `json:"accepted"`
	Duplicates int         `json:"duplicates"`
	Rejected   []Rejection `json:"rejected"`
	// Truncated — принятые события full, содержимое которых обрезано под
	// предел хранения (у события отметка details.content_truncated).
	Truncated int `json:"truncated,omitempty"`
}

// ErrBatch — пакет отвергнут целиком: не JSON, лишние поля, пустой или
// слишком большой. Текст разборщика не возвращается: в нём куски тела.
var ErrBatch = errors.New("пакет событий: неверная структура")

// DecodeBatch строго разбирает пакет: неизвестные поля, второе значение
// после первого, пустой пакет, больше MaxBatchEvents событий и данные сверх
// MaxBatchBytes — ErrBatch. Ошибка чтения тела (например,
// *http.MaxBytesError) возвращается как есть.
func DecodeBatch(r io.Reader) (*Batch, error) {
	er := &errReader{r: io.LimitReader(r, MaxBatchBytes+1)}
	dec := json.NewDecoder(er)
	dec.DisallowUnknownFields()
	var b Batch
	if err := dec.Decode(&b); err != nil {
		return nil, er.or(ErrBatch)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, er.or(ErrBatch)
	}
	if dec.InputOffset() > MaxBatchBytes || len(b.Events) == 0 || len(b.Events) > MaxBatchEvents {
		return nil, ErrBatch
	}
	if s := b.Stats; s != nil && s.StartedAt.IsZero() {
		return nil, ErrBatch
	}
	return &b, nil
}

// errReader запоминает ошибку чтения, чтобы отличить её от ошибки разбора.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		e.err = err
	}
	return n, err
}

func (e *errReader) or(def error) error {
	if e.err != nil {
		return e.err
	}
	return def
}

// Check проверяет событие пакета на сервере: схему (Validate), ID UUIDv7,
// время в окне приёма [now−MaxEventAge, now+MaxClockSkew] и рядом со
// временем из ID, пределы полей и отсутствие U+0000. Возвращает код отказа
// или пустую строку.
func Check(e *Event, now time.Time) string {
	if e.Validate() != nil {
		return RejectInvalid
	}
	id, err := ids.Parse(e.ID)
	if err != nil || id.String() != e.ID {
		return RejectID
	}
	t := e.Time
	if t.Before(now.Add(-MaxEventAge)) || t.After(now.Add(MaxClockSkew)) {
		return RejectTime
	}
	if d := t.Sub(id.Time()); d > MaxClockSkew || d < -MaxClockSkew {
		return RejectTime
	}
	if !withinLimits(e) {
		return RejectLimits
	}
	d, err := json.Marshal(e.Details())
	if err != nil || len(d) > maxDetailsBytes {
		return RejectLimits
	}
	if hasNUL(d) || hasNULString(e.App, e.Env, e.User, e.Provider, e.Model, e.Source, e.Storage) {
		return RejectNUL
	}
	if c := e.Content; c != nil && hasNULString(c.Request, c.Response) {
		return RejectNUL
	}
	if dd := e.Decision; dd != nil && hasNULString(dd.Action, dd.Rule, dd.Severity) {
		return RejectNUL
	}
	return ""
}

// Details — метаданные события для столбца details: всё, что не вынесено в
// отдельные столбцы, без содержимого запросов и ответов.
type Details struct {
	Decision    *Decision        `json:"decision,omitempty"`
	Findings    []Finding        `json:"findings,omitempty"`
	LatencyMS   map[string]int64 `json:"latency_ms,omitempty"`
	Tokens      *Tokens          `json:"tokens,omitempty"`
	Response    *Response        `json:"response,omitempty"`
	Pseudonyms  *Pseudonyms      `json:"pseudonyms,omitempty"`
	AuthFailure *AuthFailure     `json:"auth_failure,omitempty"`
	// Session — псевдоним сессии, источник и session.risk; хешей реплик
	// здесь нет (Session.stored).
	Session *Session `json:"session,omitempty"`
	// ContentTruncated — содержимое full обрезано сервером под предел
	// шифротекста (FitContent); ставит только сервер при записи.
	ContentTruncated bool `json:"content_truncated,omitempty"`
}

// WithoutFragments — копия без хешей фрагментов находок: хеш — HMAC текста
// находки, и по нему держатель ключа приложения проверяет, встречалось ли
// значение в запросах (3Н41 ревью 3.r3). Видят его только субъекты с
// правом на содержимое или на изменение политик.
func (d *Details) WithoutFragments() *Details {
	if d == nil || !slices.ContainsFunc(d.Findings, func(f Finding) bool { return f.Fragment != "" }) {
		return d
	}
	out := *d
	out.Findings = slices.Clone(d.Findings)
	for i := range out.Findings {
		out.Findings[i].Fragment = ""
	}
	return &out
}

// Details возвращает метаданные события для хранения.
func (e *Event) Details() Details {
	return Details{
		Decision: e.Decision, Findings: e.Findings, LatencyMS: e.LatencyMS, Tokens: e.Tokens,
		Response: e.Response, Pseudonyms: e.Pseudonyms, AuthFailure: e.AuthFailure, Session: e.Session.stored(),
	}
}

func withinLimits(e *Event) bool {
	for _, s := range []string{e.App, e.Env, e.User, e.Provider, e.Model, e.Source} {
		if len(s) > maxShort {
			return false
		}
	}
	if len(e.Findings) > maxFindings || len(e.Threats) > maxThreats || len(e.LatencyMS) > maxLatencies {
		return false
	}
	for k, v := range e.LatencyMS {
		if k == "" || len(k) > 64 || v < 0 {
			return false
		}
	}
	for i := range e.Findings {
		f := &e.Findings[i]
		if !short(f.Detector, f.Version, f.Category, f.Location, f.Rule) || f.Start < 0 || f.End < f.Start {
			return false
		}
	}
	if !decisionWithin(e.Decision) {
		return false
	}
	if r := e.Response; r != nil && !decisionWithin(r.Decision) {
		return false
	}
	if t := e.Tokens; t != nil && (t.Prompt < 0 || t.Completion < 0) {
		return false
	}
	if a := e.AuthFailure; a != nil && !short(a.RemoteAddr, a.KeyPrefix, a.Reason) {
		return false
	}
	if s := e.Session; s != nil && !short(s.HistoryRule, s.HistoryAction, s.HistorySeverity) {
		return false
	}
	if c := e.Content; c != nil {
		if len(c.Request) > MaxContentBytes || len(c.Response) > MaxContentBytes {
			return false
		}
		if c.Request == "" && c.Response == "" {
			return false
		}
	}
	return true
}

func decisionWithin(d *Decision) bool {
	if d == nil {
		return true
	}
	if !short(d.Action, d.Policy, d.Rule, d.Severity, d.FailMode) || d.PolicyVersion < 0 {
		return false
	}
	if len(d.Applied) > maxApplied || len(d.Trace) > maxList || len(d.Failures) > maxList {
		return false
	}
	for _, a := range d.Applied {
		if !short(a) {
			return false
		}
	}
	for _, s := range d.Trace {
		if !short(s.Rule, s.Detector, s.Action) || len(s.Note) > maxNote {
			return false
		}
	}
	for _, f := range d.Failures {
		if !short(f.Detector, f.Location, f.Reason) {
			return false
		}
	}
	return true
}

func short(ss ...string) bool {
	for _, s := range ss {
		if len(s) > maxShort {
			return false
		}
	}
	return true
}

func hasNULString(ss ...string) bool {
	for _, s := range ss {
		if bytes.IndexByte([]byte(s), 0) >= 0 {
			return true
		}
	}
	return false
}

// hasNUL ищет в JSON экранированный U+0000 («\u0000» с нечётным числом
// обратных косых черт перед «u»). Неэкранированный NUL encoding/json не
// выводит.
func hasNUL(b []byte) bool {
	const esc = `\u0000`
	for i := 0; ; {
		j := bytes.Index(b[i:], []byte(esc))
		if j < 0 {
			return false
		}
		k := i + j
		n := 0
		for p := k; p >= 0 && b[p] == '\\'; p-- {
			n++
		}
		if n%2 == 1 {
			return true
		}
		i = k + len(esc)
	}
}
