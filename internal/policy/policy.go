package policy

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Catalog — детекторы, по которым компилируется политика: *detect.Registry.
type Catalog interface {
	Get(id string) (detect.Detector, bool)
}

// Policy — проверенная политика, готовая к вычислению решений.
// Неизменяема и безопасна для одновременного использования.
type Policy struct {
	ID            string
	Name          string
	Version       int
	Mode          Mode
	NonText       NonText
	ResponseCheck ResponseCheck
	BlockMessage  string
	rules         []rule
	// exceptions — исключения версии (exception.go), в порядке спецификации.
	exceptions []ExceptionSpec
	// tools — политика вызовов инструментов (toolcall.go).
	tools toolPolicy
}

type rule struct {
	id         string
	detector   string
	directions []detect.Direction
	categories []string
	sources    []detect.Source
	threshold  float64
	action     Action
	severity   Severity
	message    string
}

// Compile проверяет спецификацию и связывает её с детекторами: каждый
// детектор правила зарегистрирован и поддерживает направления правила.
// Пустые directions — все направления детектора.
func Compile(s *Spec, c Catalog) (*Policy, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	p := &Policy{
		ID: s.ID, Name: s.Name, Version: s.Version, Mode: s.Mode,
		NonText: s.NonText, ResponseCheck: s.ResponseCheck, BlockMessage: s.BlockMessage,
	}
	if p.NonText == "" {
		p.NonText = NonTextAllowUnchecked
	}
	if p.ResponseCheck == "" {
		p.ResponseCheck = ResponseIncremental
	}
	if p.BlockMessage == "" {
		p.BlockMessage = DefaultBlockMessage
	}
	var errs []error
	for i, r := range s.Rules {
		d, ok := c.Get(r.Detector)
		if !ok {
			errs = append(errs, fmt.Errorf("политика %s: rules[%d] (%s): детектор %q не зарегистрирован", s.ID, i, r.ID, r.Detector))
			continue
		}
		dirs := slices.Clone(r.Directions)
		if len(dirs) == 0 {
			dirs = slices.Clone(d.Directions())
		}
		for _, dir := range dirs {
			if !slices.Contains(d.Directions(), dir) {
				errs = append(errs, fmt.Errorf("политика %s: rules[%d] (%s): детектор %s не проверяет направление %s", s.ID, i, r.ID, r.Detector, dir))
			}
		}
		errs = append(errs, checkCategories(s.ID, i, r, d)...)
		p.rules = append(p.rules, rule{
			id: r.ID, detector: r.Detector, directions: dirs,
			categories: slices.Clone(r.Categories), sources: slices.Clone(r.Sources),
			threshold: r.threshold(), action: r.Action, severity: r.Severity, message: r.Message,
		})
	}
	for i, e := range s.Exceptions {
		if _, ok := c.Get(e.Detector); !ok {
			errs = append(errs, fmt.Errorf("политика %s: exceptions[%d] (%s): детектор %q не зарегистрирован", s.ID, i, e.ID, e.Detector))
		}
	}
	err := errors.Join(errs...)
	if err != nil {
		return nil, err
	}
	p.exceptions = slices.Clone(s.Exceptions)
	if p.tools, err = compileTools(s.Tools); err != nil {
		return nil, fmt.Errorf("политика %s: %w", s.ID, err)
	}
	return p, nil
}

// checkCategories — каждая категория правила выдаётся детектором. Опечатка
// (pii.pasport) иначе дала бы правило, которое молча никогда не срабатывает:
// для block это незаметное ослабление защиты (ТЗ, 5.3, строгая проверка).
// Детектор без списка категорий в правиле с категориями — тоже ошибка.
func checkCategories(policyID string, i int, r RuleSpec, d detect.Detector) []error {
	if len(r.Categories) == 0 {
		return nil
	}
	cz, ok := d.(detect.Categorizer)
	if !ok {
		return []error{fmt.Errorf("политика %s: rules[%d] (%s): детектор %s не сообщает категории, правило с categories проверить нельзя", policyID, i, r.ID, r.Detector)}
	}
	known := cz.Categories()
	var errs []error
	for _, c := range r.Categories {
		if !slices.Contains(known, c) {
			errs = append(errs, fmt.Errorf("политика %s: rules[%d] (%s): детектор %s не выдаёт категорию %q", policyID, i, r.ID, r.Detector, c))
		}
	}
	return errs
}

// Detectors — детекторы, которые нужны политике для направления, в порядке
// первого упоминания в правилах. Конвейер шлюза запускает только их.
func (p *Policy) Detectors(dir detect.Direction) []string {
	var ids []string
	for _, r := range p.rules {
		if slices.Contains(r.directions, dir) && !slices.Contains(ids, r.detector) {
			ids = append(ids, r.detector)
		}
	}
	return ids
}

// Hit — находка детектора и источник текста, в котором она найдена.
type Hit struct {
	Finding detect.Finding
	Source  detect.Source
	// Fragment — хеш текста находки (HMAC на ключе шлюза, hex) для
	// исключений по фрагменту; пусто — хеша нет (ключ не задан).
	Fragment string
}

// MediaPart — нетекстовая часть запроса для non_text (DM-14). Шлюз медиа не
// декодирует: известны только вид и способ передачи.
type MediaPart struct {
	Kind string // image, audio, file, video
	// URL — ссылка, которую провайдер загрузит сам (не данные в запросе и не
	// идентификатор файла у провайдера).
	URL bool
}

// Request — что оценивается: находки по тексту одного направления.
type Request struct {
	Endpoint  Endpoint
	Direction detect.Direction
	// Mode — режим политики приложения (ТЗ, 5.4); пусто — режим политики.
	// Незнакомое значение считается enforce: ошибка вызывающего кода не
	// должна ослаблять защиту.
	Mode Mode
	// External — провайдер приложения внешний (ТЗ, 5.4); для Check API —
	// признак провайдера приложения.
	External bool
	Hits     []Hit
	// Media — нетекстовые части запроса (только вход chat/completions).
	Media []MediaPart
	// App и User — приложение и псевдоним пользователя запроса: условия
	// исключений. Пусто — условие с приложением или пользователем не совпадает.
	App  string
	User string
	// Now — время для сроков исключений; нулевое — часы процесса.
	Now time.Time
}

// NonTextRule — имя «правила» в решении, когда итог дал параметр non_text.
const NonTextRule = "non_text"

// Match — решение по одной находке.
type Match struct {
	// Hit — номер находки в Request.Hits.
	Hit int
	// Rule и Action — правило с самым сильным действием среди совпавших
	// (при равенстве — первое по порядку) и это действие.
	Rule   string
	Action Action
	// Protect и ProtectRule — самая сильная защита данных среди совпавших
	// правил (redact или pseudonymize), пусто — нет. Нужна, чтобы в monitor
	// ПДн маскировались, даже когда то же значение попало под block.
	Protect     Action
	ProtectRule string
	Severity    Severity
	// AsRedact — правило с pseudonymize выполняется как redact (эмбеддинги и
	// Check API: обратной подстановки там нет).
	AsRedact bool
	// Apply — что фактически делается с фрагментом: redact, pseudonymize
	// или ничего. Блокировку целиком отражает Decision.Block.
	Apply Action
	order int // номер правила Rule — для однозначного итога
}

// Decision — решение политики (ТЗ, 4.3 и 5.3).
type Decision struct {
	PolicyID string
	Version  int
	Mode     Mode
	// Action — итог по таблице приоритетов: что было бы сделано в enforce.
	// Без совпадений — allow.
	Action Action
	// Rule — правило, давшее итог (NonTextRule — параметр non_text).
	Rule     string
	Severity Severity
	// Block — запрос или ответ блокируется (только enforce).
	Block bool
	// Message — безопасное сообщение пользователю при блокировке.
	Message string
	Matches []Match
	// Excepted — находки, пропущенные по исключениям: в Matches их нет.
	Excepted []Excepted
	// NonTextUnchecked — нетекстовые части уходят провайдеру без проверки
	// (отметка в событии, ТЗ, 5.1).
	NonTextUnchecked bool
}

// Applied — действия, которые фактически применены, по убыванию приоритета
// (поле applied события, ТЗ, 5.3).
func (d *Decision) Applied() []Action {
	var out []Action
	if d.Block {
		out = append(out, Block)
	}
	for _, a := range []Action{Redact, Pseudonymize} {
		if slices.ContainsFunc(d.Matches, func(m Match) bool { return m.Apply == a }) {
			out = append(out, a)
		}
	}
	return out
}

// Evaluate вычисляет решение. Для каждой находки берутся все совпавшие
// правила (детектор, направление, источник, категория, порог), итог по
// находке — самое сильное действие по таблице приоритетов; итог решения —
// самое сильное по всем находкам и параметру non_text. Правило не может
// ослабить другое: allow не отменяет block. Находка под действующим
// исключением (exception.go) правилами не рассматривается: она в
// Decision.Excepted и не защищается и не блокируется.
//
// Режим monitor (ТЗ, 5.3): применяется только защита данных (redact,
// pseudonymize) во входе, если провайдер внешний, — в том числе когда итог
// block; block только журналируется. Для внутреннего провайдера и для ответа
// модели monitor ничего не применяет. Обратная подстановка псевдонимов в
// ответе — часть pseudonymize и выполняется всегда (задачи 1.20–1.23).
func (p *Policy) Evaluate(req Request) Decision {
	mode := req.Mode
	switch mode {
	case "":
		mode = p.Mode
	case Monitor, Enforce:
	default:
		mode = Enforce
	}
	d := Decision{PolicyID: p.ID, Version: p.Version, Mode: mode, Action: Allow}
	applyProtect := mode == Enforce || req.Direction == detect.Input && req.External
	best := -1
	now := req.Now
	if now.IsZero() {
		now = time.Now()
	}
	for i, h := range req.Hits {
		if id := p.exceptionFor(h, req, now); id != "" {
			d.Excepted = append(d.Excepted, Excepted{Hit: i, Exception: id})
			continue
		}
		m, ok := p.match(i, h, req)
		if !ok {
			continue
		}
		if applyProtect {
			m.Apply = m.Protect
		}
		d.Matches = append(d.Matches, m)
		if severityRank[m.Severity] > severityRank[d.Severity] {
			d.Severity = m.Severity
		}
		if best < 0 || Stronger(m.Action, d.Action) || m.Action == d.Action && m.order < best {
			d.Action, d.Rule, best = m.Action, m.Rule, m.order
		}
	}
	if p.nonTextBlocks(req.Media) {
		if Stronger(Block, d.Action) {
			d.Action, d.Rule = Block, NonTextRule
		}
		if severityRank[Medium] > severityRank[d.Severity] {
			d.Severity = Medium
		}
	}
	d.Block = mode == Enforce && d.Action == Block
	if d.Block {
		d.Message = p.BlockMessage
		if r := p.ruleByID(d.Rule); r != nil && r.message != "" {
			d.Message = r.message
		}
	}
	d.NonTextUnchecked = len(req.Media) > 0 && !d.Block
	return d
}

// match — решение по одной находке; false — ни одно правило не совпало.
func (p *Policy) match(i int, h Hit, req Request) (Match, bool) {
	m := Match{Hit: i, order: -1}
	protectOrder := -1
	f := h.Finding
	for j := range p.rules {
		r := &p.rules[j]
		if r.detector != f.Detector || !slices.Contains(r.directions, req.Direction) || f.Score < r.threshold ||
			len(r.sources) > 0 && !slices.Contains(r.sources, h.Source) ||
			len(r.categories) > 0 && !slices.Contains(r.categories, f.Category) {
			continue
		}
		a, asRedact := r.action, false
		if (req.Endpoint == EndpointEmbeddings || req.Endpoint == EndpointCheck) && a == Pseudonymize {
			a, asRedact = Redact, true
		}
		if m.order < 0 || Stronger(a, m.Action) {
			m.Rule, m.Action, m.order = r.id, a, j
		}
		if severityRank[r.severity] > severityRank[m.Severity] {
			m.Severity = r.severity
		}
		if protects(a) && (protectOrder < 0 || Stronger(a, m.Protect)) {
			m.Protect, m.ProtectRule, protectOrder = a, r.id, j
			m.AsRedact = asRedact
		}
	}
	return m, m.order >= 0
}

// nonTextBlocks — параметр non_text требует блокировать нетекстовые части.
func (p *Policy) nonTextBlocks(media []MediaPart) bool {
	switch p.NonText {
	case NonTextBlock:
		return len(media) > 0
	case NonTextAllowInline:
		return slices.ContainsFunc(media, func(m MediaPart) bool { return m.URL })
	}
	return false
}

func (p *Policy) ruleByID(id string) *rule {
	for i := range p.rules {
		if p.rules[i].id == id {
			return &p.rules[i]
		}
	}
	return nil
}
