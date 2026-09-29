package components

import (
	"errors"
	"fmt"
	"strings"
)

// Политика лицензий (CLAUDE.md, «Зависимости»).
var (
	// allowedLicenses разрешены без отдельного решения.
	allowedLicenses = map[string]bool{
		"MIT": true, "BSD-2-Clause": true, "BSD-3-Clause": true,
		"Apache-2.0": true, "ISC": true, "OFL-1.1": true,
	}
	// conditionalPrefixes — только отдельным решением (license_decision).
	conditionalPrefixes = []string{"MPL-2.0", "LGPL-"}
)

// Всё остальное запрещено: GPL, AGPL, SSPL, BUSL, Commons Clause, код без
// лицензии (NOASSERTION, NONE) и любые неизвестные идентификаторы. Для
// инструментов сборочной среды (scope: build) GPL допускается отдельным
// решением (ADR-0003).

// Verdict — результат проверки лицензии одного идентификатора.
type Verdict int

// Возможные вердикты: по возрастанию строгости.
const (
	Allowed     Verdict = iota // разрешена
	Conditional                // только отдельным решением
	Forbidden                  // запрещена
)

// classify относит идентификатор SPDX к категории. Неизвестный
// идентификатор считается запрещённым, пока его не внесут в политику.
func classify(id string) Verdict {
	if allowedLicenses[id] {
		return Allowed
	}
	for _, p := range conditionalPrefixes {
		if strings.HasPrefix(id, p) {
			return Conditional
		}
	}
	return Forbidden
}

// isGPLFamily сообщает, что идентификатор из семейства GPL, допустимого для
// инструментов сборочной среды по ADR-0003.
func isGPLFamily(id string) bool {
	return strings.HasPrefix(id, "GPL-")
}

// maxExprLen ограничивает длину выражения лицензии.
const maxExprLen = 512

// EvalExpression вычисляет итоговый вердикт выражения SPDX с операторами
// AND и OR и скобками. AND требует, чтобы подходили все части (берётся
// худший вердикт), OR — достаточно одной (лучший вердикт). Возвращает
// также список идентификаторов выражения.
func EvalExpression(expr string) (Verdict, []string, error) {
	if len(expr) > maxExprLen {
		return Forbidden, nil, fmt.Errorf("выражение лицензии длиннее %d символов", maxExprLen)
	}
	p := &exprParser{toks: tokenize(expr)}
	if len(p.toks) == 0 {
		return Forbidden, nil, errors.New("пустое выражение лицензии")
	}
	v, err := p.parseOr(0)
	if err != nil {
		return Forbidden, nil, err
	}
	if p.pos != len(p.toks) {
		return Forbidden, nil, fmt.Errorf("лишний элемент %q в выражении лицензии", p.toks[p.pos])
	}
	return v, p.ids, nil
}

func tokenize(s string) []string {
	s = strings.ReplaceAll(s, "(", " ( ")
	s = strings.ReplaceAll(s, ")", " ) ")
	return strings.Fields(s)
}

// maxDepth ограничивает вложенность скобок.
const maxDepth = 16

type exprParser struct {
	toks []string
	pos  int
	ids  []string
}

func (p *exprParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *exprParser) parseOr(depth int) (Verdict, error) {
	v, err := p.parseAnd(depth)
	if err != nil {
		return Forbidden, err
	}
	for p.peek() == "OR" {
		p.pos++
		r, err := p.parseAnd(depth)
		if err != nil {
			return Forbidden, err
		}
		v = min(v, r)
	}
	return v, nil
}

func (p *exprParser) parseAnd(depth int) (Verdict, error) {
	v, err := p.parseAtom(depth)
	if err != nil {
		return Forbidden, err
	}
	for p.peek() == "AND" {
		p.pos++
		r, err := p.parseAtom(depth)
		if err != nil {
			return Forbidden, err
		}
		v = max(v, r)
	}
	return v, nil
}

func (p *exprParser) parseAtom(depth int) (Verdict, error) {
	t := p.peek()
	switch t {
	case "":
		return Forbidden, errors.New("выражение лицензии обрывается")
	case "(":
		if depth >= maxDepth {
			return Forbidden, errors.New("слишком глубокая вложенность скобок в выражении лицензии")
		}
		p.pos++
		v, err := p.parseOr(depth + 1)
		if err != nil {
			return Forbidden, err
		}
		if p.peek() != ")" {
			return Forbidden, errors.New("не закрыта скобка в выражении лицензии")
		}
		p.pos++
		return v, nil
	case ")", "AND", "OR", "WITH":
		return Forbidden, fmt.Errorf("неожиданный элемент %q в выражении лицензии", t)
	}
	p.pos++
	p.ids = append(p.ids, t)
	return classify(t), nil
}

// CheckLicense проверяет лицензию компонента по политике. Для scope: build
// лицензии семейства GPL допустимы при заполненном license_decision
// (ADR-0003); условные лицензии всегда требуют license_decision.
func CheckLicense(c Component) error {
	v, ids, err := EvalExpression(c.License)
	if err != nil {
		return err
	}
	switch v {
	case Allowed:
		return nil
	case Conditional:
		if strings.TrimSpace(c.LicenseDecision) == "" {
			return fmt.Errorf("лицензия %q допускается только отдельным решением: заполните license_decision", c.License)
		}
		return nil
	}
	if c.Scope == ScopeBuild && strings.TrimSpace(c.LicenseDecision) != "" {
		gplOnly := true
		for _, id := range ids {
			if classify(id) == Forbidden && !isGPLFamily(id) {
				gplOnly = false
			}
		}
		if gplOnly {
			return nil
		}
	}
	return fmt.Errorf("лицензия %q запрещена (CLAUDE.md, «Зависимости»)", c.License)
}
