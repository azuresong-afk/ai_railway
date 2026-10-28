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
	// conditionalLicenses — только отдельным решением (license_decision).
	conditionalLicenses = map[string]bool{
		"MPL-2.0": true, "LGPL-2.1-only": true, "LGPL-2.1-or-later": true,
		"LGPL-3.0-only": true, "LGPL-3.0-or-later": true,
	}
	// gplLicenses допустимы только для инструментов сборочной среды (ADR-0003)
	// и внешних образов (ADR-0019).
	gplLicenses = map[string]bool{
		"GPL-2.0-only": true, "GPL-2.0-or-later": true,
		"GPL-3.0-only": true, "GPL-3.0-or-later": true,
	}
	// externalLicenses — разрешительные лицензии вне списка CLAUDE.md, которые
	// допускаются только у внешних образов (scope: external) при
	// license_decision: продукт эти компоненты не распространяет (ADR-0019).
	externalLicenses = map[string]bool{"PostgreSQL": true, "Zlib": true}
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
	if conditionalLicenses[id] {
		return Conditional
	}
	return Forbidden
}

// isGPLFamily сообщает, что идентификатор из семейства GPL, допустимого для
// инструментов сборочной среды по ADR-0003.
func isGPLFamily(id string) bool {
	return gplLicenses[id]
}

// maxExprLen ограничивает длину выражения лицензии.
const maxExprLen = 512

// EvalExpression вычисляет итоговый вердикт выражения SPDX с операторами
// AND и OR и скобками. AND требует, чтобы подходили все части (берётся
// худший вердикт), OR — достаточно одной (лучший вердикт). Возвращает
// также список идентификаторов выражения.
func EvalExpression(expr string) (Verdict, []string, error) {
	return evalExpression(expr, nil)
}

// NativeLicenses — лицензии вне списка CLAUDE.md, которые допускаются только
// у native-library при license_decision (ADR-0024: Boost.Mp11 внутри ONNX Runtime).
var NativeLicenses = map[string]bool{"BSL-1.0": true}

// NPMBuildLicenses — лицензии, которые допускаются только у npm-пакетов
// сборочной среды (достижимых лишь из devDependencies) и не попадают в
// поставку. Решение владельца от 20.10.2026, ADR-0011.
var NPMBuildLicenses = map[string]bool{
	"MPL-2.0": true, "0BSD": true, "MIT-0": true, "BlueOak-1.0.0": true,
	"CC0-1.0": true, "CC-BY-4.0": true, "Python-2.0": true,
}

// CheckNPMLicense проверяет лицензию пакета из package-lock.json. Пакеты
// поставки (product) — только по политике CLAUDE.md; пакеты сборочной среды —
// ещё и по NPMBuildLicenses.
func CheckNPMLicense(expr string, product bool) error {
	if strings.TrimSpace(expr) == "" {
		return errors.New("в package-lock.json нет лицензии пакета")
	}
	var extra map[string]bool
	if !product {
		extra = NPMBuildLicenses
	}
	v, _, err := evalExpression(expr, extra)
	if err != nil {
		return err
	}
	if v != Allowed {
		return fmt.Errorf("лицензия %q не допускается для этого пакета (CLAUDE.md, «Зависимости»; ADR-0011)", expr)
	}
	return nil
}

func evalExpression(expr string, extra map[string]bool) (Verdict, []string, error) {
	if len(expr) > maxExprLen {
		return Forbidden, nil, fmt.Errorf("выражение лицензии длиннее %d символов", maxExprLen)
	}
	p := &exprParser{toks: tokenize(expr), extra: extra}
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
	// extra — идентификаторы, разрешённые в этом разборе сверх политики.
	extra map[string]bool
	toks  []string
	pos   int
	ids   []string
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
	if p.extra[t] {
		return Allowed, nil
	}
	return classify(t), nil
}

// CheckLicense проверяет лицензию компонента по политике. Для scope: build
// и external лицензии семейства GPL (для external — и externalLicenses)
// допустимы при заполненном license_decision (ADR-0003, ADR-0019); условные
// лицензии всегда требуют license_decision.
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
	// BSL-1.0 (Boost Software License, не BUSL) — только у библиотек,
	// встроенных в сборку ONNX Runtime, по отдельному решению владельца
	// (ADR-0024, 27.10.2026).
	if c.Type == TypeNative && strings.TrimSpace(c.LicenseDecision) != "" {
		if v, _, err := evalExpression(c.License, NativeLicenses); err == nil && v == Allowed {
			return nil
		}
	}
	// Лицензии npm из NPMBuildLicenses — при отдельном решении (ADR-0011).
	if c.Type == TypeNPM && strings.TrimSpace(c.LicenseDecision) != "" {
		if v, _, err := evalExpression(c.License, NPMBuildLicenses); err == nil && v == Allowed {
			return nil
		}
	}
	if (c.Scope == ScopeBuild || c.Scope == ScopeExternal) && strings.TrimSpace(c.LicenseDecision) != "" {
		gplOnly := true
		for _, id := range ids {
			externalOK := c.Scope == ScopeExternal && externalLicenses[id]
			if classify(id) == Forbidden && !isGPLFamily(id) && !externalOK {
				gplOnly = false
			}
		}
		if gplOnly {
			return nil
		}
	}
	return fmt.Errorf("лицензия %q запрещена (CLAUDE.md, «Зависимости»)", c.License)
}
