package components

import (
	"strings"
	"testing"
)

func TestEvalExpression(t *testing.T) {
	cases := []struct {
		expr string
		want Verdict
	}{
		{"MIT", Allowed},
		{"MIT AND Apache-2.0", Allowed},
		{"MIT AND GPL-3.0-only", Forbidden},
		{"MIT OR GPL-3.0-only", Allowed},
		{"(MIT OR GPL-2.0-only) AND BSD-3-Clause", Allowed},
		{"MPL-2.0", Conditional},
		{"LGPL-2.1-only OR MPL-2.0", Conditional},
		{"MIT AND MPL-2.0", Conditional},
		{"AGPL-3.0-only", Forbidden},
		{"SSPL-1.0", Forbidden},
		{"BUSL-1.1", Forbidden},
		{"NOASSERTION", Forbidden},
		{"LicenseRef-proprietary", Forbidden},
		{"Unknown-1.0", Forbidden},
		{"OFL-1.1", Allowed},
		{"ISC", Allowed},
		{"LGPL-x", Forbidden},
		{"MPL-2.0-no-copyleft-exception", Forbidden},
		{"GPL-3.0-only", Forbidden},
	}
	for _, c := range cases {
		got, _, err := EvalExpression(c.expr)
		if err != nil {
			t.Fatalf("%q: %v", c.expr, err)
		}
		if got != c.want {
			t.Errorf("%q: вердикт %d, ожидалось %d", c.expr, got, c.want)
		}
	}
}

func TestEvalExpressionErrors(t *testing.T) {
	for _, expr := range []string{"", "   ", "MIT AND", "AND MIT", "(MIT", "MIT)", "MIT OR OR ISC", "MIT WITH x",
		strings.Repeat("(", maxDepth+1) + "MIT" + strings.Repeat(")", maxDepth+1), strings.Repeat("MIT AND ", 100) + "MIT"} {
		if _, _, err := EvalExpression(expr); err == nil {
			t.Errorf("%q: ожидалась ошибка", expr)
		}
	}
}

func TestCheckLicense(t *testing.T) {
	cases := []struct {
		name string
		c    Component
		ok   bool
	}{
		{"разрешённая", Component{License: "MIT", Scope: ScopeProduct}, true},
		{"MPL без решения", Component{License: "MPL-2.0", Scope: ScopeProduct}, false},
		{"MPL с решением", Component{License: "MPL-2.0", Scope: ScopeProduct, LicenseDecision: "ADR-9"}, true},
		{"GPL в продукте даже с решением", Component{License: "GPL-3.0-only", Scope: ScopeProduct, LicenseDecision: "ADR-3"}, false},
		{"GPL в сборке без решения", Component{License: "GPL-3.0-only", Scope: ScopeBuild}, false},
		{"GPL в сборке с решением", Component{License: "GPL-3.0-only", Scope: ScopeBuild, LicenseDecision: "ADR-0003"}, true},
		{"AGPL в сборке с решением", Component{License: "AGPL-3.0-only", Scope: ScopeBuild, LicenseDecision: "ADR-0003"}, false},
		{"выдуманный GPL в сборке", Component{License: "GPL-x", Scope: ScopeBuild, LicenseDecision: "ADR-0003"}, false},
		{"GPL и SSPL в сборке", Component{License: "GPL-3.0-only AND SSPL-1.0", Scope: ScopeBuild, LicenseDecision: "ADR-0003"}, false},
		{"испорченное выражение", Component{License: "MIT AND", Scope: ScopeProduct}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := CheckLicense(c.c)
			if (err == nil) != c.ok {
				t.Fatalf("CheckLicense(%+v) = %v, ожидалось ok=%v", c.c, err, c.ok)
			}
		})
	}
}

func FuzzEvalExpression(f *testing.F) {
	for _, s := range []string{"MIT", "(MIT OR ISC) AND Apache-2.0", "((", "AND", "GPL-3.0-only OR MIT"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, expr string) {
		v, ids, err := EvalExpression(expr)
		if err != nil {
			return
		}
		if len(ids) == 0 {
			t.Fatalf("%q: выражение без идентификаторов принято", expr)
		}
		// Выражение из одних разрешённых идентификаторов всегда разрешено.
		all := true
		for _, id := range ids {
			if classify(id) != Allowed {
				all = false
			}
		}
		if all && v != Allowed {
			t.Fatalf("%q: все идентификаторы разрешены, а вердикт %d", expr, v)
		}
	})
}
