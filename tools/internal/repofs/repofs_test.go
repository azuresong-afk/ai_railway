package repofs

import "testing"

func TestSkip(t *testing.T) {
	cases := []struct {
		p, name string
		want    bool
	}{
		{".", ".", false},
		{"vendor", "vendor", true},
		{"build", "build", true},
		{".git", ".git", true},
		{"internal/x/build", "build", false},
		{"internal/x/vendor", "vendor", false},
		{"tools/lintcheck/testdata", "testdata", true},
		{"testdata", "testdata", true},
		{"internal", "internal", false},
	}
	for _, c := range cases {
		if got := Skip(c.p, c.name); got != c.want {
			t.Errorf("Skip(%q, %q) = %v, ожидалось %v", c.p, c.name, got, c.want)
		}
	}
}
