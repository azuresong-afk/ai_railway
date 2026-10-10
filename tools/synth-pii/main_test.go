package main

import (
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	var b strings.Builder
	if err := run(&b, "inn12", 1, 3); err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(b.String())
	if len(lines) != 3 || len(lines[0]) != 12 || !strings.HasPrefix(lines[0], "00") {
		t.Fatalf("%q", b.String())
	}
	for _, bad := range []struct {
		kind string
		n    int
	}{{"passport", 1}, {"inn12", 0}, {"inn12", 10001}} {
		if err := run(&b, bad.kind, 1, bad.n); err == nil {
			t.Errorf("%+v: ожидалась ошибка", bad)
		}
	}
}
