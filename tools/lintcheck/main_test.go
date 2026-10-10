package main

import (
	"strings"
	"testing"
)

func TestParseMarkers(t *testing.T) {
	src := "package x\nimport \"os/exec\" // want:depguard\n// clean:depguard и want:forbidigo\n//want:x\n// wanted:depguard\n"
	got := parseMarkers("a.go", []byte(src))
	want := []marker{
		{"a.go", 2, "depguard", true},
		{"a.go", 3, "depguard", false},
		{"a.go", 4, "x", true},
	}
	if len(got) != len(want) {
		t.Fatalf("получено %v, ожидалось %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("маркер %d: %v, ожидалось %v", i, got[i], want[i])
		}
	}
}

func TestParseReport(t *testing.T) {
	data := []byte(`{"Issues":[{"FromLinter":"depguard","Text":"t","Pos":{"Filename":"/s/internal/a.go","Line":3}},` +
		`{"FromLinter":"gosec","Text":"u","Pos":{"Filename":"cmd/b.go","Line":1}}]}`)
	got, err := parseReport(data, "/s")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].File != "internal/a.go" || got[1].File != "cmd/b.go" {
		t.Fatalf("неверный разбор: %+v", got)
	}
	if _, err := parseReport([]byte("не json"), "/s"); err == nil {
		t.Fatal("ожидалась ошибка разбора")
	}
	if _, err := parseReport(make([]byte, maxReportSize+1), "/s"); err == nil {
		t.Fatal("ожидалась ошибка размера")
	}
}

func TestCompare(t *testing.T) {
	markers := []marker{
		{"a.go", 1, "depguard", true},  // есть
		{"a.go", 2, "depguard", true},  // нет — ошибка
		{"b.go", 5, "depguard", false}, // лишнее — ошибка
		{"b.go", 6, "depguard", false}, // чисто
	}
	issues := []issue{
		{"a.go", 1, "depguard", "x"},
		{"b.go", 5, "depguard", "y"},
		{"b.go", 6, "gosec", "не тот линтер"},
	}
	got := compare(markers, issues)
	if len(got) != 2 || !strings.Contains(got[0], "a.go:2") || !strings.Contains(got[1], "b.go:5") {
		t.Fatalf("неверные расхождения: %q", got)
	}
}

func FuzzParseReport(f *testing.F) {
	f.Add([]byte(`{"Issues":[{"FromLinter":"a","Pos":{"Filename":"/b/c.go","Line":1}}]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[`))
	f.Fuzz(func(t *testing.T, data []byte) {
		issues, err := parseReport(data, "/b")
		if err == nil && issues == nil {
			t.Fatal("без ошибки должен возвращаться непустой срез (возможно, нулевой длины)")
		}
	})
}

func FuzzParseMarkers(f *testing.F) {
	f.Add([]byte("x // want:depguard\n// clean:a"))
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, m := range parseMarkers("f.go", data) {
			if m.Line < 1 || m.Linter == "" {
				t.Fatalf("некорректный маркер %+v", m)
			}
		}
	})
}
