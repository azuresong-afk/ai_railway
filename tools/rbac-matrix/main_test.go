package main

import (
	"os"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// Матрица в docs/cert совпадает с тем, что строится из спецификации:
// новый эндпоинт без строки в матрице не пройдёт тесты.
func TestMatrixUpToDate(t *testing.T) {
	if err := run("../../api/openapi.yaml", "../../docs/cert/rbac-matrix.md", true); err != nil {
		t.Fatal(err)
	}
}

const sample = `
paths:
  /healthz:
    get: { security: [] }
  /api/v1/users:
    post: { security: [{ sessionCookie: [] }], x-permission: users.manage }
    get: { security: [{ sessionCookie: [] }], x-permission: users.read }
  /api/v1/me:
    get: { security: [{ sessionCookie: [] }], x-permission: self }
  /v1/models:
    get: {}
`

func TestOperations(t *testing.T) {
	ops, err := Operations([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	got := []string{}
	for _, o := range ops {
		got = append(got, o.Method+" "+o.Path+" "+o.Permission)
	}
	want := "GET /api/v1/me self|GET /api/v1/users users.read|POST /api/v1/users users.manage|GET /healthz "
	if strings.Join(got, "|") != want {
		t.Fatalf("%q", strings.Join(got, "|"))
	}
	md := Render(ops, auth.BuiltinRoles())
	if !strings.Contains(md, "| POST | `/api/v1/users` | `users.manage` | да | — | — | — | — |") {
		t.Fatalf("строка users.manage:\n%s", md)
	}
	if !strings.Contains(md, "| GET | `/api/v1/me` | `self` | да | да | да | да | да |") {
		t.Fatalf("строка self:\n%s", md)
	}
}

func TestOperationsRejectsMissingPermission(t *testing.T) {
	for _, bad := range []string{
		"paths:\n  /api/v1/x:\n    get: { security: [{ sessionCookie: [] }] }\n",
		"paths:\n  /api/v1/x:\n    get: { x-permission: nope.read }\n",
		"paths:\n  /api/v1/x:\n    get: { security: [], x-permission: users.read }\n",
		"paths:\n  /api/v1/x:\n    get: {}\n",
	} {
		if _, err := Operations([]byte(bad)); err == nil {
			t.Errorf("принято: %s", bad)
		}
	}
}

func TestCell(t *testing.T) {
	g := auth.Grants{"a.read": auth.ScopeAll, "b.read": auth.ScopeOwn}
	if Cell(g, "a.read") != "да" || Cell(g, "b.read") != "свои" || Cell(g, "c.read") != "—" || Cell(g, auth.PermSelf) != "—" {
		t.Fatal("неверные ячейки")
	}
}

func TestRunWritesFile(t *testing.T) {
	dir := t.TempDir()
	spec := dir + "/openapi.yaml"
	if err := os.WriteFile(spec, []byte(sample), 0o600); err != nil {
		t.Fatal(err)
	}
	out := dir + "/m.md"
	if err := run(spec, out, false); err != nil {
		t.Fatal(err)
	}
	if err := run(spec, out, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("старое"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run(spec, out, true); err == nil {
		t.Fatal("устаревший файл принят")
	}
}

// Разбор спецификации: без паники; принятые операции — только сервера,
// у защищённых разрешение из каталога или self.
func FuzzOperations(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte("paths:\n  /api/v1/x:\n    get: { security: [{ a: [] }], x-permission: users.read }\n"))
	f.Add([]byte("paths: [1, 2]"))
	f.Fuzz(func(t *testing.T, spec []byte) {
		ops, err := Operations(spec)
		if err != nil {
			return
		}
		for _, o := range ops {
			if !serverOwned(o.Path) {
				t.Fatalf("чужой путь %q", o.Path)
			}
			if _, ok := auth.LookupPermission(o.Permission); o.Permission != "" && o.Permission != auth.PermSelf && !ok {
				t.Fatalf("разрешение не из каталога: %q", o.Permission)
			}
		}
	})
}
