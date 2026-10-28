// Команда rbac-matrix строит матрицу «роль × эндпоинт» (УПД.3) из
// api/openapi.yaml (расширение x-permission у каждой защищённой операции) и
// прав предустановленных ролей (internal/auth). С -check только сверяет
// готовый файл: устаревшая матрица — ошибка.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// maxSpecSize ограничивает размер читаемой спецификации.
const maxSpecSize = 4 << 20

func main() {
	specPath := flag.String("spec", "api/openapi.yaml", "спецификация OpenAPI")
	out := flag.String("out", "docs/cert/rbac-matrix.md", "файл матрицы")
	check := flag.Bool("check", false, "только проверить, что файл матрицы актуален")
	flag.Parse()
	if err := run(*specPath, *out, *check); err != nil {
		fmt.Fprintln(os.Stderr, "rbac-matrix:", err)
		os.Exit(1)
	}
}

func run(specPath, out string, check bool) error {
	spec, err := readLimited(specPath)
	if err != nil {
		return err
	}
	ops, err := Operations(spec)
	if err != nil {
		return err
	}
	md := Render(ops, auth.BuiltinRoles())
	if check {
		cur, err := readLimited(out)
		if err != nil {
			return err
		}
		if !bytes.Equal(cur, []byte(md)) {
			return fmt.Errorf("%s устарел: выполните make rbac-matrix", out)
		}
		return nil
	}
	return os.WriteFile(out, []byte(md), 0o644) //nolint:gosec // G306: документ репозитория, не секрет
}

func readLimited(path string) ([]byte, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: путь задаёт разработчик флагом
	if err != nil {
		return nil, err
	}
	if len(b) > maxSpecSize {
		return nil, fmt.Errorf("%s: больше %d байт", path, maxSpecSize)
	}
	return b, nil
}

// Operation — операция API управления.
type Operation struct {
	Method     string // в верхнем регистре
	Path       string
	Permission string // пусто — открытая операция (security: [])
}

var methods = []string{"get", "post", "put", "patch", "delete"}

// serverOwned — пути, которые обслуживает aisec-server.
func serverOwned(p string) bool {
	return p == "/healthz" || p == "/readyz" || strings.HasPrefix(p, "/api/") || strings.HasPrefix(p, "/internal/")
}

// Operations разбирает операции сервера. Защищённая операция без
// x-permission или с разрешением не из каталога — ошибка.
func Operations(spec []byte) ([]Operation, error) {
	var doc struct {
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("разбор спецификации: %w", err)
	}
	var ops []Operation
	var errs []error
	for path, item := range doc.Paths {
		if !serverOwned(path) {
			continue
		}
		for _, m := range methods {
			node, ok := item[m]
			if !ok {
				continue
			}
			var op struct {
				Security   *[]map[string]any `yaml:"security"`
				Permission string            `yaml:"x-permission"`
			}
			if err := node.Decode(&op); err != nil {
				return nil, fmt.Errorf("%s %s: %w", m, path, err)
			}
			o := Operation{Method: strings.ToUpper(m), Path: path, Permission: op.Permission}
			public := op.Security != nil && len(*op.Security) == 0
			switch {
			case public && o.Permission != "":
				errs = append(errs, fmt.Errorf("%s %s: x-permission у открытой операции", o.Method, path))
			case !public && o.Permission == "":
				errs = append(errs, fmt.Errorf("%s %s: нет x-permission", o.Method, path))
			case !public && o.Permission != auth.PermSelf && o.Permission != auth.PermSession:
				if _, ok := auth.LookupPermission(o.Permission); !ok {
					errs = append(errs, fmt.Errorf("%s %s: разрешения %q нет в каталоге", o.Method, path, o.Permission))
				}
			}
			ops = append(ops, o)
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	slices.SortFunc(ops, func(a, b Operation) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return slices.Index(methods, strings.ToLower(a.Method)) - slices.Index(methods, strings.ToLower(b.Method))
	})
	return ops, nil
}

// Cell — доступ роли к операции: «да», «свои» (только свои объекты) или «—».
func Cell(g auth.Grants, perm string) string {
	switch g.Scope(perm) {
	case auth.ScopeAll:
		return "да"
	case auth.ScopeOwn:
		return "свои"
	}
	return "—"
}

// Render — матрица в Markdown.
func Render(ops []Operation, roles []auth.RoleDef) string {
	var b strings.Builder
	b.WriteString("# Матрица «роль × эндпоинт» (УПД.3)\n\n")
	b.WriteString("Файл создан командой `make rbac-matrix` (`tools/rbac-matrix`) из `api/openapi.yaml` (расширение `x-permission`) ")
	b.WriteString("и прав предустановленных ролей (`internal/auth/permissions.go`). Руками не правится: тест `tools/rbac-matrix` падает, если файл устарел.\n\n")
	b.WriteString("«да» — доступ есть; «свои» — только к своим объектам (УПД.8); «—» — отказ 403. ")
	b.WriteString("Каждую пару проверяет тест `TestRBACMatrixDenials` (`internal/api`): для «—» — ответ 403 и запись `access.denied` в журнале аудита, ")
	b.WriteString("для остальных — ни 401, ни 403. Тот же тест проверяет свою роль без разрешений: ей доступны только эндпоинты с `self` и `session`. ")
	b.WriteString("Сессия с временным или истёкшим паролем получает только `self` и `session`, сессия до второго фактора — только `session`, независимо от роли.\n\n")
	b.WriteString("Колонка «токен API» — можно ли выдать разрешение токену API (ИАФ.9, `auth.TokenGrantable`): функции безопасности, свои данные, сами токены и загрузка лицензии токену недоступны. ")
	b.WriteString("Права токена — пересечение его области с правами роли владельца; эти пары проверяет `TestRBACMatrixTokenDenials`.\n\n")
	b.WriteString("## Защищённые эндпоинты\n\n| Метод | Путь | Разрешение |")
	for _, r := range roles {
		b.WriteString(" " + string(r.ID) + " |")
	}
	b.WriteString(" токен API |\n|---|---|---|")
	b.WriteString(strings.Repeat("---|", len(roles)+1))
	b.WriteString("\n")
	var public []Operation
	for _, o := range ops {
		if o.Permission == "" {
			public = append(public, o)
			continue
		}
		fmt.Fprintf(&b, "| %s | `%s` | `%s` |", o.Method, o.Path, o.Permission)
		for _, r := range roles {
			// Права полностью вошедшего пользователя: роль, self и session.
			g := auth.SessionGrants(auth.Caller{Session: auth.Session{State: auth.SessionActive}}, r.Grants)
			b.WriteString(" " + Cell(g, o.Permission) + " |")
		}
		token := "—"
		if auth.TokenGrantable(o.Permission) {
			token = "да"
		}
		b.WriteString(" " + token + " |\n")
	}
	b.WriteString("\n## Открытые эндпоинты (без аутентификации)\n\n")
	for _, o := range public {
		fmt.Fprintf(&b, "- %s `%s`\n", o.Method, o.Path)
	}
	b.WriteString("\n## Предустановленные роли\n\n| Роль | Название | Второй фактор обязателен |\n|---|---|---|\n")
	for _, r := range roles {
		mfa := "нет"
		if r.MFARequired {
			mfa = "да"
		}
		fmt.Fprintf(&b, "| %s | %s | %s |\n", r.ID, r.DisplayName, mfa)
	}
	return b.String()
}
