// Пакет components — реестр заимствованных компонентов docs/cert/components.yaml
// (ТЗ, 8.6, раздел 9): загрузка со строгой проверкой схемы, разбор
// vendor/modules.txt и выражений лицензий SPDX. Используется утилитами
// license-check и sbom.
package components

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// MaxFileSize ограничивает размер реестра и modules.txt.
const MaxFileSize = 4 << 20

// Типы компонентов.
const (
	TypeGoModule     = "go-module"     // модуль Go из vendor/
	TypeToolchain    = "toolchain"     // Go toolchain и стандартная библиотека
	TypeTool         = "tool"          // инструмент сборочной среды
	TypeImage        = "image"         // образ контейнера
	TypeGitHubAction = "github-action" // шаг CI
)

// Области применения.
const (
	ScopeProduct = "product" // попадает в поставку и в SBOM продукта
	ScopeBuild   = "build"   // только сборочная среда (ADR-0003)
)

// Component — запись реестра.
type Component struct {
	Name             string `yaml:"name"`
	Version          string `yaml:"version"`
	Type             string `yaml:"type"`
	Scope            string `yaml:"scope"`
	Purpose          string `yaml:"purpose"`
	License          string `yaml:"license"`
	LicenseDecision  string `yaml:"license_decision"`
	Repository       string `yaml:"repository"`
	AttackSurface    *bool  `yaml:"attack_surface"`
	SecurityFunction *bool  `yaml:"security_function"`
	ProvidedBy       string `yaml:"provided_by"`
	Justification    string `yaml:"justification"`
	Decision         string `yaml:"decision"`
	Decided          string `yaml:"decided"`
	MakefileVar      string `yaml:"makefile_var"`
}

// Registry — весь реестр.
type Registry struct {
	SchemaVersion int         `yaml:"schema_version"`
	Components    []Component `yaml:"components"`
}

var (
	validTypes  = map[string]bool{TypeGoModule: true, TypeToolchain: true, TypeTool: true, TypeImage: true, TypeGitHubAction: true}
	validScopes = map[string]bool{ScopeProduct: true, ScopeBuild: true}
	makeVarRe   = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
)

// Parse разбирает реестр. Неизвестные поля, лишние документы и пропуски
// обязательных полей — ошибка.
func Parse(r io.Reader) (*Registry, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("реестр больше %d байт", MaxFileSize)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var reg Registry
	if err := dec.Decode(&reg); err != nil {
		return nil, fmt.Errorf("разбор реестра: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("разбор реестра: ожидается один YAML-документ")
	}
	if err := reg.validate(); err != nil {
		return nil, err
	}
	return &reg, nil
}

func (r *Registry) validate() error {
	if r.SchemaVersion != 1 {
		return fmt.Errorf("schema_version: ожидается 1, получено %d", r.SchemaVersion)
	}
	seen := map[string]bool{}
	var errs []error
	for i, c := range r.Components {
		id := fmt.Sprintf("components[%d] (%s)", i, c.Name)
		req := map[string]string{
			"name": c.Name, "version": c.Version, "type": c.Type, "scope": c.Scope,
			"purpose": c.Purpose, "license": c.License, "repository": c.Repository,
			"provided_by": c.ProvidedBy, "justification": c.Justification,
			"decision": c.Decision, "decided": c.Decided,
		}
		for _, k := range []string{"name", "version", "type", "scope", "purpose", "license", "repository", "provided_by", "justification", "decision", "decided"} {
			if strings.TrimSpace(req[k]) == "" {
				errs = append(errs, fmt.Errorf("%s: не заполнено поле %s", id, k))
			}
		}
		if c.AttackSurface == nil {
			errs = append(errs, fmt.Errorf("%s: не заполнено поле attack_surface", id))
		}
		if c.SecurityFunction == nil {
			errs = append(errs, fmt.Errorf("%s: не заполнено поле security_function", id))
		}
		if c.Type != "" && !validTypes[c.Type] {
			errs = append(errs, fmt.Errorf("%s: неизвестный type %q", id, c.Type))
		}
		if c.Scope != "" && !validScopes[c.Scope] {
			errs = append(errs, fmt.Errorf("%s: неизвестный scope %q", id, c.Scope))
		}
		if c.Decided != "" {
			if _, err := time.Parse(time.DateOnly, c.Decided); err != nil {
				errs = append(errs, fmt.Errorf("%s: decided — дата в формате ГГГГ-ММ-ДД", id))
			}
		}
		if c.Repository != "" && !strings.HasPrefix(c.Repository, "https://") {
			errs = append(errs, fmt.Errorf("%s: repository — ссылка https://", id))
		}
		if c.MakefileVar != "" && !makeVarRe.MatchString(c.MakefileVar) {
			errs = append(errs, fmt.Errorf("%s: makefile_var — имя переменной Makefile", id))
		}
		key := c.Type + " " + c.Name
		if seen[key] {
			errs = append(errs, fmt.Errorf("%s: компонент указан дважды", id))
		}
		seen[key] = true
	}
	return errors.Join(errs...)
}

// Module — модуль из vendor/modules.txt.
type Module struct {
	Path    string
	Version string
	// Replace — замена из go.mod («=> …»), если есть.
	Replace string
}

// ParseModulesTxt разбирает vendor/modules.txt: строки вида
// «# путь версия [=> замена]». Строки пакетов и «## explicit» пропускаются.
func ParseModulesTxt(data []byte) ([]Module, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("modules.txt больше %d байт", MaxFileSize)
	}
	var out []Module
	for n, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue
		}
		f := strings.Fields(line[2:])
		switch {
		case len(f) == 2:
			out = append(out, Module{Path: f[0], Version: f[1]})
		case len(f) >= 3 && f[1] == "=>":
			// Замена без версии у исходного модуля: «# путь => замена [версия]».
			out = append(out, Module{Path: f[0], Replace: strings.Join(f[2:], " ")})
		case len(f) >= 4 && f[2] == "=>":
			out = append(out, Module{Path: f[0], Version: f[1], Replace: strings.Join(f[3:], " ")})
		default:
			return nil, fmt.Errorf("modules.txt:%d: неожиданная строка %q", n+1, line)
		}
	}
	return out, nil
}
