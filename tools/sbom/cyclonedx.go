package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

// Структуры CycloneDX 1.6 — только используемые поля.

// BOM — документ CycloneDX.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

// Metadata — сведения о документе и продукте.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     Tools     `json:"tools"`
	Component Component `json:"component"`
}

// Tools — чем сформирован документ.
type Tools struct {
	Components []Component `json:"components"`
}

// Component — компонент.
type Component struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	Description        string        `json:"description,omitempty"`
	PURL               string        `json:"purl,omitempty"`
	Hashes             []Hash        `json:"hashes,omitempty"`
	Licenses           []License     `json:"licenses,omitempty"`
	ExternalReferences []ExternalRef `json:"externalReferences,omitempty"`
	Properties         []Property    `json:"properties,omitempty"`
}

// Hash — хеш компонента.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// License — лицензия в виде выражения SPDX.
type License struct {
	Expression string `json:"expression"`
}

// ExternalRef — внешняя ссылка.
type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property — свойство «имя — значение».
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency — связь «компонент зависит от».
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// Свойства по методике ФСТЭК (ТЗ, 8.6). Формат значений сверяется с
// приложением 1 методики до этапа 6.
const (
	propAttackSurface    = "GOST:attack_surface"
	propSecurityFunction = "GOST:security_function"
	propProvidedBy       = "GOST:provided_by"
	propGoModuleHash     = "go:module_hash_h1"
	productRef           = "aisec"
	productName          = "AISec"
)

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// registryEntry находит запись реестра по типу и имени (для модулей) либо
// единственную запись типа toolchain.
func registryEntry(reg *components.Registry, typ, name string) (components.Component, bool) {
	for _, c := range reg.Components {
		if c.Type != typ || c.Scope != components.ScopeProduct {
			continue
		}
		if typ == components.TypeToolchain || c.Name == name {
			return c, true
		}
	}
	return components.Component{}, false
}

func fromRegistry(c components.Component, typ, ref, name, version, purl string) Component {
	out := Component{
		Type: typ, BOMRef: ref, Name: name, Version: version, PURL: purl,
		Description: c.Purpose,
		Licenses:    []License{{Expression: c.License}},
		Properties: []Property{
			{propAttackSurface, yesNo(*c.AttackSurface)},
			{propSecurityFunction, yesNo(*c.SecurityFunction)},
			{propProvidedBy, c.ProvidedBy},
		},
	}
	if c.Repository != "" {
		out.ExternalReferences = []ExternalRef{{Type: "vcs", URL: c.Repository}}
	}
	return out
}

// Build собирает документ из сведений о бинарниках и реестра.
func Build(reg *components.Registry, bins []Binary, version string, ts time.Time, hasher aisecCrypto.Hasher) (*BOM, error) {
	var errs []error
	goVersion := ""
	modules := map[string]Dep{}
	for _, b := range bins {
		if goVersion == "" {
			goVersion = b.GoVersion
		} else if goVersion != b.GoVersion {
			errs = append(errs, fmt.Errorf("бинарники собраны разными версиями Go: %s и %s", goVersion, b.GoVersion))
		}
		for _, d := range b.Deps {
			if prev, ok := modules[d.Path]; ok && prev.Version != d.Version {
				errs = append(errs, fmt.Errorf("модуль %s в разных версиях: %s и %s", d.Path, prev.Version, d.Version))
			}
			modules[d.Path] = d
		}
	}

	var comps []Component
	std, ok := registryEntry(reg, components.TypeToolchain, "")
	switch {
	case !ok:
		errs = append(errs, errors.New("в реестре нет Go toolchain со scope: product"))
	case std.Version != goVersion:
		errs = append(errs, fmt.Errorf("бинарники собраны %s, а в реестре %s", goVersion, std.Version))
	default:
		comps = append(comps, fromRegistry(std, "library", "stdlib", "stdlib", goVersion, "pkg:golang/stdlib@"+goVersion))
	}

	paths := make([]string, 0, len(modules))
	for p := range modules {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	moduleRefs := map[string]string{}
	for _, p := range paths {
		d := modules[p]
		c, ok := registryEntry(reg, components.TypeGoModule, p)
		if !ok {
			errs = append(errs, fmt.Errorf("модуля %s нет в реестре со scope: product", p))
			continue
		}
		if c.Version != d.Version {
			errs = append(errs, fmt.Errorf("модуль %s: в бинарнике %s, в реестре %s", p, d.Version, c.Version))
		}
		purl := "pkg:golang/" + p + "@" + d.Version
		comp := fromRegistry(c, "library", purl, p, d.Version, purl)
		if h, err := h1ToSHA256(d.Sum); err == nil {
			comp.Hashes = []Hash{{Alg: "SHA-256", Content: h}}
			comp.Properties = append(comp.Properties, Property{propGoModuleHash, d.Sum})
		} else {
			errs = append(errs, fmt.Errorf("модуль %s: %w", p, err))
		}
		moduleRefs[p] = purl
		comps = append(comps, comp)
	}

	var deps []Dependency
	var binRefs []string
	for _, b := range bins {
		ref := "file:" + b.Name
		binRefs = append(binRefs, ref)
		comps = append(comps, Component{
			Type: "file", BOMRef: ref, Name: b.Name, Version: version,
			Hashes: []Hash{{Alg: "SHA-256", Content: b.SHA256}},
		})
		dep := Dependency{Ref: ref, DependsOn: []string{"stdlib"}}
		for _, d := range b.Deps {
			if r, ok := moduleRefs[d.Path]; ok {
				dep.DependsOn = append(dep.DependsOn, r)
			}
		}
		sort.Strings(dep.DependsOn)
		deps = append(deps, dep)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	deps = append([]Dependency{{Ref: productRef, DependsOn: binRefs}}, deps...)

	bom := &BOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: Metadata{
			Timestamp: ts.Format(time.RFC3339),
			Tools: Tools{Components: []Component{{
				Type: "application", Name: "aisec-sbom", Version: version,
				Description: "tools/sbom из репозитория продукта",
			}}},
			Component: Component{Type: "application", BOMRef: productRef, Name: productName, Version: version},
		},
		Components:   comps,
		Dependencies: deps,
	}
	bom.SerialNumber = serialFor(bom, hasher)
	return bom, nil
}

// h1ToSHA256 переводит хеш модуля из go.sum («h1:» + base64 SHA-256 по дереву
// файлов модуля) в шестнадцатеричный вид для поля hashes.
func h1ToSHA256(sum string) (string, error) {
	b64, ok := strings.CutPrefix(sum, "h1:")
	if !ok {
		return "", fmt.Errorf("хеш модуля %q не в формате h1", sum)
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("хеш модуля %q повреждён", sum)
	}
	return hex.EncodeToString(raw), nil
}

// serialFor выводит серийный номер из содержимого документа: одинаковый
// состав — одинаковый номер, что нужно для воспроизводимой сборки.
func serialFor(bom *BOM, hasher aisecCrypto.Hasher) string {
	var buf strings.Builder
	buf.WriteString(bom.Metadata.Component.Version + "|" + bom.Metadata.Timestamp + "|")
	for _, c := range bom.Components {
		buf.WriteString(c.BOMRef + "|" + c.Version + "|")
		for _, x := range c.Hashes {
			buf.WriteString(x.Content + "|")
		}
	}
	s := hasher.Sum([]byte(buf.String()))
	s[6] = (s[6] & 0x0f) | 0x80 // версия 8 — UUID, определяемый приложением (RFC 9562)
	s[8] = (s[8] & 0x3f) | 0x80 // вариант RFC 9562
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// Check проверяет обязательные для сертификации поля: у каждого компонента,
// кроме файлов, есть версия, лицензия, purl и свойства GOST; у файлов — хеш.
func Check(bom *BOM) error {
	var errs []error
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.6" {
		errs = append(errs, fmt.Errorf("ожидается CycloneDX 1.6, получено %s %s", bom.BOMFormat, bom.SpecVersion))
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		errs = append(errs, errors.New("нет serialNumber"))
	}
	for _, c := range bom.Components {
		id := c.BOMRef
		if c.Type == "file" {
			if len(c.Hashes) == 0 {
				errs = append(errs, fmt.Errorf("%s: у файла нет хеша", id))
			}
			continue
		}
		if c.Version == "" || c.PURL == "" || len(c.Licenses) == 0 || c.Licenses[0].Expression == "" {
			errs = append(errs, fmt.Errorf("%s: нет версии, purl или лицензии", id))
		}
		props := map[string]string{}
		for _, p := range c.Properties {
			props[p.Name] = p.Value
		}
		for _, name := range []string{propAttackSurface, propSecurityFunction, propProvidedBy} {
			if strings.TrimSpace(props[name]) == "" {
				errs = append(errs, fmt.Errorf("%s: нет свойства %s", id, name))
			}
		}
	}
	return errors.Join(errs...)
}
