package inventory

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/cyclonedx"
)

// Выгрузка AI-BOM (ТЗ 5.11; задача 5.18 этапа 5, ADR-0029, п. 3): реестр ИИ
// в CycloneDX 1.6 (ML-BOM) общим кодировщиком internal/cyclonedx. Приложения
// — компоненты application с зависимостями от моделей и сервисов
// провайдеров, модели — machine-learning-model с вложенными файлами и
// хешами SHA-256, провайдеры — services с зоной доверия и адресом без
// учётных данных (схема, хост, порт). Ключи приложений не выгружаются.
// Каждая выгрузка пишет data.export (вид aibom, число компонентов) той же
// транзакцией, что читает реестр: без записи документ не выдаётся (DM-41).

const (
	// ExportKindAIBOM — вид выгрузки в записи data.export.
	ExportKindAIBOM = "aibom"
	// MaxAIBOMFiles — файлов моделей в одной выгрузке: при пределах реестра
	// документ иначе мог бы занять сотни мегабайт памяти сервера.
	MaxAIBOMFiles = 100_000
	// aibomProduct — имя установки в metadata.component.
	aibomProduct = "AISec"
	productRef   = "aisec"
)

// ErrExportTooLarge — файлов моделей больше MaxAIBOMFiles.
var ErrExportTooLarge = errors.New("слишком много файлов моделей для выгрузки")

// Snapshot — реестр для выгрузки: действующие приложения, провайдеры с
// адресом, модели с файлами и использование.
type Snapshot struct {
	Apps      []App
	Providers []Provider
	Models    []Model
	Usage     []Usage
}

// ExportAIBOM строит AI-BOM; version — версия выпуска сервера. Запись
// data.export фиксируется до выдачи документа.
func (s *Service) ExportAIBOM(ctx context.Context, by By, version string) (*cyclonedx.BOM, error) {
	var bom *cyclonedx.BOM
	now := s.now()
	err := s.store.Export(ctx, s.orgID, func(snap Snapshot) (audit.Entry, error) {
		bom = BuildAIBOM(snap, version, now)
		bom.SerialNumber = cyclonedx.SerialFor(bom, s.hasher)
		comps := countComponents(bom.Components)
		return audit.Entry{Actor: by.Actor, SourceIP: by.IP, Action: "data.export", Object: audit.Object{Type: "inventory", ID: ExportKindAIBOM},
			Result: audit.ResultSuccess, Details: map[string]any{
				"kind": ExportKindAIBOM, "format": "cyclonedx-1.6", "components": comps, "services": len(bom.Services),
				// rows — общее поле выгрузок для правила крупных выгрузок (DM-41).
				"rows": comps + len(bom.Services),
			}}, nil
	})
	if err != nil {
		return nil, err
	}
	return bom, nil
}

func countComponents(cs []cyclonedx.Component) int {
	n := len(cs)
	for _, c := range cs {
		n += countComponents(c.Components)
	}
	return n
}

func prop(name, value string) cyclonedx.Property { return cyclonedx.Property{Name: name, Value: value} }

// BuildAIBOM собирает документ без серийного номера (его задаёт
// ExportAIBOM). Порядок компонентов и связей детерминирован.
func BuildAIBOM(snap Snapshot, version string, ts time.Time) *cyclonedx.BOM {
	bom := &cyclonedx.BOM{
		BOMFormat: cyclonedx.BOMFormat, SpecVersion: cyclonedx.SpecVersion, Version: 1,
		Metadata: cyclonedx.Metadata{
			Timestamp: ts.UTC().Format(time.RFC3339),
			Tools: cyclonedx.Tools{Components: []cyclonedx.Component{{
				Type: "application", Name: "aisec-server", Version: version, Description: "выгрузка AI-BOM реестра ИИ",
			}}},
			Component: cyclonedx.Component{Type: "application", BOMRef: productRef, Name: aibomProduct, Version: version},
		},
		Components:   []cyclonedx.Component{},
		Dependencies: []cyclonedx.Dependency{},
	}

	providers := slices.Clone(snap.Providers)
	slices.SortFunc(providers, func(a, b Provider) int { return strings.Compare(a.Slug, b.Slug) })
	known := map[string]bool{}
	for _, p := range providers {
		known[p.Slug] = true
		zone := "internal"
		if p.External {
			zone = "external"
		}
		svc := cyclonedx.Service{BOMRef: providerRef(p.Slug), Name: p.Slug, Description: p.Name, TrustZone: zone,
			Properties: []cyclonedx.Property{prop("aisec:provider_type", p.Type)}}
		if ep := endpointOf(p.Endpoint); ep != "" {
			svc.Endpoints = []string{ep}
		}
		bom.Services = append(bom.Services, svc)
	}

	models := slices.Clone(snap.Models)
	slices.SortFunc(models, func(a, b Model) int {
		if c := strings.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	byPair := map[[2]string]string{}
	var modelDeps []cyclonedx.Dependency
	for _, m := range models {
		ref := modelRef(m.ID)
		byPair[[2]string{m.Provider, m.Name}] = ref
		c := cyclonedx.Component{Type: "machine-learning-model", BOMRef: ref, Name: m.Name, Version: m.Version,
			Description: firstNonEmpty(m.Title, m.Description), Publisher: m.Owner,
			Properties: []cyclonedx.Property{prop("aisec:kind", m.Kind), prop("aisec:origin", m.Origin), prop("aisec:status", m.Status)}}
		if m.Provider != "" {
			c.Properties = append(c.Properties, prop("aisec:provider", m.Provider))
			if known[m.Provider] {
				modelDeps = append(modelDeps, cyclonedx.Dependency{Ref: ref, DependsOn: []string{providerRef(m.Provider)}})
			}
		}
		files := slices.Clone(m.Files)
		slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
		for _, f := range files {
			fc := cyclonedx.Component{Type: "file", BOMRef: ref + "/file:" + f.Path, Name: f.Path,
				Properties: []cyclonedx.Property{prop("aisec:role", f.Role), prop("aisec:size", strconv.FormatInt(f.Size, 10))}}
			if f.HashAlg == HashAlg && len(f.Hash) == 32 {
				fc.Hashes = []cyclonedx.Hash{{Alg: HashAlg, Content: hex.EncodeToString(f.Hash)}}
			}
			c.Components = append(c.Components, fc)
		}
		bom.Components = append(bom.Components, c)
	}

	apps := slices.Clone(snap.Apps)
	slices.SortFunc(apps, func(a, b App) int { return strings.Compare(a.Slug, b.Slug) })
	uses := map[string][][2]string{}
	for _, u := range snap.Usage {
		uses[u.App] = append(uses[u.App], [2]string{u.Provider, u.Model})
	}
	product := cyclonedx.Dependency{Ref: productRef, DependsOn: []string{}}
	var appDeps []cyclonedx.Dependency
	for _, a := range apps {
		if a.Archived {
			continue
		}
		ref := appRef(a.Slug)
		product.DependsOn = append(product.DependsOn, ref)
		bom.Components = append(bom.Components, cyclonedx.Component{Type: "application", BOMRef: ref, Name: a.Slug, Description: a.Name,
			Properties: []cyclonedx.Property{prop("aisec:environment", a.Env), prop("aisec:department", a.Department)}})
		set := map[string]bool{}
		pairs := uses[a.Slug]
		for _, name := range a.Models {
			pairs = append(pairs, [2]string{a.Provider, name})
		}
		if known[a.Provider] {
			set[providerRef(a.Provider)] = true
		}
		for _, p := range pairs {
			if r, ok := byPair[p]; ok {
				set[r] = true
			}
			if known[p[0]] {
				set[providerRef(p[0])] = true
			}
		}
		deps := make([]string, 0, len(set))
		for r := range set {
			deps = append(deps, r)
		}
		slices.Sort(deps)
		appDeps = append(appDeps, cyclonedx.Dependency{Ref: ref, DependsOn: deps})
	}
	bom.Dependencies = append(bom.Dependencies, product)
	bom.Dependencies = append(bom.Dependencies, appDeps...)
	bom.Dependencies = append(bom.Dependencies, modelDeps...)
	return bom
}

func appRef(slug string) string      { return "app:" + slug }
func modelRef(id string) string      { return "model:" + id }
func providerRef(slug string) string { return "provider:" + slug }

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// endpointOf — адрес провайдера без учётных данных, пути и параметров:
// только схема, хост и порт; неразборчивый адрес — пусто.
func endpointOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	host, port := u.Hostname(), u.Port()
	if host == "" {
		return ""
	}
	if port == "" {
		port = "443"
		if u.Scheme == "http" {
			port = "80"
		}
	}
	return u.Scheme + "://" + net.JoinHostPort(host, port)
}
