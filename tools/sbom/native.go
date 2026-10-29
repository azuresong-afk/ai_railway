package main

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/azuresong-afk/ai_railway/tools/internal/components"
)

// AddNative добавляет в SBOM образа aisec-ml библиотеки C/C++ из реестра
// (type: native-library, ADR-0024): ONNX Runtime и статически встроенные в
// неё. Сведений о них в бинарнике нет — состав задаёт реестр, а хеши файлов
// библиотек — -file. Версия в реестре — «выпуск (коммит)» или коммит.
func AddNative(bom *BOM, reg *components.Registry) error {
	if len(bom.Dependencies) == 0 {
		return errors.New("в документе нет корня зависимостей")
	}
	seen := map[string]bool{}
	for _, c := range bom.Components {
		seen[c.BOMRef] = true
	}
	var refs []string
	for _, c := range reg.Components {
		if c.Type != components.TypeNative || c.Scope != components.ScopeProduct {
			continue
		}
		version, _, _ := strings.Cut(c.Version, " ")
		purl := "pkg:generic/" + url.PathEscape(c.Name) + "@" + url.PathEscape(version)
		if seen[purl] {
			return fmt.Errorf("библиотека %s указана дважды", c.Name)
		}
		seen[purl] = true
		comp := fromRegistry(c, "library", purl, c.Name, version, purl)
		if version != c.Version {
			comp.Properties = append(comp.Properties, Property{propNativeSource, c.Version})
		}
		bom.Components = append(bom.Components, comp)
		refs = append(refs, purl)
	}
	if len(refs) == 0 {
		return errors.New("в реестре нет библиотек native-library")
	}
	root := &bom.Dependencies[0]
	root.DependsOn = append(root.DependsOn, refs...)
	sort.Strings(root.DependsOn)
	return nil
}
