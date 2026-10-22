package versions

import (
	"slices"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Категории детектора lists задают словари приложения (ТЗ 5.2), а политика
// в сервере не привязана к одному приложению. Поэтому при сохранении
// категории вида lists.* принимаются любые, остальные проверяются строго.
// Есть ли такой словарь у приложения, проверяют песочница с приложением и
// сборка пакета для шлюзов (задача 2.13); шлюз без словаря не примет
// политику при запуске.

// specCatalog — реестр, в котором детектор lists выдаёт и категории lists.*
// из правил спецификации s.
func specCatalog(c policy.Catalog, s *policy.Spec) policy.Catalog {
	var extra []string
	for _, r := range s.Rules {
		if r.Detector != lists.ID {
			continue
		}
		for _, cat := range r.Categories {
			if strings.HasPrefix(cat, "lists.") && !slices.Contains(extra, cat) {
				extra = append(extra, cat)
			}
		}
	}
	if len(extra) == 0 {
		return c
	}
	return listsCatalog{Catalog: c, extra: extra}
}

type listsCatalog struct {
	policy.Catalog
	extra []string
}

func (c listsCatalog) Get(id string) (detect.Detector, bool) {
	d, ok := c.Catalog.Get(id)
	if !ok || id != lists.ID {
		return d, ok
	}
	return listsCategories{Detector: d, extra: c.extra}, true
}

// listsCategories — детектор lists с дополнительными категориями.
type listsCategories struct {
	detect.Detector
	extra []string
}

func (l listsCategories) Categories() []string {
	var out []string
	if cz, ok := l.Detector.(detect.Categorizer); ok {
		out = slices.Clone(cz.Categories())
	}
	for _, c := range l.extra {
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// Check проверяет спецификацию по реестру детекторов так же, как при
// сохранении версии: категории lists.* — любые, остальные — строго. Нужна
// для политик, попадающих в БД не через сервис, — из резервной копии
// (В22 ревью 2.r4).
func Check(spec *policy.Spec, c policy.Catalog) error {
	_, err := policy.Compile(spec, specCatalog(c, spec))
	return err
}
