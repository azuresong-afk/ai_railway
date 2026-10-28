package compliance

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

// Встроенная база: requirements/*.yaml входит в бинарник сервера (go:embed)
// и поэтому покрыта хешем исполняемого файла в манифесте целостности
// (ОЦЛ.1); отдельной записи в манифесте не требует.
//
//go:embed requirements/*.yaml
var embeddedFS embed.FS

var (
	embeddedOnce sync.Once
	embeddedBase *Base
	embeddedErr  error
)

// Embedded возвращает встроенную базу. Файлы requirements/*.yaml —
// части одной базы: общие версия и дата, уникальные ID пунктов.
func Embedded() (*Base, error) {
	embeddedOnce.Do(func() { embeddedBase, embeddedErr = loadFS(embeddedFS, "requirements") })
	return embeddedBase, embeddedErr
}

func loadFS(fsys fs.FS, dir string) (*Base, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("база требований: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	var parts []*Base
	for _, n := range names {
		data, err := fs.ReadFile(fsys, dir+"/"+n)
		if err != nil {
			return nil, fmt.Errorf("база требований: %w", err)
		}
		b, err := ParseBase(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		parts = append(parts, b)
	}
	return merge(parts)
}

// merge объединяет части встроенной базы в одну.
func merge(parts []*Base) (*Base, error) {
	if len(parts) == 0 {
		return nil, errors.New("база требований: нет файлов requirements/*.yaml")
	}
	out := &Base{Format: BaseFormat, Version: parts[0].Version, Date: parts[0].Date}
	titles := map[string]string{}
	for _, p := range parts {
		if p.Version != out.Version || p.Date != out.Date {
			return nil, errors.New("база требований: у файлов requirements/*.yaml разные version или date")
		}
		for _, s := range p.Sources {
			if t, ok := titles[s.ID]; ok {
				if t != s.Title {
					return nil, fmt.Errorf("база требований: источник %s назван по-разному в разных файлах", s.ID)
				}
				continue
			}
			titles[s.ID] = s.Title
			out.Sources = append(out.Sources, s)
		}
		out.Requirements = append(out.Requirements, p.Requirements...)
	}
	if err := out.validate(); err != nil {
		return nil, fmt.Errorf("база требований: %w", err)
	}
	return out, nil
}
