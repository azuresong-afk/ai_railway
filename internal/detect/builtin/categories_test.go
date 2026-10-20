package builtin

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

// TestCategoriesComplete — каждый встроенный детектор сообщает свои
// категории (detect.Categorizer), и на корпусах не встречается категория вне
// списка: ни найденная, ни ожидаемая. По этому списку политика отвергает
// правило с опечаткой в категории (ревью 1.17–1.21, п. 7), поэтому неполный
// список отверг бы верное правило.
func TestCategoriesComplete(t *testing.T) {
	for _, d := range All() {
		cz, ok := d.(detect.Categorizer)
		if !ok {
			t.Errorf("%s: не реализует detect.Categorizer", d.ID())
			continue
		}
		cats := cz.Categories()
		if len(cats) == 0 {
			t.Errorf("%s: пустой список категорий", d.ID())
		}
		samples, err := corpus.Load(filepath.Join("..", "..", "..", "testdata", "corpus", d.ID()))
		if err != nil {
			t.Fatal(err)
		}
		rep, err := corpus.Evaluate(context.Background(), d, samples, 5*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		for c := range rep.ByCategory {
			if !slices.Contains(cats, c) {
				t.Errorf("%s: категория %s на корпусе, но не в Categories()", d.ID(), c)
			}
		}
	}
}
