package pii

import (
	"context"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

// Корпус детектора проходит с полнотой и точностью не ниже порогов из
// docs/detectors.md (сводная проверка — make detector-quality).
func TestCorpus(t *testing.T) {
	ss, err := corpus.Load("../../../testdata/corpus/pii.ru")
	if err != nil {
		t.Fatal(err)
	}
	rep, err := corpus.Evaluate(context.Background(), New(), ss, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("примеров %d, точность %.3f, полнота %.3f, ложные %v, пропуски %v", rep.Samples, rep.Total.Precision(), rep.Total.Recall(), rep.FalsePos, rep.Missed)
	if len(rep.Errors) > 0 {
		t.Fatalf("сбои: %v", rep.Errors)
	}
}
