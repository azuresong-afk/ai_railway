package pii

import (
	"context"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect/corpus"
)

// Корпус детектора проходит без сбоев, ложных срабатываний и пропусков:
// в docs/detectors.md зафиксированы точность и полнота 1,000, поэтому любая
// ошибка на корпусе — регрессия. Сводная проверка с порогами — make
// detector-quality; если в таблицу внесут значения ниже 1, здесь нужно
// перейти на те же пороги.
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
	if len(rep.Errors) > 0 || len(rep.FalsePos) > 0 || len(rep.Missed) > 0 {
		t.Fatalf("сбои %v, ложные срабатывания %v, пропуски %v", rep.Errors, rep.FalsePos, rep.Missed)
	}
}
