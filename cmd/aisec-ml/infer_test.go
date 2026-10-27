package main

import (
	"math"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/ml"
)

var clsSpec = ml.ModelSpec{ID: "injection", Version: "1.0", Task: ml.TaskClassification, Labels: []string{"injection", "benign"}, MaxTokens: 512}

func TestCheckIO(t *testing.T) {
	ins := []ioInfo{{Name: inputIDs, Kind: kindInt64, Dims: []int64{-1, -1}}, {Name: inputMask, Kind: kindInt64, Dims: []int64{-1, 512}}}
	outs := []ioInfo{{Name: outputLogits, Kind: kindFloat32, Dims: []int64{-1, 2}}}
	mio, err := checkIO(clsSpec, ins, outs)
	if err != nil || mio.TypeIDs || len(mio.Inputs) != 2 {
		t.Fatalf("%+v %v", mio, err)
	}
	withTypes := append(ins[:2:2], ioInfo{Name: inputTypeIDs, Kind: kindInt64, Dims: []int64{-1, -1}})
	if mio, err := checkIO(clsSpec, withTypes, outs); err != nil || !mio.TypeIDs {
		t.Fatalf("token_type_ids: %+v %v", mio, err)
	}
	ner := ml.ModelSpec{ID: "ner", Version: "1.0", Task: ml.TaskTokenClassification, Labels: []string{"O", "PER"}, MaxTokens: 512}
	if _, err := checkIO(ner, ins, []ioInfo{{Name: outputLogits, Kind: kindFloat32, Dims: []int64{-1, -1, 2}}}); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		spec      ml.ModelSpec
		ins, outs []ioInfo
	}{
		"нет маски":        {clsSpec, ins[:1], outs},
		"чужой вход":       {clsSpec, append(ins[:2:2], ioInfo{Name: "pixel_values", Kind: kindFloat32, Dims: []int64{-1, -1}}), outs},
		"вход float":       {clsSpec, []ioInfo{ins[0], {Name: inputMask, Kind: kindFloat32, Dims: []int64{-1, -1}}}, outs},
		"окно меньше":      {clsSpec, []ioInfo{ins[0], {Name: inputMask, Kind: kindInt64, Dims: []int64{-1, 128}}}, outs},
		"повтор входа":     {clsSpec, []ioInfo{ins[0], ins[0], ins[1]}, outs},
		"нет logits":       {clsSpec, ins, []ioInfo{{Name: "scores", Kind: kindFloat32, Dims: []int64{-1, 2}}}},
		"меток больше":     {clsSpec, ins, []ioInfo{{Name: outputLogits, Kind: kindFloat32, Dims: []int64{-1, 3}}}},
		"logits int64":     {clsSpec, ins, []ioInfo{{Name: outputLogits, Kind: kindInt64, Dims: []int64{-1, 2}}}},
		"разметка без O":   {ml.ModelSpec{Task: ml.TaskTokenClassification, Labels: []string{"PER", "LOC"}, MaxTokens: 512}, ins, []ioInfo{{Name: outputLogits, Kind: kindFloat32, Dims: []int64{-1, -1, 2}}}},
		"разметка 2 измер": {ner, ins, outs},
	} {
		if _, err := checkIO(tc.spec, tc.ins, tc.outs); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
}

func TestSoftmax(t *testing.T) {
	p, err := softmax([]float32{1000, 1000})
	if err != nil || math.Abs(p[0]-0.5) > 1e-9 {
		t.Fatalf("%v %v", p, err)
	}
	for _, bad := range [][]float32{nil, {float32(math.NaN())}, {float32(math.Inf(1)), 0}} {
		if _, err := softmax(bad); err == nil {
			t.Errorf("%v: принято", bad)
		}
	}
}

func TestClassify(t *testing.T) {
	offs := [][2]int{{0, 0}, {3, 9}, {10, 16}, {0, 0}}
	s, err := classify([]float32{2, 0}, clsSpec.Labels, offs)
	if err != nil || len(s) != 2 || s[0].Start != 3 || s[0].End != 16 || s[0].Score <= s[1].Score {
		t.Fatalf("%+v %v", s, err)
	}
	if _, err := classify([]float32{1}, clsSpec.Labels, offs); err == nil {
		t.Fatal("число выходов не совпало, но принято")
	}
	if s, err := classify([]float32{0, 0}, clsSpec.Labels, [][2]int{{0, 0}}); err != nil || s[0].Start != 0 || s[0].End != 0 {
		t.Fatalf("только служебные токены: %+v", s)
	}
}

func TestTokenSpans(t *testing.T) {
	labels := []string{"O", "PER", "LOC"}
	// [CLS] Иван Петров из Москвы [SEP]
	text := "Иван Петров из Москвы"
	offs := [][2]int{{0, 0}, {0, 8}, {9, 21}, {22, 26}, {27, 39}, {0, 0}}
	logits := []float32{
		9, 0, 0, // CLS
		0, 5, 0, // Иван — PER
		0, 3, 0, // Петров — PER
		5, 0, 0, // из — O
		0, 0, 4, // Москвы — LOC
		9, 0, 0, // SEP
	}
	s, err := tokenSpans(logits, labels, offs)
	if err != nil || len(s) != 2 {
		t.Fatalf("%+v %v", s, err)
	}
	if text[s[0].Start:s[0].End] != "Иван Петров" || s[0].Label != "PER" || text[s[1].Start:s[1].End] != "Москвы" {
		t.Fatalf("фрагменты: %+v", s)
	}
	if _, err := tokenSpans(logits[:5], labels, offs); err == nil {
		t.Fatal("неполный выход принят")
	}
	// Находок не больше предела протокола.
	n := ml.MaxFindings + 10
	many := make([]float32, 0, n*4)
	manyOffs := make([][2]int, 0, n*2)
	for i := range n { // PER, O, PER, O…
		many = append(many, 0, 1, 1, 0)
		manyOffs = append(manyOffs, [2]int{4 * i, 4*i + 1}, [2]int{4*i + 2, 4*i + 3})
	}
	if s, err := tokenSpans(many, []string{"O", "PER"}, manyOffs); err != nil || len(s) != ml.MaxFindings {
		t.Fatalf("предел находок: %d %v", len(s), err)
	}
}

func TestNoTokenizerIn418(t *testing.T) {
	if _, err := newTokenizer(clsSpec, []byte(`{"model":{"type":"WordPiece"}}`)); err == nil || !strings.Contains(err.Error(), "4.19") {
		t.Fatalf("токенизатор: %v", err)
	}
}

func TestEncodeInputs(t *testing.T) {
	in := encodeInputs(modelIO{TypeIDs: true}, []int64{101, 7, 102})
	if len(in[inputMask]) != 3 || in[inputMask][2] != 1 || len(in[inputTypeIDs]) != 3 || in[inputTypeIDs][0] != 0 {
		t.Fatalf("%v", in)
	}
}
