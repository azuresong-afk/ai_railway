package ml

import (
	"strings"
	"testing"
)

func TestEntityOf(t *testing.T) {
	for label, want := range map[string]struct {
		entity    string
		begin, ok bool
	}{
		"b-per": {"per", true, true},
		"i-per": {"per", false, true},
		"addr":  {"addr", false, true},
		"o":     {"", false, false},
		"b-":    {"", true, false},
		"i-o":   {"o", false, false},
	} {
		e, b, ok := EntityOf(label)
		if e != want.entity || b != want.begin || ok != want.ok {
			t.Errorf("%q: %q %v %v", label, e, b, ok)
		}
	}
	info := ModelInfo{Labels: []string{"o", "b-per", "i-per", "loc"}}
	if !info.HasLabel("per") || !info.HasLabel("loc") || info.HasLabel("org") {
		t.Fatal("HasLabel")
	}
}

// tok — токен text[start:start+len(w)] с меткой.
func tok(label string, score float64, start int, w string) TokenLabel {
	return TokenLabel{Label: label, Score: score, Start: start, End: start + len(w)}
}

// Склейка BIO (задача 4.20): начало и продолжение, части одного слова,
// пропущенное «b-», смена сущности, служебные токены и «o».
// Покрывает: DM-31 (NER), DM-09 (NER).
func TestMergeTokens(t *testing.T) {
	text := "Иванову Петру из ООО Ромашка, г. Тверь"
	at := func(w string) int { return strings.Index(text, w) }
	toks := []TokenLabel{
		{Label: "o"},                            // [CLS]
		tok("b-per", 0.9, at("Ив"), "Ив"),       // начало имени
		tok("b-per", 0.8, at("анову"), "анову"), // часть того же слова вплотную
		tok("i-per", 0.95, at("Петру"), "Петру"),
		tok("o", 0.99, at("из"), "из"),
		tok("i-org", 0.7, at("ООО"), "ООО"), // пропущено «b-» — открывает фрагмент
		tok("i-org", 0.9, at("Ромашка"), "Ромашка"),
		tok("o", 0.99, at(","), ","),
		tok("b-loc", 0.6, at("г."), "г."),
		tok("b-loc", 0.6, at("Тверь"), "Тверь"), // «b-» после пробела — новый фрагмент
		{Label: "o"}, // [SEP]
	}
	got, cut := MergeTokens(toks)
	if cut {
		t.Fatal("ложный признак усечения")
	}
	want := []struct {
		label, frag string
		score       float64
	}{{"per", "Иванову Петру", 0.8}, {"org", "ООО Ромашка", 0.7}, {"loc", "г.", 0.6}, {"loc", "Тверь", 0.6}}
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i, w := range want {
		if got[i].Label != w.label || text[got[i].Start:got[i].End] != w.frag || got[i].Score != w.score {
			t.Errorf("%d: %+v %q, ожидалось %+v", i, got[i], text[got[i].Start:got[i].End], w)
		}
	}
	// 4В33: неуверенный кусок (ниже MinTokenScore) — граница фрагмента, а не
	// наименьшая оценка всего имени: «Иванов Пётр Сер» и «вич» остаются
	// находками, «##гее» шлюз закроет расширением до слова.
	name := "Иванов Пётр Сергеевич"
	nt := func(w string) int { return strings.Index(name, w) }
	unsure, _ := MergeTokens([]TokenLabel{
		tok("b-per", 0.99, nt("Иванов"), "Иванов"), tok("i-per", 0.97, nt("Пётр"), "Пётр"),
		tok("i-per", 0.9, nt("Сер"), "Сер"), tok("i-per", 0.45, nt("гее"), "гее"), tok("i-per", 0.9, nt("вич"), "вич"),
	})
	if len(unsure) != 2 || name[unsure[0].Start:unsure[0].End] != "Иванов Пётр Сер" || unsure[0].Score < MinTokenScore ||
		name[unsure[1].Start:unsure[1].End] != "вич" || unsure[1].Score < MinTokenScore {
		t.Fatalf("неуверенный кусок имени: %+v", unsure)
	}
	// Позиции назад (неверный токенизатор) фрагмент не продолжают.
	back, _ := MergeTokens([]TokenLabel{tok("b-per", 1, 10, "abcd"), tok("i-per", 1, 5, "abcd")})
	if len(back) != 1 || back[0].End != 14 {
		t.Fatalf("позиции назад: %+v", back)
	}
}

// Пределы: фрагмент не длиннее MaxSpanBytes, находок не больше MaxFindings,
// а сверх предела — признак усечения (имена после 512-й находки не уходят
// провайдеру незаметно).
// Покрывает: DM-31 (NER), DM-09 (NER).
func TestMergeTokensLimits(t *testing.T) {
	var long []TokenLabel
	for i := range 400 { // «слово » × 400 — 2 400 байт под одной меткой
		long = append(long, TokenLabel{Label: "i-addr", Score: 1, Start: 6 * i, End: 6*i + 5})
	}
	got, cut := MergeTokens(long)
	if cut || len(got) < 4 || got[0].Start != 0 || got[len(got)-1].End != 6*399+5 {
		t.Fatalf("длинный фрагмент: %+v", got)
	}
	for _, s := range got {
		if s.End-s.Start > MaxSpanBytes {
			t.Fatalf("фрагмент %d байт", s.End-s.Start)
		}
	}
	var many []TokenLabel
	for i := range MaxFindings + 10 {
		many = append(many, TokenLabel{Label: "b-per", Score: 1, Start: 4 * i, End: 4*i + 2})
	}
	if got, cut := MergeTokens(many); len(got) != MaxFindings || !cut {
		t.Fatalf("предел находок: %d, усечение %v", len(got), cut)
	}
	if got, cut := MergeTokens(many[:MaxFindings]); len(got) != MaxFindings || cut {
		t.Fatalf("ровно на пределе: %d, усечение %v", len(got), cut)
	}
}

// FuzzMergeTokens — постобработка разметки на произвольных метках и
// позициях: находки по порядку, не пересекаются, границы — границы токенов,
// метка — сущность одного из токенов, оценка не выше оценок токенов,
// фрагмент длиннее MaxSpanBytes — только из одного токена.
// Покрывает: DM-31 (NER), DM-09 (NER).
func FuzzMergeTokens(f *testing.F) {
	f.Add([]byte{1, 0, 4, 200, 2, 1, 5, 100, 0, 1, 1, 255, 3, 0, 6, 50})
	f.Add([]byte{4, 0, 255, 255, 4, 0, 255, 255, 5, 0, 3, 10})
	labels := []string{"o", "b-per", "i-per", "b-org", "i-addr", "addr", "b-", "i-o"}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4*4096 {
			return
		}
		var toks []TokenLabel
		pos := 0
		for i := 0; i+4 <= len(data); i += 4 {
			gap, n := int(data[i+1])-8, int(data[i+2])*3-16 // отрицательные — назад и пустые
			start := pos + gap
			toks = append(toks, TokenLabel{Label: labels[int(data[i])%len(labels)], Score: float64(data[i+3]) / 255,
				Start: start, End: start + n})
			pos = max(pos, start+max(n, 0))
		}
		got, cut := MergeTokens(toks)
		if len(got) > MaxFindings || cut && len(got) != MaxFindings {
			t.Fatalf("находок %d, усечение %v", len(got), cut)
		}
		starts, ends := map[int]bool{}, map[int]bool{}
		single := map[[2]int]bool{}
		for _, tk := range toks {
			starts[tk.Start], ends[tk.End] = true, true
			single[[2]int{tk.Start, tk.End}] = true
		}
		prev := -1 << 62
		for _, s := range got {
			if s.End <= s.Start || s.Start < prev || !starts[s.Start] || !ends[s.End] {
				t.Fatalf("фрагмент %+v (предыдущий конец %d)", s, prev)
			}
			if s.End-s.Start > MaxSpanBytes && !single[[2]int{s.Start, s.End}] {
				t.Fatalf("длинный фрагмент из нескольких токенов: %+v", s)
			}
			if s.Score < 0 || s.Score > 1 {
				t.Fatalf("оценка %v", s.Score)
			}
			if _, _, ok := EntityOf(s.Label); !ok || strings.HasPrefix(s.Label, "b-") {
				t.Fatalf("метка %q", s.Label)
			}
			prev = s.End
		}
	})
}
