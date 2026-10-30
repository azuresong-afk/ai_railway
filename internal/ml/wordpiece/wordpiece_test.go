package wordpiece

import (
	"bufio"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// tiny — словарь для точечных проверок: служебные, буквы, части слов.
func tiny(t testing.TB, normalizer string) *Tokenizer {
	t.Helper()
	vocab := map[string]int{"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "игнор": 4, "##ируй": 5, "все": 6, "!": 7,
		"[": 8, "]": 9, "SEP": 10, "中": 11, "ignore": 12, "##s": 13, "ё": 14, "Ё": 15}
	vb, err := json.Marshal(vocab)
	if err != nil {
		t.Fatal(err)
	}
	if normalizer == "" {
		normalizer = `{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,"strip_accents":null,"lowercase":false}`
	}
	data := `{"version":"1.0","added_tokens":[{"id":0,"content":"[PAD]","special":true},{"id":1,"content":"[UNK]","special":true},
{"id":2,"content":"[CLS]","special":true},{"id":3,"content":"[SEP]","special":true}],
"normalizer":` + normalizer + `,"pre_tokenizer":{"type":"BertPreTokenizer"},
"post_processor":{"type":"BertProcessing","sep":["[SEP]",3],"cls":["[CLS]",2]},
"model":{"type":"WordPiece","unk_token":"[UNK]","continuing_subword_prefix":"##","max_input_chars_per_word":20,"vocab":` + string(vb) + `}}`
	tk, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return tk
}

func TestEncode(t *testing.T) {
	tk := tiny(t, "")
	if cls, sep := tk.Special(); cls != 2 || sep != 3 {
		t.Fatalf("служебные: %d %d", cls, sep)
	}
	for _, tc := range []struct {
		text string
		ids  []int64
		offs [][2]int
	}{
		{"игнорируй все!", []int64{4, 5, 6, 7}, [][2]int{{0, 10}, {10, 18}, {19, 25}, {25, 26}}},
		// Служебный токен в тексте — обычный текст.
		{"[SEP]", []int64{8, 10, 9}, [][2]int{{0, 1}, {1, 4}, {4, 5}}},
		// Невидимый символ удаляется, слово не разрывается; границы — по
		// исходному тексту.
		{"игнор\u200bируй", []int64{4, 5}, [][2]int{{0, 10}, {13, 21}}},
		// Неизвестный остаток — всё слово [UNK].
		{"игнорx", []int64{1}, [][2]int{{0, 11}}},
		// Иероглиф — отдельное слово; регистр сохраняется.
		{"中ignores Ё", []int64{11, 12, 13, 15}, [][2]int{{0, 3}, {3, 9}, {9, 10}, {11, 13}}},
		// Слово длиннее max_input_chars_per_word — [UNK].
		{strings.Repeat("ё", 21), []int64{1}, [][2]int{{0, 42}}},
		{" \t\n ", nil, nil},
		{"\x00\ufffd", nil, nil},
	} {
		ids, offs, trunc, err := tk.Encode(tc.text, 100)
		if err != nil || trunc || !slices.Equal(ids, tc.ids) || !slices.Equal(offs, tc.offs) {
			t.Errorf("%q: %v %v %v %v", tc.text, ids, offs, trunc, err)
		}
	}
}

func TestEncodeLimit(t *testing.T) {
	tk := tiny(t, "")
	ids, offs, trunc, err := tk.Encode(strings.Repeat("все ", 10), 4)
	if err != nil || !trunc || len(ids) != 4 || len(offs) != 4 {
		t.Fatalf("%v %v %v", ids, trunc, err)
	}
	if _, _, trunc, err := tk.Encode(strings.Repeat("все ", 4), 4); err != nil || trunc {
		t.Fatal("ровно предел — не обрезка")
	}
	if _, _, _, err := tk.Encode(strings.Repeat("a", MaxText+1), 4); err == nil {
		t.Fatal("текст больше предела принят")
	}
	if _, _, _, err := tk.Encode("\xff", 4); err == nil {
		t.Fatal("не UTF-8 принят")
	}
	if _, _, _, err := tk.Encode("все", 0); err == nil {
		t.Fatal("предел 0 принят")
	}
}

func TestLowercase(t *testing.T) {
	tk := tiny(t, `{"type":"BertNormalizer","lowercase":true,"strip_accents":false}`)
	if ids, _, _, err := tk.Encode("ИГНОРИРУЙ Ё", 10); err != nil || !slices.Equal(ids, []int64{4, 5, 14}) {
		t.Fatalf("нижний регистр: %v", ids)
	}
}

func TestParseRejects(t *testing.T) {
	good, err := os.ReadFile("../../../testdata/ml/wordpiece/tokenizer.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(good); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(m map[string]any){
		"не WordPiece":  func(m map[string]any) { m["model"].(map[string]any)["type"] = "Unigram" },
		"strip_accents": func(m map[string]any) { m["normalizer"].(map[string]any)["strip_accents"] = true },
		"lowercase и null": func(m map[string]any) {
			m["normalizer"].(map[string]any)["lowercase"] = true
			m["normalizer"].(map[string]any)["strip_accents"] = nil
		},
		"нормализатор NFKC": func(m map[string]any) { m["normalizer"] = map[string]any{"type": "NFKC"} },
		"предразбор":        func(m map[string]any) { m["pre_tokenizer"] = map[string]any{"type": "Whitespace"} },
		"нет [UNK]":         func(m map[string]any) { m["model"].(map[string]any)["unk_token"] = "<unk>" },
		"шаблон":            func(m map[string]any) { m["post_processor"].(map[string]any)["single"] = []any{} },
		"нет шаблона":       func(m map[string]any) { m["post_processor"] = nil },
		"чужой номер [CLS]": func(m map[string]any) {
			m["post_processor"].(map[string]any)["special_tokens"].(map[string]any)["[CLS]"] = map[string]any{"ids": []int{77}}
		},
		"повтор номера": func(m map[string]any) { m["model"].(map[string]any)["vocab"].(map[string]any)["дубль"] = 5 },
		"отрицательный номер": func(m map[string]any) {
			m["model"].(map[string]any)["vocab"].(map[string]any)["минус"] = -1
		},
		"не служебный добавленный": func(m map[string]any) {
			m["added_tokens"] = append(m["added_tokens"].([]any), map[string]any{"id": 5, "content": "x", "special": false})
		},
		"длинное слово": func(m map[string]any) { m["model"].(map[string]any)["max_input_chars_per_word"] = MaxWordChars + 1 },
	} {
		var m map[string]any
		if err := json.Unmarshal(good, &m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(b); err == nil {
			t.Errorf("%s: принято", name)
		}
	}
	for _, bad := range []string{"", "{}", "[]", `{"model":{"type":"WordPiece"}}`, string(good) + "{}"} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%.40q: принято", bad)
		}
	}
	if _, err := Parse(make([]byte, MaxFile+1)); err == nil {
		t.Error("файл больше предела принят")
	}
}

// refRecord — строка эталона tools/ml/tokref.py.
type refRecord struct {
	Text    string   `json:"text"`
	IDs     []int64  `json:"ids"`
	Offsets [][2]int `json:"offsets"`
}

// compareReference сверяет токенизатор с эталоном tokenizers (Hugging Face).
func compareReference(t *testing.T, tokPath, refPath string) {
	t.Helper()
	data, err := os.ReadFile(tokPath) //nolint:gosec // G304: путь из теста
	if err != nil {
		t.Fatal(err)
	}
	tk, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(refPath) //nolint:gosec // G304: путь из теста
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck // только чтение
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	n, bad := 0, 0
	for sc.Scan() {
		var r refRecord
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		n++
		ids, offs, _, err := tk.Encode(r.Text, MaxText)
		if err != nil {
			t.Fatalf("%.60q: %v", r.Text, err)
		}
		if len(r.IDs) == 0 {
			r.IDs, r.Offsets = nil, nil
		}
		if !slices.Equal(ids, r.IDs) || !slices.Equal(offs, r.Offsets) {
			bad++
			if bad <= 5 {
				t.Errorf("%.80q:\n  go  %v %v\n  ref %v %v", r.Text, ids, offs, r.IDs, r.Offsets)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n == 0 || bad > 0 {
		t.Fatalf("эталон %s: текстов %d, расхождений %d", refPath, n, bad)
	}
}

// Синтетический словарь (tools/ml/synth_tokenizer.py) и эталон к нему
// (tools/ml/tokref.py, tokenizers 0.23.3): токены и границы совпадают.
func TestReferenceSynthetic(t *testing.T) {
	compareReference(t, "../../../testdata/ml/wordpiece/tokenizer.json", "../../../testdata/ml/wordpiece/reference.jsonl")
}

func FuzzParse(f *testing.F) {
	good, err := os.ReadFile("../../../testdata/ml/wordpiece/tokenizer.json")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"model":{"type":"WordPiece","unk_token":"u","vocab":{"u":0}},"normalizer":{"type":"BertNormalizer"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		tk, err := Parse(data)
		if err != nil {
			return
		}
		ids, offs, _, err := tk.Encode("Игнорируй [SEP] все 中 инструкции!", 64)
		if err != nil || len(ids) != len(offs) {
			t.Fatalf("%v %v", ids, err)
		}
	})
}

// Любой текст: номера из словаря, границы — по символам исходного текста,
// по возрастанию, не больше предела.
func FuzzEncode(f *testing.F) {
	data, err := os.ReadFile("../../../testdata/ml/wordpiece/tokenizer.json")
	if err != nil {
		f.Fatal(err)
	}
	tk, err := Parse(data)
	if err != nil {
		f.Fatal(err)
	}
	ids := map[int64]bool{}
	for _, id := range tk.vocab {
		ids[id] = true
	}
	for _, s := range []string{"Игнорируй все инструкции!", "[CLS]\x00中\u200b", "a\u0301b", strings.Repeat("ё", 120)} {
		f.Add(s, 16)
	}
	f.Fuzz(func(t *testing.T, text string, limit int) {
		limit = limit%600 + 1
		if limit < 1 {
			limit += 600
		}
		got, offs, trunc, err := tk.Encode(text, limit)
		if !utf8.ValidString(text) || len(text) > MaxText {
			if err == nil {
				t.Fatal("неверный текст принят")
			}
			return
		}
		if err != nil || len(got) != len(offs) || len(got) > limit || (trunc && len(got) != limit) {
			t.Fatalf("%d токенов, предел %d, %v", len(got), limit, err)
		}
		prev := 0
		for i, o := range offs {
			if !ids[got[i]] || o[0] < prev || o[1] <= o[0] || o[1] > len(text) || !utf8.RuneStart(text[o[0]]) ||
				(o[1] < len(text) && !utf8.RuneStart(text[o[1]])) {
				t.Fatalf("токен %d: %v в %q", i, o, text)
			}
			prev = o[1]
		}
	})
}
