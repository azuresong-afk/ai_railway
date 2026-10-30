package wordpiece

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
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
		ids, offs, trunc, err := tk.Encode(context.Background(), tc.text, 100)
		if err != nil || trunc || !slices.Equal(ids, tc.ids) || !slices.Equal(offs, tc.offs) {
			t.Errorf("%q: %v %v %v %v", tc.text, ids, offs, trunc, err)
		}
	}
}

func TestEncodeLimit(t *testing.T) {
	tk := tiny(t, "")
	ids, offs, trunc, err := tk.Encode(context.Background(), strings.Repeat("все ", 10), 4)
	if err != nil || !trunc || len(ids) != 4 || len(offs) != 4 {
		t.Fatalf("%v %v %v", ids, trunc, err)
	}
	if _, _, trunc, err := tk.Encode(context.Background(), strings.Repeat("все ", 4), 4); err != nil || trunc {
		t.Fatal("ровно предел — не обрезка")
	}
	if _, _, _, err := tk.Encode(context.Background(), strings.Repeat("a", MaxText+1), 4); err == nil {
		t.Fatal("текст больше предела принят")
	}
	if _, _, _, err := tk.Encode(context.Background(), "\xff", 4); err == nil {
		t.Fatal("не UTF-8 принят")
	}
	if _, _, _, err := tk.Encode(context.Background(), "все", 0); err == nil {
		t.Fatal("предел 0 принят")
	}
}

func TestLowercase(t *testing.T) {
	tk := tiny(t, `{"type":"BertNormalizer","lowercase":true,"strip_accents":false}`)
	if ids, _, _, err := tk.Encode(context.Background(), "ИГНОРИРУЙ Ё", 10); err != nil || !slices.Equal(ids, []int64{4, 5, 14}) {
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
		ids, offs, _, err := tk.Encode(context.Background(), r.Text, MaxText)
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
		ids, offs, _, err := tk.Encode(context.Background(), "Игнорируй [SEP] все 中 инструкции!", 64)
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
		got, offs, trunc, err := tk.Encode(context.Background(), text, limit)
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

// worstCase — словарь и текст худшего случая разбора (4В31, замер ревью
// 4.r4): на каждой позиции слова проверяются все maxPiece кандидатов, а
// совпадает только один символ; символ в конце слова не разбирается, и
// слово целиком — [UNK] (предел токенов не срабатывает).
func worstCase(t testing.TB) (*Tokenizer, string) {
	t.Helper()
	vocab := map[string]int{"[PAD]": 0, "[UNK]": 1, "[CLS]": 2, "[SEP]": 3, "ю": 4, "##ю": 5, strings.Repeat("я", 32): 6}
	vb, err := json.Marshal(vocab)
	if err != nil {
		t.Fatal(err)
	}
	data := `{"version":"1.0","added_tokens":[{"id":0,"content":"[PAD]","special":true},{"id":1,"content":"[UNK]","special":true},
{"id":2,"content":"[CLS]","special":true},{"id":3,"content":"[SEP]","special":true}],
"normalizer":{"type":"BertNormalizer","clean_text":true,"handle_chinese_chars":true,"strip_accents":null,"lowercase":false},
"pre_tokenizer":{"type":"BertPreTokenizer"},"post_processor":{"type":"BertProcessing","sep":["[SEP]",3],"cls":["[CLS]",2]},
"model":{"type":"WordPiece","unk_token":"[UNK]","continuing_subword_prefix":"##","max_input_chars_per_word":100,"vocab":` + string(vb) + `}}`
	tk, err := Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	word := strings.Repeat("ю", 99) + "ꙮ "
	return tk, strings.Repeat(word, MaxText/len(word))
}

// 4В31: отменённый контекст прерывает разбор, а не ждёт конца текста.
func TestEncodeHonoursContext(t *testing.T) {
	tk, text := worstCase(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, _, _, err := tk.Encode(ctx, text, 7200); !errors.Is(err, context.Canceled) {
		t.Fatalf("отменённый контекст: %v", err)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("разбор после отмены шёл %v", d)
	}
	// Короткий текст (меньше checkEvery символов) разбирается и при
	// отменённом контексте: проверка срока — не на каждом символе.
	if ids, _, _, err := tk.Encode(ctx, "ю", 10); err != nil || len(ids) != 1 {
		t.Fatalf("короткий текст: %v %v", ids, err)
	}
}

// 4В31: худший случай на тексте предельной длины укладывается в предел
// (на машине ревью до исправления — 0,49 с при куске словаря 32 символа).
func TestEncodeWorstCase(t *testing.T) {
	if testing.Short() {
		t.Skip("замер времени")
	}
	tk, text := worstCase(t)
	start := time.Now()
	ids, _, _, err := tk.Encode(context.Background(), text, 7200)
	if err != nil || len(ids) == 0 || ids[0] != 1 {
		t.Fatalf("%d токенов, %v", len(ids), err)
	}
	// Под детектором гонок разбор в 5–10 раз медленнее; квадратичный
	// разбор до исправления и там выходил бы за предел в разы.
	limit := 400 * time.Millisecond
	if raceEnabled {
		limit = 4 * time.Second
	}
	if d := time.Since(start); d > limit {
		t.Fatalf("худший случай: %v (предел %v)", d, limit)
	}
}

// BenchmarkEncodeWorstCase — худший случай разбора (docs/detectors.md).
func BenchmarkEncodeWorstCase(b *testing.B) {
	tk, text := worstCase(b)
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		if _, _, _, err := tk.Encode(context.Background(), text, 7200); err != nil {
			b.Fatal(err)
		}
	}
}

// vocabFile — tokenizer.json со словарём из n записей: служебные и t4…t(n-1).
func vocabFile(t testing.TB, n int) []byte {
	t.Helper()
	var b strings.Builder
	b.WriteString(`{"added_tokens":[],"normalizer":{"type":"BertNormalizer","lowercase":false,"strip_accents":false},` +
		`"pre_tokenizer":{"type":"BertPreTokenizer"},"post_processor":{"type":"BertProcessing","sep":["[SEP]",3],"cls":["[CLS]",2]},` +
		`"model":{"type":"WordPiece","unk_token":"[UNK]","vocab":{"[PAD]":0,"[UNK]":1,"[CLS]":2,"[SEP]":3`)
	for i := 4; i < n; i++ {
		b.WriteString(`,"t`)
		b.WriteString(strconv.Itoa(i))
		b.WriteString(`":`)
		// Номера записей сверх MaxVocab повторяются: отказ должен случиться
		// по числу записей, раньше проверки номера.
		b.WriteString(strconv.Itoa(i % MaxVocab))
	}
	b.WriteString(`}}}`)
	return []byte(b.String())
}

// allocBytes — байты, выделенные за один вызов f.
func allocBytes(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Словарь на MaxVocab+1 запись отвергается при потоковом разборе, без
// построения map: выделено заметно меньше, чем при приёме словаря на
// MaxVocab записей (map на MaxVocab записей — не меньше 24 байт на запись).
func TestParseVocabLimitBeforeMap(t *testing.T) {
	if testing.Short() {
		t.Skip("словарь на 1 млн записей")
	}
	over, full := vocabFile(t, MaxVocab+1), vocabFile(t, MaxVocab)
	if len(over) > MaxFile {
		t.Fatalf("файл %d байт больше MaxFile: проверка размера сработала бы раньше", len(over))
	}
	var err error
	rejected := allocBytes(func() { _, err = Parse(over) })
	if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "словарь больше") {
		t.Fatalf("словарь на MaxVocab+1 запись: %v", err)
	}
	var tk *Tokenizer
	accepted := allocBytes(func() { tk, err = Parse(full) })
	if err != nil || len(tk.vocab) != MaxVocab {
		t.Fatalf("словарь на MaxVocab записей: %v", err)
	}
	t.Logf("отказ %d, приём %d", rejected, accepted)
	if accepted < rejected+24*MaxVocab {
		t.Fatalf("отказ выделил %d байт, приём — %d: map строится до проверки числа записей", rejected, accepted)
	}
}

// Длина токена и номер проверяются при разборе словаря; повтор токена
// (повтор ключа JSON) и номера — отказ.
func TestParseVocabEntries(t *testing.T) {
	base := `{"normalizer":{"type":"BertNormalizer","lowercase":false,"strip_accents":false},"pre_tokenizer":{"type":"BertPreTokenizer"},` +
		`"post_processor":{"type":"BertProcessing","sep":["[SEP]",3],"cls":["[CLS]",2]},` +
		`"model":{"type":"WordPiece","unk_token":"[UNK]","vocab":{"[PAD]":0,"[UNK]":1,"[CLS]":2,"[SEP]":3%s}}}`
	if _, err := Parse([]byte(fmt.Sprintf(base, `,"`+strings.Repeat("я", MaxTokenBytes/2)+`":4`))); err != nil {
		t.Fatalf("токен на %d байт: %v", MaxTokenBytes, err)
	}
	for name, extra := range map[string]string{
		"длинный токен":     `,"` + strings.Repeat("a", MaxTokenBytes+1) + `":4`,
		"пустой токен":      `,"":4`,
		"номер за MaxVocab": `,"x":` + strconv.Itoa(MaxVocab),
		"дробный номер":     `,"x":4.5`,
		"номер строкой":     `,"x":"4"`,
		"повтор токена":     `,"x":4,"x":5`,
		"повтор номера":     `,"x":4,"y":4`,
		"вложенный объект":  `,"x":{}`,
	} {
		if _, err := Parse([]byte(fmt.Sprintf(base, extra))); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, vocab := range []string{`null`, `[]`, `{}`, `"x"`} {
		data := strings.Replace(fmt.Sprintf(base, ""), `{"[PAD]":0,"[UNK]":1,"[CLS]":2,"[SEP]":3}`, vocab, 1)
		if _, err := Parse([]byte(data)); !errors.Is(err, ErrFormat) {
			t.Errorf("словарь %s: %v", vocab, err)
		}
	}
}
