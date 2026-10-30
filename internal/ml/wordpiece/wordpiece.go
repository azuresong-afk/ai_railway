// Пакет wordpiece — токенизатор WordPiece (BERT) по tokenizer.json формата
// Hugging Face tokenizers, без библиотек: только пакет unicode (ADR-0024,
// раздел 6; задача 4.19). Общий для моделей aisec-ml (injection.ml,
// toxicity.ml, pii.ner).
//
// Поддерживается ровно то, что нужно моделям семейства BERT: нормализатор
// BertNormalizer без снятия диакритики, предразбор BertPreTokenizer, модель
// WordPiece, служебные [CLS] и [SEP] (TemplateProcessing или
// BertProcessing). tokenizer.json с другими частями не принимается: модель
// с неверными номерами токенов хуже, чем незагруженная.
//
// Служебные токены в тексте пользователя ([SEP], [CLS] и т. п.) разбираются
// как обычный текст, а не как служебные: иначе текст мог бы менять
// структуру входа модели. Эталонный токенизатор в tools/ml работает так же
// (encode_special_tokens).
package wordpiece

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf8"
)

// Пределы tokenizer.json: файл проверен по хешу пакета, но разбирается как
// недоверенный вход (FuzzParse).
const (
	// MaxFile — предел tokenizer.json (как у роли tokenizer пакета моделей).
	MaxFile = 32 << 20
	// MaxVocab — предел словаря.
	MaxVocab = 1 << 20
	// MaxTokenBytes — предел длины токена словаря в байтах.
	MaxTokenBytes = 256
	// MaxWordChars — предел max_input_chars_per_word.
	MaxWordChars = 1000
	// MaxText — предел текста одного вызова Encode (как у кадра detect).
	MaxText = 256 << 10
	// MaxAddedTokens — предел служебных токенов.
	MaxAddedTokens = 1024
)

// ErrFormat — tokenizer.json не поддерживается или неверен.
var ErrFormat = errors.New("tokenizer.json: формат не поддерживается")

// Tokenizer — токенизатор WordPiece. Безопасен для одновременного вызова.
type Tokenizer struct {
	vocab     map[string]int64
	unk       int64
	cls, sep  int64
	prefix    string
	maxChars  int
	maxPiece  int // наибольшая длина токена словаря в символах (без префикса)
	lowercase bool
	cleanText bool
	chinese   bool
}

type fileJSON struct {
	AddedTokens   []addedToken    `json:"added_tokens"`
	Normalizer    *normalizerJSON `json:"normalizer"`
	PreTokenizer  *typed          `json:"pre_tokenizer"`
	PostProcessor json.RawMessage `json:"post_processor"`
	Model         *modelJSON      `json:"model"`
}

type typed struct {
	Type string `json:"type"`
}

type addedToken struct {
	ID      int64  `json:"id"`
	Content string `json:"content"`
	Special bool   `json:"special"`
}

type normalizerJSON struct {
	Type               string `json:"type"`
	CleanText          *bool  `json:"clean_text"`
	HandleChineseChars *bool  `json:"handle_chinese_chars"`
	StripAccents       *bool  `json:"strip_accents"`
	Lowercase          *bool  `json:"lowercase"`
}

type modelJSON struct {
	Type                    string    `json:"type"`
	UnkToken                string    `json:"unk_token"`
	ContinuingSubwordPrefix *string   `json:"continuing_subword_prefix"`
	MaxInputCharsPerWord    *int      `json:"max_input_chars_per_word"`
	Vocab                   vocabList `json:"vocab"`
}

// vocabEntry — запись словаря в порядке файла.
type vocabEntry struct {
	tok string
	id  int64
}

// vocabList — словарь до проверки: map строится в Parse только после всех
// проверок записей (ревью 4.r4, «ниже порога»).
type vocabList []vocabEntry

// UnmarshalJSON разбирает словарь потоково (json.Decoder.Token): число
// записей, длина токена и номер проверяются по ходу разбора, до того как
// запись попадёт в список. Словарь больше MaxVocab отвергается на записи
// MaxVocab+1, map при этом не строится.
func (v *vocabList) UnmarshalJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return fmt.Errorf("%w: словарь не объект", ErrFormat)
	}
	var list vocabList
	for dec.More() {
		if len(list) == MaxVocab {
			return fmt.Errorf("%w: словарь больше %d токенов", ErrFormat, MaxVocab)
		}
		k, err := dec.Token()
		key, ok := k.(string)
		if err != nil || !ok || key == "" || len(key) > MaxTokenBytes || !utf8.ValidString(key) {
			return fmt.Errorf("%w: токен словаря", ErrFormat)
		}
		n, err := dec.Token()
		num, ok := n.(json.Number)
		if err != nil || !ok {
			return fmt.Errorf("%w: номер токена словаря", ErrFormat)
		}
		id, err := num.Int64()
		if err != nil || id < 0 || id >= MaxVocab {
			return fmt.Errorf("%w: номер токена словаря", ErrFormat)
		}
		list = append(list, vocabEntry{tok: key, id: id})
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return fmt.Errorf("%w: словарь не объект", ErrFormat)
	}
	*v = list
	return nil
}

// Parse разбирает tokenizer.json. Размер файла (MaxFile) проверяется до
// разбора, число записей словаря и длина токена — при потоковом разборе
// словаря (vocabList), до построения map.
func Parse(data []byte) (*Tokenizer, error) {
	if len(data) > MaxFile {
		return nil, fmt.Errorf("%w: больше %d байт", ErrFormat, MaxFile)
	}
	var f fileJSON
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, ErrFormat) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: разбор JSON", ErrFormat)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: данные после объекта", ErrFormat)
	}
	m := f.Model
	if m == nil || m.Type != "WordPiece" {
		return nil, fmt.Errorf("%w: модель не WordPiece", ErrFormat)
	}
	if len(m.Vocab) == 0 {
		return nil, fmt.Errorf("%w: словарь пуст", ErrFormat)
	}
	t := &Tokenizer{prefix: "##", maxChars: 100}
	if m.ContinuingSubwordPrefix != nil {
		t.prefix = *m.ContinuingSubwordPrefix
	}
	if m.MaxInputCharsPerWord != nil {
		t.maxChars = *m.MaxInputCharsPerWord
	}
	if t.prefix == "" || len(t.prefix) > 8 || !utf8.ValidString(t.prefix) || t.maxChars < 1 || t.maxChars > MaxWordChars {
		return nil, fmt.Errorf("%w: префикс продолжения или max_input_chars_per_word", ErrFormat)
	}
	// Записи уже проверены по пределам при разборе; здесь — повторы токенов
	// и номеров. Номер меньше MaxVocab: занятые номера — битовая карта.
	used := make([]uint64, MaxVocab/64)
	t.vocab = make(map[string]int64, len(m.Vocab))
	for _, e := range m.Vocab {
		if _, dup := t.vocab[e.tok]; dup || used[e.id/64]&(1<<(e.id%64)) != 0 {
			return nil, fmt.Errorf("%w: повтор токена или номера в словаре", ErrFormat)
		}
		used[e.id/64] |= 1 << (e.id % 64)
		t.vocab[e.tok] = e.id
		n := utf8.RuneCountInString(e.tok)
		if len(e.tok) > len(t.prefix) && e.tok[:len(t.prefix)] == t.prefix {
			n -= utf8.RuneCountInString(t.prefix)
		}
		t.maxPiece = max(t.maxPiece, n)
	}
	unk, ok := t.vocab[m.UnkToken]
	if !ok {
		return nil, fmt.Errorf("%w: unk_token не в словаре", ErrFormat)
	}
	t.unk = unk
	if err := t.parseNormalizer(f.Normalizer); err != nil {
		return nil, err
	}
	if f.PreTokenizer == nil || f.PreTokenizer.Type != "BertPreTokenizer" {
		return nil, fmt.Errorf("%w: предразбор не BertPreTokenizer", ErrFormat)
	}
	if len(f.AddedTokens) > MaxAddedTokens {
		return nil, fmt.Errorf("%w: служебных токенов больше %d", ErrFormat, MaxAddedTokens)
	}
	for _, a := range f.AddedTokens {
		// Несущественный добавленный токен эталон выделяет из текста до
		// разбора; у моделей BERT их нет, а повторять это поведение не нужно.
		if !a.Special {
			return nil, fmt.Errorf("%w: добавленный токен %q не служебный", ErrFormat, a.Content)
		}
		if id, ok := t.vocab[a.Content]; !ok || id != a.ID {
			return nil, fmt.Errorf("%w: служебный токен %q не совпадает со словарём", ErrFormat, a.Content)
		}
	}
	if err := t.parsePost(f.PostProcessor); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *Tokenizer) parseNormalizer(n *normalizerJSON) error {
	if n == nil || n.Type != "BertNormalizer" {
		return fmt.Errorf("%w: нормализатор не BertNormalizer", ErrFormat)
	}
	// Значения по умолчанию — как у tokenizers.
	t.cleanText, t.chinese = true, true
	if n.CleanText != nil {
		t.cleanText = *n.CleanText
	}
	if n.HandleChineseChars != nil {
		t.chinese = *n.HandleChineseChars
	}
	if n.Lowercase == nil || *n.Lowercase {
		t.lowercase = true
	}
	// strip_accents: null — как lowercase. Снятие диакритики требует NFD,
	// которой нет в стандартной библиотеке: такие модели не принимаются.
	strip := t.lowercase
	if n.StripAccents != nil {
		strip = *n.StripAccents
	}
	if strip {
		return fmt.Errorf("%w: strip_accents (нужна нормализация NFD) не поддерживается", ErrFormat)
	}
	return nil
}

// parsePost находит [CLS] и [SEP]: шаблон «[CLS] $A [SEP]» (TemplateProcessing)
// или BertProcessing.
func (t *Tokenizer) parsePost(raw json.RawMessage) error {
	var p struct {
		Type   string            `json:"type"`
		Sep    []json.RawMessage `json:"sep"`
		Cls    []json.RawMessage `json:"cls"`
		Single []struct {
			SpecialToken *struct {
				ID string `json:"id"`
			} `json:"SpecialToken"`
			Sequence *struct {
				ID string `json:"id"`
			} `json:"Sequence"`
		} `json:"single"`
		SpecialTokens map[string]struct {
			IDs []int64 `json:"ids"`
		} `json:"special_tokens"`
	}
	if len(raw) == 0 || json.Unmarshal(raw, &p) != nil {
		return fmt.Errorf("%w: post_processor", ErrFormat)
	}
	var clsTok, sepTok string
	var clsID, sepID int64
	switch p.Type {
	case "BertProcessing":
		if len(p.Sep) != 2 || len(p.Cls) != 2 || json.Unmarshal(p.Sep[0], &sepTok) != nil || json.Unmarshal(p.Sep[1], &sepID) != nil ||
			json.Unmarshal(p.Cls[0], &clsTok) != nil || json.Unmarshal(p.Cls[1], &clsID) != nil {
			return fmt.Errorf("%w: BertProcessing", ErrFormat)
		}
	case "TemplateProcessing":
		s := p.Single
		if len(s) != 3 || s[0].SpecialToken == nil || s[1].Sequence == nil || s[1].Sequence.ID != "A" || s[2].SpecialToken == nil {
			return fmt.Errorf("%w: шаблон post_processor не «[CLS] $A [SEP]»", ErrFormat)
		}
		clsTok, sepTok = s[0].SpecialToken.ID, s[2].SpecialToken.ID
		c, okC := p.SpecialTokens[clsTok]
		e, okS := p.SpecialTokens[sepTok]
		if !okC || !okS || len(c.IDs) != 1 || len(e.IDs) != 1 {
			return fmt.Errorf("%w: служебные токены шаблона", ErrFormat)
		}
		clsID, sepID = c.IDs[0], e.IDs[0]
	default:
		return fmt.Errorf("%w: post_processor %q", ErrFormat, p.Type)
	}
	if id, ok := t.vocab[clsTok]; !ok || id != clsID {
		return fmt.Errorf("%w: [CLS] не совпадает со словарём", ErrFormat)
	}
	if id, ok := t.vocab[sepTok]; !ok || id != sepID {
		return fmt.Errorf("%w: [SEP] не совпадает со словарём", ErrFormat)
	}
	t.cls, t.sep = clsID, sepID
	return nil
}

// Special — номера [CLS] и [SEP].
func (t *Tokenizer) Special() (cls, sep int64) { return t.cls, t.sep }

// Encode — токены текста без служебных: номера и байтовые границы в text.
// Не больше limit токенов; truncated — у текста есть ещё токены. Длина
// текста проверяется до разбора. Срок ctx проверяется каждые checkEvery
// символов (4В31): разбор идёт в слоте исполнителя aisec-ml, и брошенный
// шлюзом запрос не должен занимать его до конца текста.
func (t *Tokenizer) Encode(ctx context.Context, text string, limit int) (ids []int64, offsets [][2]int, truncated bool, err error) {
	if len(text) > MaxText || !utf8.ValidString(text) {
		return nil, nil, false, fmt.Errorf("wordpiece: текст больше %d байт или не UTF-8", MaxText)
	}
	if limit < 1 {
		return nil, nil, false, errors.New("wordpiece: предел токенов меньше 1")
	}
	e := encoder{t: t, limit: limit}
	n := 0
	for pos := 0; pos < len(text) && !e.full(); {
		if n++; n%checkEvery == 0 && ctx.Err() != nil {
			return nil, nil, false, fmt.Errorf("wordpiece: %w", context.Cause(ctx))
		}
		r, size := utf8.DecodeRuneInString(text[pos:])
		e.char(r, pos, pos+size)
		pos += size
	}
	if !e.full() {
		e.flush()
	}
	if len(e.ids) > limit {
		return e.ids[:limit], e.offs[:limit], true, nil
	}
	return e.ids, e.offs, false, nil
}

// checkEvery — через сколько символов Encode проверяет срок: разбор
// тысячи символов в худшем случае — десятки микросекунд.
const checkEvery = 1024

// encoder — разбор одного текста: слово копится символами (нормализованный
// символ и его байтовые границы в исходном тексте) и разбирается WordPiece
// на границе слова.
type encoder struct {
	t     *Tokenizer
	limit int
	ids   []int64
	offs  [][2]int
	word  []rune
	spans [][2]int
	buf   []byte
	// ends — конец каждого символа кандидата в buf: префиксы кандидата
	// проверяются по этим границам без повторной сборки строки.
	ends []int
}

// full — набрано на один токен больше предела: известно, что текст длиннее.
func (e *encoder) full() bool { return len(e.ids) > e.limit }

func (e *encoder) char(r rune, start, end int) {
	t := e.t
	if t.cleanText {
		if r == 0 || r == utf8.RuneError || isControl(r) {
			return
		}
		if isWhitespace(r) {
			r = ' '
		}
	}
	switch {
	case isWhitespace(r):
		e.flush()
	case isPunct(r) || (t.chinese && isChinese(r)):
		e.flush()
		e.word, e.spans = append(e.word, e.lower(r)), append(e.spans, [2]int{start, end})
		e.flush()
	default:
		e.word, e.spans = append(e.word, e.lower(r)), append(e.spans, [2]int{start, end})
	}
}

func (e *encoder) lower(r rune) rune {
	if e.t.lowercase {
		return unicode.ToLower(r)
	}
	return r
}

// flush разбирает накопленное слово: жадно, самый длинный токен словаря с
// начала; если какой-то остаток не разбирается — всё слово [UNK].
func (e *encoder) flush() {
	w, spans := e.word, e.spans
	e.word, e.spans = e.word[:0], e.spans[:0]
	if len(w) == 0 || e.full() {
		return
	}
	t := e.t
	if len(w) > t.maxChars {
		e.emit(t.unk, spans[0][0], spans[len(spans)-1][1])
		return
	}
	mark := len(e.ids)
	for start := 0; start < len(w); {
		// Кандидат на позиции собирается один раз (4В31): префиксы —
		// срезы buf по границам символов, от самого длинного.
		last := min(len(w), start+t.maxPiece)
		e.buf, e.ends = e.buf[:0], e.ends[:0]
		if start > 0 {
			e.buf = append(e.buf, t.prefix...)
		}
		for _, r := range w[start:last] {
			e.buf = utf8.AppendRune(e.buf, r)
			e.ends = append(e.ends, len(e.buf))
		}
		found := false
		for k := len(e.ends); k > 0; k-- {
			if id, ok := t.vocab[string(e.buf[:e.ends[k-1]])]; ok {
				end := start + k
				e.ids, e.offs = append(e.ids, id), append(e.offs, [2]int{spans[start][0], spans[end-1][1]})
				start, found = end, true
				break
			}
		}
		if !found {
			e.ids, e.offs = e.ids[:mark], e.offs[:mark]
			e.emit(t.unk, spans[0][0], spans[len(spans)-1][1])
			return
		}
	}
}

func (e *encoder) emit(id int64, start, end int) {
	e.ids, e.offs = append(e.ids, id), append(e.offs, [2]int{start, end})
}

// isWhitespace — как в tokenizers: \t, \n, \r и свойство White_Space.
func isWhitespace(r rune) bool {
	return r == '\t' || r == '\n' || r == '\r' || unicode.IsSpace(r)
}

// isControl — как в tokenizers: категории Cc, Cf, Co, Cs и неназначенные
// (Cn), кроме \t, \n, \r.
func isControl(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return unicode.In(r, unicode.Cc, unicode.Cf, unicode.Co, unicode.Cs) || !assigned(r)
}

var assignedTables = []*unicode.RangeTable{unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.C}

// assigned — символ назначен (не Cn) в таблицах Unicode пакета unicode.
func assigned(r rune) bool { return unicode.In(r, assignedTables...) }

// isPunct — как в BertPreTokenizer: знаки ASCII (в том числе $+<=>^`|~) и
// категория P.
func isPunct(r rune) bool {
	if r < 0x80 {
		return (r >= 33 && r <= 47) || (r >= 58 && r <= 64) || (r >= 91 && r <= 96) || (r >= 123 && r <= 126)
	}
	return unicode.IsPunct(r)
}

// isChinese — блоки унифицированных иероглифов CJK (как в BERT).
func isChinese(r rune) bool {
	return (r >= 0x4E00 && r <= 0x9FFF) || (r >= 0x3400 && r <= 0x4DBF) || (r >= 0x20000 && r <= 0x2A6DF) ||
		(r >= 0x2A700 && r <= 0x2B73F) || (r >= 0x2B740 && r <= 0x2B81F) || (r >= 0x2B920 && r <= 0x2CEAF) ||
		(r >= 0xF900 && r <= 0xFAFF) || (r >= 0x2F800 && r <= 0x2FA1F)
}
