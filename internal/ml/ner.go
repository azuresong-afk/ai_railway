package ml

import "strings"

// Разметка токенов (задача 4.20, pii.ner). Метки модели — схема BIO:
// LabelOutside («вне фрагмента»), «b-<сущность>» (начало фрагмента) и
// «i-<сущность>» (продолжение); метка без приставки — схема IO (каждый токен
// — продолжение). Находка aisec-ml несёт сущность без приставки
// («per»), поэтому шлюз проверяет метки находок через ModelInfo.HasLabel.

// LabelOutside — метка «вне фрагмента» у разметки токенов.
const LabelOutside = "o"

// MaxSpanBytes — предел длины фрагмента разметки в байтах. Имя,
// организация и почтовый адрес короче; длиннее — модель «разлила» метку на
// абзац, и такой фрагмент режется на части (каждая остаётся находкой, так
// что маскирование закрывает весь текст под меткой). Режется только по
// границам токенов: один токен длиннее предела ([UNK] на длинном слове)
// остаётся одной находкой — маскируется больше, а не меньше.
const MaxSpanBytes = 512

// Приставки меток схемы BIO.
const (
	prefixBegin  = "b-"
	prefixInside = "i-"
)

// EntityOf — сущность метки и признак начала фрагмента: «b-per» → per,
// true; «i-per» → per, false; «per» → per, false. ok == false — метка
// LabelOutside или пустая сущность.
func EntityOf(label string) (entity string, begin, ok bool) {
	switch {
	case label == LabelOutside:
		return "", false, false
	case strings.HasPrefix(label, prefixBegin):
		entity, begin = label[len(prefixBegin):], true
	case strings.HasPrefix(label, prefixInside):
		entity = label[len(prefixInside):]
	default:
		entity = label
	}
	return entity, begin, entity != "" && entity != LabelOutside
}

// HasLabel — метка находки l есть у модели: сама метка (классификация,
// схема IO) или начало фрагмента «b-l» (схема BIO).
func (m ModelInfo) HasLabel(l string) bool {
	for _, x := range m.Labels {
		if x == l || x == prefixBegin+l {
			return true
		}
	}
	return false
}

// TokenLabel — лучшая метка токена: метка модели, её вероятность и
// байтовые границы токена в тексте (у служебных токенов End <= Start).
type TokenLabel struct {
	Label      string
	Score      float64
	Start, End int
}

// MergeTokens склеивает размеченные токены во фрагменты (находки) по схеме
// BIO. Токены — по возрастанию позиций, как их выдаёт токенизатор.
//   - LabelOutside, служебный токен или позиции назад — фрагмент закрывается.
//   - «i-X» (и метка без приставки) продолжает открытый фрагмент X, иначе
//     открывает новый: модель могла пропустить «b-».
//   - «b-X» открывает новый фрагмент, кроме токена вплотную к открытому
//     фрагменту X: это часть того же слова («Ив», «##анов»), два разных
//     имени без пробела между ними не стоят.
//   - Фрагмент длиннее MaxSpanBytes закрывается, следующий токен открывает
//     новый.
//
// Оценка фрагмента — наименьшая вероятность его токенов. Находок не больше
// MaxFindings: остаток отбрасывается, и truncated == true — разметка
// проверила не весь текст (Result.Truncated), иначе имена после предела
// ушли бы провайдеру незаметно.
func MergeTokens(tokens []TokenLabel) (out []Score, truncated bool) {
	cur := -1 // индекс открытого фрагмента в out
	pos := 0  // конец предыдущего токена
	for _, t := range tokens {
		entity, begin, ok := EntityOf(t.Label)
		if !ok || t.End <= t.Start || t.Start < pos {
			cur = -1
			pos = max(pos, t.End)
			continue
		}
		pos = t.End
		if cur >= 0 && out[cur].Label == entity && t.End-out[cur].Start <= MaxSpanBytes &&
			(!begin || t.Start == out[cur].End) {
			out[cur].End = t.End
			out[cur].Score = min(out[cur].Score, t.Score)
			continue
		}
		if len(out) == MaxFindings {
			return out, true
		}
		out = append(out, Score{Label: entity, Score: t.Score, Start: t.Start, End: t.End})
		cur = len(out) - 1
	}
	return out, false
}
