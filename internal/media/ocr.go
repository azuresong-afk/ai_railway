package media

import (
	"context"
	"errors"
	"fmt"
	"image"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// OCR (задача 5.42, ADR-0033): модели PaddleOCR в ONNX — детектор строк
// PP-OCRv6 small и распознавание cyrillic PP-OCRv5 mobile. Модели
// исполняет OCREngine (ONNX Runtime в cmd/aisec-media под сборочным
// тегом); пред- и постобработка — здесь, на Go без библиотек.
//
// Проходы (ТЗ 5.17; ADR-0033, п. 2): обычный и «контраст» — всегда;
// третий — обычный растр при детекторе ×2, только когда на изображении
// есть мелкие строки и до срока анализа остаётся время. Текст каждого
// прохода — блоками строк (абзацами) в порядке чтения: детекторы видят
// фразу, перенесённую на следующую строку, целиком, а рамка блока — в
// пикселях исходного изображения.

// OCREngine — исполнитель моделей OCR. Реализация безопасна для
// одновременного вызова; отмена ctx прерывает вывод.
type OCREngine interface {
	// Detect — карта вероятностей текста [h·w] для входа NCHW [1, 3, h, w].
	Detect(ctx context.Context, x []float32, h, w int) ([]float32, error)
	// Recognize — вероятности классов по шагам [T·C] для строки NCHW
	// [1, 3, 48, w]; второй итог — C, число классов.
	Recognize(ctx context.Context, x []float32, w int) ([]float32, int, error)
	// Charset — символы классов 1…C−1 (класс 0 — пустой символ CTC).
	Charset() []string
}

// Параметры OCR. Пороги карты и расширение рамки — значения PaddleOCR,
// проверенные экспериментом 5.40; порог мелких строк, бюджет прохода ×2 и
// пределы — по корпусу testdata/corpus/media (5.42, docs/detectors.md).
const (
	detLimit    = 960 // большая сторона входа детектора, кратно 32
	detAlign    = 32
	detThresh   = 0.3
	boxThresh   = 0.6
	unclipRatio = 1.5
	minBoxSide  = 2  // меньшая сторона рамки на карте детектора, пикселей
	minAreaPts  = 10 // точек в области карты
	// maxOCRLines — строк на проход: дальше области карты не разбираются.
	maxOCRLines = 512
	// smallLineDet — строка, у которой меньшая сторона области карты
	// детектора (до расширения рамки) меньше этого числа пикселей, считается
	// мелкой и включает проход ×2. Подобрано по корпусу: у обычного текста
	// скриншотов и сканов сторона 7–18, у шрифта 7 px (small-01, small-02) —
	// 3–4, и такая строка распознаётся обрывками.
	smallLineDet = 6
	// x2Budget — проход ×2 по всему кадру начинается, только если до срока
	// анализа остаётся не меньше x2Budget длительностей обычного прохода: по
	// корпусу он длится 1,7–2,7 обычного (детектор вчетверо больше). Проход
	// по полосам мелких строк (их суммарная высота не больше x2BandShare
	// кадра) намного короче, ему достаточно одной длительности.
	x2Budget    = 3
	x2BandShare = 0.5
	// x2MaxBands — полос мелких строк; больше — проход по всему кадру.
	x2MaxBands = 8
	// maxCharset — предел таблицы символов модели.
	maxCharset = 1 << 16
)

// ErrOCRModel — исполнитель вернул итог, не совместимый с моделью.
var ErrOCRModel = errors.New("aisec-media: итог модели OCR не совпадает с её описанием")

// OCR — распознавание текста на растре.
type OCR struct {
	engine  OCREngine
	charset []string
	// now — часы (тесты подменяют).
	now func() time.Time
}

// NewOCR проверяет таблицу символов исполнителя.
func NewOCR(e OCREngine) (*OCR, error) {
	cs := e.Charset()
	if len(cs) == 0 || len(cs) > maxCharset {
		return nil, fmt.Errorf("aisec-media: таблица символов модели OCR — от 1 до %d символов, получено %d", maxCharset, len(cs))
	}
	for _, c := range cs {
		if c == "" || !utf8.ValidString(c) || cleanText(c) != c && c != " " {
			return nil, errors.New("aisec-media: таблица символов модели OCR: пустой, не UTF-8 или управляющий символ")
		}
	}
	return &OCR{engine: e, charset: slices.Clone(cs), now: time.Now}, nil
}

// ocrLine — распознанная строка в пикселях исходного растра.
type ocrLine struct {
	text           string
	x0, y0, x1, y1 float64
	small          bool // меньшая сторона области карты ниже smallLineDet
}

// Read распознаёт текст кадра и передаёт блоки строк в ts. Ошибка —
// отмена ctx (срок анализа) или сбой исполнителя: тогда итога нет.
func (o *OCR) Read(ctx context.Context, img image.Image, ts *textSet) error {
	rgb := rgbRaster(img)
	start := o.now()
	normal, err := o.pass(ctx, rgb, 1)
	if err != nil {
		return err
	}
	took := o.now().Sub(start)
	seen := map[string]bool{}
	emitBlocks(ts, wire.SourceOCR, normal, rgb.w, rgb.h, seen)
	contrast, err := o.pass(ctx, contrastRaster(rgb), 1)
	if err != nil {
		return err
	}
	emitBlocks(ts, wire.SourceOCRContrast, contrast, rgb.w, rgb.h, seen)
	bs := smallBands(normal, rgb.h)
	if len(bs) == 0 {
		return nil
	}
	total := 0
	for _, b := range bs {
		total += b[1] - b[0]
	}
	whole := len(bs) > x2MaxBands || float64(total) > x2BandShare*float64(rgb.h)
	budget := took
	if whole {
		budget = x2Budget * took
	}
	if deadline, ok := ctx.Deadline(); ok && deadline.Sub(o.now()) < budget {
		return nil
	}
	if whole {
		bs = [][2]int{{0, rgb.h}}
	}
	var x2 []ocrLine
	for _, b := range bs {
		ls, err := o.pass(ctx, rgb.rows(b[0], b[1]), 2)
		if err != nil {
			return err
		}
		for _, l := range ls {
			l.y0 += float64(b[0])
			l.y1 += float64(b[0])
			x2 = append(x2, l)
		}
	}
	emitBlocks(ts, wire.SourceOCR, x2, rgb.w, rgb.h, seen)
	return nil
}

// smallBands — полосы кадра по вертикали вокруг мелких строк для прохода
// ×2: строка с запасом в две свои высоты сверху и снизу (продолжение
// строки детектор мог не увидеть вовсе), пересекающиеся полосы сливаются.
// Полоса идёт на всю ширину кадра.
func smallBands(lines []ocrLine, h int) [][2]int {
	var bs [][2]int
	for _, l := range lines {
		if !l.small {
			continue
		}
		pad := 2 * (l.y1 - l.y0)
		bs = append(bs, [2]int{max(0, int(math.Floor(l.y0-pad))), min(h, int(math.Ceil(l.y1+pad)))})
	}
	slices.SortFunc(bs, func(a, b [2]int) int { return a[0] - b[0] })
	var out [][2]int
	for _, b := range bs {
		if b[1] <= b[0] {
			continue
		}
		if n := len(out); n > 0 && b[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], b[1])
			continue
		}
		out = append(out, b)
	}
	return out
}

// pass — один проход: детектор строк при масштабе k (1 или 2), затем
// распознавание каждой строки.
func (o *OCR) pass(ctx context.Context, r *raster, k float64) ([]ocrLine, error) {
	s := k * math.Min(1, detLimit/float64(max(r.w, r.h)))
	rh := max(detAlign, int(math.RoundToEven(float64(r.h)*s/detAlign))*detAlign)
	rw := max(detAlign, int(math.RoundToEven(float64(r.w)*s/detAlign))*detAlign)
	prob, err := o.engine.Detect(ctx, detInput(r, rh, rw), rh, rw)
	if err != nil {
		return nil, err
	}
	if len(prob) != rh*rw {
		return nil, ErrOCRModel
	}
	sx, sy := float64(r.w)/float64(rw), float64(r.h)/float64(rh)
	var out []ocrLine
	for _, c := range components(prob, rh, rw, detThresh, maxOCRLines) {
		if len(c.pts) < minAreaPts || c.score < boxThresh {
			continue
		}
		box := minAreaRect(c.pts)
		side := math.Min(box.a1-box.a0, box.b1-box.b0)
		if side < minBoxSide {
			continue
		}
		q := box.unclip(unclipRatio).corners()
		for i := range q {
			q[i] = point{clampF(q[i].x*sx, 0, float64(r.w)), clampF(q[i].y*sy, 0, float64(r.h))}
		}
		q = order(q)
		x, n := recInput(r, q, k)
		if x == nil {
			continue
		}
		text, err := o.recognize(ctx, x, n)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(text) == "" {
			continue
		}
		x0, y0, x1, y1 := q.bounds(r.w, r.h)
		out = append(out, ocrLine{text: text, x0: x0, y0: y0, x1: x1, y1: y1, small: side < smallLineDet})
	}
	return out, nil
}

// recognize — распознавание строки и жадное декодирование CTC: на каждом
// шаге класс с наибольшей вероятностью, без пустого символа и повторов.
func (o *OCR) recognize(ctx context.Context, x []float32, w int) (string, error) {
	probs, classes, err := o.engine.Recognize(ctx, x, w)
	if err != nil {
		return "", err
	}
	if classes != len(o.charset)+1 || len(probs)%classes != 0 {
		return "", ErrOCRModel
	}
	var b strings.Builder
	prev := 0
	for t := 0; t < len(probs); t += classes {
		best := 0
		for c := 1; c < classes; c++ {
			if probs[t+c] > probs[t+best] {
				best = c
			}
		}
		if best != 0 && best != prev {
			b.WriteString(o.charset[best-1])
		}
		prev = best
	}
	return normalizeScripts(b.String()), nil
}

// emitBlocks собирает строки прохода в блоки и передаёт их в ts. Блок,
// текст которого уже дал другой проход, не повторяется.
func emitBlocks(ts *textSet, src wire.Source, lines []ocrLine, w, h int, seen map[string]bool) {
	for _, b := range blocks(lines) {
		if seen[b.text] {
			continue
		}
		seen[b.text] = true
		x0, y0 := int(math.Floor(b.x0)), int(math.Floor(b.y0))
		x1, y1 := int(math.Ceil(b.x1)), int(math.Ceil(b.y1))
		x0, y0 = min(max(x0, 0), w-1), min(max(y0, 0), h-1)
		box := &wire.Box{X: int64(x0), Y: int64(y0), W: int64(max(1, min(x1, w)-x0)), H: int64(max(1, min(y1, h)-y0))}
		if !ts.add(src, b.text, box) {
			return
		}
	}
}

// blocks — строки в порядке чтения, собранные в блоки. Рамки с близким
// центром по вертикали (ближе половины меньшей высоты) — одна строка,
// внутри — слева направо через пробел. Соседние строки с промежутком не
// больше высоты строки и пересекающиеся по горизонтали — один блок через
// перевод строки.
func blocks(lines []ocrLine) []ocrLine {
	ls := slices.Clone(lines)
	center := func(l ocrLine) float64 { return (l.y0 + l.y1) / 2 }
	slices.SortStableFunc(ls, func(a, b ocrLine) int { return cmpF(center(a), center(b)) })
	var rows [][]ocrLine
	for _, l := range ls {
		if n := len(rows); n > 0 {
			first := rows[n-1][0]
			if math.Abs(center(l)-center(first)) < 0.5*math.Min(l.y1-l.y0, first.y1-first.y0) {
				rows[n-1] = append(rows[n-1], l)
				continue
			}
		}
		rows = append(rows, []ocrLine{l})
	}
	var out []ocrLine
	for _, row := range rows {
		slices.SortStableFunc(row, func(a, b ocrLine) int { return cmpF(a.x0, b.x0) })
		r := row[0]
		parts := []string{r.text}
		for _, l := range row[1:] {
			parts = append(parts, l.text)
			r.x0, r.y0, r.x1, r.y1 = math.Min(r.x0, l.x0), math.Min(r.y0, l.y0), math.Max(r.x1, l.x1), math.Max(r.y1, l.y1)
		}
		r.text = strings.Join(parts, " ")
		if n := len(out); n > 0 {
			last := &out[n-1]
			gap := r.y0 - last.y1
			if gap <= math.Min(r.y1-r.y0, rowHeight(*last)) && r.x0 < last.x1 && last.x0 < r.x1 {
				last.text += "\n" + r.text
				last.x0, last.x1, last.y1 = math.Min(last.x0, r.x0), math.Max(last.x1, r.x1), math.Max(last.y1, r.y1)
				last.y0 = math.Min(last.y0, r.y0)
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// rowHeight — высота последней строки блока: высота блока, делённая на
// число строк.
func rowHeight(b ocrLine) float64 {
	return (b.y1 - b.y0) / float64(strings.Count(b.text, "\n")+1)
}

func cmpF(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// PassTexts — текст обычного прохода и прохода «контраст» в порядке чтения
// (блоки через перевод строки), без предела протокола: замер CER на корпусе
// (критерий ADR-0033, п. 1; make media-ocr-test). Изображение проверяется
// и декодируется, как в Analyze.
func (a Analyzer) PassTexts(ctx context.Context, data []byte) (normal, contrast string, err error) {
	if a.OCR == nil {
		return "", "", errors.New("aisec-media: OCR не подключён")
	}
	if int64(len(data)) > a.Limits.MaxBytes {
		return "", "", errors.New("aisec-media: изображение больше предела")
	}
	info, err := ParseHeader(data)
	if err != nil {
		return "", "", err
	}
	if reason := a.Limits.exceeded(info); reason != "" || !canDecode(info) {
		return "", "", fmt.Errorf("aisec-media: изображение не принято (%s)", reason)
	}
	frames, err := decode(data, info, a.Limits.rasterBudget())
	if err != nil {
		return "", "", err
	}
	rgb := rgbRaster(frames[0])
	join := func(r *raster) (string, error) {
		lines, err := a.OCR.pass(ctx, r, 1)
		if err != nil {
			return "", err
		}
		var parts []string
		for _, b := range blocks(lines) {
			parts = append(parts, b.text)
		}
		return strings.Join(parts, "\n"), nil
	}
	if normal, err = join(rgb); err != nil {
		return "", "", err
	}
	contrast, err = join(contrastRaster(rgb))
	return normal, contrast, err
}
