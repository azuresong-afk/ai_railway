// Command ocr-eval — оценка кандидатов OCR на корпусе изображений (задача
// 5.40, ADR-0033): CER по русскому и английскому, находки текстовых
// детекторов по распознанному тексту (DM-45, DM-46), ложные находки на
// чистых образцах и время. Распознавание выполняет run_ocr.py рядом
// (Python, только для разработки); этот инструмент читает его итог и
// корпус testdata/corpus/media и пишет таблицу Markdown для ADR-0033.
//
// Изображения здесь не декодируются (декодеры — только в internal/media):
// на входе только JSON с текстом строк и рамками.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
)

// Пределы входа: итог run_ocr.py и файлы корпуса — свои, но читаются с
// пределом, как любой вход.
const (
	maxRunBytes    = 64 << 20
	maxCorpusBytes = 1 << 20
)

// Проходы OCR: обычный и с повышенной контрастностью (ADR-0033).
const (
	passNormal   = "ocr"
	passContrast = "ocr_contrast"
)

type line struct {
	Text  string  `json:"text"`
	Score float64 `json:"score"`
	Box   [4]int  `json:"box"`
}

type pass struct {
	Lines   []line   `json:"lines"`
	MS      float64  `json:"ms"`
	ModelMS *float64 `json:"model_ms,omitempty"`
}

type runImage struct {
	ID      string                     `json:"id"`
	Engines map[string]map[string]pass `json:"engines"`
}

type runFile struct {
	Threads int        `json:"threads"`
	CPUs    []int      `json:"cpus"`
	Images  []runImage `json:"images"`
}

type expect struct {
	Type   string `json:"type"`
	Source string `json:"source"`
	Text   string `json:"text"`
}

type sample struct {
	ID     string   `json:"id"`
	Lang   string   `json:"lang"`
	DM     []string `json:"dm"`
	Expect []expect `json:"expect"`
	ref    string
}

func main() {
	run := flag.String("run", "", "итоги run_ocr.py (JSON) через запятую: кандидаты объединяются по изображению")
	corpus := flag.String("corpus", "testdata/corpus/media", "каталог корпуса")
	out := flag.String("out", "", "файл отчёта Markdown (пусто — стандартный вывод)")
	flag.Parse()
	if err := report(*run, *corpus, *out); err != nil {
		fmt.Fprintln(os.Stderr, "ocr-eval:", err)
		os.Exit(1)
	}
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт разработчик
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // только чтение
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: больше %d байт", path, limit)
	}
	return b, nil
}

func loadSamples(dir string) (map[string]*sample, error) {
	b, err := readLimited(filepath.Join(dir, "manifest.json"), maxCorpusBytes)
	if err != nil {
		return nil, err
	}
	var m struct {
		Images []struct {
			ID string `json:"id"`
		} `json:"images"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	out := map[string]*sample{}
	for _, img := range m.Images {
		if img.ID == "" || strings.ContainsAny(img.ID, "/\\.") {
			return nil, fmt.Errorf("manifest.json: недопустимый ID %q", img.ID)
		}
		b, err := readLimited(filepath.Join(dir, img.ID+".json"), maxCorpusBytes)
		if err != nil {
			return nil, err
		}
		var s sample
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, fmt.Errorf("%s.json: %w", img.ID, err)
		}
		ref, err := readLimited(filepath.Join(dir, img.ID+".txt"), maxCorpusBytes)
		if err != nil {
			return nil, err
		}
		s.ref = normalize(string(ref))
		out[img.ID] = &s
	}
	return out, nil
}

// normalize — строки без пустых, пробелы внутри строки схлопнуты.
func normalize(s string) string {
	var lines []string
	for l := range strings.SplitSeq(s, "\n") {
		if f := strings.Fields(l); len(f) > 0 {
			lines = append(lines, strings.Join(f, " "))
		}
	}
	return strings.Join(lines, "\n")
}

// readingOrder собирает строки изображения в порядке чтения: рамки с
// близким центром по вертикали — одна строка, внутри — слева направо.
func readingOrder(ls []line) string {
	ls = slices.Clone(ls)
	sort.SliceStable(ls, func(i, j int) bool { return center(ls[i]) < center(ls[j]) })
	var rows [][]line
	for _, l := range ls {
		if n := len(rows); n > 0 {
			last := rows[n-1]
			if abs(center(l)-center(last[0])) < 0.5*float64(min(l.Box[3], last[0].Box[3])) {
				rows[n-1] = append(last, l)
				continue
			}
		}
		rows = append(rows, []line{l})
	}
	var out []string
	for _, r := range rows {
		sort.SliceStable(r, func(i, j int) bool { return r[i].Box[0] < r[j].Box[0] })
		parts := make([]string, len(r))
		for i, l := range r {
			parts[i] = l.Text
		}
		out = append(out, strings.Join(parts, " "))
	}
	return normalize(strings.Join(out, "\n"))
}

func center(l line) float64 { return float64(l.Box[1]) + float64(l.Box[3])/2 }

func abs(v float64) float64 {
	if v < 0 {
		return -v
	}
	return v
}

// distance — расстояние Левенштейна по символам Unicode.
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			c := prev[j-1]
			if ra[i-1] != rb[j-1] {
				c++
			}
			cur[j] = min(c, prev[j]+1, cur[j-1]+1)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// findings — категории текстовых детекторов входа на тексте.
func findings(dets []detect.Detector, text, lang string) ([]detect.Finding, error) {
	var out []detect.Finding
	for _, d := range dets {
		if !slices.Contains(d.Directions(), detect.Input) {
			continue
		}
		fs, err := d.Detect(context.Background(), detect.Text{Text: text, Direction: detect.Input, Source: detect.SourceUser, Lang: lang})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.ID(), err)
		}
		out = append(out, fs...)
	}
	return out, nil
}

// engineScore — итог кандидата.
type engineScore struct {
	errs, refs    map[string]int // по языку: правки и символы эталона, обычный проход
	errsC         map[string]int // то же, проход с контрастностью
	want, found   map[string]int // по строке матрицы: ожидаемые находки OCR и найденные
	missed        []string
	falsePos      []string
	ms, modelMS   []float64 // оба прохода на изображение
	perImageCER   map[string]float64
	perImageCERC  map[string]float64
	modelMeasured bool
}

// loadRuns читает итоги прогонов и объединяет кандидатов по изображению.
func loadRuns(paths []string) (runFile, error) {
	var out runFile
	at := map[string]int{}
	for _, p := range paths {
		b, err := readLimited(p, maxRunBytes)
		if err != nil {
			return out, err
		}
		var rf runFile
		if err := json.Unmarshal(b, &rf); err != nil {
			return out, fmt.Errorf("%s: %w", p, err)
		}
		if out.Threads == 0 {
			out.Threads, out.CPUs = rf.Threads, rf.CPUs
		} else if rf.Threads != out.Threads || !slices.Equal(rf.CPUs, out.CPUs) {
			return out, fmt.Errorf("%s: другие потоки или ядра, время несравнимо", p)
		}
		for _, img := range rf.Images {
			i, ok := at[img.ID]
			if !ok {
				at[img.ID] = len(out.Images)
				out.Images = append(out.Images, runImage{ID: img.ID, Engines: map[string]map[string]pass{}})
				i = len(out.Images) - 1
			}
			for name, ps := range img.Engines {
				if _, dup := out.Images[i].Engines[name]; dup {
					return out, fmt.Errorf("%s: %s у %s уже есть в другом прогоне", p, name, img.ID)
				}
				out.Images[i].Engines[name] = ps
			}
		}
	}
	return out, nil
}

func report(runPath, corpus, outPath string) error {
	if runPath == "" {
		return errors.New("нужен -run")
	}
	rf, err := loadRuns(strings.Split(runPath, ","))
	if err != nil {
		return err
	}
	samples, err := loadSamples(corpus)
	if err != nil {
		return err
	}
	dets := builtin.All()
	scores := map[string]*engineScore{}
	var engines []string
	for _, img := range rf.Images {
		s, ok := samples[img.ID]
		if !ok {
			return fmt.Errorf("%s: нет в корпусе", img.ID)
		}
		for name, passes := range img.Engines {
			es := scores[name]
			if es == nil {
				es = &engineScore{errs: map[string]int{}, refs: map[string]int{}, errsC: map[string]int{},
					want: map[string]int{}, found: map[string]int{}, perImageCER: map[string]float64{}, perImageCERC: map[string]float64{}}
				scores[name] = es
				engines = append(engines, name)
			}
			texts := map[string]string{}
			var total, model float64
			for _, p := range []string{passNormal, passContrast} {
				texts[p] = readingOrder(passes[p].Lines)
				total += passes[p].MS
				if passes[p].ModelMS != nil {
					model += *passes[p].ModelMS
					es.modelMeasured = true
				}
			}
			es.ms, es.modelMS = append(es.ms, total), append(es.modelMS, model)
			if s.ref != "" {
				n := len([]rune(s.ref))
				d := distance(texts[passNormal], s.ref)
				es.errs[s.Lang] += d
				dc := distance(texts[passContrast], s.ref)
				es.errsC[s.Lang] += dc
				es.perImageCERC[img.ID] = float64(dc) / float64(n)
				es.refs[s.Lang] += n
				es.perImageCER[img.ID] = float64(d) / float64(n)
			}
			// Находки — по тексту обоих проходов, как в aisec-media (5.42).
			var got []detect.Finding
			for _, p := range []string{passNormal, passContrast} {
				fs, err := findings(dets, texts[p], s.Lang)
				if err != nil {
					return err
				}
				got = append(got, fs...)
			}
			var allowed []string
			for _, e := range s.Expect {
				if e.Source != passNormal && e.Source != passContrast {
					continue // метаданные и QR — задача 5.43
				}
				allowed = append(allowed, e.Type)
				dm := s.DM[0]
				es.want[dm]++
				if slices.ContainsFunc(got, func(f detect.Finding) bool { return f.Category == e.Type }) {
					es.found[dm]++
				} else {
					es.missed = append(es.missed, fmt.Sprintf("%s: %s", img.ID, e.Type))
				}
			}
			for _, f := range got {
				if !slices.Contains(allowed, f.Category) {
					fp := fmt.Sprintf("%s: %s", img.ID, f.Category)
					if !slices.Contains(es.falsePos, fp) {
						es.falsePos = append(es.falsePos, fp)
					}
				}
			}
		}
	}
	sort.Strings(engines)
	var w strings.Builder
	fmt.Fprintf(&w, "Изображений: %d, потоков: %d, ядра: %v.\n\n", len(rf.Images), rf.Threads, rf.CPUs)
	w.WriteString("| Кандидат | CER RU | CER RU, контраст | CER EN | CER EN, контраст | DM-45 | DM-46 | Ложные | Время на изображение, медиана / p95, мс | Из них модель, медиана, мс |\n")
	w.WriteString("|---|---|---|---|---|---|---|---|---|---|\n")
	for _, name := range engines {
		es := scores[name]
		model := "—"
		if es.modelMeasured {
			model = fmt.Sprintf("%.0f", quantile(es.modelMS, 0.5))
		}
		fmt.Fprintf(&w, "| %s | %s | %s | %s | %s | %d/%d | %d/%d | %d | %.0f / %.0f | %s |\n", name,
			pct(es.errs["ru"], es.refs["ru"]), pct(es.errsC["ru"], es.refs["ru"]),
			pct(es.errs["en"], es.refs["en"]), pct(es.errsC["en"], es.refs["en"]),
			es.found["DM-45"], es.want["DM-45"], es.found["DM-46"], es.want["DM-46"], len(es.falsePos),
			quantile(es.ms, 0.5), quantile(es.ms, 0.95), model)
	}
	for _, name := range engines {
		es := scores[name]
		fmt.Fprintf(&w, "\n**%s.** Пропущено: %s. Ложные: %s.\n", name, list(es.missed), list(es.falsePos))
		ids := make([]string, 0, len(es.perImageCER))
		for id := range es.perImageCER {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = fmt.Sprintf("%s %.1f / %.1f %%", id, 100*es.perImageCER[id], 100*es.perImageCERC[id])
		}
		fmt.Fprintf(&w, "CER по изображениям (обычный / контраст): %s.\n", strings.Join(parts, ", "))
	}
	if outPath == "" {
		_, err := io.WriteString(os.Stdout, w.String())
		return err
	}
	return os.WriteFile(outPath, []byte(w.String()), 0o600)
}

func pct(errs, refs int) string {
	if refs == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f %%", 100*float64(errs)/float64(refs))
}

func quantile(v []float64, q float64) float64 {
	if len(v) == 0 {
		return 0
	}
	s := slices.Clone(v)
	slices.Sort(s)
	i := int(q*float64(len(s))+0.5) - 1
	return s[max(0, min(i, len(s)-1))]
}

func list(v []string) string {
	if len(v) == 0 {
		return "нет"
	}
	return strings.Join(v, "; ")
}
