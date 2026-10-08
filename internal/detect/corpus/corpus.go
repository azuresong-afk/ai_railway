// Пакет corpus — корпусный стенд качества детекторов (ТЗ, 5.2): размеченные
// примеры в testdata/corpus/<детектор>/*.jsonl, расчёт точности и полноты.
//
// Формат строки:
//
//	{"id":"snils-001","lang":"ru","direction":"input","source":"user",
//	 "text":"...","expect":["pii.snils"],"note":"контрольное число верно"}
//
// expect — категории находок, которые детектор обязан найти; пустой список —
// негативный пример (в том числе текст, похожий на атаку или ПДн, но
// безопасный: ложные срабатывания для пилота дороже пропусков, ТЗ 1.6).
// ПДн в корпусе — только синтетические.
package corpus

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// Пределы корпуса.
const (
	MaxFileBytes = 16 << 20
	MaxLineBytes = 1 << 20
	MaxTextBytes = 256 << 10
)

// Sample — размеченный пример.
type Sample struct {
	ID        string           `json:"id"`
	Lang      string           `json:"lang"`
	Direction detect.Direction `json:"direction"`
	Source    detect.Source    `json:"source"`
	Text      string           `json:"text"`
	Expect    []string         `json:"expect"`
	Note      string           `json:"note"`
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	langs      = map[string]bool{"": true, "ru": true, "en": true, "mixed": true}
	sources    = map[detect.Source]bool{"": true, detect.SourceUser: true, detect.SourceRAG: true, detect.SourceTool: true, detect.SourceOutput: true}
)

// Parse читает примеры одного файла JSONL со строгой схемой.
func Parse(r io.Reader) ([]Sample, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxFileBytes {
		return nil, fmt.Errorf("файл корпуса больше %d байт", MaxFileBytes)
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64<<10), MaxLineBytes)
	var out []Sample
	for n := 1; sc.Scan(); n++ {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var s Sample
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("строка %d: %w", n, err)
		}
		if dec.More() {
			return nil, fmt.Errorf("строка %d: данные после объекта", n)
		}
		if err := s.validate(); err != nil {
			return nil, fmt.Errorf("строка %d (%s): %w", n, s.ID, err)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Sample) validate() error {
	switch {
	case !idRe.MatchString(s.ID):
		return errors.New("id — [a-z0-9_.-], до 64 символов")
	case !langs[s.Lang]:
		return errors.New("lang — ru, en, mixed или пусто")
	case s.Direction != detect.Input && s.Direction != detect.Output:
		return errors.New("direction — input или output")
	case !sources[s.Source]:
		return errors.New("source — user, rag, tool, output или пусто")
	case s.Text == "" || len(s.Text) > MaxTextBytes:
		return fmt.Errorf("text — от 1 до %d байт", MaxTextBytes)
	}
	for _, c := range s.Expect {
		if !categoryRe.MatchString(c) {
			return fmt.Errorf("категория %q", c)
		}
	}
	return nil
}

// Load читает все *.jsonl каталога; ID примеров уникальны в корпусе.
func Load(dir string) ([]Sample, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("%s: нет файлов корпуса *.jsonl", dir)
	}
	seen := map[string]string{}
	var all []Sample
	for _, f := range files {
		fh, err := os.Open(f) //nolint:gosec // G304: каталог корпуса задаёт утилита или тест из репозитория
		if err != nil {
			return nil, err
		}
		ss, err := Parse(fh)
		if cerr := fh.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for _, s := range ss {
			if prev, dup := seen[s.ID]; dup {
				return nil, fmt.Errorf("%s: id %s уже есть в %s", f, s.ID, prev)
			}
			seen[s.ID] = f
		}
		all = append(all, ss...)
	}
	return all, nil
}

// Counts — счётчики по категории или в целом.
type Counts struct {
	TP, FP, FN int
}

// Precision — доля верных среди найденного; без находок — 1.
func (c Counts) Precision() float64 {
	if c.TP+c.FP == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FP)
}

// Recall — доля найденного среди ожидаемого; без ожидаемого — 1.
func (c Counts) Recall() float64 {
	if c.TP+c.FN == 0 {
		return 1
	}
	return float64(c.TP) / float64(c.TP+c.FN)
}

// Report — результат оценки детектора на корпусе.
type Report struct {
	Detector    string
	Samples     int
	Total       Counts
	ByCategory  map[string]Counts
	FalsePos    []string // ID примеров с ложными срабатываниями
	Missed      []string // ID примеров с пропусками
	Errors      []string // ID примеров, на которых детектор дал сбой
	MaxDuration time.Duration
}

// MinScore — находки с оценкой ниже не считаются срабатыванием.
const MinScore = 0.5

// Evaluate прогоняет детектор по корпусу. Счёт — по категориям: категория,
// найденная и ожидаемая, — TP; найденная без ожидания — FP; ожидаемая и не
// найденная — FN. Сбой детектора на примере считается пропуском всех
// ожидаемых категорий.
func Evaluate(ctx context.Context, d detect.Detector, samples []Sample, timeout time.Duration) (*Report, error) {
	reg, err := detect.NewRegistry(d)
	if err != nil {
		return nil, err
	}
	rep := &Report{Detector: d.ID(), Samples: len(samples), ByCategory: map[string]Counts{}}
	add := func(cat string, f func(*Counts)) {
		c := rep.ByCategory[cat]
		f(&c)
		rep.ByCategory[cat] = c
		f(&rep.Total)
	}
	for _, s := range samples {
		start := time.Now()
		fs, runErrs, err := reg.Run(ctx, []string{d.ID()}, detect.Text{Text: s.Text, Direction: s.Direction, Source: s.Source, Lang: s.Lang}, timeout)
		if err != nil {
			return nil, err
		}
		if el := time.Since(start); el > rep.MaxDuration {
			rep.MaxDuration = el
		}
		got := map[string]bool{}
		if len(runErrs) > 0 {
			rep.Errors = append(rep.Errors, s.ID)
		}
		for _, f := range fs {
			if f.Score >= MinScore {
				got[f.Category] = true
			}
		}
		fp, fn := false, false
		for _, c := range s.Expect {
			if got[c] {
				add(c, func(x *Counts) { x.TP++ })
			} else {
				add(c, func(x *Counts) { x.FN++ })
				fn = true
			}
		}
		for c := range got {
			if !slices.Contains(s.Expect, c) {
				add(c, func(x *Counts) { x.FP++ })
				fp = true
			}
		}
		if fp {
			rep.FalsePos = append(rep.FalsePos, s.ID)
		}
		if fn {
			rep.Missed = append(rep.Missed, s.ID)
		}
	}
	return rep, nil
}
