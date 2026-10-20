package detect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sync"
	"time"
	"unicode/utf8"
)

// Direction — направление проверки.
type Direction string

// Направления.
const (
	Input  Direction = "input"  // запрос к модели, документы RAG, ответы инструментов
	Output Direction = "output" // ответ модели, аргументы tool_calls
)

// Source — откуда текст (ТЗ, 5.1, Check API).
type Source string

// Источники.
const (
	SourceUser   Source = "user"
	SourceRAG    Source = "rag"
	SourceTool   Source = "tool"
	SourceOutput Source = "output"
)

// Text — проверяемый текст.
type Text struct {
	Text      string
	Direction Direction
	Source    Source
	// Lang — язык, если известен: ru, en; пусто — неизвестен.
	Lang string
}

// Finding — находка детектора. Исходных чувствительных значений не
// содержит: только категория, оценка и позиции в тексте.
type Finding struct {
	Detector string
	Version  string
	// Category — вид находки: pii.snils, injection.override и т. п.
	Category string
	// Threat — ID строки матрицы обнаружения (DM-NN, ТЗ 5.16).
	Threat string
	// Score — уверенность 0–1.
	Score float64
	// Start, End — байтовые позиции в Text.Text, [Start, End).
	Start, End int
	// Rule — правило детектора, которое сработало (для трассировки решения).
	Rule string
}

// Detector — детектор (ТЗ, 5.2). Реализация безопасна для одновременного
// вызова и работает за линейное время от длины текста (только RE2,
// без возвратов).
type Detector interface {
	ID() string
	// Version попадает в событие вместе с находкой.
	Version() string
	// Directions — где детектор применим.
	Directions() []Direction
	Detect(ctx context.Context, t Text) ([]Finding, error)
}

// Categorizer — необязательный интерфейс детектора: все категории находок,
// которые он может выдать. По нему политика проверяет категории правил:
// опечатка в категории не должна давать правило, которое молча никогда не
// срабатывает (ТЗ, 5.3). Встроенные детекторы реализуют его все.
type Categorizer interface {
	Categories() []string
}

var (
	idRe       = regexp.MustCompile(`^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*)*$`)
	versionRe  = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	categoryRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)
	threatRe   = regexp.MustCompile(`^DM-\d{2}$`)
	ruleRe     = regexp.MustCompile(`^[a-z0-9_.-]{0,64}$`)
)

// ValidateFinding проверяет находку относительно текста: детектор с ошибкой
// не должен испортить событие или маскирование (неверные позиции, в том
// числе посреди символа UTF-8 — маскирование оставило бы обрывок символа).
func ValidateFinding(f Finding, d Detector, text string) error {
	textLen := len(text)
	switch {
	case f.Detector != d.ID() || f.Version != d.Version():
		return errors.New("находка: детектор или версия не совпадают")
	case !categoryRe.MatchString(f.Category):
		return fmt.Errorf("находка: категория %q", f.Category)
	case !threatRe.MatchString(f.Threat):
		return fmt.Errorf("находка: строка матрицы %q", f.Threat)
	case math.IsNaN(f.Score) || f.Score < 0 || f.Score > 1:
		return fmt.Errorf("находка: оценка %v вне 0–1", f.Score)
	case f.Start < 0 || f.End < f.Start || f.End > textLen:
		return fmt.Errorf("находка: позиции [%d, %d) вне текста длиной %d", f.Start, f.End, textLen)
	case !OnRuneBoundary(text, f.Start) || !OnRuneBoundary(text, f.End):
		return fmt.Errorf("находка: позиции [%d, %d) разрезают символ UTF-8", f.Start, f.End)
	case !ruleRe.MatchString(f.Rule):
		return errors.New("находка: недопустимое имя правила")
	}
	return nil
}

// OnRuneBoundary — позиция p (0 ≤ p ≤ len(text)) не разрезает символ UTF-8:
// совпадает с началом символа при декодировании текста слева направо.
// В невалидном тексте одиночный байт продолжения — отдельный символ.
// Проверка локальная: символ UTF-8 не длиннее 4 байт.
func OnRuneBoundary(text string, p int) bool {
	if p <= 0 || p >= len(text) {
		return p == 0 || p == len(text)
	}
	if utf8.RuneStart(text[p]) {
		return true
	}
	for q := p - 1; q >= 0 && q >= p-3; q-- {
		if utf8.RuneStart(text[q]) {
			_, size := utf8.DecodeRuneInString(text[q:])
			return q+size <= p
		}
	}
	return true
}

// Registry — зарегистрированные детекторы.
type Registry struct {
	byID  map[string]Detector
	order []string
}

// NewRegistry регистрирует детекторы: ID уникальны, версии — x.y.z.
func NewRegistry(ds ...Detector) (*Registry, error) {
	r := &Registry{byID: map[string]Detector{}}
	for _, d := range ds {
		if !idRe.MatchString(d.ID()) || !versionRe.MatchString(d.Version()) || len(d.Directions()) == 0 {
			return nil, fmt.Errorf("детектор %q: неверные ID, версия или направления", d.ID())
		}
		if _, dup := r.byID[d.ID()]; dup {
			return nil, fmt.Errorf("детектор %s зарегистрирован дважды", d.ID())
		}
		r.byID[d.ID()] = d
		r.order = append(r.order, d.ID())
	}
	return r, nil
}

// Get возвращает детектор по ID.
func (r *Registry) Get(id string) (Detector, bool) {
	d, ok := r.byID[id]
	return d, ok
}

// IDs — идентификаторы в порядке регистрации.
func (r *Registry) IDs() []string { return slices.Clone(r.order) }

// RunError — сбой детектора: ошибка, превышение срока, паника или
// некорректная находка. Что с этим делать (fail_open, fail_closed), решает
// конвейер шлюза.
type RunError struct {
	Detector string
	Err      error
}

func (e RunError) Error() string { return e.Detector + ": " + e.Err.Error() }

// ErrDetectorTimeout — детектор не уложился в срок.
var ErrDetectorTimeout = errors.New("детектор не уложился в срок")

// Run запускает детекторы ids, применимые к направлению текста,
// параллельно, каждому — не дольше timeout. Находки — в порядке ids.
// Неизвестный ID — ошибка вызывающего кода, а не сбой детектора.
func (r *Registry) Run(ctx context.Context, ids []string, t Text, timeout time.Duration) ([]Finding, []RunError, error) {
	type result struct {
		id  string
		fs  []Finding
		err error
	}
	results := make([]result, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		d, ok := r.byID[id]
		if !ok {
			return nil, nil, fmt.Errorf("неизвестный детектор %q", id)
		}
		if !slices.Contains(d.Directions(), t.Direction) {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			fs, err := runOne(ctx, d, t, timeout)
			results[i] = result{id: d.ID(), fs: fs, err: err}
		}()
	}
	wg.Wait()
	var all []Finding
	var errs []RunError
	for _, res := range results {
		if res.err != nil {
			errs = append(errs, RunError{Detector: res.id, Err: res.err})
			continue
		}
		all = append(all, res.fs...)
	}
	return all, errs, nil
}

// runOne выполняет детектор со сроком. Детектор, который не реагирует на
// контекст, продолжит работу в своей горутине, но результат уже не ждут;
// линейное время детекторов ограничивает такую утечку.
func runOne(parent context.Context, d Detector, t Text, timeout time.Duration) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	type out struct {
		fs  []Finding
		err error
	}
	ch := make(chan out, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				// Содержимое паники может включать фрагмент текста — не передаём.
				ch <- out{err: errors.New("детектор завершился аварийно")}
			}
		}()
		fs, err := d.Detect(ctx, t)
		ch <- out{fs, err}
	}()
	select {
	case o := <-ch:
		if o.err != nil {
			if ctx.Err() != nil {
				return nil, stopReason(parent)
			}
			return nil, o.err
		}
		for _, f := range o.fs {
			if err := ValidateFinding(f, d, t.Text); err != nil {
				return nil, err
			}
		}
		return o.fs, nil
	case <-ctx.Done():
		return nil, stopReason(parent)
	}
}

// stopReason — почему детектор остановлен: вызывающий отменил проверку или
// истёк его общий срок (клиент ушёл) — ошибка его контекста; иначе —
// детектор не уложился в свой срок.
func stopReason(parent context.Context) error {
	if err := parent.Err(); err != nil {
		return err
	}
	return ErrDetectorTimeout
}
