// Пакет mltest — тестовый исполнитель моделей без ONNX Runtime и сборка
// подписанного пакета моделей для тестов (ADR-0024). В поставку не входит:
// импортируется только из тестов.
package mltest

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Score — оценка тестовой модели для найденного слова.
const Score = 0.9

// Executor — тестовый исполнитель: модель ищет слова из своего
// «токенизатора» (JSON {"words": {"слово": "метка"}}) и отмечает каждое
// вхождение с оценкой Score.
type Executor struct {
	// Hook, если задан, вызывается перед каждым выводом: так тесты имитируют
	// зависание, панику и сбой исполнителя.
	Hook func(ctx context.Context, text string) error
}

type tokenizer struct {
	Words map[string]string `json:"words"`
}

// Load — модель из проверенных байтов пакета.
func (e Executor) Load(m ml.LoadedModel) (ml.Model, error) {
	var tk tokenizer
	if err := json.Unmarshal(m.Tokenizer, &tk); err != nil {
		return nil, fmt.Errorf("тестовая модель %s: %w", m.Spec.ID, err)
	}
	words := make([]string, 0, len(tk.Words))
	for w := range tk.Words {
		words = append(words, w)
	}
	sort.Strings(words)
	return &Model{info: m.Spec.Info(), words: words, labels: tk.Words, hook: e.Hook}, nil
}

// Model — тестовая модель.
type Model struct {
	info   ml.ModelInfo
	words  []string
	labels map[string]string
	hook   func(ctx context.Context, text string) error
}

// NewModel — тестовая модель без пакета.
func NewModel(info ml.ModelInfo, words map[string]string, hook func(ctx context.Context, text string) error) *Model {
	ws := make([]string, 0, len(words))
	for w := range words {
		ws = append(ws, w)
	}
	sort.Strings(ws)
	return &Model{info: info, words: ws, labels: words, hook: hook}
}

// Info — описание модели.
func (m *Model) Info() ml.ModelInfo { return m.info }

// Run — вхождения слов модели.
func (m *Model) Run(ctx context.Context, text string) (ml.Result, error) {
	if m.hook != nil {
		if err := m.hook(ctx, text); err != nil {
			return ml.Result{}, err
		}
	}
	res := ml.Result{Findings: []ml.Score{}}
	for _, w := range m.words {
		for off := 0; ; {
			i := strings.Index(text[off:], w)
			if i < 0 {
				break
			}
			start := off + i
			res.Findings = append(res.Findings, ml.Score{Label: m.labels[w], Score: Score, Start: start, End: start + len(w)})
			off = start + len(w)
		}
	}
	return res, nil
}

// Close ничего не освобождает.
func (m *Model) Close() error { return nil }

// Spec — модель тестового пакета.
type Spec struct {
	ID         string
	Version    string
	Directions []string
	// Words — слово → метка; метки модели — значения Words.
	Words map[string]string
}

// Info — описание модели протокола.
func (s Spec) Info() ml.ModelInfo {
	return ml.ModelInfo{ID: s.ID, Version: s.Version, Labels: s.labels(), Directions: s.Directions}
}

func (s Spec) labels() []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range s.Words {
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// WritePackage пишет в dir подписанный пакет моделей: файлы моделей,
// манифест и подпись signer. Возвращает манифест.
func WritePackage(dir string, p aisecCrypto.Provider, signer aisecCrypto.Signer, specs ...Spec) (*ml.ModelsManifest, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	m := &ml.ModelsManifest{Format: ml.ModelsFormatV1, Version: "test-1", Profile: p.Name(), HashAlg: h.Name(),
		Created: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC)}
	for _, s := range specs {
		if err := os.MkdirAll(filepath.Join(dir, s.ID), 0o750); err != nil {
			return nil, err
		}
		tok, err := json.Marshal(tokenizer{Words: s.Words})
		if err != nil {
			return nil, err
		}
		bom, err := json.Marshal(map[string]any{
			"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
			"components": []map[string]any{{"type": "machine-learning-model", "name": s.ID, "version": s.Version}},
		})
		if err != nil {
			return nil, err
		}
		files := []struct {
			name, role string
			data       []byte
		}{
			{"model.onnx", ml.RoleModel, []byte("test-onnx:" + s.ID)},
			{"tokenizer.json", ml.RoleTokenizer, tok},
			{"mlbom.cdx.json", ml.RoleMLBOM, bom},
		}
		spec := ml.ModelSpec{ID: s.ID, Version: s.Version, Task: ml.TaskClassification, Labels: s.labels(),
			Directions: s.Directions, MaxTokens: 512}
		for _, f := range files {
			rel := s.ID + "/" + f.name
			if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), f.data, 0o600); err != nil {
				return nil, err
			}
			spec.Files = append(spec.Files, ml.ModelFile{Path: rel, Role: f.role, Size: int64(len(f.data)), Hash: hex.EncodeToString(h.Sum(f.data))})
		}
		m.Models = append(m.Models, spec)
	}
	data, err := ml.MarshalModelsManifest(m)
	if err != nil {
		return nil, err
	}
	sig, err := ml.SignModels(signer, data)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, ml.ModelsManifestFile), data, 0o600); err != nil {
		return nil, err
	}
	return m, os.WriteFile(filepath.Join(dir, ml.ModelsSignatureFile), sig, 0o600)
}
