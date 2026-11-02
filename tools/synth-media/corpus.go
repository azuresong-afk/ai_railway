package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пределы aisec-media по умолчанию (ADR-0032, раздел 6): ни один файл
// корпуса не должен отклоняться по размеру — тяжёлые файлы для DM-50
// строятся отдельно (задача 5.44).
const (
	limitBytes  = 10 << 20
	limitPixels = 25_000_000
	// maxSideFile — предел текстового файла корпуса (эталон, ожидания,
	// манифест) при чтении.
	maxSideFile = 1 << 20
)

const (
	manifestName = "manifest.json"
	readmeName   = "README.md"
)

type manifest struct {
	Version   int          `json:"version"`
	Generator string       `json:"generator"`
	Limits    limits       `json:"limits"`
	Images    []imageEntry `json:"images"`
	Files     []fileEntry  `json:"files"`
}

type limits struct {
	MaxBytes  int `json:"max_bytes"`
	MaxPixels int `json:"max_pixels"`
}

type imageEntry struct {
	ID     string   `json:"id"`
	File   string   `json:"file"`
	Format string   `json:"format"`
	Width  int      `json:"width"`
	Height int      `json:"height"`
	Bytes  int      `json:"bytes"`
	Kind   string   `json:"kind"`
	Lang   string   `json:"lang"`
	DM     []string `json:"dm"`
}

type fileEntry struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// expectDoc — ожидания по изображению (<id>.json): текст метаданных и QR,
// которые записал генератор, и находки текстовых детекторов по источникам.
type expectDoc struct {
	ID          string     `json:"id"`
	File        string     `json:"file"`
	TextFile    string     `json:"text_file"`
	Kind        string     `json:"kind"`
	Lang        string     `json:"lang"`
	DM          []string   `json:"dm"`
	Description string     `json:"description"`
	Metadata    []metaItem `json:"metadata"`
	QR          []string   `json:"qr"`
	Expect      []finding  `json:"expect"`
}

func (s *sample) expectJSON() ([]byte, error) {
	d := expectDoc{ID: s.ID, File: s.file(), TextFile: s.ID + ".txt", Kind: s.Kind, Lang: s.Lang, DM: s.DM,
		Description: s.Desc, Metadata: s.Meta, QR: s.qrTexts(), Expect: s.Expect}
	if d.Metadata == nil {
		d.Metadata = []metaItem{}
	}
	if d.QR == nil {
		d.QR = []string{}
	}
	if d.Expect == nil {
		d.Expect = []finding{}
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func sha256Hex(b []byte) (string, error) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return "", err
	}
	h, err := p.Hasher()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(b)), nil
}

// generate отрисовывает образцы (все или only) и пишет корпус и манифест.
func generate(r *renderer, dir string, only string) error {
	all := samples()
	for i := range all {
		s := &all[i]
		if only != "" && s.ID != only {
			continue
		}
		img, err := r.renderPNG(s)
		if err != nil {
			return fmt.Errorf("%s: %w", s.ID, err)
		}
		if s.Format == "jpeg" {
			if img, err = r.toJPEG(s.ID, img, s.Quality); err != nil {
				return fmt.Errorf("%s: %w", s.ID, err)
			}
		}
		if len(s.Meta) > 0 {
			if s.Format == "png" {
				img, err = addPNGText(img, s.Meta)
			} else {
				img, err = addJPEGMeta(img, s.Meta)
			}
			if err != nil {
				return fmt.Errorf("%s: %w", s.ID, err)
			}
		}
		exp, err := s.expectJSON()
		if err != nil {
			return err
		}
		for name, data := range map[string][]byte{s.file(): img, s.ID + ".txt": []byte(s.refText()), s.ID + ".json": exp} {
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
				return err
			}
		}
	}
	return writeManifest(dir, all)
}

func writeManifest(dir string, all []sample) error {
	m := manifest{Version: 1, Generator: "go run ./tools/synth-media", Limits: limits{limitBytes, limitPixels}}
	for i := range all {
		s := &all[i]
		data, err := readLimited(filepath.Join(dir, s.file()), limitBytes+1)
		if err != nil {
			return err
		}
		format, w, ht, _, err := imageInfo(data)
		if err != nil {
			return fmt.Errorf("%s: %w", s.file(), err)
		}
		m.Images = append(m.Images, imageEntry{ID: s.ID, File: s.file(), Format: format, Width: w, Height: ht,
			Bytes: len(data), Kind: s.Kind, Lang: s.Lang, DM: s.DM})
		for _, name := range []string{s.file(), s.ID + ".txt", s.ID + ".json"} {
			b, err := readLimited(filepath.Join(dir, name), limitBytes+1)
			if err != nil {
				return err
			}
			sum, err := sha256Hex(b)
			if err != nil {
				return err
			}
			m.Files = append(m.Files, fileEntry{Path: name, Bytes: len(b), SHA256: sum})
		}
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, manifestName), append(b, '\n'), 0o600)
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь внутри каталога корпуса
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() //nolint:gosec // G104: файл только читался
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: больше %d байт", path, limit)
	}
	return b, nil
}

// verify сверяет каталог корпуса с манифестом и составом образцов: список
// файлов, SHA-256, размеры по заголовку и пределы ADR-0032, эталон и
// ожидания у каждого изображения, текст метаданных в самих файлах.
// Возвращает список расхождений.
func verify(dir string) ([]string, error) {
	raw, err := readLimited(filepath.Join(dir, manifestName), maxSideFile)
	if err != nil {
		return nil, err
	}
	var m manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", manifestName, err)
	}
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	if m.Version != 1 || m.Limits != (limits{limitBytes, limitPixels}) {
		bad("манифест: версия %d или пределы %+v не те", m.Version, m.Limits)
	}

	// Файлы каталога и манифеста — одни и те же, хеши сходятся.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	onDisk := map[string]bool{}
	for _, e := range entries {
		if e.Name() == manifestName || e.Name() == readmeName {
			continue
		}
		if !e.Type().IsRegular() {
			bad("%s: не обычный файл", e.Name())
			continue
		}
		onDisk[e.Name()] = true
	}
	listed := map[string]bool{}
	for _, f := range m.Files {
		if listed[f.Path] {
			bad("%s: дважды в манифесте", f.Path)
		}
		listed[f.Path] = true
		if filepath.Base(f.Path) != f.Path || !onDisk[f.Path] {
			bad("%s: в манифесте, но нет в каталоге", f.Path)
			continue
		}
		b, err := readLimited(filepath.Join(dir, f.Path), limitBytes)
		if err != nil {
			bad("%v", err)
			continue
		}
		sum, err := sha256Hex(b)
		if err != nil {
			return nil, err
		}
		if sum != f.SHA256 || len(b) != f.Bytes {
			bad("%s: SHA-256 или размер не совпадают с манифестом", f.Path)
		}
	}
	for name := range onDisk {
		if !listed[name] {
			bad("%s: файла нет в манифесте", name)
		}
	}

	// Образцы генератора и изображения манифеста — в одном порядке.
	all := samples()
	if len(all) != len(m.Images) {
		bad("в манифесте %d изображений, в генераторе %d: перегенерируйте корпус (make media-corpus)", len(m.Images), len(all))
	}
	for i := range min(len(all), len(m.Images)) {
		s, im := &all[i], m.Images[i]
		if s.ID != im.ID || s.file() != im.File || s.Kind != im.Kind || s.Lang != im.Lang || !slices.Equal(s.DM, im.DM) {
			bad("%s: запись манифеста не совпадает с образцом генератора %s", im.ID, s.ID)
			continue
		}
		for _, name := range []string{im.File, s.ID + ".txt", s.ID + ".json"} {
			if !listed[name] {
				bad("%s: нет файла %s в манифесте", s.ID, name)
			}
		}
		verifyImage(dir, s, im, bad)
	}
	sort.Strings(problems)
	return problems, nil
}

func verifyImage(dir string, s *sample, im imageEntry, bad func(string, ...any)) {
	data, err := readLimited(filepath.Join(dir, im.File), limitBytes)
	if err != nil {
		bad("%s: %v (предел ADR-0032 — %d байт)", im.File, err, limitBytes)
		return
	}
	format, w, ht, meta, err := imageInfo(data)
	switch {
	case err != nil:
		bad("%s: %v", im.File, err)
		return
	case format != s.Format || format != im.Format:
		bad("%s: формат по сигнатуре %s, ожидается %s", im.File, format, s.Format)
	case w != im.Width || ht != im.Height || w != s.Width || ht != s.Height:
		bad("%s: размеры по заголовку %d×%d, в манифесте %d×%d, в образце %d×%d", im.File, w, ht, im.Width, im.Height, s.Width, s.Height)
	case w*ht > limitPixels:
		bad("%s: %d пикселей — больше предела ADR-0032 (%d)", im.File, w*ht, limitPixels)
	case len(data) != im.Bytes:
		bad("%s: размер %d, в манифесте %d", im.File, len(data), im.Bytes)
	}
	for _, want := range s.Meta {
		if !slices.Contains(meta, want) {
			bad("%s: в файле нет метаданных %s/%s", im.File, want.Container, want.Field)
		}
	}
	// Эталон и ожидания строятся из образца детерминированно — без Chromium.
	txt, err := readLimited(filepath.Join(dir, s.ID+".txt"), maxSideFile)
	if err != nil || string(txt) != s.refText() {
		bad("%s.txt: эталон устарел или отсутствует: перегенерируйте корпус (make media-corpus)", s.ID)
	}
	exp, err := readLimited(filepath.Join(dir, s.ID+".json"), maxSideFile)
	want, merr := s.expectJSON()
	if merr != nil || err != nil || !bytes.Equal(exp, want) {
		bad("%s.json: ожидания устарели или отсутствуют: перегенерируйте корпус (make media-corpus)", s.ID)
	}
}

var errProblems = errors.New("корпус не сходится с манифестом")
