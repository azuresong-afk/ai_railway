package ml

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Пакет моделей (ADR-0024, раздел 5).
const (
	// ModelsFormatV1 — версия формата манифеста пакета моделей.
	ModelsFormatV1 = "aisec-ml-models-v1"
	// ModelsManifestFile — манифест пакета в каталоге моделей.
	ModelsManifestFile = "aisec-models.json"
	// ModelsSignatureFile — подпись манифеста пакета.
	ModelsSignatureFile = ModelsManifestFile + ".sig"
)

// Роли файлов модели: у каждой модели ровно по одному файлу каждой роли.
const (
	RoleModel     = "model"     // веса ONNX
	RoleTokenizer = "tokenizer" // tokenizer.json
	RoleMLBOM     = "mlbom"     // ML-BOM CycloneDX (ТЗ 8.12)
)

// Задачи моделей.
const (
	TaskClassification      = "classification"       // оценка текста целиком (injection.ml, toxicity.ml)
	TaskTokenClassification = "token_classification" // разметка фрагментов (pii.ner)
)

// Лимиты пакета: манифест и файлы — недоверенный вход (каталог мог быть
// подменён), они проверяются до чтения содержимого.
const (
	MaxModelsManifest = 1 << 20
	maxSignatureFile  = 1 << 10
	MaxModelFile      = 2 << 30
	MaxTokenizerFile  = 32 << 20
	MaxMLBOMFile      = 4 << 20
	// MaxModelTokens — предел окна модели.
	MaxModelTokens = 512
	maxPathLen     = 160
)

var roleLimit = map[string]int64{RoleModel: MaxModelFile, RoleTokenizer: MaxTokenizerFile, RoleMLBOM: MaxMLBOMFile}

// signContext разделяет подписи ключа производителя: подпись манифеста
// выпуска нельзя выдать за подпись пакета моделей и наоборот (ADR-0022).
const signContext = "aisec-ml-models-v1\n"

// ModelFile — файл модели в пакете.
type ModelFile struct {
	Path string `json:"path"` // <id>/<имя>, относительно каталога моделей
	Role string `json:"role"`
	Size int64  `json:"size"`
	Hash string `json:"hash"` // хеш профиля, шестнадцатеричный, строчными
}

// ModelSpec — модель в манифесте пакета.
type ModelSpec struct {
	ID         string      `json:"id"`
	Version    string      `json:"version"`
	Task       string      `json:"task"`
	Labels     []string    `json:"labels"`
	Directions []string    `json:"directions"`
	MaxTokens  int         `json:"max_tokens"`
	Files      []ModelFile `json:"files"`
}

// Info — описание модели для протокола.
func (m ModelSpec) Info() ModelInfo {
	return ModelInfo{ID: m.ID, Version: m.Version, Labels: slices.Clone(m.Labels), Directions: slices.Clone(m.Directions)}
}

// ModelsManifest — манифест пакета моделей.
type ModelsManifest struct {
	Format  string      `json:"format"`
	Version string      `json:"version"`
	Profile string      `json:"profile"`
	HashAlg string      `json:"hash_alg"`
	Created time.Time   `json:"created"`
	Models  []ModelSpec `json:"models"`
}

// ErrModelsManifest — манифест пакета моделей неверен.
var ErrModelsManifest = errors.New("манифест пакета моделей неверен")

// ParseModelsManifest разбирает манифест строго (FuzzParseModelsManifest).
func ParseModelsManifest(data []byte) (*ModelsManifest, error) {
	if len(data) > MaxModelsManifest {
		return nil, fmt.Errorf("%w: больше %d байт", ErrModelsManifest, MaxModelsManifest)
	}
	var m ModelsManifest
	if err := decodeStrict(data, &m); err != nil {
		return nil, fmt.Errorf("%w: разбор JSON", ErrModelsManifest)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

// MarshalModelsManifest кодирует манифест; он проверяется тем же правилом,
// что и при чтении.
func MarshalModelsManifest(m *ModelsManifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	b = append(b, '\n')
	if len(b) > MaxModelsManifest {
		return nil, fmt.Errorf("%w: больше %d байт", ErrModelsManifest, MaxModelsManifest)
	}
	return b, nil
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrModelsManifest, fmt.Sprintf(format, args...))
}

func (m *ModelsManifest) validate() error {
	if m.Format != ModelsFormatV1 {
		return bad("формат не %s", ModelsFormatV1)
	}
	if !printable(m.Version, maxVersion) || !printable(m.Profile, 32) || !printable(m.HashAlg, 32) || m.Created.IsZero() {
		return bad("версия, профиль, алгоритм хеша или время")
	}
	if len(m.Models) == 0 || len(m.Models) > MaxModels {
		return bad("моделей должно быть от 1 до %d", MaxModels)
	}
	ids := make(map[string]bool, len(m.Models))
	for i, spec := range m.Models {
		if err := spec.validate(); err != nil {
			return fmt.Errorf("модель %d: %w", i, err)
		}
		if ids[spec.ID] {
			return bad("модель %s повторяется", spec.ID)
		}
		ids[spec.ID] = true
	}
	return nil
}

func (m ModelSpec) validate() error {
	if err := m.Info().Validate(); err != nil {
		return bad("ID, версия, метки или направления")
	}
	if m.Task != TaskClassification && m.Task != TaskTokenClassification {
		return bad("задача модели")
	}
	if m.MaxTokens < 1 || m.MaxTokens > MaxModelTokens {
		return bad("max_tokens от 1 до %d", MaxModelTokens)
	}
	if len(m.Files) != len(roleLimit) {
		return bad("у модели ровно %d файла", len(roleLimit))
	}
	roles := map[string]bool{}
	for _, f := range m.Files {
		lim, ok := roleLimit[f.Role]
		if !ok || roles[f.Role] {
			return bad("роль файла")
		}
		roles[f.Role] = true
		if err := validFilePath(f.Path, m.ID); err != nil {
			return err
		}
		if f.Size < 0 || f.Size > lim {
			return bad("размер файла %s", f.Path)
		}
		if f.Hash == "" || len(f.Hash) > 128 || len(f.Hash)%2 != 0 || strings.ToLower(f.Hash) != f.Hash {
			return bad("хеш файла %s", f.Path)
		}
		if _, err := hex.DecodeString(f.Hash); err != nil {
			return bad("хеш файла %s", f.Path)
		}
	}
	return nil
}

// validFilePath — путь <id>/<имя>: ровно две части, без «..», «\», пустых
// частей и управляющих символов; имя — латиница, цифры, «.», «_», «-».
func validFilePath(p, id string) error {
	if len(p) > maxPathLen || !strings.HasPrefix(p, id+"/") {
		return bad("путь файла вне каталога модели")
	}
	name := strings.TrimPrefix(p, id+"/")
	if name == "" || name == "." || name == ".." || path.Clean(p) != p {
		return bad("путь файла")
	}
	for _, r := range name {
		if !nameRune(r) {
			return bad("путь файла")
		}
	}
	return nil
}

func signedMessage(data []byte) []byte {
	return append([]byte(signContext), data...)
}

// SignModels подписывает манифест пакета и возвращает содержимое файла
// подписи (base64 и перевод строки).
func SignModels(s aisecCrypto.Signer, manifest []byte) ([]byte, error) {
	if s == nil {
		return nil, errors.New("подпись пакета моделей: нет ключа")
	}
	sig, err := s.Sign(signedMessage(manifest))
	if err != nil {
		return nil, fmt.Errorf("подпись пакета моделей: %w", err)
	}
	out := base64.StdEncoding.AppendEncode(nil, sig)
	return append(out, '\n'), nil
}

// ErrModelsSignature — подпись пакета моделей неверна.
var ErrModelsSignature = errors.New("подпись пакета моделей неверна")

// VerifyModelsSignature проверяет подпись до разбора манифеста.
func VerifyModelsSignature(v aisecCrypto.Verifier, manifest, sigFile []byte) error {
	if v == nil {
		return errors.New("проверка пакета моделей: нет ключа проверки")
	}
	if len(sigFile) > maxSignatureFile {
		return ErrModelsSignature
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(string(bytes.TrimSuffix(sigFile, []byte("\n"))))
	if err != nil || len(sig) == 0 || !v.Verify(signedMessage(manifest), sig) {
		return ErrModelsSignature
	}
	return nil
}

// LoadedModel — модель после проверки: байты файлов сверены с подписанным
// манифестом и дальше передаются исполнителю только из памяти.
type LoadedModel struct {
	Spec      ModelSpec
	Model     []byte
	Tokenizer []byte
	MLBOM     []byte
}

// ErrModelFile — файл модели не совпадает с манифестом пакета.
var ErrModelFile = errors.New("файл модели не совпадает с манифестом пакета")

// LoadOptions — проверка пакета моделей.
type LoadOptions struct {
	Provider aisecCrypto.Provider
	// Verifier — ключ производителя (integrity.EmbeddedVerifier).
	Verifier aisecCrypto.Verifier
	// MaxTotal — предел суммарного размера файлов моделей в памяти.
	MaxTotal int64
	// ManifestHash — хеш aisec-models.json из подписанного манифеста выпуска
	// (4В23): пакет другой версии, хоть и подписанный, отвергается. Пусто —
	// без привязки (проверка пакета при сборке, tools/manifest).
	ManifestHash []byte
}

// ErrNotInRelease — манифест пакета моделей не совпадает с записью манифеста
// выпуска: пакет от другого выпуска (откат версии моделей).
var ErrNotInRelease = errors.New("пакет моделей не совпадает с манифестом выпуска")

// DefaultMaxModelBytes — предел суммарного размера моделей по умолчанию.
const DefaultMaxModelBytes = 1 << 30

// LoadModels проверяет пакет в каталоге dir и читает его целиком: подпись
// до разбора, строгий разбор, затем каждый файл — обычный файл заявленного
// размера с совпадающим хешем, и ML-BOM. Любое несовпадение — ошибка без
// частичной загрузки (ADR-0024, раздел 5).
func LoadModels(dir string, opt LoadOptions) ([]LoadedModel, *ModelsManifest, error) {
	if opt.Provider == nil {
		return nil, nil, errors.New("проверка пакета моделей: нет криптопрофиля")
	}
	if opt.MaxTotal <= 0 {
		opt.MaxTotal = DefaultMaxModelBytes
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("каталог моделей: %w", err)
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	data, err := readRegular(root, ModelsManifestFile, MaxModelsManifest)
	if err != nil {
		return nil, nil, fmt.Errorf("манифест пакета моделей: %w", err)
	}
	sig, err := readRegular(root, ModelsSignatureFile, maxSignatureFile)
	if err != nil {
		return nil, nil, fmt.Errorf("подпись пакета моделей: %w", err)
	}
	if err := VerifyModelsSignature(opt.Verifier, data, sig); err != nil {
		return nil, nil, err
	}
	hasher, err := opt.Provider.Hasher()
	if err != nil {
		return nil, nil, err
	}
	if opt.ManifestHash != nil && !aisecCrypto.Equal(hasher.Sum(data), opt.ManifestHash) {
		return nil, nil, ErrNotInRelease
	}
	m, err := ParseModelsManifest(data)
	if err != nil {
		return nil, nil, err
	}
	if m.Profile != opt.Provider.Name() || m.HashAlg != hasher.Name() {
		return nil, nil, bad("профиль %s и хеш %s, а aisec-ml работает в профиле %s", m.Profile, m.HashAlg, opt.Provider.Name())
	}
	var total int64
	for _, spec := range m.Models {
		for _, f := range spec.Files {
			total += f.Size
		}
	}
	if total > opt.MaxTotal {
		return nil, nil, fmt.Errorf("модели занимают %d байт, предел %d", total, opt.MaxTotal)
	}
	out := make([]LoadedModel, 0, len(m.Models))
	for _, spec := range m.Models {
		lm := LoadedModel{Spec: spec}
		for _, f := range spec.Files {
			b, err := readRegular(root, f.Path, f.Size)
			if err != nil || int64(len(b)) != f.Size {
				return nil, nil, fmt.Errorf("%w: %s (размер или чтение)", ErrModelFile, f.Path)
			}
			want, _ := hex.DecodeString(f.Hash) //nolint:gosec // G104: формат хеша проверен разбором
			if !aisecCrypto.Equal(hasher.Sum(b), want) {
				return nil, nil, fmt.Errorf("%w: %s (хеш)", ErrModelFile, f.Path)
			}
			switch f.Role {
			case RoleModel:
				lm.Model = b
			case RoleTokenizer:
				lm.Tokenizer = b
			case RoleMLBOM:
				lm.MLBOM = b
			}
		}
		if err := CheckMLBOM(lm.MLBOM, spec); err != nil {
			return nil, nil, fmt.Errorf("модель %s: %w", spec.ID, err)
		}
		out = append(out, lm)
	}
	return out, m, nil
}

// readRegular читает обычный файл (не ссылку) внутри root не больше limit
// байт: файл длиннее предела не дочитывается.
func readRegular(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", name)
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("%s: больше %d байт", name, limit)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // файл только читается
	st, err := f.Stat()
	if err != nil || !os.SameFile(info, st) {
		return nil, fmt.Errorf("%s: файл заменён во время проверки", name)
	}
	// Ровно заявленный размер; файл, выросший после проверки, отвергается.
	b := make([]byte, st.Size())
	if _, err := io.ReadFull(f, b); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if n, _ := f.Read(make([]byte, 1)); n != 0 { //nolint:gosec // G104: важен только факт лишних байтов
		return nil, fmt.Errorf("%s: файл изменён во время чтения", name)
	}
	return b, nil
}

// ErrMLBOM — ML-BOM модели неверен.
var ErrMLBOM = errors.New("ML-BOM модели неверен")

type mlbom struct {
	BOMFormat   string `json:"bomFormat"`
	SpecVersion string `json:"specVersion"`
	Components  []struct {
		Type    string `json:"type"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
}

// CheckMLBOM — ML-BOM CycloneDX (ТЗ 8.12): есть компонент
// machine-learning-model с ID и версией модели. Полный состав полей
// карточки модели проверяет tools/sbom при сборке пакета (4.19).
func CheckMLBOM(data []byte, spec ModelSpec) error {
	var b mlbom
	// Неизвестные поля CycloneDX допустимы: формат богаче проверяемого.
	if len(data) > MaxMLBOMFile || json.Unmarshal(data, &b) != nil {
		return ErrMLBOM
	}
	if b.BOMFormat != "CycloneDX" || (b.SpecVersion != "1.6" && b.SpecVersion != "1.7") {
		return fmt.Errorf("%w: не CycloneDX 1.6 или 1.7", ErrMLBOM)
	}
	for _, c := range b.Components {
		if c.Type == "machine-learning-model" && c.Name == spec.ID && c.Version == spec.Version {
			return nil
		}
	}
	return fmt.Errorf("%w: нет компонента machine-learning-model %s %s", ErrMLBOM, spec.ID, spec.Version)
}

// nameRune — допустимый знак имени файла модели.
func nameRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-'
}

// Имена файлов модели в каталоге <id>/ пакета (ADR-0024, раздел 5).
const (
	ModelFileName     = "model.onnx"
	TokenizerFileName = "tokenizer.json" //nolint:gosec // G101: имя файла токенизатора модели, не секрет
	MLBOMFileName     = "mlbom.cdx.json"
)

// BuildModelsManifest собирает манифест пакета моделей из каталога dir
// (команда подписи пакета, tools/manifest sign-models): у каждой модели
// specs (без Files) читаются <id>/model.onnx, tokenizer.json и
// mlbom.cdx.json — обычные файлы в пределах роли, — считаются размер и
// хеш, ML-BOM сверяется с моделью. Манифест проверяется тем же правилом,
// что и при загрузке.
func BuildModelsManifest(p aisecCrypto.Provider, dir, version string, created time.Time, specs []ModelSpec) (*ModelsManifest, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог моделей: %w", err)
	}
	defer root.Close() //nolint:errcheck // каталог только читается
	m := &ModelsManifest{Format: ModelsFormatV1, Version: version, Profile: p.Name(), HashAlg: h.Name(), Created: created.UTC()}
	for _, spec := range specs {
		if len(spec.Files) > 0 {
			return nil, bad("модель %s: файлы считает сборка пакета", spec.ID)
		}
		if !ValidModelID(spec.ID) {
			return nil, bad("ID модели")
		}
		var bom []byte
		for _, f := range []struct{ name, role string }{
			{ModelFileName, RoleModel}, {TokenizerFileName, RoleTokenizer}, {MLBOMFileName, RoleMLBOM},
		} {
			rel := spec.ID + "/" + f.name
			info, err := root.Lstat(rel)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
			b, err := readRegular(root, rel, min(info.Size(), roleLimit[f.role]))
			if err != nil {
				return nil, err
			}
			if f.role == RoleMLBOM {
				bom = b
			}
			spec.Files = append(spec.Files, ModelFile{Path: rel, Role: f.role, Size: int64(len(b)), Hash: hex.EncodeToString(h.Sum(b))})
		}
		if err := CheckMLBOM(bom, spec); err != nil {
			return nil, fmt.Errorf("модель %s: %w", spec.ID, err)
		}
		m.Models = append(m.Models, spec)
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return m, nil
}
