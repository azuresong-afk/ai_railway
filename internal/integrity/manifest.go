package integrity

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Формат и имена файлов манифеста (ОЦЛ.1, ADR-0012).
const (
	// FormatV1 — версия формата; новая версия — вместе с проверкой, которая
	// читает прежние.
	FormatV1 = "aisec-manifest-v1"
	// ManifestFile — имя файла манифеста в корне установки (рядом с bin/).
	ManifestFile = "aisec-manifest.json"
	// SignatureFile — отделённая подпись манифеста.
	SignatureFile = ManifestFile + ".sig"
)

// Лимиты разбора: манифест — недоверенный вход (файл мог быть подменён).
const (
	MaxManifestSize = 4 << 20
	MaxEntries      = 10000
	// MaxFileSize — предел размера одного файла в манифесте.
	MaxFileSize   = 4 << 30
	maxPathLen    = 512
	maxVersionLen = 128
	maxHashAlgLen = 32
)

// Kind — вид файла манифеста. Каждому виду соответствует свой каталог.
type Kind string

// Виды файлов.
const (
	KindBinary     Kind = "binary"      // исполняемые файлы, bin/
	KindStatic     Kind = "static"      // статика веб-консоли, web/dist/ (встроена в aisec-server)
	KindMigration  Kind = "migration"   // миграции схемы, migrations/ (встроены в aisec-cli)
	KindDetectorDB Kind = "detector_db" // служебные базы детекторов, detect/
	KindConfig     Kind = "config"      // эталонная конфигурация, config/
	// KindLibrary — разделяемые библиотеки aisec-ml: ONNX Runtime и
	// системные библиотеки образа, lib/ (ADR-0024, раздел 8).
	KindLibrary Kind = "library"
	// KindModel — пакет моделей ML-детекторов, models/ (ADR-0024, раздел 5).
	KindModel Kind = "model"
)

// kindPrefix — каталог вида: путь записи обязан начинаться с него, поэтому
// один файл не может числиться под двумя видами.
var kindPrefix = map[Kind]string{
	KindBinary:     "bin/",
	KindStatic:     "web/dist/",
	KindMigration:  "migrations/",
	KindDetectorDB: "detect/",
	KindConfig:     "config/",
	KindLibrary:    "lib/",
	KindModel:      "models/",
}

// Embedded — файлы вида встроены в бинарники (go:embed): их сверяет
// компонент, который их встраивает, а не поиск на диске.
func (k Kind) Embedded() bool { return k == KindStatic || k == KindMigration }

// Entry — файл манифеста.
type Entry struct {
	Path string `json:"path"` // относительно корня установки, через «/»
	Kind Kind   `json:"kind"`
	Size int64  `json:"size"`
	Hash string `json:"hash"` // хеш профиля, шестнадцатеричный, строчными
}

// Manifest — манифест целостности.
type Manifest struct {
	Format  string    `json:"format"`
	Version string    `json:"version"`  // версия продукта
	Profile string    `json:"profile"`  // криптопрофиль сборки
	HashAlg string    `json:"hash_alg"` // имя Hasher профиля
	Created time.Time `json:"created"`  // время последнего коммита: сборка воспроизводима
	Files   []Entry   `json:"files"`    // по возрастанию пути, без повторов
}

// Marshal кодирует манифест в файл. Манифест проверяется тем же правилом,
// что и при чтении: подписанный файл всегда разбирается.
func Marshal(m *Manifest) ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("манифест: %w", err)
	}
	out = append(out, '\n')
	if len(out) > MaxManifestSize {
		return nil, fmt.Errorf("манифест больше %d байт", MaxManifestSize)
	}
	return out, nil
}

// Parse разбирает манифест. Вызывается только после проверки подписи
// (VerifySignature); разбор всё равно строгий — покрыт FuzzParseManifest.
func Parse(data []byte) (*Manifest, error) {
	if len(data) > MaxManifestSize {
		return nil, fmt.Errorf("манифест больше %d байт", MaxManifestSize)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, errors.New("манифест: неверный JSON")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("манифест: данные после объекта")
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Manifest) validate() error {
	switch {
	case m.Format != FormatV1:
		return fmt.Errorf("манифест: формат %q не поддерживается", truncate(m.Format, 32))
	case !printable(m.Version, maxVersionLen):
		return errors.New("манифест: версия пустая, длиннее предела или с непечатаемыми символами")
	case m.Profile != aisecCrypto.ProfileStandard && m.Profile != aisecCrypto.ProfileGOST:
		return errors.New("манифест: неизвестный криптопрофиль")
	case !printable(m.HashAlg, maxHashAlgLen):
		return errors.New("манифест: неверное имя алгоритма хеша")
	case m.Created.IsZero():
		return errors.New("манифест: нет времени сборки")
	case len(m.Files) == 0 || len(m.Files) > MaxEntries:
		return fmt.Errorf("манифест: от 1 до %d файлов", MaxEntries)
	}
	hashLen := -1
	for i, e := range m.Files {
		if err := e.validate(); err != nil {
			return fmt.Errorf("манифест, запись %d: %w", i, err)
		}
		// Длина хеша одна на манифест: смешение алгоритмов — подмена.
		if hashLen < 0 {
			hashLen = len(e.Hash)
		} else if len(e.Hash) != hashLen {
			return fmt.Errorf("манифест, запись %d: хеш другой длины", i)
		}
		if i > 0 && m.Files[i-1].Path >= e.Path {
			return fmt.Errorf("манифест, запись %d: пути не по возрастанию или повторяются", i)
		}
	}
	return nil
}

func (e Entry) validate() error {
	prefix, ok := kindPrefix[e.Kind]
	if !ok {
		return errors.New("неизвестный вид файла")
	}
	if err := ValidPath(e.Path); err != nil {
		return err
	}
	if !strings.HasPrefix(e.Path, prefix) {
		return fmt.Errorf("файл вида %s должен лежать в %s", e.Kind, prefix)
	}
	if e.Size < 0 || e.Size > MaxFileSize {
		return errors.New("неверный размер файла")
	}
	// 16–64 байта: от 128 до 512 бит, строчные шестнадцатеричные цифры.
	if len(e.Hash) < 32 || len(e.Hash) > 128 || len(e.Hash)%2 != 0 || strings.ToLower(e.Hash) != e.Hash {
		return errors.New("неверный хеш")
	}
	if _, err := hex.DecodeString(e.Hash); err != nil {
		return errors.New("неверный хеш")
	}
	return nil
}

// ValidPath проверяет путь записи: относительный, через «/», без «.» и
// «..», без пустых частей, обратной косой черты и непечатаемых символов.
func ValidPath(p string) error {
	if !printable(p, maxPathLen) || !fs.ValidPath(p) || p == "." || strings.ContainsRune(p, '\\') {
		return errors.New("недопустимый путь файла")
	}
	return nil
}

func printable(s string, limit int) bool {
	if s == "" || len(s) > limit || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// truncate укорачивает недоверенную строку для сообщения об ошибке.
func truncate(s string, n int) string {
	s = strings.ToValidUTF8(s, "�")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
