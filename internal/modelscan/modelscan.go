// Пакет modelscan проверяет файлы моделей на узле заказчика (ТЗ 5.12,
// DM-27, ADR-0029, п. 4). Формат определяется по сигнатуре содержимого, а не
// по расширению; каждый формат разбирается своим кодом с пределами, файлы
// читаются потоково, в память попадают только заголовки до предела формата.
// Ничего из файла не исполняется и не десериализуется: поток pickle
// просматривается по опкодам как байты.
//
// pickle и форматы на его основе (архив PyTorch, joblib, .npy/.npz с типом
// object) дают находку pickle с запретом. Переопределить её нельзя: в пакете
// нет ни флага, ни настройки, которые меняли бы её вес.
//
// Пакет импортируют только cmd/aisec-cli и тесты (правило depguard
// model-scanner): разбор недоверенных файлов моделей не входит в сервер и
// шлюз.
package modelscan

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Format — формат файла по сигнатуре.
type Format string

// Форматы.
const (
	FormatEmpty           Format = "empty"
	FormatPickle          Format = "pickle"
	FormatPyTorch         Format = "pytorch"
	FormatZip             Format = "zip"
	FormatNumpy           Format = "npy"
	FormatNumpyZip        Format = "npz"
	FormatCompressed      Format = "compressed"
	FormatSafetensors     Format = "safetensors"
	FormatGGUF            Format = "gguf"
	FormatONNX            Format = "onnx"
	FormatTokenizerConfig Format = "tokenizer_config"
	FormatJSON            Format = "json"
	FormatText            Format = "text"
	FormatUnknown         Format = "unknown"
)

// Severity — вес находки: block — модель не допускается, warn — оповещение.
type Severity string

// Веса находок.
const (
	SeverityBlock Severity = "block"
	SeverityWarn  Severity = "warn"
)

// Коды находок.
const (
	// CodePickle — pickle или формат на его основе: запрет без исключений.
	CodePickle = "pickle"
	// CodeMalformed — нарушена структура формата (обрезанный заголовок,
	// смещение за концом, перекрытие данных, неверный JSON).
	CodeMalformed = "malformed"
	// CodeLimitExceeded — превышен предел формата: файл не проверен целиком.
	CodeLimitExceeded = "limit_exceeded"
	// CodeUnknownFormat — формат не распознан или содержимое не проверить.
	CodeUnknownFormat = "unknown_format"
	// CodeNotScanned — часть файла не проверена (сжатие ZIP, ссылка на каталог).
	CodeNotScanned = "not_scanned"
	// CodeONNXDomain — оператор ONNX вне доменов ai.onnx и ai.onnx.ml.
	CodeONNXDomain = "onnx_domain"
	// CodeExternalData — внешние данные ONNX вне каталога модели, через
	// символьную ссылку или за концом файла.
	CodeExternalData = "external_data"
	// CodeExternalDataMissing — файла внешних данных ONNX нет.
	CodeExternalDataMissing = "external_data_missing"
)

// Finding — находка по файлу. Detail — пояснение для людей без содержимого
// весов; имена из файла (тензоры, модули pickle) укорочены и очищены от
// управляющих символов.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail,omitempty"`
}

// ChatTemplate — шаблон чата из метаданных модели (GGUF или
// tokenizer_config.json). Его проверяет сервер (DM-28, задача 5.21).
type ChatTemplate struct {
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	Text   string `json:"text"`
}

// FileReport — итог проверки одного файла.
type FileReport struct {
	Path          string         `json:"path"`
	Size          int64          `json:"size"`
	Symlink       bool           `json:"symlink,omitempty"`
	Format        Format         `json:"format"`
	Tensors       int            `json:"tensors,omitempty"`
	Findings      []Finding      `json:"findings,omitempty"`
	FindingsCut   bool           `json:"findings_truncated,omitempty"`
	ChatTemplates []ChatTemplate `json:"chat_templates,omitempty"`

	// external — ссылки ONNX на внешние данные, их сверяет ScanPath.
	external []externalRef
}

// Blocked — есть находка с запретом.
func (r *FileReport) Blocked() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityBlock {
			return true
		}
	}
	return false
}

// HasFinding — есть находка с кодом code.
func (r *FileReport) HasFinding(code string) bool {
	for _, f := range r.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func (r *FileReport) add(code string, sev Severity, format string, args ...any) {
	if len(r.Findings) >= maxFindingsPerFile {
		r.FindingsCut = true
		return
	}
	r.Findings = append(r.Findings, Finding{Code: code, Severity: sev, Detail: fmt.Sprintf(format, args...)})
}

// Report — итог проверки файла или каталога модели.
type Report struct {
	Files     []FileReport `json:"files"`
	Findings  []Finding    `json:"findings,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
}

// Blocked — хотя бы одна находка с запретом.
func (r *Report) Blocked() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityBlock {
			return true
		}
	}
	for i := range r.Files {
		if r.Files[i].Blocked() {
			return true
		}
	}
	return false
}

// maxFindingsPerFile — находок на файл (ADR-0029, п. 4: до 100).
const maxFindingsPerFile = 100

// Limits — пределы разбора. Нулевое значение поля — значение по умолчанию.
type Limits struct {
	// MaxFiles — файлов в каталоге модели (ADR-0029: до 10 000 в отчёте).
	MaxFiles int
	// MaxZipEntries — записей в центральном каталоге ZIP.
	MaxZipEntries uint64
	// MaxZipDirectory — размер центрального каталога ZIP, байт.
	MaxZipDirectory uint64
	// MaxSafetensorsHeader — заголовок safetensors, байт (100 МиБ).
	MaxSafetensorsHeader uint64
	// MaxTensors — тензоров в заголовке safetensors или GGUF.
	MaxTensors uint64
	// MaxNumpyHeader — заголовок .npy, байт.
	MaxNumpyHeader uint32
	// MaxGGUFMetadata — записей метаданных GGUF.
	MaxGGUFMetadata uint64
	// MaxGGUFString — строка GGUF, байт (1 МиБ).
	MaxGGUFString uint64
	// MaxGGUFArray — элементов массива метаданных GGUF.
	MaxGGUFArray uint64
	// MaxChatTemplate — шаблон чата, байт (64 КиБ).
	MaxChatTemplate int
	// MaxONNXDepth — вложенность сообщений protobuf ONNX.
	MaxONNXDepth int
	// MaxONNXItems — узлов, тензоров и функций ONNX вместе.
	MaxONNXItems int
	// MaxTokenizerConfig — размер tokenizer_config.json, байт.
	MaxTokenizerConfig int64
}

// DefaultLimits — пределы по умолчанию.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:             10_000,
		MaxZipEntries:        65_536,
		MaxZipDirectory:      64 << 20,
		MaxSafetensorsHeader: 100 << 20,
		MaxTensors:           1 << 20,
		MaxNumpyHeader:       64 << 10,
		MaxGGUFMetadata:      1 << 16,
		MaxGGUFString:        1 << 20,
		MaxGGUFArray:         1 << 22,
		MaxChatTemplate:      64 << 10,
		MaxONNXDepth:         32,
		MaxONNXItems:         1 << 20,
		MaxTokenizerConfig:   16 << 20,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxZipEntries == 0 {
		l.MaxZipEntries = d.MaxZipEntries
	}
	if l.MaxZipDirectory == 0 {
		l.MaxZipDirectory = d.MaxZipDirectory
	}
	if l.MaxSafetensorsHeader == 0 {
		l.MaxSafetensorsHeader = d.MaxSafetensorsHeader
	}
	if l.MaxTensors == 0 {
		l.MaxTensors = d.MaxTensors
	}
	if l.MaxNumpyHeader == 0 {
		l.MaxNumpyHeader = d.MaxNumpyHeader
	}
	if l.MaxGGUFMetadata == 0 {
		l.MaxGGUFMetadata = d.MaxGGUFMetadata
	}
	if l.MaxGGUFString == 0 {
		l.MaxGGUFString = d.MaxGGUFString
	}
	if l.MaxGGUFArray == 0 {
		l.MaxGGUFArray = d.MaxGGUFArray
	}
	if l.MaxChatTemplate <= 0 {
		l.MaxChatTemplate = d.MaxChatTemplate
	}
	if l.MaxONNXDepth <= 0 {
		l.MaxONNXDepth = d.MaxONNXDepth
	}
	if l.MaxONNXItems <= 0 {
		l.MaxONNXItems = d.MaxONNXItems
	}
	if l.MaxTokenizerConfig <= 0 {
		l.MaxTokenizerConfig = d.MaxTokenizerConfig
	}
	return l
}

// Scanner проверяет файлы моделей.
type Scanner struct {
	limits Limits
}

// New — сканер с пределами l (нулевые поля — по умолчанию).
func New(l Limits) *Scanner {
	return &Scanner{limits: l.withDefaults()}
}

// headSize — сколько байт начала файла читается для определения формата.
const headSize = 4096

// ScanReader проверяет содержимое одного файла. name — имя файла (последний
// элемент пути): по нему отличается tokenizer_config.json от прочего JSON,
// формат всегда определяется по содержимому. Внешние данные ONNX сверяются
// здесь только по записи пути; наличие файлов проверяет ScanPath.
func (s *Scanner) ScanReader(r io.ReaderAt, size int64, name string) FileReport {
	fr := FileReport{Path: name, Size: size}
	if size <= 0 {
		fr.Format = FormatEmpty
		return fr
	}
	head := make([]byte, min(size, headSize))
	if n, err := r.ReadAt(head, 0); n < len(head) {
		fr.Format = FormatUnknown
		fr.add(CodeNotScanned, SeverityWarn, "файл не прочитан: %v", errText(err))
		return fr
	}
	fr.Format = detect(head, size)
	switch fr.Format {
	case FormatZip:
		s.scanZip(r, size, &fr)
	case FormatPickle:
		s.scanPickle(r, size, &fr)
	case FormatNumpy:
		s.scanNumpy(io.NewSectionReader(r, 0, size), size, &fr, "")
	case FormatSafetensors:
		s.scanSafetensors(r, size, &fr)
	case FormatCompressed:
		scanCompressed(head, &fr)
	case FormatUnknown:
		fr.add(CodeUnknownFormat, SeverityWarn, "формат не распознан%s", unknownHint(head))
	}
	return fr
}

// ScanPath проверяет файл или каталог модели. Символьные ссылки на файлы
// проверяются по содержимому цели (каталоги моделей из кэша загрузки
// ссылаются на общие файлы), на каталоги — не обходятся.
func (s *Scanner) ScanPath(root string) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	if !info.IsDir() {
		fr, err := s.scanFile(root, filepath.Base(root), false)
		if err != nil {
			return nil, err
		}
		s.checkExternal(filepath.Dir(root), "", &fr)
		rep.Files = append(rep.Files, fr)
		return rep, nil
	}
	fsys := os.DirFS(root)
	walkErr := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if len(rep.Files) >= s.limits.MaxFiles {
			rep.Truncated = true
			return fs.SkipAll
		}
		link := d.Type()&fs.ModeSymlink != 0
		full := filepath.Join(root, filepath.FromSlash(p))
		if link {
			if !isRegularTarget(full) {
				fr := FileReport{Path: p, Symlink: true, Format: FormatUnknown}
				fr.add(CodeNotScanned, SeverityWarn, "символьная ссылка не на обычный файл не проверяется")
				rep.Files = append(rep.Files, fr)
				return nil
			}
		} else if !d.Type().IsRegular() {
			fr := FileReport{Path: p, Format: FormatUnknown}
			fr.add(CodeNotScanned, SeverityWarn, "не обычный файл")
			rep.Files = append(rep.Files, fr)
			return nil
		}
		fr, err := s.scanFile(full, p, link)
		if err != nil {
			return err
		}
		s.checkExternal(root, path.Dir(p), &fr)
		rep.Files = append(rep.Files, fr)
		return nil
	})
	if walkErr != nil {
		return nil, walkErr
	}
	if rep.Truncated {
		rep.Findings = append(rep.Findings, Finding{
			Code: CodeLimitExceeded, Severity: SeverityBlock,
			Detail: fmt.Sprintf("в каталоге больше %d файлов, проверены первые", s.limits.MaxFiles),
		})
	}
	return rep, nil
}

// isRegularTarget — символьная ссылка ведёт на обычный файл.
func isRegularTarget(full string) bool {
	ti, err := os.Stat(full)
	return err == nil && ti.Mode().IsRegular()
}

func (s *Scanner) scanFile(full, rel string, link bool) (FileReport, error) {
	f, err := os.Open(full) //nolint:gosec // G304: путь к файлам модели задаёт администратор узла
	if err != nil {
		return FileReport{}, err
	}
	defer f.Close() //nolint:errcheck // файл открыт только для чтения
	info, err := f.Stat()
	if err != nil {
		return FileReport{}, err
	}
	fr := s.ScanReader(f, info.Size(), path.Base(rel))
	fr.Path = rel
	fr.Symlink = link
	return fr, nil
}

// checkExternal сверяет ссылки ONNX на внешние данные с файловой системой:
// файл в каталоге модели, ни один элемент пути не символьная ссылка, данные
// внутри файла. root — каталог проверки, dir — каталог файла ONNX в нём.
func (s *Scanner) checkExternal(root, dir string, fr *FileReport) {
	for _, ext := range fr.external {
		rel := path.Join(dir, ext.location)
		parts := strings.Split(rel, "/")
		cur := root
		for i, part := range parts {
			if part == "." {
				continue
			}
			cur = filepath.Join(cur, part)
			fi, err := os.Lstat(cur)
			if errors.Is(err, fs.ErrNotExist) {
				fr.add(CodeExternalDataMissing, SeverityWarn, "нет файла внешних данных %s", clean(ext.location))
				break
			}
			if err != nil {
				fr.add(CodeExternalData, SeverityBlock, "внешние данные %s не проверены: %v", clean(ext.location), errText(err))
				break
			}
			if fi.Mode()&fs.ModeSymlink != 0 {
				fr.add(CodeExternalData, SeverityBlock, "внешние данные %s — через символьную ссылку", clean(ext.location))
				break
			}
			if i == len(parts)-1 {
				if !fi.Mode().IsRegular() {
					fr.add(CodeExternalData, SeverityBlock, "внешние данные %s — не обычный файл", clean(ext.location))
				} else if ext.hasRange && (ext.offset > uint64(fi.Size()) || ext.length > uint64(fi.Size())-ext.offset) {
					fr.add(CodeExternalData, SeverityBlock, "внешние данные %s за концом файла", clean(ext.location))
				}
			}
		}
	}
	fr.external = nil
}

// externalRef — ссылка тензора ONNX на внешние данные.
type externalRef struct {
	location       string
	offset, length uint64
	hasRange       bool
}

// detect определяет формат по началу файла.
func detect(head []byte, size int64) Format {
	switch {
	case hasPrefix(head, "PK\x03\x04"), hasPrefix(head, "PK\x05\x06"), hasPrefix(head, "PK\x06\x06"):
		return FormatZip
	case len(head) >= 2 && head[0] == opProto && head[1] <= 5:
		return FormatPickle
	case hasPrefix(head, "\x93NUMPY"):
		return FormatNumpy
	case isSafetensors(head, size):
		return FormatSafetensors
	case compressionName(head) != "":
		return FormatCompressed
	case looksLikePickle(head):
		return FormatPickle
	case isText(head):
		return FormatText
	}
	return FormatUnknown
}

func hasPrefix(b []byte, p string) bool { return len(b) >= len(p) && string(b[:len(p)]) == p }

// isSafetensors — восемь байт длины заголовка (до 2^48, иначе это не
// заголовок) и «{» сразу за ними.
func isSafetensors(head []byte, size int64) bool {
	if len(head) < 9 || size < 9 || head[8] != '{' {
		return false
	}
	return head[6] == 0 && head[7] == 0 && le64(head) > 0
}

// isText — начало файла — текст UTF-8 без управляющих символов, кроме
// табуляции и перевода строк (README, LICENSE, словари токенизатора).
func isText(head []byte) bool {
	b := head
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		if r == utf8.RuneError && n == 1 {
			// Обрезанный на границе буфера символ — не ошибка.
			return len(b) < utf8.UTFMax && len(head) == headSize
		}
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' && r != '\f' || r == 0x7f {
			return false
		}
		b = b[n:]
	}
	return true
}

// unknownHint — пояснение для известных, но не разбираемых сигнатур.
func unknownHint(head []byte) string {
	switch {
	case hasPrefix(head, "\x89HDF\r\n\x1a\n"):
		return " (HDF5: содержимое не проверяется)"
	case len(head) >= 262 && string(head[257:262]) == "ustar":
		return " (архив tar: содержимое не проверяется)"
	}
	return ""
}

func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func le16(b []byte) uint16 { return uint16(b[0]) | uint16(b[1])<<8 }

// maxNameInDetail — длина имени из файла в пояснении находки.
const maxNameInDetail = 128

// clean укорачивает имя из файла и заменяет управляющие символы и символы
// форматирования: пояснение показывается в консоли и журналах.
func clean(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if n == maxNameInDetail {
			b.WriteString("…")
			break
		}
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			r = '?'
		}
		b.WriteRune(r)
		n++
	}
	return b.String()
}

func errText(err error) string {
	if err == nil {
		return "файл короче заявленного размера"
	}
	return err.Error()
}
