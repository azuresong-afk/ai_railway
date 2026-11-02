package inventory

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Отчёт сканера моделей (ТЗ 5.12; задачи 5.21 и 5.22 этапа 5, ADR-0029,
// п. 4). Его присылает aisec-cli models scan или models verify с узла, где
// лежат файлы модели: пути, размеры, форматы, хеши SHA-256, находки по
// файлам и шаблоны чата из метаданных. Весов и их фрагментов в отчёте нет.
// Разбор строгий: неизвестные поля, повтор значения и мусор после него —
// отказ; тексты ошибок не содержат значений из отчёта.

// Пределы отчёта (ADR-0029, п. 4).
const (
	// MaxReportBody — тело отчёта.
	MaxReportBody = 4 << 20
	// MaxReportFiles — файлов в отчёте.
	MaxReportFiles = 10_000
	// MaxReportFindings — находок на файл и на отчёт в целом.
	MaxReportFindings = 100
	// MaxFileTemplates — шаблонов чата в одном файле (GGUF и конфигурации
	// токенизатора дают основной и именованные шаблоны).
	MaxFileTemplates = 32
	// MaxReportTemplates — шаблонов чата в отчёте всего.
	MaxReportTemplates = 128
	// MaxTemplateBytes — шаблон чата, байт (как предел сканера).
	MaxTemplateBytes = 64 << 10
	// MaxFindingDetail — пояснение находки, байт.
	MaxFindingDetail = 1024
	// MaxTensors — тензоров в файле (как предел сканера).
	MaxTensors = 1 << 20
	// maxReportErrors — ошибок разбора в ответе: дальше — одной строкой.
	maxReportErrors = 20
)

// Виды отчёта.
const (
	ReportScan   = "scan"   // форматы, находки, шаблоны чата и хеши
	ReportVerify = "verify" // только хеши (сверка с реестром, DM-29)
)

// Веса находок сканера (internal/modelscan).
const (
	SeverityBlock = "block"
	SeverityWarn  = "warn"
)

// ReportFinding — находка сканера.
type ReportFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Detail   string `json:"detail,omitempty"`
}

// ReportTemplate — шаблон чата из метаданных файла модели.
type ReportTemplate struct {
	Source string `json:"source"`
	Name   string `json:"name,omitempty"`
	Text   string `json:"text"`
}

// ReportFile — файл в отчёте. SHA256 — хеш содержимого (пусто — файл не
// прочитан: ссылка на каталог, не обычный файл).
type ReportFile struct {
	Path              string           `json:"path"`
	Size              int64            `json:"size"`
	Symlink           bool             `json:"symlink,omitempty"`
	Format            string           `json:"format,omitempty"`
	Tensors           int              `json:"tensors,omitempty"`
	SHA256            string           `json:"sha256,omitempty"`
	Findings          []ReportFinding  `json:"findings,omitempty"`
	FindingsTruncated bool             `json:"findings_truncated,omitempty"`
	ChatTemplates     []ReportTemplate `json:"chat_templates,omitempty"`
}

// ReportInput — отчёт сканера, как его присылает aisec-cli.
type ReportInput struct {
	Kind           string          `json:"kind"`
	Host           string          `json:"host"`
	ScannerVersion string          `json:"scanner_version"`
	Files          []ReportFile    `json:"files"`
	Findings       []ReportFinding `json:"findings,omitempty"`
	// Truncated — в каталоге больше файлов, чем проверяет сканер.
	Truncated bool `json:"truncated,omitempty"`
}

var (
	codeRe    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	formatRe  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	hostRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$`)
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}$`)
	sourceRe  = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,63}$`)
)

// weightFormats — форматы, в которых хранятся веса и адаптеры: лишний файл
// такого формата в каталоге модели — расхождение с реестром (DM-29).
var weightFormats = map[string]bool{"safetensors": true, "gguf": true, "onnx": true, "pytorch": true, "pickle": true,
	"npy": true, "npz": true, "zip": true}

// errList копит ошибки разбора с пределом числа.
type errList struct {
	errs []error
	more int
}

func (l *errList) add(format string, args ...any) {
	if len(l.errs) >= maxReportErrors {
		l.more++
		return
	}
	l.errs = append(l.errs, fmt.Errorf(format, args...))
}

func (l *errList) err() error {
	if len(l.errs) == 0 {
		return nil
	}
	if l.more > 0 {
		l.errs = append(l.errs, fmt.Errorf("и ещё ошибок: %d", l.more))
	}
	return invalid(l.errs...)
}

// decodeStrictLimit — как decodeStrict, с пределом limit.
func decodeStrictLimit(data []byte, dst any, limit int) error {
	if len(data) > limit {
		return invalid(fmt.Errorf("тело — не больше %d КиБ", limit>>10))
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return invalid(errors.New("тело — некорректный JSON или неизвестные поля"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return invalid(errors.New("после JSON-значения есть лишние данные"))
	}
	return nil
}

// ParseReport разбирает и проверяет отчёт сканера. Ошибка — *InputError.
func ParseReport(data []byte) (ReportInput, error) {
	var in ReportInput
	if err := decodeStrictLimit(data, &in, MaxReportBody); err != nil {
		return ReportInput{}, err
	}
	var l errList
	if in.Kind != ReportScan && in.Kind != ReportVerify {
		l.add("kind — scan или verify")
	}
	if !hostRe.MatchString(in.Host) {
		l.add("host — имя узла: латинские буквы, цифры, «.», «-», «_», до 253 символов")
	}
	if !versionRe.MatchString(in.ScannerVersion) {
		l.add("scanner_version — версия сканера: латинские буквы, цифры, «.», «+», «-», «_», до 64 символов")
	}
	if in.Files == nil {
		l.add("files — обязательно (пустой каталог — [])")
	}
	if len(in.Files) > MaxReportFiles {
		l.add("files — не больше %d файлов", MaxReportFiles)
		return ReportInput{}, l.err()
	}
	checkFindings(&l, "findings", in.Findings)
	seen := make(map[string]bool, len(in.Files))
	templates := 0
	for i, f := range in.Files {
		field := fmt.Sprintf("files[%d]", i)
		if err := checkPath(f.Path); err != nil {
			l.add("%s.path — %v", field, err)
		} else if seen[f.Path] {
			l.add("%s.path — путь повторяется", field)
		}
		seen[f.Path] = true
		if f.Size < 0 || f.Size > MaxFileSize {
			l.add("%s.size — от 0 до 2^50 байт", field)
		}
		if f.SHA256 != "" && !hashRe.MatchString(f.SHA256) {
			l.add("%s.sha256 — 64 шестнадцатеричных символа в нижнем регистре", field)
		}
		if f.Tensors < 0 || f.Tensors > MaxTensors {
			l.add("%s.tensors — от 0 до %d", field, MaxTensors)
		}
		if in.Kind == ReportVerify {
			// Сверка хешей не разбирает форматы: в отчёте только пути,
			// размеры и хеши.
			if f.Format != "" || f.Tensors != 0 || len(f.Findings) > 0 || f.FindingsTruncated || len(f.ChatTemplates) > 0 {
				l.add("%s — в отчёте verify только path, size, symlink и sha256", field)
			}
			continue
		}
		if !formatRe.MatchString(f.Format) {
			l.add("%s.format — формат сканера (строчные латинские буквы, цифры и «_»)", field)
		}
		checkFindings(&l, field+".findings", f.Findings)
		if len(f.ChatTemplates) > MaxFileTemplates {
			l.add("%s.chat_templates — не больше %d", field, MaxFileTemplates)
			continue
		}
		templates += len(f.ChatTemplates)
		for j, t := range f.ChatTemplates {
			tf := fmt.Sprintf("%s.chat_templates[%d]", field, j)
			if !sourceRe.MatchString(t.Source) {
				l.add("%s.source — источник шаблона (строчные латинские буквы, цифры, «_» и «.»)", tf)
			}
			if len(t.Name) > 128 || !utf8.ValidString(t.Name) || strings.IndexFunc(t.Name, hidden) >= 0 {
				l.add("%s.name — до 128 байт без управляющих символов", tf)
			}
			if t.Text == "" || len(t.Text) > MaxTemplateBytes || !utf8.ValidString(t.Text) || strings.ContainsRune(t.Text, 0) {
				l.add("%s.text — от 1 байта до %d КиБ в UTF-8 без нулевых символов", tf, MaxTemplateBytes>>10)
			}
		}
	}
	if templates > MaxReportTemplates {
		l.add("chat_templates — не больше %d шаблонов в отчёте", MaxReportTemplates)
	}
	if in.Kind == ReportVerify && len(in.Findings) > 0 {
		l.add("findings — в отчёте verify находок нет")
	}
	if err := l.err(); err != nil {
		return ReportInput{}, err
	}
	return in, nil
}

func checkFindings(l *errList, field string, fs []ReportFinding) {
	if len(fs) > MaxReportFindings {
		l.add("%s — не больше %d находок", field, MaxReportFindings)
		return
	}
	for i, f := range fs {
		ff := fmt.Sprintf("%s[%d]", field, i)
		if !codeRe.MatchString(f.Code) {
			l.add("%s.code — код находки (строчные латинские буквы, цифры и «_»)", ff)
		}
		if f.Severity != SeverityBlock && f.Severity != SeverityWarn {
			l.add("%s.severity — block или warn", ff)
		}
		if len(f.Detail) > MaxFindingDetail || !utf8.ValidString(f.Detail) || strings.IndexFunc(f.Detail, hidden) >= 0 {
			l.add("%s.detail — до %d байт без управляющих символов", ff, MaxFindingDetail)
		}
	}
}

// fileHash — хеш файла отчёта в байтах; nil — хеша нет.
func (f ReportFile) fileHash() []byte {
	if f.SHA256 == "" {
		return nil
	}
	h, err := hex.DecodeString(f.SHA256)
	if err != nil {
		return nil
	}
	return h
}
