package rag

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Разбор и проверка манифеста коллекции (ADR-0029, п. 5). Тело — до
// MaxBody, строгий JSON: неизвестные поля и данные после значения — отказ.
// Тексты ошибок показываются пользователю и не содержат значений: ID
// документа — данные заказчика, ошибка называет только номер записи.

// DocumentInput — документ во входе манифеста.
type DocumentInput struct {
	ID     string `json:"id"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Excluded — индексатор не индексирует документ: проверка до
	// индексации вернула «исключить» (задача 5.25).
	Excluded bool `json:"excluded,omitempty"`
}

// ManifestInput — тело PUT …/manifest.
type ManifestInput struct {
	Documents []DocumentInput `json:"documents"`
}

var (
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidSlug — ID коллекции: строчные латинские буквы, цифры и «-», до 63
// символов, не с «-».
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// CheckDocumentID — ID документа: 1–MaxDocumentID байт UTF-8 без
// управляющих символов и символов форматирования Unicode (Cf, в том числе
// смены направления текста — иначе консоль и оповещение показали бы
// подменённый ID) и без пробелов в начале и в конце. Общая проверка
// манифеста, исключений и пакета проверки до индексации.
func CheckDocumentID(id string) error {
	switch {
	case id == "" || len(id) > MaxDocumentID:
		return fmt.Errorf("от 1 до %d байт", MaxDocumentID)
	case !utf8.ValidString(id):
		return errors.New("строка UTF-8")
	case strings.ContainsFunc(id, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }):
		return errors.New("без управляющих символов и символов форматирования")
	case id != strings.TrimSpace(id):
		return errors.New("без пробелов в начале и в конце")
	}
	return nil
}

// maxReportedErrors — ошибок в ответе на неверный манифест: остальные
// только числом (100 000 неверных записей не дают ответа в мегабайты).
const maxReportedErrors = 20

// ParseManifest разбирает и проверяет манифест: число документов до
// MaxDocuments, ID без повторов, хеш — 64 шестнадцатеричных символа в
// нижнем регистре, размер — от 0 до MaxDocumentSize. Документы
// возвращаются в порядке входа.
func ParseManifest(data []byte) ([]Document, error) {
	if len(data) > MaxBody {
		return nil, invalid(fmt.Errorf("тело — не больше %d МиБ", MaxBody>>20))
	}
	var in ManifestInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return nil, invalid(errors.New("тело — некорректный JSON или неизвестные поля"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, invalid(errors.New("после JSON-значения есть лишние данные"))
	}
	if in.Documents == nil {
		return nil, invalid(errors.New("documents — обязательный список (пустой — коллекция без документов)"))
	}
	if len(in.Documents) > MaxDocuments {
		return nil, invalid(fmt.Errorf("documents — не больше %d документов", MaxDocuments))
	}
	var errs []error
	more := 0
	fail := func(err error) {
		if len(errs) < maxReportedErrors {
			errs = append(errs, err)
			return
		}
		more++
	}
	seen := make(map[string]struct{}, len(in.Documents))
	out := make([]Document, 0, len(in.Documents))
	for i, d := range in.Documents {
		ok := true
		if err := CheckDocumentID(d.ID); err != nil {
			fail(fmt.Errorf("documents[%d].id — %w", i, err))
			ok = false
		} else if _, dup := seen[d.ID]; dup {
			fail(fmt.Errorf("documents[%d].id — повтор ID документа", i))
			ok = false
		}
		if !hashRe.MatchString(d.SHA256) {
			fail(fmt.Errorf("documents[%d].sha256 — 64 шестнадцатеричных символа в нижнем регистре", i))
			ok = false
		}
		if d.Size < 0 || d.Size > MaxDocumentSize {
			fail(fmt.Errorf("documents[%d].size — от 0 до %d байт", i, MaxDocumentSize))
			ok = false
		}
		if !ok {
			continue
		}
		seen[d.ID] = struct{}{}
		h, _ := hex.DecodeString(d.SHA256) //nolint:gosec // G104: формат проверен hashRe
		out = append(out, Document{ID: d.ID, SHA256: h, Size: d.Size, Excluded: d.Excluded})
	}
	if more > 0 {
		errs = append(errs, fmt.Errorf("documents — ещё ошибок: %d", more))
	}
	if len(errs) > 0 {
		return nil, invalid(errs...)
	}
	return out, nil
}

// ExclusionInput — тело POST …/exclusions.
type ExclusionInput struct {
	DocumentID string `json:"document_id"`
	Reason     string `json:"reason"`
}

// ParseExclusion разбирает исключение документа администратором: ID
// документа — по правилам манифеста, причина — до MaxReason символов без
// управляющих символов (перевод строки допустим).
func ParseExclusion(data []byte) (ExclusionInput, error) {
	if len(data) > MaxExclusionBody {
		return ExclusionInput{}, invalid(fmt.Errorf("тело — не больше %d КиБ", MaxExclusionBody>>10))
	}
	var in ExclusionInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return ExclusionInput{}, invalid(errors.New("тело — некорректный JSON или неизвестные поля"))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return ExclusionInput{}, invalid(errors.New("после JSON-значения есть лишние данные"))
	}
	if errs := checkExclusion(in.DocumentID, in.Reason); len(errs) > 0 {
		return ExclusionInput{}, invalid(errs...)
	}
	return in, nil
}

func checkExclusion(docID, reason string) []error {
	var errs []error
	if err := CheckDocumentID(docID); err != nil {
		errs = append(errs, fmt.Errorf("document_id — %w", err))
	}
	switch {
	case !utf8.ValidString(reason) || utf8.RuneCountInString(reason) > MaxReason:
		errs = append(errs, fmt.Errorf("reason — строка UTF-8 не длиннее %d символов", MaxReason))
	case strings.ContainsFunc(reason, func(r rune) bool {
		return r != '\n' && (unicode.IsControl(r) || unicode.Is(unicode.Cf, r))
	}):
		errs = append(errs, errors.New("reason — без управляющих символов и символов форматирования"))
	}
	return errs
}

// CheckExclusion проверяет исключение документа из резервной копии
// конфигурации до записи (ревью 5.r2, 5Н15): ID коллекции, ID документа и
// причина — по правилам API, автор — 1–128 символов.
func CheckExclusion(slug, docID, reason, createdBy string) error {
	errs := checkExclusion(docID, reason)
	if !ValidSlug(slug) {
		errs = append(errs, errors.New("slug — ID коллекции: строчные латинские буквы, цифры и «-», до 63 символов"))
	}
	if n := utf8.RuneCountInString(createdBy); n < 1 || n > 128 || !utf8.ValidString(createdBy) {
		errs = append(errs, errors.New("created_by — от 1 до 128 символов"))
	}
	if len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}
