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
	"unicode"
	"unicode/utf8"
)

// Разбор и проверка ручной записи (ADR-0029, п. 8). Тело — до MaxBody,
// строгий JSON: неизвестные поля, повтор значения и мусор после него —
// отказ. Тексты ошибок показываются пользователю и не содержат значений.

// FileInput — файл модели во входе: хеш — 64 шестнадцатеричных символа в
// нижнем регистре.
type FileInput struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

// ModelInput — ручная модель.
type ModelInput struct {
	Kind        string      `json:"kind"`
	Provider    string      `json:"provider"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Title       string      `json:"title"`
	Description string      `json:"description"`
	Owner       string      `json:"owner"`
	Files       []FileInput `json:"files"`

	hashes [][]byte
}

// ModelPatch — изменение модели: nil — поле не меняется; files заменяет
// список целиком.
type ModelPatch struct {
	Kind        *string      `json:"kind"`
	Version     *string      `json:"version"`
	Title       *string      `json:"title"`
	Description *string      `json:"description"`
	Owner       *string      `json:"owner"`
	Files       *[]FileInput `json:"files"`

	hashes [][]byte
}

var (
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

var validRoles = map[string]bool{RoleWeights: true, RoleAdapter: true, RoleTokenizer: true, RoleConfig: true, RoleOther: true}

// decodeStrict разбирает одно JSON-значение без неизвестных полей.
func decodeStrict(data []byte, dst any) error {
	if len(data) > MaxBody {
		return invalid(fmt.Errorf("тело — не больше %d КиБ", MaxBody>>10))
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

// ParseModelInput разбирает и проверяет ручную модель.
func ParseModelInput(data []byte) (ModelInput, error) {
	var in ModelInput
	if err := decodeStrict(data, &in); err != nil {
		return ModelInput{}, err
	}
	var errs []error
	switch in.Kind {
	case KindProvider:
		if in.Provider == "" {
			errs = append(errs, errors.New("provider — обязателен у модели провайдера"))
		}
	case KindCustomer:
	default:
		errs = append(errs, errors.New("kind — provider или customer"))
	}
	if in.Provider != "" && !slugRe.MatchString(in.Provider) {
		errs = append(errs, errors.New("provider — ID провайдера: строчные латинские буквы, цифры и «-», до 63 символов"))
	}
	errs = append(errs, text("name", in.Name, 1, maxName)...)
	if in.Name != strings.TrimSpace(in.Name) {
		errs = append(errs, errors.New("name — без пробелов в начале и в конце"))
	}
	errs = append(errs, text("version", in.Version, 0, maxVersion)...)
	errs = append(errs, text("title", in.Title, 0, maxTitle)...)
	errs = append(errs, text("owner", in.Owner, 0, maxOwner)...)
	errs = append(errs, multiline("description", in.Description, maxDescription)...)
	h, ferrs := checkFiles(in.Files)
	errs = append(errs, ferrs...)
	if len(errs) > 0 {
		return ModelInput{}, invalid(errs...)
	}
	in.hashes = h
	return in, nil
}

// ParseModelPatch разбирает и проверяет изменение модели.
func ParseModelPatch(data []byte) (ModelPatch, error) {
	var p ModelPatch
	if err := decodeStrict(data, &p); err != nil {
		return ModelPatch{}, err
	}
	var errs []error
	if p.Kind != nil && *p.Kind != KindProvider && *p.Kind != KindCustomer {
		errs = append(errs, errors.New("kind — provider или customer"))
	}
	if p.Version != nil {
		errs = append(errs, text("version", *p.Version, 0, maxVersion)...)
	}
	if p.Title != nil {
		errs = append(errs, text("title", *p.Title, 0, maxTitle)...)
	}
	if p.Owner != nil {
		errs = append(errs, text("owner", *p.Owner, 0, maxOwner)...)
	}
	if p.Description != nil {
		errs = append(errs, multiline("description", *p.Description, maxDescription)...)
	}
	if p.Files != nil {
		h, ferrs := checkFiles(*p.Files)
		errs = append(errs, ferrs...)
		p.hashes = h
	}
	if len(errs) > 0 {
		return ModelPatch{}, invalid(errs...)
	}
	return p, nil
}

func (in ModelInput) files() []File { return toFiles(in.Files, in.hashes) }

func (p ModelPatch) files() []File {
	if p.Files == nil {
		return nil
	}
	return toFiles(*p.Files, p.hashes)
}

func toFiles(fs []FileInput, hashes [][]byte) []File {
	out := make([]File, len(fs))
	for i, f := range fs {
		out[i] = File{Path: f.Path, Size: f.Size, Role: f.Role, HashAlg: HashAlg, Hash: hashes[i]}
	}
	return out
}

// checkFiles проверяет список файлов и возвращает хеши в байтах.
func checkFiles(fs []FileInput) ([][]byte, []error) {
	if len(fs) > MaxFiles {
		return nil, []error{fmt.Errorf("files — не больше %d файлов", MaxFiles)}
	}
	var errs []error
	seen := make(map[string]bool, len(fs))
	hashes := make([][]byte, len(fs))
	for i, f := range fs {
		field := fmt.Sprintf("files[%d]", i)
		if err := checkPath(f.Path); err != nil {
			errs = append(errs, fmt.Errorf("%s.path — %w", field, err))
		} else if seen[f.Path] {
			errs = append(errs, fmt.Errorf("%s.path — путь повторяется", field))
		}
		seen[f.Path] = true
		if f.Size < 0 || f.Size > MaxFileSize {
			errs = append(errs, fmt.Errorf("%s.size — от 0 до 2^50 байт", field))
		}
		if !validRoles[f.Role] {
			errs = append(errs, fmt.Errorf("%s.role — weights, adapter, tokenizer, config или other", field))
		}
		if !hashRe.MatchString(f.SHA256) {
			errs = append(errs, fmt.Errorf("%s.sha256 — 64 шестнадцатеричных символа в нижнем регистре", field))
			continue
		}
		h, err := hex.DecodeString(f.SHA256)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s.sha256 — неверная запись", field))
			continue
		}
		hashes[i] = h
	}
	return hashes, errs
}

// hidden — управляющие символы (Cc) и символы форматирования (Cf, в том
// числе смена направления текста U+202E): в консоли они подменяли бы
// видимое имя (ревью 5.17).
func hidden(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }

// checkPath — путь относительно каталога модели: части через «/», без
// пустых частей, «.», «..», «\», двоеточия (диск и потоки NTFS) и
// управляющих символов.
func checkPath(p string) error {
	if p == "" || len(p) > MaxPathBytes {
		return fmt.Errorf("от 1 до %d байт", MaxPathBytes)
	}
	if !utf8.ValidString(p) {
		return errors.New("не UTF-8")
	}
	if strings.ContainsRune(p, '\\') || strings.IndexFunc(p, hidden) >= 0 {
		return errors.New("без «\\» и управляющих символов")
	}
	parts := strings.Split(p, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return errors.New("относительный путь без пустых частей, «.» и «..»")
		}
	}
	if strings.ContainsRune(p, ':') {
		return errors.New("относительный путь без «:» (имя диска, потоки NTFS)")
	}
	return nil
}

// text — строка в одну линию: длина в символах и без управляющих символов.
func text(field, v string, lo, hi int) []error {
	var errs []error
	if !utf8.ValidString(v) {
		return []error{errors.New(field + " — не UTF-8")}
	}
	if n := utf8.RuneCountInString(v); n < lo || n > hi {
		if lo > 0 {
			errs = append(errs, fmt.Errorf("%s — от %d до %d символов", field, lo, hi))
		} else {
			errs = append(errs, fmt.Errorf("%s — не больше %d символов", field, hi))
		}
	}
	if strings.IndexFunc(v, hidden) >= 0 {
		errs = append(errs, errors.New(field+" — без управляющих символов"))
	}
	return errs
}

// multiline — как text, но разрешены переводы строк.
func multiline(field, v string, hi int) []error {
	var errs []error
	if !utf8.ValidString(v) {
		return []error{errors.New(field + " — не UTF-8")}
	}
	if utf8.RuneCountInString(v) > hi {
		errs = append(errs, fmt.Errorf("%s — не больше %d символов", field, hi))
	}
	if strings.IndexFunc(v, func(r rune) bool { return hidden(r) && r != '\n' }) >= 0 {
		errs = append(errs, errors.New(field+" — без управляющих символов, кроме перевода строки"))
	}
	return errs
}
