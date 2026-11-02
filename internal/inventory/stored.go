package inventory

import (
	"errors"
	"fmt"
	"strings"
)

// StoredModel — модель реестра в том виде, в каком её хранит БД и переносит
// резервная копия конфигурации (остаток 5.17 этапа 5, дополнение ADR-0017).
type StoredModel struct {
	Kind        string
	Provider    string
	Name        string
	Version     string
	Title       string
	Description string
	Owner       string
	Origin      string
	Status      string
	Files       []File
}

// CheckStoredModel проверяет сохранённую модель правилами ручной записи
// (ParseModelInput): вид, провайдер, имя, тексты без управляющих символов,
// происхождение и состояние, файлы — путь, размер, роль и хеш SHA-256 из
// 32 байт без повторов путей. Существование провайдера не проверяется:
// модель удалённого провайдера остаётся в реестре (ADR-0029). Вызывает
// восстановление копии до записи в БД. Ошибка — *InputError.
func CheckStoredModel(m StoredModel) error {
	var errs []error
	switch m.Kind {
	case KindProvider:
		if m.Provider == "" {
			errs = append(errs, errors.New("provider — обязателен у модели провайдера"))
		}
	case KindCustomer:
	default:
		errs = append(errs, errors.New("kind — provider или customer"))
	}
	if m.Provider != "" && !slugRe.MatchString(m.Provider) {
		errs = append(errs, errors.New("provider — ID провайдера: строчные латинские буквы, цифры и «-», до 63 символов"))
	}
	errs = append(errs, text("name", m.Name, 1, maxName)...)
	if m.Name != strings.TrimSpace(m.Name) {
		errs = append(errs, errors.New("name — без пробелов в начале и в конце"))
	}
	errs = append(errs, text("version", m.Version, 0, maxVersion)...)
	errs = append(errs, text("title", m.Title, 0, maxTitle)...)
	errs = append(errs, text("owner", m.Owner, 0, maxOwner)...)
	errs = append(errs, multiline("description", m.Description, maxDescription)...)
	if m.Origin != OriginManual && m.Origin != OriginTraffic {
		errs = append(errs, errors.New("origin — manual или traffic"))
	}
	if m.Status != StatusActive {
		errs = append(errs, errors.New("status — active"))
	}
	errs = append(errs, checkStoredFiles(m.Files)...)
	if len(errs) > 0 {
		return invalid(errs...)
	}
	return nil
}

// checkStoredFiles — файлы сохранённой модели, как checkFiles для входа.
func checkStoredFiles(fs []File) []error {
	if len(fs) > MaxFiles {
		return []error{fmt.Errorf("files — не больше %d файлов", MaxFiles)}
	}
	var errs []error
	seen := make(map[string]bool, len(fs))
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
		if f.HashAlg != HashAlg || len(f.Hash) != 32 {
			errs = append(errs, fmt.Errorf("%s.hash — %s, 32 байта", field, HashAlg))
		}
	}
	return errs
}
