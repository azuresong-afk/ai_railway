// Package servicedb — служебные базы (ОБН.4, ADR-0028): общий механизм для
// каталога теневого ИИ, базы требований и следующих баз (эталоны шаблонов
// чата, сценарии тестирования устойчивости). Формат файла и подписи —
// ADR-0027, п. 3; подпись и заверение проверяет только internal/crypto,
// отзыв — integrity.RevokedServiceDB. Пакет знает только вид базы: версию,
// дату и число записей возвращает разборщик вида, который регистрирует
// модуль. Здесь — проверка, хранение текущей и предыдущей версии, правило
// версии, откат, проверка сохранённых файлов при запуске, аудит и состояние.
package servicedb

import (
	"errors"
	"fmt"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// MaxVersion — наибольшая версия базы (целое без потерь в JSON).
const MaxVersion = 1<<53 - 1

// Kind — вид служебной базы, который регистрирует модуль.
type Kind struct {
	// Name — имя вида в подписи (латиница в нижнем регистре, цифры и «_»).
	Name string
	// Title — название для людей (аудит, CLI, консоль).
	Title string
	// Parse разбирает содержимое после проверки подписи. Ошибка — отказ
	// «содержимое». Разборщик обязан ограничивать размер и сложность входа.
	Parse func(payload []byte) (Content, error)
}

// Content — разобранное содержимое базы.
type Content struct {
	// Value — разобранная база модуля (например, *shadowai.Catalog).
	Value any
	// Version — версия базы, 1…MaxVersion; строго растёт.
	Version uint64
	// Date — сутки выпуска (UTC, полночь).
	Date time.Time
	// Records — число записей (сервисов, пунктов, сценариев).
	Records int
}

// Verified — проверенная база.
type Verified struct {
	Kind        string
	Content     Content
	Endorsement aisecCrypto.Endorsement
	// Fingerprint — отпечаток рабочего ключа (как у ключа производителя).
	Fingerprint string
}

// Ошибки проверки и хранения. Текст не содержит байтов файла.
var (
	// ErrDate — дата выпуска базы вне срока заверения рабочего ключа.
	ErrDate = errors.New("служебная база: дата выпуска вне срока заверения рабочего ключа")
	// ErrContent — содержимое не прошло разбор вида.
	ErrContent = errors.New("служебная база: содержимое не прошло проверку")
	// ErrStale — версия не больше текущей.
	ErrStale = errors.New("служебная база: версия не больше текущей")
	// ErrNoPrevious — предыдущей версии нет, откатывать некуда.
	ErrNoPrevious = errors.New("служебная база: предыдущей версии нет")
	// ErrUnknownKind — вид не зарегистрирован в выпуске.
	ErrUnknownKind = errors.New("служебная база: вид неизвестен этому выпуску")
)

// Причины отказа (аудит, ответы API, состояние).
const (
	ReasonSignature  = "signature"
	ReasonPurpose    = "purpose"
	ReasonKind       = "kind"
	ReasonStale      = "stale_version"
	ReasonExpired    = "expired"
	ReasonDate       = "date"
	ReasonRevoked    = "revoked"
	ReasonContent    = "content"
	ReasonFormat     = "format"
	ReasonNoPrevious = "no_previous"
)

// Reason — код причины по ошибке проверки или хранения.
func Reason(err error) string {
	switch {
	case errors.Is(err, aisecCrypto.ErrEndorsementSignature), errors.Is(err, aisecCrypto.ErrServiceDBSignature):
		return ReasonSignature
	case errors.Is(err, aisecCrypto.ErrEndorsementPurpose):
		return ReasonPurpose
	case errors.Is(err, aisecCrypto.ErrEndorsementExpired):
		return ReasonExpired
	case errors.Is(err, aisecCrypto.ErrEndorsementRevoked):
		return ReasonRevoked
	case errors.Is(err, aisecCrypto.ErrServiceDBKind), errors.Is(err, ErrUnknownKind):
		return ReasonKind
	case errors.Is(err, ErrDate):
		return ReasonDate
	case errors.Is(err, ErrContent):
		return ReasonContent
	case errors.Is(err, ErrStale):
		return ReasonStale
	case errors.Is(err, ErrNoPrevious):
		return ReasonNoPrevious
	}
	return ReasonFormat
}

// RejectError — отказ в загрузке или откате с кодом причины.
type RejectError struct {
	Kind   string
	Reason string
	Err    error
}

func (e *RejectError) Error() string { return e.Err.Error() }
func (e *RejectError) Unwrap() error { return e.Err }

// EmbeddedVendor — встроенный ключ производителя: тестовый в сборке без тега
// aisec_release, ключ производителя в поставочной (ADR-0022, п. 7).
func EmbeddedVendor(p aisecCrypto.Provider) (aisecCrypto.Verifier, error) {
	v, _, err := integrity.EmbeddedVerifier(p)
	return v, err
}

// Verify проверяет файл базы вида k ключом производителя vendor: заверение
// (назначение service_db, отзыв, срок на момент at; нулевой at — срок не
// проверяется: уже загруженная база, ADR-0027, п. 3), подпись содержимого,
// вид, затем разбор содержимого и дату выпуска внутри срока заверения.
func Verify(p aisecCrypto.Provider, vendor aisecCrypto.Verifier, k Kind, data []byte, at time.Time) (Verified, error) {
	if k.Parse == nil {
		return Verified{}, ErrUnknownKind
	}
	db, err := aisecCrypto.VerifyServiceDB(p, vendor, data, k.Name, aisecCrypto.EndorsementCheck{At: at, Revoked: integrity.RevokedServiceDB})
	if err != nil {
		return Verified{}, err
	}
	c, err := k.Parse(db.Payload)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrContent, err)
	}
	if c.Version == 0 || c.Version > MaxVersion || c.Records < 0 {
		return Verified{}, ErrContent
	}
	// Дата базы — сутки выпуска: заверение должно действовать хотя бы в
	// часть этих суток.
	e := db.Endorsement
	day := c.Date.UTC()
	if day.Add(24*time.Hour).Before(e.NotBefore) || day.After(e.NotAfter) {
		return Verified{}, ErrDate
	}
	fp, err := integrity.Fingerprint(p, e.PublicKey)
	if err != nil {
		return Verified{}, fmt.Errorf("служебная база: %w", err)
	}
	return Verified{Kind: db.Kind, Content: c, Endorsement: e, Fingerprint: fp}, nil
}
