// Пакет bundle — подписанный пакет конфигурации для шлюзов (решение Р7,
// ТЗ 5.3 «Доставка в шлюзы», ОЦЛ.3, DM-42; задача 2.13 этапа 2, ADR-0009).
//
// Пакет — JSON-конверт с тремя частями в base64: заголовок (формат, версия,
// шлюз, хеш содержимого), содержимое (Content: приложения с хешами ключей и
// словарями, провайдеры без учётных данных, политики) и секреты (учётные
// данные провайдеров, зашифрованные для ключа конкретного шлюза, HPKE).
// Подпись Ed25519 ставится над байтами частей, а не над разобранной
// структурой, поэтому канонизация JSON не нужна. Шлюз проверяет размер,
// подпись, шлюз и версию до разбора содержимого (Open).
//
// Пакет не зависит от сервера: его импортирует шлюз. Сборку из данных
// сервера выполняет подпакет build.
package bundle

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Format — формат конверта и заголовка; он же разделитель домена подписи.
const Format = "aisec-config-bundle/1"

// MaxSize — предел размера пакета целиком, байт.
const MaxSize = 8 << 20

// maxHeader — предел заголовка, байт.
const maxHeader = 4 << 10

// Причины отказа (Reason у RejectError): попадают в технический журнал
// шлюза и в отчёт серверу (bundle.rejected в аудите).
const (
	ReasonTooLarge        = "too_large"
	ReasonFormat          = "format"
	ReasonSignature       = "signature"
	ReasonGatewayMismatch = "gateway_mismatch"
	ReasonRollback        = "rollback"
	ReasonInvalidContent  = "invalid_content"
	ReasonDecrypt         = "decrypt"
)

// Reasons — допустимые причины отказа.
var Reasons = []string{ReasonTooLarge, ReasonFormat, ReasonSignature, ReasonGatewayMismatch, ReasonRollback, ReasonInvalidContent, ReasonDecrypt}

// RejectError — пакет отклонён. Текст не содержит секретов и содержимого.
type RejectError struct {
	Reason string
	Err    error
}

func (e *RejectError) Error() string {
	return "пакет конфигурации отклонён (" + e.Reason + "): " + e.Err.Error()
}

func (e *RejectError) Unwrap() error { return e.Err }

func reject(reason string, format string, a ...any) error {
	return &RejectError{Reason: reason, Err: fmt.Errorf(format, a...)}
}

// Reason — причина отказа из ошибки Open; не RejectError — invalid_content.
func Reason(err error) string {
	var re *RejectError
	if errors.As(err, &re) {
		return re.Reason
	}
	return ReasonInvalidContent
}

// Header — подписанный заголовок пакета.
type Header struct {
	Format string `json:"format"`
	// Version строго растёт от пакета к пакету (сервер: max(прежняя+1,
	// время сборки в мс)); шлюз не принимает версию меньше применённой.
	Version  int64     `json:"version"`
	IssuedAt time.Time `json:"issued_at"`
	// GatewayID — CN сертификата шлюза: секреты зашифрованы для него, и
	// чужой шлюз пакет не примет.
	GatewayID string `json:"gateway_id"`
	// ContentHash — хеш байтов содержимого (хеш профиля, hex), HashAlg — его имя.
	ContentHash string `json:"content_hash"`
	HashAlg     string `json:"hash_alg"`
}

// envelope — конверт пакета; части — стандартный base64.
type envelope struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Header    string `json:"header"`
	Content   string `json:"content"`
	Secrets   string `json:"secrets"`
	Signature string `json:"signature"`
}

// ETag — значение заголовка ETag для версии пакета.
func ETag(version int64) string { return `"` + strconv.FormatInt(version, 10) + `"` }

// KeyID — идентификатор ключа подписи: первые 8 байт хеша открытого ключа.
func KeyID(h aisecCrypto.Hasher, publicKey []byte) string {
	return hex.EncodeToString(h.Sum(publicKey)[:8])
}

// signedMessage — подписываемые байты: формат, затем части с длинами
// (4 байта big-endian): части нельзя сдвинуть одна в другую.
func signedMessage(header, content, secrets []byte) []byte {
	msg := make([]byte, 0, len(Format)+1+12+len(header)+len(content)+len(secrets))
	msg = append(msg, Format...)
	msg = append(msg, 0)
	for _, part := range [][]byte{header, content, secrets} {
		msg = binary.BigEndian.AppendUint32(msg, uint32(len(part))) //nolint:gosec // G115: части ограничены MaxSize
		msg = append(msg, part...)
	}
	return msg
}

// secretsInfo — info HPKE: шифротекст секретов привязан к формату, шлюзу,
// версии и содержимому и не переносится в другой пакет.
func secretsInfo(h Header) []byte {
	return []byte(Format + "|secrets|" + h.GatewayID + "|" + strconv.FormatInt(h.Version, 10) + "|" + h.ContentHash)
}

// Secrets — учётные данные провайдеров по ID провайдера. Только в памяти:
// в пакете — шифротекст, в журналы не выводится.
type Secrets map[string]string

// Format выводит только число секретов при любом глаголе fmt.
func (s Secrets) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, s.summary()) //nolint:gosec // G104: у fmt.Formatter нет способа вернуть ошибку записи
}

// LogValue выводит в slog только число секретов.
func (s Secrets) LogValue() slog.Value { return slog.StringValue(s.summary()) }

func (s Secrets) summary() string { return "Secrets(" + strconv.Itoa(len(s)) + ")" }

// Clear затирает строки секретов, насколько это возможно в Go: строки
// неизменяемы, поэтому из карты удаляются ссылки.
func (s Secrets) Clear() {
	for k := range s {
		delete(s, k)
	}
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func decodeB64(s string, limit int) ([]byte, error) {
	if len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, errors.New("часть больше предела")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}
