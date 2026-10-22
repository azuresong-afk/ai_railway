package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Файл копии (ADR-0017): первая строка — открытый заголовок JSON (формат,
// версия, профиль, параметры Argon2id и соль), остальное — шифротекст
// AES-256-GCM содержимого. Заголовок целиком входит в AAD: подмена версии,
// соли или параметров ломает расшифрование.
const (
	// FormatName — значение поля format заголовка.
	FormatName = "aisec-config-backup"
	// FormatVersion — версия формата файла и содержимого.
	FormatVersion = 1
	// maxHeader — предел строки заголовка, байт.
	maxHeader = 1 << 10
	// MaxFileSize — предел файла копии: заголовок и шифротекст содержимого
	// не длиннее предела одного шифрования.
	MaxFileSize = maxHeader + crypto.MaxAEADPlaintext + 64
	// MinPassphraseChars — минимальная длина парольной фразы, символов (H-Р1).
	MinPassphraseChars = 16
	// MinPassphraseDistinct — минимум разных символов в фразе новой копии
	// (Н41 ревью 2.r4).
	MinPassphraseDistinct = 8
	// PassphraseHint — как выбрать фразу.
	PassphraseHint = "возьмите 4–5 случайных слов через пробел"
)

// Контексты выведения ключей копии из результата Argon2id: ключ содержимого
// и ключ секретов разные, шифротекст одного не открывается другим.
const (
	payloadKeyInfo = "aisec-backup-v1|payload"
	secretKeyInfo  = "aisec-backup-v1|secret"
	payloadAADPart = "payload"
	secretAADTable = "backup"
)

var (
	// ErrDecrypt — неверная парольная фраза или файл повреждён либо подменён.
	// Причины намеренно не различаются.
	ErrDecrypt = errors.New("резервная копия: неверная парольная фраза, файл повреждён или подменён")
	// ErrFormat — файл не похож на копию конфигурации или нарушает схему.
	ErrFormat = errors.New("резервная копия: неверный формат файла")
	// ErrVersion — копия сделана версией формата, которую этот выпуск не знает.
	ErrVersion = errors.New("резервная копия: неподдерживаемая версия формата")
)

// header — первая строка файла.
type header struct {
	Format    string    `json:"format"`
	Version   int       `json:"version"`
	Profile   string    `json:"profile"`
	KDF       string    `json:"kdf"`
	KDFParams string    `json:"kdf_params"`
	Salt      []byte    `json:"salt"`
	AEAD      string    `json:"aead"`
	CreatedAt time.Time `json:"created_at"`
}

// Keys — ключи копии, выведенные из парольной фразы. Открытых ключей не
// хранят: только развёрнутые объекты AEAD.
type Keys struct {
	payload crypto.AEAD
	secret  crypto.AEAD
}

// CheckPassphrase проверяет фразу по H-Р1: валидный UTF-8, не короче
// MinPassphraseChars символов и не длиннее предела пароля.
func CheckPassphrase(p []byte) error {
	if !utf8.Valid(p) {
		return errors.New("парольная фраза — не текст в UTF-8")
	}
	if n := utf8.RuneCount(p); n < MinPassphraseChars {
		return fmt.Errorf("парольная фраза короче %d символов", MinPassphraseChars)
	}
	if len(p) > crypto.MaxPasswordLen {
		return fmt.Errorf("парольная фраза длиннее %d байт", crypto.MaxPasswordLen)
	}
	return nil
}

// CheckNewPassphrase проверяет фразу новой копии: CheckPassphrase и
// стойкость (Н41 ревью 2.r4) — не меньше MinPassphraseDistinct разных
// символов, не повтор короткого фрагмента, не последовательность
// (abcd…, 1234…, в обе стороны) и не совпадает ни с одним из forbidden
// (имя пользователя ОС, название организации) без учёта регистра и
// пробелов по краям. Фраза открываемой копии так не проверяется: копия,
// снятая до этих правил, должна восстанавливаться.
func CheckNewPassphrase(p []byte, forbidden ...string) error {
	if err := CheckPassphrase(p); err != nil {
		return err
	}
	s := string(p)
	rs := []rune(s)
	distinct := map[rune]bool{}
	for _, r := range rs {
		distinct[r] = true
	}
	switch {
	case len(distinct) < MinPassphraseDistinct:
		return fmt.Errorf("в парольной фразе меньше %d разных символов: %s", MinPassphraseDistinct, PassphraseHint)
	case periodic(rs):
		return fmt.Errorf("парольная фраза — повтор одного фрагмента: %s", PassphraseHint)
	case sequential(rs):
		return fmt.Errorf("парольная фраза — последовательность символов: %s", PassphraseHint)
	}
	for _, f := range forbidden {
		if f = strings.TrimSpace(f); f != "" && strings.EqualFold(strings.TrimSpace(s), f) {
			return fmt.Errorf("парольная фраза совпадает с именем пользователя или названием организации: %s", PassphraseHint)
		}
	}
	return nil
}

// periodic — строка из не меньше чем двух повторов фрагмента.
func periodic(rs []rune) bool {
	for k := 1; k <= len(rs)/2; k++ {
		same := true
		for i := k; i < len(rs) && same; i++ {
			same = rs[i] == rs[i-k]
		}
		if same {
			return true
		}
	}
	return false
}

// sequential — каждый следующий символ на 1 больше (или меньше)
// предыдущего; после 9 идёт 0.
func sequential(rs []rune) bool {
	up, down := true, true
	for i := 1; i < len(rs); i++ {
		a, b := rs[i-1], rs[i]
		up = up && (b == a+1 || a == '9' && b == '0')
		down = down && (b == a-1 || a == '0' && b == '9')
	}
	return up || down
}

// deriveKeys выводит ключи копии: Argon2id из фразы, затем HKDF.
func deriveKeys(ctx context.Context, p crypto.Provider, passphrase, salt []byte, params string) (*Keys, error) {
	kdf, err := p.PassphraseKDF()
	if err != nil {
		return nil, err
	}
	master, err := kdf.Derive(ctx, passphrase, salt, params)
	if err != nil {
		return nil, err
	}
	defer clear(master)
	hk, err := p.NewKDF(master)
	if err != nil {
		return nil, err
	}
	k := &Keys{}
	for _, d := range []struct {
		info string
		dst  *crypto.AEAD
	}{{payloadKeyInfo, &k.payload}, {secretKeyInfo, &k.secret}} {
		key, err := hk.Derive([]byte(d.info), crypto.AEADKeySize)
		if err != nil {
			return nil, err
		}
		*d.dst, err = p.NewAEAD(key)
		clear(key)
		if err != nil {
			return nil, err
		}
	}
	return k, nil
}

// SealSecret шифрует секрет ключом секретов копии; AAD — вид секрета и ID
// строки, поэтому шифротекст не переносится на другой объект.
func (k *Keys) SealSecret(plaintext []byte, kind, id string) ([]byte, error) {
	aad, err := crypto.StorageAAD(secretAADTable, kind, id)
	if err != nil {
		return nil, err
	}
	return k.secret.Seal(plaintext, aad)
}

// OpenSecret расшифровывает секрет копии. Открытый текст вызывающий
// затирает сразу после использования.
func (k *Keys) OpenSecret(sealed []byte, kind, id string) ([]byte, error) {
	aad, err := crypto.StorageAAD(secretAADTable, kind, id)
	if err != nil {
		return nil, err
	}
	out, err := k.secret.Open(sealed, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return out, nil
}

// Writer создаёт файл копии: соль, ключи и заголовок готовы до чтения БД,
// чтобы секреты шифровались ключом копии сразу после расшифрования.
type Writer struct {
	keys   *Keys
	header []byte
}

// NewWriter выводит ключи новой копии из фразы со свежей солью.
func NewWriter(ctx context.Context, p crypto.Provider, passphrase []byte, now time.Time) (*Writer, error) {
	if err := CheckNewPassphrase(passphrase); err != nil {
		return nil, err
	}
	kdf, err := p.PassphraseKDF()
	if err != nil {
		return nil, err
	}
	rnd, err := p.Random()
	if err != nil {
		return nil, err
	}
	salt, err := crypto.RandomBytes(rnd, crypto.PassphraseSaltSize)
	if err != nil {
		return nil, err
	}
	keys, err := deriveKeys(ctx, p, passphrase, salt, kdf.Params())
	if err != nil {
		return nil, err
	}
	h := header{Format: FormatName, Version: FormatVersion, Profile: p.Name(), KDF: kdf.Name(), KDFParams: kdf.Params(),
		Salt: salt, AEAD: keys.payload.Name(), CreatedAt: now.UTC().Truncate(time.Microsecond)}
	line, err := json.Marshal(h)
	if err != nil {
		return nil, err
	}
	line = append(line, '\n')
	if len(line) > maxHeader {
		return nil, errors.New("резервная копия: заголовок длиннее предела")
	}
	return &Writer{keys: keys, header: line}, nil
}

// Keys — ключи копии для шифрования секретов при снятии снимка.
func (w *Writer) Keys() *Keys { return w.keys }

// Seal кодирует снимок и возвращает содержимое файла. Открытый JSON
// затирается после шифрования; секреты в нём уже зашифрованы ключом копии.
func (w *Writer) Seal(s *Snapshot) ([]byte, error) {
	s.Version = FormatVersion
	payload, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer clear(payload)
	sealed, err := w.keys.payload.Seal(payload, payloadAAD(w.header))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(w.header)+len(sealed))
	out = append(out, w.header...)
	return append(out, sealed...), nil
}

// payloadAAD — заголовок с меткой назначения: заголовок целиком входит в
// присоединённые данные.
func payloadAAD(headerLine []byte) []byte {
	aad := make([]byte, 0, len(payloadAADPart)+1+len(headerLine))
	aad = append(aad, payloadAADPart...)
	aad = append(aad, '|')
	return append(aad, headerLine...)
}

// Archive — расшифрованная и проверенная копия.
type Archive struct {
	Profile   string
	CreatedAt time.Time
	Snapshot  *Snapshot
	keys      *Keys
}

// Keys — ключи копии для расшифрования секретов при восстановлении.
func (a *Archive) Keys() *Keys { return a.keys }

// parseHeader разбирает открытый заголовок. Он ещё не проверен AEAD,
// поэтому здесь отсекается только то, без чего нельзя вывести ключ:
// длина, JSON без лишних полей, соль и параметры (их границы проверяет
// PassphraseKDF). Версия сверяется после расшифрования.
func parseHeader(data []byte) (h header, line, rest []byte, err error) {
	i := bytes.IndexByte(data[:min(len(data), maxHeader)], '\n')
	if i < 0 {
		return h, nil, nil, ErrFormat
	}
	line, rest = data[:i+1], data[i+1:]
	dec := json.NewDecoder(bytes.NewReader(line[:i]))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return h, nil, nil, ErrFormat
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return h, nil, nil, ErrFormat
	}
	if h.Format != FormatName || h.KDF == "" || h.KDFParams == "" ||
		len(h.Salt) < crypto.PassphraseSaltSize || len(h.Salt) > 64 {
		return h, nil, nil, ErrFormat
	}
	return h, line, rest, nil
}

// Open расшифровывает и проверяет файл копии. Порядок (H-Р1, задача 2.19):
// сначала AEAD (фраза и целостность заголовка и содержимого), затем версия
// формата, затем строгая схема содержимого.
func Open(ctx context.Context, p crypto.Provider, passphrase, data []byte) (*Archive, error) {
	if len(data) > MaxFileSize {
		return nil, fmt.Errorf("%w: файл больше %d байт", ErrFormat, MaxFileSize)
	}
	h, line, sealed, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	if h.Profile != p.Name() {
		return nil, fmt.Errorf("%w: копия профиля %q, установка работает в профиле %q", ErrFormat, h.Profile, p.Name())
	}
	kdf, err := p.PassphraseKDF()
	if err != nil {
		return nil, err
	}
	if h.KDF != kdf.Name() {
		return nil, fmt.Errorf("%w: вывод ключа %q не поддерживается", ErrFormat, h.KDF)
	}
	keys, err := deriveKeys(ctx, p, passphrase, h.Salt, h.KDFParams)
	if err != nil {
		if ctx.Err() != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
	}
	payload, err := keys.payload.Open(sealed, payloadAAD(line))
	if err != nil {
		if h.Version != FormatVersion {
			// Другой выпуск мог изменить и вывод ключей: подсказка, а не диагноз.
			return nil, fmt.Errorf("%w (копия формата версии %d, этот выпуск поддерживает %d)", ErrDecrypt, h.Version, FormatVersion)
		}
		return nil, ErrDecrypt
	}
	defer clear(payload)
	if h.Version != FormatVersion {
		return nil, fmt.Errorf("%w: %d (поддерживается %d)", ErrVersion, h.Version, FormatVersion)
	}
	if h.AEAD != keys.payload.Name() {
		return nil, fmt.Errorf("%w: алгоритм %q", ErrFormat, h.AEAD)
	}
	s, err := decodeSnapshot(payload)
	if err != nil {
		return nil, err
	}
	hasher, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	if err := s.verifyHashes(hasher); err != nil {
		return nil, err
	}
	return &Archive{Profile: h.Profile, CreatedAt: h.CreatedAt, Snapshot: s, keys: keys}, nil
}
