package crypto

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Ограничения пароля, байт. Верхняя граница защищает от отказа в
// обслуживании длинным вводом; правила сложности — в internal/auth (ИАФ.2).
const (
	MinPasswordLen = 1
	MaxPasswordLen = 1024
)

// ErrInvalidPasswordHash — сохранённый хеш пароля не разобран или его параметры вне допустимых границ.
var ErrInvalidPasswordHash = errors.New("хеш пароля: неверный формат или параметры")

// PasswordHasher — хеширование паролей учётных записей (ТЗ, 10.2, ИАФ.1).
// Хеш хранится строкой в формате PHC вместе с солью и параметрами, поэтому
// параметры можно повышать без миграции: Verify сообщает, что хеш пора обновить.
type PasswordHasher interface {
	Name() string
	// Hash вычисляет хеш со свежей солью. Ждёт свободного слота вычисления не дольше, чем живёт ctx.
	Hash(ctx context.Context, password []byte) (string, error)
	// Verify сравнивает пароль с хешем за постоянное время. needsRehash — хеш
	// получен с другими параметрами: после успешного входа его стоит пересчитать.
	// Неверный пароль — ok = false без ошибки; ошибка — только у повреждённого
	// хеша, недопустимого пароля или истёкшего ctx.
	Verify(ctx context.Context, password []byte, encoded string) (ok, needsRehash bool, err error)
}

// argon2Params — параметры Argon2id. memory — в КиБ, как в RFC 9106 и x/crypto.
type argon2Params struct {
	memory  uint32
	time    uint32
	threads uint8
	saltLen int
	keyLen  int
}

// Параметры по решению Р3 этапа 2 (ADR-0006): выше минимума OWASP (19 МиБ, t = 2).
var argon2Default = argon2Params{memory: 64 * 1024, time: 3, threads: 2, saltLen: 16, keyLen: 32}

// Границы параметров разбираемого хеша. Нижние — минимум OWASP (m = 19 МиБ при
// t ≥ 2 или m = 46 МиБ при t = 1). Верхняя граница памяти равна параметру по
// умолчанию: запись из БД или импорта не поднимет пиковую память выше
// 64 МиБ × число слотов; при повышении параметров граница растёт вместе с ними.
const (
	argon2MinMemory   = 19 * 1024
	argon2MinMemoryT1 = 46 * 1024
	argon2MaxMemory   = 64 * 1024
	argon2MaxTime     = 16
	argon2MaxThreads  = 16
	argon2MinSaltLen  = 16
	argon2MaxSaltLen  = 64
	argon2MinKeyLen   = 16
	argon2MaxKeyLen   = 64
	argon2MaxEncoded  = 256
	argon2PHCVersion  = "v=19"
	argon2PHCIdent    = "argon2id"
	argon2DisplayName = "Argon2id"
)

// argon2MaxSlots — потолок слотов на машинах с большим числом CPU: пиковая
// память на хеши не больше 1 ГиБ.
const argon2MaxSlots = 16

// argon2Slots ограничивает число одновременных вычислений Argon2id в процессе
// числом доступных CPU (Р3), но не больше argon2MaxSlots: иначе поток попыток
// входа исчерпает память (до 64 МиБ на вычисление) и процессор. Общий на
// процесс, а не на экземпляр.
var argon2Slots = sync.OnceValue(func() chan struct{} {
	return make(chan struct{}, min(argon2MaxSlots, max(1, runtime.GOMAXPROCS(0))))
})

type argon2idHasher struct {
	params argon2Params
	random Random
}

func newArgon2id(r Random) PasswordHasher {
	return argon2idHasher{params: argon2Default, random: r}
}

func (argon2idHasher) Name() string { return argon2DisplayName }

func (h argon2idHasher) Hash(ctx context.Context, password []byte) (string, error) {
	if err := checkPasswordLen(password); err != nil {
		return "", err
	}
	salt, err := RandomBytes(h.random, h.params.saltLen)
	if err != nil {
		return "", err
	}
	key, err := argon2Compute(ctx, password, salt, h.params)
	if err != nil {
		return "", err
	}
	return encodeArgon2id(h.params, salt, key), nil
}

func (h argon2idHasher) Verify(ctx context.Context, password []byte, encoded string) (bool, bool, error) {
	if err := checkPasswordLen(password); err != nil {
		return false, false, err
	}
	p, salt, want, err := parseArgon2id(encoded)
	if err != nil {
		return false, false, err
	}
	got, err := argon2Compute(ctx, password, salt, p)
	if err != nil {
		return false, false, err
	}
	if !Equal(got, want) {
		return false, false, nil
	}
	return true, p != h.params, nil
}

func checkPasswordLen(password []byte) error {
	if len(password) < MinPasswordLen || len(password) > MaxPasswordLen {
		return fmt.Errorf("длина пароля должна быть от %d до %d байт", MinPasswordLen, MaxPasswordLen)
	}
	return nil
}

// argon2Compute занимает слот вычисления и считает Argon2id. Само вычисление
// не прерывается: ctx ограничивает только ожидание слота.
func argon2Compute(ctx context.Context, password, salt []byte, p argon2Params) ([]byte, error) {
	slots := argon2Slots()
	select {
	case slots <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("хеш пароля: нет свободного слота вычисления: %w", ctx.Err())
	}
	defer func() { <-slots }()
	return argon2.IDKey(password, salt, p.time, p.memory, p.threads, uint32(p.keyLen)), nil //nolint:gosec // G115: keyLen ограничен argon2MaxKeyLen
}

var phcB64 = base64.RawStdEncoding.Strict()

// encodeArgon2id — строка PHC: $argon2id$v=19$m=65536,t=3,p=2$<соль>$<хеш>,
// base64 без дополнения (как у эталонной реализации Argon2).
func encodeArgon2id(p argon2Params, salt, key []byte) string {
	return fmt.Sprintf("$%s$%s$m=%d,t=%d,p=%d$%s$%s", argon2PHCIdent, argon2PHCVersion,
		p.memory, p.time, p.threads, phcB64.EncodeToString(salt), phcB64.EncodeToString(key))
}

// parseArgon2id строго разбирает строку PHC: только argon2id версии 19,
// параметры в порядке m, t, p, десятичные числа без знака и ведущих нулей,
// base64 без дополнения и без лишних битов. Вход недоверенный (БД, импорт).
func parseArgon2id(s string) (p argon2Params, salt, key []byte, err error) {
	if len(s) > argon2MaxEncoded {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != argon2PHCIdent || parts[2] != argon2PHCVersion {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	kv := strings.Split(parts[3], ",")
	if len(kv) != 3 {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	m, ok1 := phcUint(kv[0], "m=", argon2MinMemory, argon2MaxMemory)
	t, ok2 := phcUint(kv[1], "t=", 1, argon2MaxTime)
	th, ok3 := phcUint(kv[2], "p=", 1, argon2MaxThreads)
	if !ok1 || !ok2 || !ok3 || (t == 1 && m < argon2MinMemoryT1) {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	salt, err1 := phcB64.DecodeString(parts[4])
	key, err2 := phcB64.DecodeString(parts[5])
	// Декодер base64 пропускает \r и \n даже в режиме Strict: обратное
	// кодирование отсекает их и делает разбор однозначным.
	if err1 != nil || err2 != nil ||
		phcB64.EncodeToString(salt) != parts[4] || phcB64.EncodeToString(key) != parts[5] ||
		len(salt) < argon2MinSaltLen || len(salt) > argon2MaxSaltLen ||
		len(key) < argon2MinKeyLen || len(key) > argon2MaxKeyLen {
		return p, nil, nil, ErrInvalidPasswordHash
	}
	p = argon2Params{memory: uint32(m), time: uint32(t), threads: uint8(th), saltLen: len(salt), keyLen: len(key)} //nolint:gosec // G115: значения ограничены границами выше
	return p, salt, key, nil
}

// phcUint разбирает «префикс + десятичное число» в границах [lo, hi].
func phcUint(s, prefix string, lo, hi uint64) (uint64, bool) {
	digits, ok := strings.CutPrefix(s, prefix)
	if !ok || digits == "" || len(digits) > 10 || (len(digits) > 1 && digits[0] == '0') {
		return 0, false
	}
	for i := range len(digits) {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || v < lo || v > hi {
		return 0, false
	}
	return v, true
}
