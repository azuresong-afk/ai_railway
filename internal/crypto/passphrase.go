package crypto

import (
	"context"
	"fmt"
	"strings"
)

// PassphraseSaltSize — длина соли для выведения ключа из парольной фразы, байт.
const PassphraseSaltSize = 16

// PassphraseKDF — выведение ключа шифрования из парольной фразы
// администратора: резервная копия конфигурации (РВ.1, ADR-0017). Копия
// шифруется не мастер-ключом установки: восстановление должно работать и
// после его потери.
type PassphraseKDF interface {
	Name() string
	// Params — параметры для новой копии строкой вида «m=65536,t=3,p=2»;
	// хранятся в заголовке копии вместе с солью.
	Params() string
	// Derive выводит ключ длины AEADKeySize из фразы, соли (16–64 байт) и
	// параметров. Параметры и соль читаются из файла, поэтому разбираются
	// строго, в тех же границах, что хеши паролей: подложенный файл не
	// поднимет память выше параметров по умолчанию (64 МиБ), а время — выше
	// t = 16 и p = 16.
	// Ждёт свободного слота вычисления не дольше, чем живёт ctx.
	Derive(ctx context.Context, passphrase, salt []byte, params string) ([]byte, error)
}

// argon2idKDF — Argon2id с параметрами решения Р3 (ADR-0006), тот же
// ограничитель одновременных вычислений, что у хешей паролей.
type argon2idKDF struct{ params argon2Params }

func newArgon2idKDF() PassphraseKDF {
	return argon2idKDF{params: argon2Default}
}

func (argon2idKDF) Name() string { return argon2DisplayName }

func (k argon2idKDF) Params() string {
	return fmt.Sprintf("m=%d,t=%d,p=%d", k.params.memory, k.params.time, k.params.threads)
}

func (k argon2idKDF) Derive(ctx context.Context, passphrase, salt []byte, params string) ([]byte, error) {
	if err := checkPasswordLen(passphrase); err != nil {
		return nil, err
	}
	if len(salt) < argon2MinSaltLen || len(salt) > argon2MaxSaltLen {
		return nil, fmt.Errorf("соль — от %d до %d байт", argon2MinSaltLen, argon2MaxSaltLen)
	}
	p, err := parseKDFParams(params)
	if err != nil {
		return nil, err
	}
	p.saltLen, p.keyLen = len(salt), AEADKeySize
	return argon2Compute(ctx, passphrase, salt, p)
}

// parseKDFParams строго разбирает «m=…,t=…,p=…» — часть строки PHC.
func parseKDFParams(s string) (argon2Params, error) {
	errBad := fmt.Errorf("параметры Argon2id: неверный формат или значения вне границ (%q)", truncate(s, 64))
	kv := strings.Split(s, ",")
	if len(s) > 64 || len(kv) != 3 {
		return argon2Params{}, errBad
	}
	m, ok1 := phcUint(kv[0], "m=", argon2MinMemory, argon2MaxMemory)
	t, ok2 := phcUint(kv[1], "t=", 1, argon2MaxTime)
	th, ok3 := phcUint(kv[2], "p=", 1, argon2MaxThreads)
	if !ok1 || !ok2 || !ok3 || (t == 1 && m < argon2MinMemoryT1) {
		return argon2Params{}, errBad
	}
	return argon2Params{memory: uint32(m), time: uint32(t), threads: uint8(th)}, nil //nolint:gosec // G115: значения ограничены границами выше
}
