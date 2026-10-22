package crypto

import (
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Файлы ключей aisec-cli init (ADR-0007): PEM с одним блоком, типом по
// назначению ключа и заголовком Profile — криптопрофилем, для которого ключ
// создан. Смена профиля — перевыпуск ключей (ТЗ, 10.2), поэтому ключ чужого
// профиля распознаётся при чтении, а не при первой ошибке расшифрования.
const (
	// KeyKindMaster — мастер-ключ: шифрует ключ данных (ЗИ.1, Р4).
	KeyKindMaster = "AISEC MASTER KEY"
	// KeyKindSigning — закрытый ключ подписи пакетов конфигурации (Р7).
	KeyKindSigning = "AISEC SIGNING KEY"
	// KeyKindSigningPublic — открытый ключ проверки пакетов для шлюзов.
	KeyKindSigningPublic = "AISEC SIGNING PUBLIC KEY"
	// KeyKindAuditSigning — закрытый ключ подписи контрольных точек
	// архивации журнала аудита (РСБ.4, ADR-0008). Отдельный вид: ключ пакетов
	// нельзя подложить вместо него и наоборот.
	KeyKindAuditSigning = "AISEC AUDIT SIGNING KEY"
	// KeyKindAuditSigningPublic — открытый ключ проверки контрольных точек.
	KeyKindAuditSigningPublic = "AISEC AUDIT SIGNING PUBLIC KEY"
	// KeyKindManifestSigning — закрытый ключ производителя для подписи
	// манифеста целостности (ОЦЛ.1, Р10). Хранится вне репозитория и
	// установки; в репозитории — только тестовая пара «не для поставки».
	KeyKindManifestSigning = "AISEC MANIFEST SIGNING KEY"
	// KeyKindManifestSigningPublic — открытый ключ проверки манифеста,
	// встраивается в бинарники (ТЗ, 10.4).
	KeyKindManifestSigningPublic = "AISEC MANIFEST SIGNING PUBLIC KEY"
	// KeyKindBundleEncryption — закрытый ключ получателя шлюза: им шлюз
	// расшифровывает секреты провайдеров в пакете конфигурации (Р7).
	KeyKindBundleEncryption = "AISEC BUNDLE ENCRYPTION KEY"
)

// maxKeyFile ограничивает размер файла ключа: ключ — десятки байт.
const maxKeyFile = 4 << 10

const profileHeader = "Profile"

// keyFileSize — длина ключа каждого вида в профиле standard.
var keyFileSize = map[string]int{
	KeyKindMaster:                AEADKeySize,
	KeyKindSigning:               SigningSeedSize,
	KeyKindSigningPublic:         PublicKeySize,
	KeyKindAuditSigning:          SigningSeedSize,
	KeyKindAuditSigningPublic:    PublicKeySize,
	KeyKindManifestSigning:       SigningSeedSize,
	KeyKindManifestSigningPublic: PublicKeySize,
	KeyKindBundleEncryption:      RecipientKeySize,
}

// EncodeKeyPEM кодирует ключ вида kind для профиля profile.
func EncodeKeyPEM(kind, profile string, key []byte) ([]byte, error) {
	if err := checkKeyFile(kind, profile, key); err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: kind, Headers: map[string]string{profileHeader: profile}, Bytes: key}), nil
}

// DecodeKeyPEM разбирает файл ключа вида kind: ровно один блок PEM нужного
// типа, единственный заголовок Profile с допустимым профилем, ключ нужной
// длины, после блока — только пробельные символы. Вход недоверенный (файл
// мог быть подменён), разбор покрыт fuzz-тестом FuzzDecodeKeyPEM.
func DecodeKeyPEM(data []byte, kind string) (profile string, key []byte, err error) {
	if _, ok := keyFileSize[kind]; !ok {
		return "", nil, fmt.Errorf("неизвестный вид ключа %q", kind)
	}
	if len(data) > maxKeyFile {
		return "", nil, fmt.Errorf("файл ключа больше %d байт", maxKeyFile)
	}
	if !startsWithPEM(data) {
		return "", nil, errors.New("файл ключа: данные перед блоком PEM или нет блока")
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return "", nil, errors.New("файл ключа: нет блока PEM")
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return "", nil, errors.New("файл ключа: данные после блока PEM")
	}
	if block.Type != kind {
		return "", nil, fmt.Errorf("файл ключа: ожидается %q, получен %q", kind, truncate(block.Type, 64))
	}
	if len(block.Headers) != 1 {
		return "", nil, fmt.Errorf("файл ключа: нужен ровно один заголовок %s", profileHeader)
	}
	profile = block.Headers[profileHeader]
	if err := checkKeyFile(kind, profile, block.Bytes); err != nil {
		return "", nil, err
	}
	return profile, block.Bytes, nil
}

func checkKeyFile(kind, profile string, key []byte) error {
	size, ok := keyFileSize[kind]
	if !ok {
		return fmt.Errorf("неизвестный вид ключа %q", kind)
	}
	if profile != ProfileStandard && profile != ProfileGOST {
		return fmt.Errorf("файл ключа: недопустимый профиль %q", truncate(profile, 32))
	}
	// Длины ключей профиля gost определит выбор СКЗИ (этап 6); до этого
	// формат один для обоих профилей.
	if len(key) != size {
		return fmt.Errorf("файл ключа %s: длина %d байт, ожидается %d", kind, len(key), size)
	}
	return nil
}

// Пределы частей присоединённых данных StorageAAD.
const maxAADPart = 128

// aadSep разделяет части AAD; в самих частях он запрещён, поэтому разные
// тройки (таблица, столбец, строка) не дают одинаковых AAD.
const aadSep = "|"

// StorageAAD — присоединённые данные для шифротекста, хранимого в БД
// (решение Р4): таблица, столбец и ID строки. Шифротекст, переставленный в
// другую строку или столбец, не расшифруется. Формат единый для всех
// пакетов, поэтому собирается только здесь.
func StorageAAD(table, column, rowID string) ([]byte, error) {
	for _, part := range []string{table, column, rowID} {
		if part == "" || len(part) > maxAADPart || strings.Contains(part, aadSep) {
			return nil, fmt.Errorf("AAD: часть пустая, длиннее %d байт или содержит %q", maxAADPart, aadSep)
		}
	}
	return []byte("aisec-aad-v1" + aadSep + table + aadSep + column + aadSep + rowID), nil
}

// startsWithPEM: pem.Decode молча пропускает всё до первого блока, а файл
// ключа должен начинаться с блока (допустимы только пробельные символы).
func startsWithPEM(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimLeft(data, " \t\r\n"), []byte("-----BEGIN "))
}

// truncate укорачивает недоверенную строку для сообщения об ошибке.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// LoadVerifierFile читает открытый ключ вида kind (например,
// KeyKindAuditSigningPublic) из файла и проверяет, что он создан для
// профиля p.
func LoadVerifierFile(p Provider, path, kind string) (Verifier, error) {
	data, err := ReadPEMFile(path)
	if err != nil {
		return nil, err
	}
	return ParseVerifierPEM(p, path, data, kind)
}

// ParseVerifierPEM — ключ проверки из уже прочитанного файла name: так
// компонент работает с теми же байтами, хеш которых берёт под контроль
// целостности (Н37 ревью 2.r4).
func ParseVerifierPEM(p Provider, name string, data []byte, kind string) (Verifier, error) {
	profile, pub, err := DecodeKeyPEM(data, kind)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, а установка — %s", name, profile, p.Name())
	}
	return p.NewVerifier(pub)
}
