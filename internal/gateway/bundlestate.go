package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Каталог состояния шлюза в режиме с сервером (задача 2.13): ключ
// получателя для секретов пакета и последний применённый пакет. Каталог —
// 0700, файлы — 0600; все операции — через os.Root: символическая ссылка
// не уводит запись за пределы каталога.
const (
	// BundleFile — последний применённый пакет как получен (подписанный
	// конверт): при запуске шлюз проверяет его заново.
	BundleFile = "bundle.json"
	// BundleKeyFile — закрытый ключ получателя (HPKE X25519): им шлюз
	// расшифровывает учётные данные провайдеров. Создаётся при первом запуске.
	BundleKeyFile = "bundle-enc.key"
	// maxKeyFile — предел файла ключа: PEM 32 байт с заголовком.
	maxKeyFile = 4 << 10
	// TrustFile — принятые заявления о доверии (ADR-0018, п. 4.4): при
	// запуске шлюз заново проверяет их по цепочке от -bundle-pub.
	TrustFile = "trust.json"
	// ClientPairFile — перевыпущенный сертификат шлюза и его ключ (ADR-0018,
	// п. 6.3): при запуске предпочитается -client-cert, если новее.
	ClientPairFile = "client.pem"
	// trustFormat — формат trust.json.
	trustFormat = "aisec-gateway-trust/1"
	// MaxTrustStored — сколько заявлений хранит trust.json. Хранятся все от
	// №1: цепочка проверяется от -bundle-pub, и без первых заявлений шлюз
	// после перезапуска откатился бы к якорю (3Н1 ревью 3.r1). Тысяча
	// ротаций ключа подписи и УЦ — века эксплуатации; сверх — отказ записи,
	// прежний файл остаётся.
	MaxTrustStored = 1024
	// maxTrustFile — предел trust.json: MaxTrustStored заявлений по 16 КиБ
	// в base64 с запасом на разметку.
	maxTrustFile = MaxTrustStored*((bundle.MaxTrustStatement+2)/3*4+3) + 1<<10
	// maxPairFile — предел client.pem.
	maxPairFile = 16 << 10
)

// BundleState — каталог состояния шлюза.
type BundleState struct {
	root *os.Root
	dir  string
	rnd  aisecCrypto.Random
}

// OpenBundleState открывает каталог состояния. Каталог должен существовать
// и быть закрыт для группы и остальных: в нём ключ шлюза.
func OpenBundleState(dir string, rnd aisecCrypto.Random) (*BundleState, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог состояния: %w", err)
	}
	info, err := root.Stat(".")
	if err != nil {
		_ = root.Close() //nolint:gosec // G104: ошибка Stat важнее
		return nil, fmt.Errorf("каталог состояния: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		_ = root.Close() //nolint:gosec // G104: каталог отклонён, закрытие ничего не теряет
		return nil, fmt.Errorf("%s: каталог состояния доступен группе или остальным (права %04o); нужно 0700", dir, info.Mode().Perm())
	}
	return &BundleState{root: root, dir: dir, rnd: rnd}, nil
}

// Close закрывает каталог.
func (s *BundleState) Close() error { return s.root.Close() }

// Recipient читает ключ получателя или создаёт его при первом запуске
// (O_EXCL, 0600). Ключ профиля, отличного от p, — отказ.
func (s *BundleState) Recipient(p aisecCrypto.Provider) (aisecCrypto.Recipient, error) {
	data, err := s.read(BundleKeyFile, maxKeyFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s.newRecipient(p)
	case err != nil:
		return nil, err
	}
	defer clear(data)
	profile, key, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindBundleEncryption)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", BundleKeyFile, err)
	}
	defer clear(key)
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, а шлюз — %s", BundleKeyFile, profile, p.Name())
	}
	return p.NewRecipient(key)
}

func (s *BundleState) newRecipient(p aisecCrypto.Provider) (aisecCrypto.Recipient, error) {
	r, err := p.GenerateRecipient()
	if err != nil {
		return nil, err
	}
	key, err := r.PrivateKey()
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pemData, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindBundleEncryption, p.Name(), key)
	if err != nil {
		return nil, err
	}
	defer clear(pemData)
	if err := writeSynced(s.root, BundleKeyFile, pemData, os.O_EXCL); err != nil {
		return nil, fmt.Errorf("%s: %w", BundleKeyFile, err)
	}
	if err := s.syncDir(); err != nil {
		return nil, err
	}
	return r, nil
}

// Load читает сохранённый пакет; нет файла — nil без ошибки.
func (s *BundleState) Load() ([]byte, error) {
	data, err := s.read(BundleFile, bundle.MaxSize)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

// Save записывает пакет атомарно: временный файл 0600 с O_EXCL, сброс на
// диск, переименование поверх прежнего и сброс каталога. Сбой на любом шаге
// оставляет прежний файл целым.
func (s *BundleState) Save(data []byte) error { return s.saveAtomic(BundleFile, data) }

func (s *BundleState) saveAtomic(name string, data []byte) error {
	b, err := aisecCrypto.RandomBytes(s.rnd, 8)
	if err != nil {
		return err
	}
	tmp := "." + name + "." + hex.EncodeToString(b) + ".tmp"
	if err := writeSynced(s.root, tmp, data, os.O_EXCL); err != nil {
		_ = s.root.Remove(tmp) //nolint:gosec // G104: уборка неудавшейся записи; важна исходная ошибка
		return fmt.Errorf("%s: %w", name, err)
	}
	if err := s.root.Rename(tmp, name); err != nil {
		_ = s.root.Remove(tmp) //nolint:gosec // G104: уборка неудавшейся записи; важна исходная ошибка
		return fmt.Errorf("%s: %w", name, err)
	}
	return s.syncDir()
}

// trustDoc — содержимое trust.json: заявления по порядку, каждое в base64.
type trustDoc struct {
	Format     string   `json:"format"`
	Statements []string `json:"statements"`
}

// SaveTrust сохраняет все принятые заявления о доверии (от №1) атомарно.
// Больше MaxTrustStored — ошибка без записи: прежний файл остаётся.
func (s *BundleState) SaveTrust(raws [][]byte) error {
	if len(raws) > MaxTrustStored {
		return fmt.Errorf("%s: заявлений о доверии больше %d — файл не обновлён", TrustFile, MaxTrustStored)
	}
	doc := trustDoc{Format: trustFormat, Statements: []string{}}
	for _, raw := range raws {
		doc.Statements = append(doc.Statements, base64.StdEncoding.EncodeToString(raw))
	}
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	if len(data) > maxTrustFile {
		return fmt.Errorf("%s: больше %d байт", TrustFile, maxTrustFile)
	}
	return s.saveAtomic(TrustFile, data)
}

// LoadTrust читает сохранённые заявления; нет файла — nil без ошибки.
// Заявления не проверяются здесь: их проверяет цепочка от -bundle-pub.
func (s *BundleState) LoadTrust() ([][]byte, error) {
	data, err := s.read(TrustFile, maxTrustFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseTrust(data)
}

// parseTrust разбирает trust.json. Вход недоверенный (каталог состояния
// мог быть изменён), разбор покрыт FuzzParseTrust (3Н4 ревью 3.r1).
func parseTrust(data []byte) ([][]byte, error) {
	if len(data) > maxTrustFile {
		return nil, fmt.Errorf("%s: файл больше %d байт", TrustFile, maxTrustFile)
	}
	var doc trustDoc
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil || doc.Format != trustFormat || len(doc.Statements) > MaxTrustStored || dec.More() {
		return nil, fmt.Errorf("%s: неверный формат", TrustFile)
	}
	out := make([][]byte, 0, len(doc.Statements))
	for _, item := range doc.Statements {
		raw, err := base64.StdEncoding.Strict().DecodeString(item)
		if err != nil {
			return nil, fmt.Errorf("%s: неверный формат", TrustFile)
		}
		out = append(out, raw)
	}
	return out, nil
}

// SaveClientPair сохраняет перевыпущенный сертификат и ключ шлюза в
// client.pem (0600) атомарно.
func (s *BundleState) SaveClientPair(certPEM, keyPEM []byte) error {
	data := append(append(bytes.Clone(certPEM), '\n'), keyPEM...)
	defer clear(data)
	return s.saveAtomic(ClientPairFile, data)
}

// LoadClientPair читает client.pem: блок CERTIFICATE и блок PRIVATE KEY;
// нет файла — nil без ошибки.
func (s *BundleState) LoadClientPair() (certPEM, keyPEM []byte, err error) {
	data, err := s.read(ClientPairFile, maxPairFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	defer clear(data)
	return parseClientPair(data)
}

// parseClientPair разбирает client.pem: ровно один CERTIFICATE и один
// PRIVATE KEY. Вход недоверенный, разбор покрыт FuzzParseClientPair (3Н4
// ревью 3.r1); сертификат и ключ дальше проверяет VerifyClientCert.
func parseClientPair(data []byte) (certPEM, keyPEM []byte, err error) {
	if len(data) > maxPairFile {
		return nil, nil, fmt.Errorf("%s: файл больше %d байт", ClientPairFile, maxPairFile)
	}
	rest := data
	for len(bytes.TrimSpace(rest)) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		switch {
		case block == nil:
			return nil, nil, fmt.Errorf("%s: неверный формат", ClientPairFile)
		case block.Type == "CERTIFICATE" && certPEM == nil:
			certPEM = pem.EncodeToMemory(block)
		case block.Type == "PRIVATE KEY" && keyPEM == nil:
			keyPEM = pem.EncodeToMemory(block)
		default:
			return nil, nil, fmt.Errorf("%s: лишний блок %s", ClientPairFile, block.Type)
		}
	}
	if certPEM == nil || keyPEM == nil {
		return nil, nil, fmt.Errorf("%s: нужны сертификат и ключ", ClientPairFile)
	}
	return certPEM, keyPEM, nil
}

// read читает обычный файл каталога не больше limit байт; файл, доступный
// группе или остальным, отклоняется.
func (s *BundleState) read(name string, limit int) (data []byte, err error) {
	f, err := s.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", name)
	}
	if !aisecCrypto.KeyFilePermsOK(info) {
		return nil, fmt.Errorf("%s: файл доступен группе или остальным (права %o); нужно 0600", name, info.Mode().Perm())
	}
	if info.Size() > int64(limit) {
		return nil, fmt.Errorf("%s: файл больше %d байт", name, limit)
	}
	data, err = io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > limit {
		return nil, fmt.Errorf("%s: файл больше %d байт", name, limit)
	}
	return data, nil
}

func (s *BundleState) syncDir() error {
	d, err := s.root.Open(".")
	if err != nil {
		return err
	}
	err = d.Sync()
	_ = d.Close() //nolint:gosec // G104: важна ошибка Sync; каталог открыт только для чтения
	if err != nil {
		return fmt.Errorf("каталог состояния: %w", err)
	}
	return nil
}

// writeSynced создаёт файл 0600 и сбрасывает его на диск.
func writeSynced(root *os.Root, name string, data []byte, flag int) (err error) {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|flag, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
