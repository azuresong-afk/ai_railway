package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// maxPEMFile ограничивает размер файлов сертификатов и ключей.
const maxPEMFile = 1 << 20

// TLSProvider выдаёт готовые настройки TLS. Остальные пакеты используют
// возвращённый *tls.Config, не импортируя crypto/tls.
type TLSProvider interface {
	// ServerConfig — настройки сервера с сертификатом и ключом в PEM.
	ServerConfig(certPEM, keyPEM []byte) (*tls.Config, error)
	// ClientConfig — настройки клиента, который доверяет только корневым
	// сертификатам rootsPEM (системное хранилище не используется).
	ClientConfig(rootsPEM []byte) (*tls.Config, error)
}

// standardTLS — TLS 1.2 и 1.3 средствами Go (ТЗ, 10.3).
type standardTLS struct{}

// tls12Suites — для TLS 1.2 только ECDHE и AEAD. Наборы TLS 1.3 в Go не
// настраиваются и все относятся к AEAD.
var tls12Suites = []uint16{
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
}

// curves — обмен ключами: гибридный постквантовый X25519MLKEM768 и классические.
var curves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384}

func baseConfig() *tls.Config {
	return &tls.Config{
		MinVersion:       tls.VersionTLS12,
		CipherSuites:     tls12Suites,
		CurvePreferences: curves,
	}
}

func (standardTLS) ServerConfig(certPEM, keyPEM []byte) (*tls.Config, error) {
	if len(certPEM) > maxPEMFile || len(keyPEM) > maxPEMFile {
		return nil, errors.New("TLS: сертификат или ключ слишком большой")
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		// Текст ошибки tls не содержит ключевого материала.
		return nil, fmt.Errorf("TLS: сертификат и ключ сервера: %w", err)
	}
	cfg := baseConfig()
	cfg.Certificates = []tls.Certificate{cert}
	return cfg, nil
}

func (standardTLS) ClientConfig(rootsPEM []byte) (*tls.Config, error) {
	if len(rootsPEM) > maxPEMFile {
		return nil, errors.New("TLS: файл корневых сертификатов слишком большой")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootsPEM) {
		return nil, errors.New("TLS: не найдено ни одного корневого сертификата")
	}
	cfg := baseConfig()
	cfg.RootCAs = pool
	return cfg, nil
}

// ReadPEMFile читает файл сертификата или ключа с ограничением размера.
func ReadPEMFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: не обычный файл", path)
	}
	if info.Size() > maxPEMFile {
		return nil, fmt.Errorf("%s: файл больше %d байт", path, maxPEMFile)
	}
	return os.ReadFile(path) //nolint:gosec // G304: путь к сертификату задаёт администратор в конфигурации
}

// KeyFilePermsOK сообщает, что файл ключа недоступен группе и остальным.
func KeyFilePermsOK(info fs.FileInfo) bool {
	return info.Mode().Perm()&0o077 == 0
}
