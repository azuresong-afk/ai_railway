package crypto

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

// ClientTLS поднимает TLS поверх уже установленного соединения conn с
// настройками cfg из TLSProvider и завершает рукопожатие в пределах ctx.
// Нужен пакетам без crypto/tls (depguard): syslog по TLS (задача 3.13).
// Соединение устанавливает вызывающий — с адресом, заданным
// администратором. При ошибке conn закрывается.
func ClientTLS(ctx context.Context, conn net.Conn, cfg *tls.Config) (net.Conn, error) {
	if conn == nil || cfg == nil {
		return nil, errors.New("TLS: нет соединения или настроек")
	}
	if cfg.ServerName == "" {
		_ = conn.Close() //nolint:gosec // G104: ошибка настройки важнее ошибки закрытия
		return nil, errors.New("TLS: не задано имя сервера для проверки сертификата")
	}
	c := tls.Client(conn, cfg)
	if err := c.HandshakeContext(ctx); err != nil {
		_ = c.Close() //nolint:gosec // G104: возвращается ошибка рукопожатия
		return nil, err
	}
	return c, nil
}

// ServerTLS — серверная сторона TLS поверх принятого соединения (локальные
// приёмники в тестах: SMTP с STARTTLS, syslog по TLS). Рукопожатие
// выполняется при первом чтении или записи.
func ServerTLS(conn net.Conn, cfg *tls.Config) net.Conn {
	return tls.Server(conn, cfg)
}

// TLSListener — приём соединений TLS поверх l с настройками cfg.
func TLSListener(l net.Listener, cfg *tls.Config) net.Listener {
	return tls.NewListener(l, cfg)
}
