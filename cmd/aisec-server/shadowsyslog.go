package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// startShadowSyslog открывает порт приёма журналов прокси по syslog
// (теневой ИИ, задача 4.23) и запускает его. Выключен (нет адреса) — nil.
// TLS — только из internal/crypto: свой сертификат слушателя и, если задан
// корень клиентов, обязательный клиентский сертификат (mTLS). Возвращает
// канал, который закрывается после остановки и последней записи сводок.
func startShadowSyslog(ctx context.Context, c shadowSyslogConfig, tp aisecCrypto.TLSProvider, svc *shadowai.Service,
	auditLog *audit.Log, logger *slog.Logger) (<-chan struct{}, error) {
	if c.Listen == "" {
		return nil, nil
	}
	sc := shadowai.SyslogConfig{Addr: c.Listen, Format: c.Format, Insecure: c.Insecure, Allowed: c.AllowedNetworks,
		MaxConns: c.MaxConns, MaxConnsPerIP: c.MaxConnsPerIP, LinesPerSecond: c.LinesPerSecond}
	if !c.Insecure {
		certPEM, err := aisecCrypto.ReadPEMFile(c.TLSCertFile)
		if err != nil {
			return nil, fmt.Errorf("сертификат слушателя syslog: %w", err)
		}
		keyPEM, err := aisecCrypto.ReadKeyFile(c.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ключ слушателя syslog: %w", err)
		}
		tlsCfg, err := tp.ServerConfig(certPEM, keyPEM)
		if c.ClientCAFile != "" {
			caPEM, cerr := aisecCrypto.ReadPEMFile(c.ClientCAFile)
			if cerr != nil {
				return nil, fmt.Errorf("корень клиентов syslog: %w", cerr)
			}
			tlsCfg, err = tp.MutualServerConfig(certPEM, keyPEM, caPEM)
			sc.ClientCert = true
		}
		if err != nil {
			return nil, fmt.Errorf("TLS слушателя syslog: %w", err)
		}
		sc.TLS = func(conn net.Conn) net.Conn { return aisecCrypto.ServerTLS(conn, tlsCfg) }
	}
	l, err := svc.ListenSyslog(ctx, sc)
	if err != nil {
		return nil, err
	}
	nets := make([]string, 0, len(c.AllowedNetworks))
	for _, p := range c.AllowedNetworks {
		nets = append(nets, p.String())
	}
	if err := auditLog.Record(ctx, audit.Entry{Actor: audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"},
		Action: "shadow_ai.syslog_started", Object: audit.Object{Type: "shadow_ai_syslog", ID: l.Addr()}, Result: audit.ResultSuccess,
		Details: map[string]any{"address": l.Addr(), "format": c.Format, "tls": !c.Insecure, "client_cert_required": sc.ClientCert,
			"allowed_networks": nets, "max_connections": c.MaxConns, "max_connections_per_address": c.MaxConnsPerIP,
			"lines_per_second": c.LinesPerSecond}}); err != nil {
		logger.Error("запуск приёма по syslog не записан в журнал аудита", "class", "db", "error", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := l.Run(ctx); err != nil {
			logger.Error("теневой ИИ: приём по syslog остановлен с ошибкой", "error", err)
		}
	}()
	return done, nil
}
