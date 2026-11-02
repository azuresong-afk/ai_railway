package apps

import (
	"context"
	"errors"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Сертификат заказчика для адреса шлюза (S1, ТЗ 5.4; решение Р9 этапа 3,
// задача 3.27, миграция 0039_gateway_tls). Путь ключа повторяет учётные
// данные провайдеров (2.13): при хранении — ключ данных с AAD места
// хранения (ЗИ.1, ADR-0007), в шлюзы — раздел пакета конфигурации и ключ,
// зашифрованный для каждого шлюза (HPKE). В ответах API — только сведения о
// сертификате и признак «ключ задан».

// Место хранения ключа: AAD gateway_tls|key|<org_id> (keyring.Rewrap).
const (
	gatewayTLSTable  = "gateway_tls"
	gatewayTLSColumn = "key"
)

// ErrNoGatewayTLS — сертификат заказчика не задан.
var ErrNoGatewayTLS = errors.New("сертификат заказчика для адреса шлюза не задан")

// GatewayTLS — сертификат заказчика: проверенные сведения, цепочка и
// зашифрованный ключ.
type GatewayTLS struct {
	OrgID string
	// Host — имя адреса шлюза для приложений.
	Host string
	Cert aisecCrypto.ServerCert
	Key  Sealed
	// CreatedAt и CreatedBy — первая загрузка; UpdatedAt и UpdatedBy —
	// последняя замена.
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// GatewayTLSInput — загружаемые цепочка и ключ в PEM.
type GatewayTLSInput struct {
	Host     string
	ChainPEM []byte
	KeyPEM   []byte
}

// SetGatewayTLS проверяет и сохраняет сертификат заказчика (новый или
// замена): цепочку до корня, срок, имя адреса в SAN, пару ключу. Ключ
// шифруется ключом данных; запись gateway_tls.set — той же транзакцией.
func (s *Service) SetGatewayTLS(ctx context.Context, by By, in GatewayTLSInput) (GatewayTLS, error) {
	if s.box == nil {
		return GatewayTLS{}, ErrNoDataKey
	}
	host, cert, key, err := ParseGatewayTLS(in, s.clock())
	if err != nil {
		return GatewayTLS{}, err
	}
	keyID, sealed, err := s.box.SealKey(ctx, key, gatewayTLSTable, gatewayTLSColumn, s.orgID)
	clear(key)
	if err != nil {
		return GatewayTLS{}, err
	}
	return s.store.SetGatewayTLS(ctx, s.orgID, func(prev *GatewayTLS) (GatewayTLS, audit.Entry, error) {
		now := s.now()
		next := GatewayTLS{OrgID: s.orgID, Host: host, Cert: cert, Key: Sealed{Data: sealed, KeyID: keyID, Alg: s.box.Alg(), SetAt: now},
			CreatedAt: now, CreatedBy: by.ref(), UpdatedAt: now, UpdatedBy: by.ref()}
		d := gatewayTLSDetails(next)
		d["replaced"] = prev != nil
		if prev != nil {
			next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
			d["previous_fingerprint"], d["previous_host"] = prev.Cert.Fingerprint, prev.Host
		}
		return next, by.entry("gateway_tls.set", "gateway_tls", s.orgID, d), nil
	})
}

// ParseGatewayTLS проверяет сертификат заказчика правилами загрузки: имя
// адреса шлюза, цепочку до корня, срок на now, имя адреса в SAN, пару ключу
// (aisecCrypto.ParseServerCert). Возвращает имя в нижнем регистре,
// сведения и ключ в PKCS#8 PEM (вызывающий затирает его); ошибка —
// *InputError.
func ParseGatewayTLS(in GatewayTLSInput, now time.Time) (string, aisecCrypto.ServerCert, []byte, error) {
	host, err := aisecCrypto.NormalizeHost(in.Host)
	if err != nil {
		return "", aisecCrypto.ServerCert{}, nil, invalid(err)
	}
	cert, key, err := aisecCrypto.ParseServerCert(in.ChainPEM, in.KeyPEM, host, now)
	if err != nil {
		return "", aisecCrypto.ServerCert{}, nil, invalid(err)
	}
	return host, cert, key, nil
}

// CheckStoredGatewayTLS проверяет сохранённый сертификат заказчика
// правилами загрузки (ParseGatewayTLS): ключ — пара листу цепочки, имя
// адреса в SAN, цепочка до корня; имя, отпечаток листа и срок — те, что
// записаны рядом. Срок цепочки проверяется на момент внутри него (notAfter
// минус секунда, как у шлюза): сертификат, истёкший после снятия копии, —
// не повод для отказа, о нём сообщает «Состояние системы» (gateway_tls).
// Вызывает восстановление копии конфигурации до записи в БД (остаток 5.8,
// остатки волны A этапа 5).
func CheckStoredGatewayTLS(host string, chainPEM, keyPEM []byte, fingerprint string, notAfter time.Time) error {
	h, cert, key, err := ParseGatewayTLS(GatewayTLSInput{Host: host, ChainPEM: chainPEM, KeyPEM: keyPEM}, notAfter.Add(-time.Second))
	clear(key)
	if err != nil {
		return err
	}
	if h != host || cert.Fingerprint != fingerprint || !cert.NotAfter.Equal(notAfter) {
		return invalidf("сведения о сертификате (имя адреса, отпечаток, срок) не совпадают с цепочкой")
	}
	return nil
}

// GatewayTLS — сертификат заказчика организации (ErrNoGatewayTLS — нет).
func (s *Service) GatewayTLS(ctx context.Context) (GatewayTLS, error) {
	return s.store.GatewayTLS(ctx, s.orgID)
}

// DeleteGatewayTLS удаляет сертификат заказчика: шлюзы возвращаются к
// своему сертификату (-tls-cert) с новым пакетом конфигурации.
func (s *Service) DeleteGatewayTLS(ctx context.Context, by By) (GatewayTLS, error) {
	return s.store.DeleteGatewayTLS(ctx, s.orgID, func(t GatewayTLS) (audit.Entry, error) {
		return by.entry("gateway_tls.delete", "gateway_tls", s.orgID, gatewayTLSDetails(t)), nil
	})
}

// OpenGatewayTLSKey расшифровывает ключ сертификата заказчика: только для
// шифрования в пакет конфигурации шлюза (HPKE). Вызывающий затирает ключ.
func (s *Service) OpenGatewayTLSKey(ctx context.Context, t GatewayTLS) ([]byte, error) {
	if s.box == nil {
		return nil, ErrNoDataKey
	}
	return s.box.OpenContext(ctx, t.Key.KeyID, t.Key.Data, gatewayTLSTable, gatewayTLSColumn, t.OrgID)
}

// gatewayTLSDetails — подробности записи аудита: сведения о сертификате
// без цепочки и ключа.
func gatewayTLSDetails(t GatewayTLS) map[string]any {
	return map[string]any{"host": t.Host, "fingerprint": t.Cert.Fingerprint, "subject": t.Cert.Subject,
		"issuer": t.Cert.Issuer, "serial": t.Cert.Serial, "not_after": t.Cert.NotAfter.UTC().Format(time.RFC3339),
		"key_alg": t.Cert.KeyAlg, "chain_len": t.Cert.ChainLen}
}

func cloneGatewayTLS(t GatewayTLS) GatewayTLS {
	t.Cert.DNSNames = append([]string{}, t.Cert.DNSNames...)
	t.Cert.IPAddresses = append([]string{}, t.Cert.IPAddresses...)
	t.Cert.ChainPEM = append([]byte(nil), t.Cert.ChainPEM...)
	t.Key.Data = append([]byte(nil), t.Key.Data...)
	return t
}

// SetGatewayTLS — см. Store.
func (m *Memory) SetGatewayTLS(_ context.Context, orgID string, fn func(prev *GatewayTLS) (GatewayTLS, audit.Entry, error)) (GatewayTLS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var prev *GatewayTLS
	if t, ok := m.gatewayTLS[orgID]; ok {
		c := cloneGatewayTLS(t)
		prev = &c
	}
	next, rec, err := fn(prev)
	if err != nil {
		return GatewayTLS{}, err
	}
	m.gatewayTLS[orgID] = cloneGatewayTLS(next)
	m.records = append(m.records, rec)
	return next, nil
}

// GatewayTLS — см. Store.
func (m *Memory) GatewayTLS(_ context.Context, orgID string) (GatewayTLS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.gatewayTLS[orgID]
	if !ok {
		return GatewayTLS{}, ErrNoGatewayTLS
	}
	return cloneGatewayTLS(t), nil
}

// DeleteGatewayTLS — см. Store.
func (m *Memory) DeleteGatewayTLS(_ context.Context, orgID string, fn func(GatewayTLS) (audit.Entry, error)) (GatewayTLS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.gatewayTLS[orgID]
	if !ok {
		return GatewayTLS{}, ErrNoGatewayTLS
	}
	rec, err := fn(cloneGatewayTLS(t))
	if err != nil {
		return GatewayTLS{}, err
	}
	delete(m.gatewayTLS, orgID)
	m.records = append(m.records, rec)
	return t, nil
}
