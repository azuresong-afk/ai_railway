package apps

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Сертификат заказчика в PostgreSQL (миграция 0039_gateway_tls).

const gatewayTLSCols = `org_id::text, host, chain_pem, chain_len, subject, issuer, serial, fingerprint, not_before, not_after,
	dns_names, ip_addresses, cert_key_alg, key_sealed, key_key_id::text, key_alg, created_at, created_by, updated_at, updated_by`

func scanGatewayTLS(row pgx.Row) (GatewayTLS, error) {
	var t GatewayTLS
	var chain string
	err := row.Scan(&t.OrgID, &t.Host, &chain, &t.Cert.ChainLen, &t.Cert.Subject, &t.Cert.Issuer, &t.Cert.Serial,
		&t.Cert.Fingerprint, &t.Cert.NotBefore, &t.Cert.NotAfter, &t.Cert.DNSNames, &t.Cert.IPAddresses, &t.Cert.KeyAlg,
		&t.Key.Data, &t.Key.KeyID, &t.Key.Alg, &t.CreatedAt, &t.CreatedBy, &t.UpdatedAt, &t.UpdatedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return GatewayTLS{}, ErrNoGatewayTLS
	}
	if err != nil {
		return GatewayTLS{}, fmt.Errorf("приложения: сертификат заказчика: %w", err)
	}
	t.Cert.ChainPEM = []byte(chain)
	t.Cert.NotBefore, t.Cert.NotAfter = t.Cert.NotBefore.UTC(), t.Cert.NotAfter.UTC()
	t.CreatedAt, t.UpdatedAt = t.CreatedAt.UTC(), t.UpdatedAt.UTC()
	t.Key.SetAt = t.UpdatedAt
	return t, nil
}

// SetGatewayTLS — см. Store.
func (s *PGStore) SetGatewayTLS(ctx context.Context, orgID string, fn func(prev *GatewayTLS) (GatewayTLS, audit.Entry, error)) (GatewayTLS, error) {
	var out GatewayTLS
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		// Advisory-блокировка упорядочивает первую загрузку: строки
		// сертификата ещё нет, и FOR UPDATE ниже ничего бы не заблокировал.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('gateway_tls:' || $1::text))`, orgID); err != nil {
			return fmt.Errorf("приложения: сертификат заказчика: %w", err)
		}
		var prev *GatewayTLS
		switch t, err := scanGatewayTLS(tx.QueryRow(ctx, `SELECT `+gatewayTLSCols+` FROM gateway_tls WHERE org_id = $1 FOR UPDATE`, orgID)); {
		case err == nil:
			prev = &t
		case !errors.Is(err, ErrNoGatewayTLS):
			return err
		}
		next, rec, err := fn(prev)
		if err != nil {
			return err
		}
		c := next.Cert
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_tls (org_id, host, chain_pem, chain_len, subject, issuer, serial, fingerprint,
				not_before, not_after, dns_names, ip_addresses, cert_key_alg, key_sealed, key_key_id, key_alg,
				created_at, created_by, updated_at, updated_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
			ON CONFLICT (org_id) DO UPDATE SET host = EXCLUDED.host, chain_pem = EXCLUDED.chain_pem, chain_len = EXCLUDED.chain_len,
				subject = EXCLUDED.subject, issuer = EXCLUDED.issuer, serial = EXCLUDED.serial, fingerprint = EXCLUDED.fingerprint,
				not_before = EXCLUDED.not_before, not_after = EXCLUDED.not_after, dns_names = EXCLUDED.dns_names,
				ip_addresses = EXCLUDED.ip_addresses, cert_key_alg = EXCLUDED.cert_key_alg, key_sealed = EXCLUDED.key_sealed,
				key_key_id = EXCLUDED.key_key_id, key_alg = EXCLUDED.key_alg, updated_at = EXCLUDED.updated_at,
				updated_by = EXCLUDED.updated_by`,
			orgID, next.Host, string(c.ChainPEM), c.ChainLen, c.Subject, c.Issuer, c.Serial, c.Fingerprint, c.NotBefore, c.NotAfter,
			c.DNSNames, c.IPAddresses, c.KeyAlg, next.Key.Data, next.Key.KeyID, next.Key.Alg,
			next.CreatedAt, next.CreatedBy, next.UpdatedAt, next.UpdatedBy); err != nil {
			return fmt.Errorf("приложения: сертификат заказчика: %w", err)
		}
		out = next
		return s.record(ctx, tx, rec)
	})
	return out, err
}

// GatewayTLS — см. Store.
func (s *PGStore) GatewayTLS(ctx context.Context, orgID string) (GatewayTLS, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return scanGatewayTLS(s.db.QueryRow(ctx, `SELECT `+gatewayTLSCols+` FROM gateway_tls WHERE org_id = $1`, orgID))
}

// DeleteGatewayTLS — см. Store.
func (s *PGStore) DeleteGatewayTLS(ctx context.Context, orgID string, fn func(GatewayTLS) (audit.Entry, error)) (GatewayTLS, error) {
	var out GatewayTLS
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		t, err := scanGatewayTLS(tx.QueryRow(ctx, `SELECT `+gatewayTLSCols+` FROM gateway_tls WHERE org_id = $1 FOR UPDATE`, orgID))
		if err != nil {
			return err
		}
		rec, err := fn(t)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM gateway_tls WHERE org_id = $1`, orgID); err != nil {
			return fmt.Errorf("приложения: сертификат заказчика: %w", err)
		}
		out = t
		return s.record(ctx, tx, rec)
	})
	return out, err
}
