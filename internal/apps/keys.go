package apps

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/config"
)

// KeyInput — выпуск ключа приложения.
type KeyInput struct {
	Name string
	// ExpiresInDays — срок в сутках по 24 ч; 0 — DefaultKeyDays.
	ExpiresInDays int
	// AllowedCIDRs — привязка к подсетям (ИАФ.8); пусто — с любых адресов.
	AllowedCIDRs []string
}

// RotateInput — ротация ключа.
type RotateInput struct {
	// Overlap — сколько ещё действует прежний ключ; nil — DefaultOverlap,
	// 0 — прежний ключ перестаёт действовать сразу.
	Overlap *time.Duration
	// ExpiresInDays — срок нового ключа; 0 — DefaultKeyDays.
	ExpiresInDays int
}

func keyDays(n int) (time.Duration, error) {
	if n == 0 {
		n = DefaultKeyDays
	}
	if n < 1 || n > MaxKeyDays {
		return 0, invalidf("expires_in_days — от 1 до %d суток", MaxKeyDays)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

func parseCIDRs(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) > MaxCIDRs {
		return nil, invalidf("allowed_cidrs — не больше %d подсетей", MaxCIDRs)
	}
	if errs := config.CheckCIDRs(cidrs); len(errs) > 0 {
		return nil, invalid(errs...)
	}
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, invalidf("allowed_cidrs — подсеть вида 10.0.0.0/8")
		}
		out = append(out, p)
	}
	return out, nil
}

func cidrStrings(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// newKey выпускает ключ (формат — Р1 этапа 1, auth.NewAppKey): сам ключ
// возвращается один раз, в хранилище — префикс и хеш профиля.
func (s *Service) newKey() (raw, prefix string, hash []byte, err error) {
	raw, prefix, hexHash, err := auth.NewAppKey(s.random, s.hasher)
	if err != nil {
		return "", "", nil, err
	}
	hash, err = hex.DecodeString(hexHash)
	if err != nil {
		return "", "", nil, err
	}
	return raw, prefix, hash, nil
}

func keyDetails(a Application, k Key) map[string]any {
	return map[string]any{"application": a.Slug, "prefix": k.Prefix, "name": k.Name,
		"expires_at": k.ExpiresAt.Format(time.RFC3339), "allowed_cidrs": cidrStrings(k.AllowedCIDRs)}
}

// IssueKey выпускает ключ приложения. ownerID не пуст — только для своего
// приложения. Возвращает ключ без секрета и сам ключ (показывается один раз).
func (s *Service) IssueKey(ctx context.Context, by By, appID, ownerID string, in KeyInput) (Key, string, error) {
	var errs []error
	if err := textLen("name", in.Name, 1, maxName); err != nil {
		errs = append(errs, err)
	}
	if err := noControl("name", in.Name); err != nil {
		errs = append(errs, err)
	}
	ttl, err := keyDays(in.ExpiresInDays)
	if err != nil {
		errs = append(errs, err)
	}
	cidrs, err := parseCIDRs(in.AllowedCIDRs)
	if err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return Key{}, "", flatten(errs)
	}
	raw, prefix, hash, err := s.newKey()
	if err != nil {
		return Key{}, "", err
	}
	id, err := s.newID()
	if err != nil {
		return Key{}, "", err
	}
	now := s.now()
	k, err := s.store.CreateKey(ctx, s.orgID, appID, now, func(a Application, active int) (Key, audit.Entry, error) {
		if err := visible(a, ownerID); err != nil {
			return Key{}, audit.Entry{}, err
		}
		if a.Archived() {
			return Key{}, audit.Entry{}, ErrArchived
		}
		if active >= MaxActiveKeys {
			return Key{}, audit.Entry{}, ErrTooManyKeys
		}
		k := Key{ID: id, OrgID: s.orgID, AppID: a.ID, Name: in.Name, Prefix: prefix, Hash: hash, HashAlg: s.hasher.Name(),
			AllowedCIDRs: cidrs, ExpiresAt: now.Add(ttl), CreatedAt: now, CreatedBy: by.ref()}
		return k, by.entry("app_key.issue", "app_key", id, keyDetails(a, k)), nil
	})
	if err != nil {
		return Key{}, "", err
	}
	return k, raw, nil
}

// RotateKey выпускает новый ключ вместо действующего с теми же именем и
// подсетями; прежний действует ещё Overlap (срок только сокращается). Новый
// ключ считается в MaxActiveKeys, как при выпуске (Н24 ревью 2.r3b): иначе
// повторные ротации набирали бы сколько угодно действующих ключей.
// Возвращает новый ключ, его секрет и прежний ключ.
func (s *Service) RotateKey(ctx context.Context, by By, keyID, ownerID string, in RotateInput) (Key, string, Key, error) {
	overlap := DefaultOverlap
	if in.Overlap != nil {
		overlap = *in.Overlap
	}
	if overlap < 0 || overlap > MaxOverlap {
		return Key{}, "", Key{}, invalidf("overlap_hours — от 0 до %d часов", int(MaxOverlap/time.Hour))
	}
	ttl, err := keyDays(in.ExpiresInDays)
	if err != nil {
		return Key{}, "", Key{}, err
	}
	raw, prefix, hash, err := s.newKey()
	if err != nil {
		return Key{}, "", Key{}, err
	}
	id, err := s.newID()
	if err != nil {
		return Key{}, "", Key{}, err
	}
	now := s.now()
	var created Key
	old, err := s.store.UpdateKey(ctx, s.orgID, keyID, now, func(k *Key, a Application, active int) (*Key, audit.Entry, error) {
		if err := visible(a, ownerID); err != nil {
			return nil, audit.Entry{}, err
		}
		if a.Archived() {
			return nil, audit.Entry{}, ErrArchived
		}
		if k.Status(now) != KeyActive {
			return nil, audit.Entry{}, ErrKeyInactive
		}
		if active >= MaxActiveKeys {
			return nil, audit.Entry{}, ErrTooManyKeys
		}
		created = Key{ID: id, OrgID: s.orgID, AppID: a.ID, Name: k.Name, Prefix: prefix, Hash: hash, HashAlg: s.hasher.Name(),
			AllowedCIDRs: k.AllowedCIDRs, ExpiresAt: now.Add(ttl), CreatedAt: now, CreatedBy: by.ref(), RotatedFrom: k.ID}
		if until := now.Add(overlap); until.Before(k.ExpiresAt) {
			k.ExpiresAt = until
		}
		d := keyDetails(a, created)
		d["rotated_from"] = k.ID
		d["previous_prefix"] = k.Prefix
		d["previous_expires_at"] = k.ExpiresAt.Format(time.RFC3339)
		return &created, by.entry("app_key.rotate", "app_key", id, d), nil
	})
	if err != nil {
		return Key{}, "", Key{}, err
	}
	return created, raw, old, nil
}

// RevokeKey отзывает ключ сразу (в шлюзе — с доставкой пакета, задача
// 2.13). Отозванный ключ не оживает.
func (s *Service) RevokeKey(ctx context.Context, by By, keyID, ownerID string) (Key, error) {
	return s.store.UpdateKey(ctx, s.orgID, keyID, s.now(), func(k *Key, a Application, _ int) (*Key, audit.Entry, error) {
		if err := visible(a, ownerID); err != nil {
			return nil, audit.Entry{}, err
		}
		if !k.RevokedAt.IsZero() {
			return nil, audit.Entry{}, ErrKeyInactive
		}
		k.RevokedAt, k.RevokedBy = s.now(), by.ref()
		return nil, by.entry("app_key.revoke", "app_key", k.ID, keyDetails(a, *k)), nil
	})
}

// BundleKeysAt — ключи всех приложений для пакета конфигурации на момент
// now (Н25 ревью 2.r3b): одним запросом и без предела выдачи. Кроме
// действующих — неистёкшие ключи, отозванные позже revokedSince: шлюз
// отличает отозванный ключ от неизвестного (DM-38, Д-E2E-1).
func (s *Service) BundleKeysAt(ctx context.Context, now, revokedSince time.Time) ([]Key, error) {
	return s.store.BundleKeys(ctx, s.orgID, now, revokedSince)
}

// Keys — ключи приложения (новые первыми); ownerID не пуст — только своего.
func (s *Service) Keys(ctx context.Context, appID, ownerID string) ([]Key, error) {
	if _, err := s.Application(ctx, appID, ownerID); err != nil {
		return nil, err
	}
	return s.store.Keys(ctx, s.orgID, appID)
}

// flatten объединяет ошибки ввода в одну InputError.
func flatten(errs []error) error {
	var out []error
	for _, e := range errs {
		var ie *InputError
		if errors.As(e, &ie) {
			out = append(out, ie.Errs...)
		} else {
			out = append(out, e)
		}
	}
	return invalid(out...)
}
