package build

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/apps"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// addUserTokens добавляет разделы user_tokens и user_token_keys (задача
// 4.21 этапа 4, ADR-0025, раздел 4): настройки приложений пакета с
// проверкой JWT и ключи подписи IdP. Режим off и исключённые приложения в
// раздел не входят; группы для моделей, которых у приложения уже нет,
// отбрасываются (запись остаётся и снова действует, если модель вернут).
//
// Ключи берутся у настроенного IdP только для издателя, которого ждут
// приложения. Если IdP недоступен, в пакет идут ключи из последней версии
// (без них шлюзы отклонили бы все JWT), но не дольше MaxStaleUserTokenKeys;
// если их нет — раздела нет, и шлюзы отвечают 401 на JWT, а в режиме
// optional принимают X-AISec-User.
func (s *Service) addUserTokens(ctx context.Context, c *bundle.Content, appSlugs map[string]string, now time.Time) error {
	list, err := s.apps.UserAccessList(ctx)
	if err != nil {
		return err
	}
	bySlug := make(map[string]bundle.Application, len(c.Applications))
	for _, a := range c.Applications {
		bySlug[a.ID] = a
	}
	wanted := map[string]bool{}
	for _, u := range list {
		slug, ok := appSlugs[u.AppID]
		if !ok || u.Mode == apps.UserTokenOff {
			continue
		}
		ba := bySlug[slug]
		ut := bundle.UserToken{App: slug, Mode: u.Mode, Issuer: u.Issuer, Audience: u.Audience, GroupsClaim: u.GroupsClaim,
			Leeway: u.Leeway}
		for m, groups := range u.ModelGroups {
			if _, alias := ba.Aliases[m]; alias || slices.Contains(ba.Models, m) {
				if ut.ModelGroups == nil {
					ut.ModelGroups = map[string][]string{}
				}
				ut.ModelGroups[m] = slices.Clone(groups)
			}
		}
		c.UserTokens = append(c.UserTokens, ut)
		wanted[u.Issuer] = true
	}
	if len(c.UserTokens) == 0 {
		return nil
	}
	slices.SortFunc(c.UserTokens, func(a, b bundle.UserToken) int { return strings.Compare(a.App, b.App) })
	if s.idpKeys == nil || s.jwt == nil {
		return nil
	}
	// Пакет собирается заново не реже UserTokenKeysRefresh: смена ключей
	// у IdP не меняет счётчик изменений конфигурации.
	if refresh := now.Add(UserTokenKeysRefresh); s.collected.IsZero() || refresh.Before(s.collected) {
		s.collected = refresh
	}
	s.loadKeysAt(ctx)
	issuer, keys, err := s.idpKeys(ctx)
	if err == nil && issuer != "" && wanted[issuer] {
		var raw []byte
		if raw, err = s.jwt.MarshalJWKS(keys); err == nil {
			c.UserTokenKeys = []bundle.IssuerKeys{{Issuer: issuer, JWKS: raw}}
			s.saveKeysAt(ctx, now)
			return nil
		}
	}
	if err == nil {
		// IdP не настроен или приложения ждут другого издателя: ключей нет.
		s.saveKeysAt(ctx, now)
		return nil
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if now.Sub(s.keysAt) > MaxStaleUserTokenKeys {
		s.logger.Error("ключи IdP для проверки JWT пользователей не получены дольше допустимого: в пакете их нет, шлюзы отклоняют JWT",
			"error", err, "since", s.keysAt)
		return nil
	}
	prev, perr := s.previousUserTokenKeys(ctx)
	for _, k := range prev {
		if wanted[k.Issuer] {
			c.UserTokenKeys = append(c.UserTokenKeys, k)
		}
	}
	s.logger.Warn("ключи IdP для проверки JWT пользователей не получены: в пакете ключи прежней версии",
		"error", err, "previous", len(c.UserTokenKeys), "previous_error", perr)
	return nil
}

// loadKeysAt один раз читает момент последнего получения ключей из
// хранилища (4Н14 ревью 4.r2): срок прежних ключей не начинается заново
// при перезапуске сервера. Сбой чтения — отсчёт от запуска, повтор при
// следующей сборке.
func (s *Service) loadKeysAt(ctx context.Context) {
	ks, ok := s.store.(KeysTimeStore)
	if s.keysLoaded || !ok {
		return
	}
	at, err := ks.UserTokenKeysAt(ctx, s.orgID)
	if err != nil {
		s.logger.Warn("момент получения ключей IdP не прочитан: срок прежних ключей — от запуска сервера", "error", err)
		return
	}
	s.keysLoaded, s.keysSaved = true, at
	if !at.IsZero() && at.Before(s.keysAt) {
		s.keysAt = at
	}
}

// saveKeysAt отмечает успешное получение ключей и записывает момент в
// хранилище не чаще UserTokenKeysRefresh: после перезапуска срок прежних
// ключей короче не больше чем на этот интервал.
func (s *Service) saveKeysAt(ctx context.Context, now time.Time) {
	s.keysAt = now
	ks, ok := s.store.(KeysTimeStore)
	if !ok || now.Sub(s.keysSaved) < UserTokenKeysRefresh {
		return
	}
	if err := ks.SetUserTokenKeysAt(ctx, s.orgID, now); err != nil {
		s.logger.Warn("момент получения ключей IdP не записан", "error", err)
		return
	}
	s.keysSaved = now
}

// previousUserTokenKeys — раздел user_token_keys последней версии пакета.
func (s *Service) previousUserTokenKeys(ctx context.Context) ([]bundle.IssuerKeys, error) {
	latest, err := s.store.Latest(ctx, s.orgID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var part struct {
		Keys []bundle.IssuerKeys `json:"user_token_keys"`
	}
	if err := json.Unmarshal(latest.Content, &part); err != nil {
		return nil, err
	}
	slices.SortFunc(part.Keys, func(a, b bundle.IssuerKeys) int { return strings.Compare(a.Issuer, b.Issuer) })
	return slices.CompactFunc(part.Keys, func(a, b bundle.IssuerKeys) bool { return a.Issuer == b.Issuer }), nil
}
