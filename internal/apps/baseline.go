package apps

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
)

// Эталон системного промпта приложения (ТЗ 5.4, 5.16 DM-26; задача 4.14
// этапа 4, миграция 0051_prompt_baselines). Текст эталона шифруется ключом
// данных с AAD места хранения (ЗИ.1, ADR-0007) и показывается только
// обладателю права applications.policy; в пакет конфигурации шлюзов —
// хеш нормализованного текста (session.PromptHash) и режим контроля.
//
// Изменение эталона — действие администратора с записью аудита той же
// транзакцией. Понижение режима контроля (block → alert → off) и снятие
// действующего эталона — ослабление защиты: повторная проверка субъекта и
// признак weakening в аудите (DM-40).

// Режимы контроля эталона.
const (
	PromptOff   = "off"
	PromptAlert = "alert"
	PromptBlock = "block"
)

// Место хранения текста: AAD prompt_baselines|text|<app_id> (keyring.Rewrap).
const (
	promptTable  = "prompt_baselines"
	promptColumn = "text"
)

// ErrNoPromptBaseline — эталон системного промпта не задан.
var ErrNoPromptBaseline = errors.New("эталон системного промпта не задан")

// PromptBaseline — эталон системного промпта приложения.
type PromptBaseline struct {
	AppID string
	OrgID string
	Mode  string
	// Hash — session.PromptHash текста, 64 hex.
	Hash string
	// Size — размер текста, байт.
	Size      int
	Text      Sealed
	CreatedAt time.Time
	CreatedBy string
	UpdatedAt time.Time
	UpdatedBy string
}

// PromptBaselineInput — новый эталон или режим. Text = nil — текст прежний
// (смена режима).
type PromptBaselineInput struct {
	Text *string
	Mode string
}

// promptRank — сила режима контроля: понижение — ослабление.
func promptRank(mode string) int {
	switch mode {
	case PromptAlert:
		return 1
	case PromptBlock:
		return 2
	}
	return 0
}

// checkPromptText — текст эталона: UTF-8 до session.MaxPrompt байт, без
// управляющих символов, кроме табуляции и перевода строки, и не из одних
// пробельных символов.
func checkPromptText(text string) error {
	switch {
	case len(text) > session.MaxPrompt:
		return fmt.Errorf("text — не больше %d байт", session.MaxPrompt)
	case !utf8.ValidString(text):
		return errors.New("text — текст в UTF-8")
	case session.Normalize(text) == "":
		return errors.New("text — эталон не может быть пустым")
	}
	for _, r := range text {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0x7f {
			return errors.New("text — без управляющих символов, кроме табуляции и перевода строки")
		}
	}
	return nil
}

// SetPromptBaseline задаёт эталон или режим его контроля (право
// applications.policy). Понижение режима требует повторной проверки.
func (s *Service) SetPromptBaseline(ctx context.Context, by By, appID string, in PromptBaselineInput) (PromptBaseline, error) {
	var errs []error
	if in.Mode != PromptOff && in.Mode != PromptAlert && in.Mode != PromptBlock {
		errs = append(errs, errors.New("mode — off (не сверять), alert (оповещать) или block (блокировать)"))
	}
	if in.Text != nil {
		if err := checkPromptText(*in.Text); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return PromptBaseline{}, invalid(errs...)
	}
	var text *Sealed
	var hash string
	size := 0
	if in.Text != nil {
		if s.box == nil {
			return PromptBaseline{}, ErrNoDataKey
		}
		keyID, sealed, err := s.box.SealKey(ctx, []byte(*in.Text), promptTable, promptColumn, appID)
		if err != nil {
			return PromptBaseline{}, err
		}
		text = &Sealed{Data: sealed, KeyID: keyID, Alg: s.box.Alg()}
		hash, size = session.PromptHash(s.hasher, *in.Text), len(*in.Text)
	}
	b, err := s.store.SetPromptBaseline(ctx, s.orgID, appID, func(a Application, prev *PromptBaseline) (PromptBaseline, audit.Entry, error) {
		if a.Archived() {
			return PromptBaseline{}, audit.Entry{}, ErrArchived
		}
		now := s.now()
		next := PromptBaseline{AppID: a.ID, OrgID: s.orgID, Mode: in.Mode, CreatedAt: now, CreatedBy: by.ref(),
			UpdatedAt: now, UpdatedBy: by.ref()}
		switch {
		case text != nil:
			next.Hash, next.Size, next.Text = hash, size, *text
			next.Text.SetAt = now
		case prev != nil:
			next.Hash, next.Size, next.Text = prev.Hash, prev.Size, prev.Text
		default:
			return PromptBaseline{}, audit.Entry{}, invalid(errors.New("text — у приложения ещё нет эталона: задайте текст"))
		}
		if prev != nil {
			next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
			if prev.Mode == next.Mode && prev.Hash == next.Hash {
				return PromptBaseline{}, audit.Entry{}, errUnchanged
			}
		}
		weak := prev != nil && promptRank(next.Mode) < promptRank(prev.Mode)
		if weak {
			if err := by.confirm(ctx); err != nil {
				return PromptBaseline{}, audit.Entry{}, err
			}
		}
		d := map[string]any{"slug": a.Slug, "before": promptDetails(prev), "after": promptDetails(&next), "weakening": weak}
		if weak {
			d["weakening_reasons"] = []any{"prompt_baseline_mode"}
		}
		return next, by.entry("application.prompt_baseline_set", "application", a.ID, d), nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.PromptBaseline(ctx, s.orgID, appID)
	}
	return b, err
}

// DeletePromptBaseline снимает эталон. Снятие эталона с режимом alert или
// block — ослабление: повторная проверка и weakening в аудите.
func (s *Service) DeletePromptBaseline(ctx context.Context, by By, appID string) (PromptBaseline, error) {
	return s.store.DeletePromptBaseline(ctx, s.orgID, appID, func(a Application, b PromptBaseline) (audit.Entry, error) {
		weak := promptRank(b.Mode) > 0
		if weak {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, err
			}
		}
		d := map[string]any{"slug": a.Slug, "before": promptDetails(&b), "weakening": weak}
		if weak {
			d["weakening_reasons"] = []any{"prompt_baseline_removed"}
		}
		return by.entry("application.prompt_baseline_removed", "application", a.ID, d), nil
	})
}

// PromptBaseline — эталон приложения (ErrNoPromptBaseline — не задан).
func (s *Service) PromptBaseline(ctx context.Context, appID string) (PromptBaseline, error) {
	return s.store.PromptBaseline(ctx, s.orgID, appID)
}

// PromptBaselines — эталоны организации для пакета конфигурации.
func (s *Service) PromptBaselines(ctx context.Context) ([]PromptBaseline, error) {
	return s.store.PromptBaselines(ctx, s.orgID)
}

// OpenPromptText расшифровывает текст эталона для показа обладателю права
// applications.policy.
func (s *Service) OpenPromptText(ctx context.Context, b PromptBaseline) (string, error) {
	if s.box == nil {
		return "", ErrNoDataKey
	}
	plain, err := s.box.OpenContext(ctx, b.Text.KeyID, b.Text.Data, promptTable, promptColumn, b.AppID)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// promptDetails — подробности записи аудита: режим, хеш и размер без
// текста.
func promptDetails(b *PromptBaseline) map[string]any {
	if b == nil {
		return nil
	}
	return map[string]any{"mode": b.Mode, "hash": b.Hash, "bytes": b.Size}
}

func clonePrompt(b PromptBaseline) PromptBaseline {
	b.Text.Data = append([]byte(nil), b.Text.Data...)
	return b
}

// SetPromptBaseline — см. Store.
func (m *Memory) SetPromptBaseline(_ context.Context, orgID, appID string,
	fn func(a Application, prev *PromptBaseline) (PromptBaseline, audit.Entry, error)) (PromptBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[appID]
	if !ok || a.OrgID != orgID {
		return PromptBaseline{}, ErrNotFound
	}
	var prev *PromptBaseline
	if b, ok := m.prompts[appID]; ok {
		c := clonePrompt(b)
		prev = &c
	}
	next, rec, err := fn(cloneApp(a), prev)
	if err != nil {
		return PromptBaseline{}, err
	}
	m.prompts[appID] = clonePrompt(next)
	m.records = append(m.records, rec)
	return next, nil
}

// DeletePromptBaseline — см. Store.
func (m *Memory) DeletePromptBaseline(_ context.Context, orgID, appID string,
	fn func(a Application, b PromptBaseline) (audit.Entry, error)) (PromptBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.apps[appID]
	if !ok || a.OrgID != orgID {
		return PromptBaseline{}, ErrNotFound
	}
	b, ok := m.prompts[appID]
	if !ok {
		return PromptBaseline{}, ErrNoPromptBaseline
	}
	rec, err := fn(cloneApp(a), clonePrompt(b))
	if err != nil {
		return PromptBaseline{}, err
	}
	delete(m.prompts, appID)
	m.records = append(m.records, rec)
	return b, nil
}

// PromptBaseline — см. Store.
func (m *Memory) PromptBaseline(_ context.Context, orgID, appID string) (PromptBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.apps[appID]; !ok || a.OrgID != orgID {
		return PromptBaseline{}, ErrNotFound
	}
	b, ok := m.prompts[appID]
	if !ok {
		return PromptBaseline{}, ErrNoPromptBaseline
	}
	return clonePrompt(b), nil
}

// PromptBaselines — см. Store.
func (m *Memory) PromptBaselines(_ context.Context, orgID string) ([]PromptBaseline, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []PromptBaseline
	for _, b := range m.prompts {
		if b.OrgID == orgID {
			out = append(out, clonePrompt(b))
		}
	}
	slices.SortFunc(out, func(a, b PromptBaseline) int { return strings.Compare(a.AppID, b.AppID) })
	return out, nil
}
