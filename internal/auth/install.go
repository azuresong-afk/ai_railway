package auth

import (
	"context"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// InstallSettings — настройки установки (ВРМ.2, ТЗ 5.5; H-Р10, В26 ревью
// 2.r5): единственный источник часового пояса показа и режима хранения по
// умолчанию. До первичной настройки строки нет — умолчания.
func (s *Service) InstallSettings(ctx context.Context) (InstallSettings, error) {
	cfg, ok, err := s.store.InstallSettings(ctx, s.orgID)
	if err != nil {
		return InstallSettings{}, err
	}
	if !ok {
		return InstallSettings{Timezone: DefaultTimezone, RetentionMode: DefaultRetentionMode}, nil
	}
	return cfg, nil
}

// SetInstallSettings меняет настройки установки с записью
// setup.settings_changed. Пустое поле оставляет прежнее значение. Переход
// умолчания хранения на none или full ослабляет защиту, как у приложений
// (DM-40): только с повторной проверкой паролем или кодом, в журнале —
// weakening.
func (s *Service) SetInstallSettings(ctx context.Context, by Caller, in InstallSettings, password, code string) (InstallSettings, error) {
	before, err := s.InstallSettings(ctx)
	if err != nil {
		return InstallSettings{}, err
	}
	if in.Timezone == "" {
		in.Timezone = before.Timezone
	}
	if in.RetentionMode == "" {
		in.RetentionMode = before.RetentionMode
	}
	cfg, err := in.Normalize()
	if err != nil {
		return InstallSettings{}, err
	}
	weakening := cfg.RetentionMode != before.RetentionMode && cfg.RetentionMode != RetentionMasked
	if weakening {
		if err := s.reauthenticate(ctx, by, password, code, "setup.settings_changed"); err != nil {
			return InstallSettings{}, err
		}
	}
	rec := s.entry(by.actor(), by.SourceIP, "setup.settings_changed", audit.Object{Type: "install_settings", ID: s.orgID},
		audit.ResultSuccess, map[string]any{
			"before":    map[string]any{"timezone": before.Timezone, "retention_mode": before.RetentionMode},
			"after":     map[string]any{"timezone": cfg.Timezone, "retention_mode": cfg.RetentionMode},
			"weakening": weakening,
		})
	if err := s.store.SetInstallSettings(ctx, s.orgID, cfg, s.clock(), rec); err != nil {
		return InstallSettings{}, err
	}
	return cfg, nil
}
