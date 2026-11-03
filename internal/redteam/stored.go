package redteam

import (
	"context"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Проверка сохранённых объектов правилами API: резервная копия
// конфигурации (internal/backup, aisec-cli backup restore) проверяет цели и
// расписания копии до записи теми же функциями, что POST и PUT
// /api/v1/redteam/* (G3 этапа 5, ADR-0017, дополнение). Повторная проверка
// паролем при восстановлении не нужна: восстановление выполняет владелец
// установки из консоли сервера, оно пишется в аудит.

// CheckStoredTarget проверяет цель копии: поля — TargetInput.Target,
// ссылки — как при сохранении через API (приложение и модель цели
// gateway, корневой сертификат, оценщик «у заказчика»).
func CheckStoredTarget(ctx context.Context, tp aisecCrypto.TLSProvider, refs TargetRefs, t Target) error {
	limits := t.Limits
	in := TargetInput{Name: t.Name, Kind: t.Kind, AppID: t.AppID, Model: t.Model, URL: t.URL, RequestTemplate: t.RequestTemplate,
		ResponsePath: t.ResponsePath, Headers: t.Headers, AuthHeader: t.AuthHeader, CAPEM: t.CAPEM,
		AuthorizationNote: t.AuthorizationNote, Storage: t.Storage, JudgeProvider: t.JudgeProvider, JudgeModel: t.JudgeModel,
		Limits: &limits}
	got, err := in.Target()
	if err != nil {
		return err
	}
	// Умолчания пределов и режима хранения в сохранённой цели уже
	// подставлены: расхождение — значит, значение вне правил API.
	if got.Limits != t.Limits {
		return invalidf("limits — значения вне пределов")
	}
	return checkTargetRefs(ctx, tp, refs, got)
}

// CheckStoredSchedule проверяет расписание копии: поля — ScheduleInput.
// Schedule, цель — из копии; цель с секретным заголовком по расписанию не
// запускается (authHeader — её auth_header).
func CheckStoredSchedule(sc Schedule, authHeader string) error {
	enabled := sc.Enabled
	in := ScheduleInput{Name: sc.Name, TargetID: sc.TargetID, Frequency: sc.Frequency, Weekday: sc.Weekday, Day: sc.Day, At: sc.At,
		Threats: sc.Threats, Lang: sc.Lang, Enabled: &enabled}
	got, err := in.Schedule()
	if err != nil {
		return err
	}
	if got.Name != sc.Name {
		return invalidf("name — пробелы по краям")
	}
	if authHeader != "" {
		return invalidf("target_id — у цели секретный заголовок %s: по расписанию такая цель не запускается", authHeader)
	}
	return nil
}
