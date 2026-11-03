//go:build e2e

package e2e

// «Состояние системы» (ЗИ.6, РСБ.7, ОЦЛ.5): условия, которые пишет сервер.

import (
	"strings"
	"testing"
	"time"
)

// Дефект, найденный при 5.49 (stage-5.md, «Открытые вопросы»): ограничение
// system_alert_state_condition_check, последний раз обновлённое миграцией
// 0064, не знает условий shadow_ai_storage и shadow_ai_full (этап 4),
// gateway_limits, service_db_previous и service_db_unused (5.9),
// gateway_media_overloaded, gateway_media_unavailable и gateway_media_selftest
// (5.44). Запись состояния уведомления по ним отклоняется базой, сервер пишет
// «уведомления состояния системы не обновлены», и оповещение «Состояния
// системы» о них не живёт между проверками. Тест воспроизводит дефект и
// пропущен до исправления (новая миграция с полным списком условий).
func TestE2EStage5_SystemAlertStateConditions(t *testing.T) {
	t.Skip("дефект 5.49-1 (stage-5.md, «Открытые вопросы»): CHECK system_alert_state не знает условий этапов 4 и 5")
	st := s3NewStack(t, s3Opts{})
	// Первый обход состояния системы идёт сразу после запуска сервера.
	time.Sleep(10 * time.Second)
	if log := st.s.srv.log(); strings.Contains(log, "уведомления состояния системы не обновлены") {
		t.Fatalf("сервер не смог записать состояния уведомлений:\n%s", log)
	}
}
