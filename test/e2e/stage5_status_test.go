//go:build e2e

package e2e

// «Состояние системы» (ЗИ.6, РСБ.7, ОЦЛ.5): условия, которые пишет сервер.

import (
	"strings"
	"testing"
	"time"
)

// 5В5 ревью 5.r4 этапа 5 (дефект 5.49-1, найден при 5.49): ограничение
// system_alert_state_condition_check не знало условий этапов 4 и 5
// (shadow_ai_*, gateway_limits, service_db_*, gateway_media_*), и сервер
// писал «уведомления состояния системы не обновлены». Исправлено миграцией
// 0078; сверку кода с ограничением ведёт TestStoredConditionsMatchCheck
// (internal/sysstatus). Тест проверяет, что первый обход на живом стенде
// записывает состояния без отказа базы.
func TestE2EStage5_SystemAlertStateConditions(t *testing.T) {
	st := s3NewStack(t, s3Opts{})
	// Первый обход состояния системы идёт сразу после запуска сервера.
	time.Sleep(10 * time.Second)
	if log := st.s.srv.log(); strings.Contains(log, "уведомления состояния системы не обновлены") {
		t.Fatalf("сервер не смог записать состояния уведомлений:\n%s", log)
	}
}
