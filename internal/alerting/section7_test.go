package alerting

import (
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Уведомления раздела 7 доставляются каналами (задача 3.14): каждое
// оповещение ИАФ.4, ИАФ.5, УПД.6, РСБ.4, РСБ.5, РСБ.6, ОЦЛ.5 и ВРМ.1 при
// создании ставится в очередь доставки той же транзакцией.
func TestSection7NotificationsEnqueued(t *testing.T) {
	e := newEnv(t)
	sys := audit.Actor{Type: audit.ActorSystem, ID: "system-status"}
	// ИАФ.4 — блокировка учётной записи.
	e.audit(t, e.rec(t, tUser, "192.0.2.10", "auth.locked", audit.Object{Type: "user", ID: tUser.ID}, audit.ResultFailure, nil))
	// ИАФ.5 — сброс второго фактора (ослабление).
	e.audit(t, e.rec(t, tOther, "", "auth.mfa_reset", audit.Object{Type: "user", ID: tUser.ID}, audit.ResultSuccess, nil))
	// УПД.6 — серия отказов в доступе.
	for range DeniedThreshold {
		e.audit(t, e.rec(t, tUser, "192.0.2.10", "access.denied", audit.Object{Type: "route", ID: "/api/v1/users"},
			audit.ResultDenied, map[string]any{"path": "/api/v1/users", "permission": "users.manage"}))
	}
	// РСБ.4 — нарушена цепочка журнала.
	e.audit(t, e.rec(t, sys, "", "audit.chain_broken", audit.Object{Type: "audit_log", ID: "chain"}, audit.ResultFailure,
		map[string]any{"reason": "hash_mismatch", "broken_seq": 42}))
	// РСБ.5, РСБ.6, ОЦЛ.5, ВРМ.1 — условия «Состояния системы» и передачи в SIEM.
	e.systemAlert(t, "audit_storage", "raised", map[string]any{"requirement": "РСБ.5"})
	e.systemAlert(t, "audit_stream_lag:01900000-0000-7000-8000-0000000000d1", "raised",
		map[string]any{"requirement": "РСБ.6", "channel_name": "SIEM"})
	e.systemAlert(t, "integrity:server", "raised", map[string]any{"requirement": "ОЦЛ.5", "component": "server"})
	e.systemAlert(t, "time_sync", "raised", map[string]any{"requirement": "ВРМ.1"})

	queued := e.mem.Enqueued()
	for _, key := range []string{BuiltinConsoleBrute, BuiltinWeakening, BuiltinAccessDenied, BuiltinAuditChain,
		BuiltinAuditStorage, BuiltinAuditStream, BuiltinIntegrity, BuiltinTimeSync} {
		got := e.alerts(t, key)
		if len(got) != 1 {
			t.Fatalf("%s: оповещений %d", key, len(got))
		}
		if !slices.Contains(queued, got[0].ID) {
			t.Fatalf("%s: оповещение не поставлено в очередь доставки", key)
		}
	}
	if s := e.alerts(t, BuiltinAuditStream)[0]; s.Values["channel"] != "SIEM" {
		t.Fatalf("канал в оповещении: %+v", s.Values)
	}
}
