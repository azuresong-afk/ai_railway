package alerting

import "testing"

// Покрывает: DM-03, DM-06, DM-26
// Встроенные правила задач 4.13 и 4.14: находка session.risk, расхождение
// с эталоном системного промпта и подмена истории дают оповещение высокой
// серьёзности, по одному на приложение; другие угрозы — нет.
func TestDM03_DM06_DM26_SessionAlerts(t *testing.T) {
	e := newEnv(t)
	for key, threat := range map[string]string{
		BuiltinSessionRisk: "DM-06", BuiltinPromptIntegrity: "DM-26", BuiltinHistoryIntegrity: "DM-03",
	} {
		e.ingest(t, e.event(t, "crm-bot", "gigachat", "log", "DM-31"))
		if got := e.alerts(t, key); len(got) != 0 {
			t.Fatalf("%s: оповещение без угрозы: %+v", key, got)
		}
		e.ingest(t, e.event(t, "crm-bot", "gigachat", "log", threat), e.event(t, "crm-bot", "gigachat", "block", threat))
		got := e.alerts(t, key)
		if len(got) != 1 || got[0].Count != 2 || got[0].Severity != "high" || got[0].Values["app"] != "crm-bot" {
			t.Fatalf("%s: %+v", key, got)
		}
	}
}
