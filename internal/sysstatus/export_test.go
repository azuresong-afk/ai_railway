package sysstatus

// StoredConditionSamples — по одному коду каждого условия, состояние
// которого сервер хранит в system_alert_state (ключи collect.conditions):
// условия без компонента, коды «семейство:ID шлюза» с gatewayID и
// «семейство:вид базы» для каждого из dbKinds. Тесты сверяют их с
// ограничением system_alert_state_condition_check последней миграции (5В5
// ревью 5.r4): новое условие без миграции не пройдёт сборку.
func StoredConditionSamples(gatewayID string, dbKinds []string) []string {
	skip := map[string]bool{ConditionAccount: true, ConditionDenied: true} // счётчики аудита, не состояния
	for _, f := range gatewayFamilies {
		skip[f] = true
	}
	for _, f := range serviceDBFamilies {
		skip[f] = true
	}
	var out []string
	for _, ci := range conditionInfo {
		if !skip[ci.code] {
			out = append(out, ci.code)
		}
	}
	out = append(out, integrityServer, integrityGateway+gatewayID, caExpiryCritical, customerCertCritical, licenseExpiryCritical)
	for _, f := range gatewayFamilies {
		out = append(out, f+":"+gatewayID)
	}
	for _, f := range serviceDBFamilies {
		for _, k := range dbKinds {
			out = append(out, f+":"+k)
		}
	}
	return out
}
