package alerting

import "fmt"

// Встроенное правило лицензии (ТЗ 5.15, 5.16; задача 4.26 этапа 4,
// ADR-0026, п. 8). Срабатывает по записи system.alert условий license_*
// «Состояния системы».
const (
	// BuiltinLicenseExpiry — срок лицензии подходит к концу, идёт льготный
	// период, изменения запрещены, лицензия не прошла проверку подписи или
	// часы сервера отстают от отметки (DM-44). Системное: не отключается.
	BuiltinLicenseExpiry = "system.license_expiry"
	// LicenseStageField — значение группировки: стадия.
	LicenseStageField = "stage"
)

// licenseRules — встроенное правило задачи 4.26.
func licenseRules() []Rule {
	none := Recipients{Roles: []string{}, Users: []string{}}
	return []Rule{
		{BuiltinKey: BuiltinLicenseExpiry, Kind: KindSystem, Name: "Лицензия",
			Description: "DM-44, ТЗ 5.15: до конца срока лицензии 30 суток и меньше (ещё одно оповещение — за 7 суток), идёт " +
				"льготный период, после него изменения конфигурации запрещены, загруженная лицензия не прошла проверку " +
				"подписи или часы сервера отстали от отметки времени. Трафик и защита работают во всех стадиях.",
			Enabled: true, Severity: "high", GroupBy: []string{LicenseStageField}, SuppressMinutes: 0, Recipients: none},
	}
}

// licenseStage — стадия для заголовка оповещения по коду условия.
func licenseStage(code string, d map[string]any) string {
	days := func() string {
		if n, ok := d["days_left"].(float64); ok {
			return fmt.Sprintf("осталось %d сут.", int(n))
		}
		if n, ok := d["days_left"].(int); ok {
			return fmt.Sprintf("осталось %d сут.", n)
		}
		return "срок подходит к концу"
	}
	switch code {
	case "license_expiry", "license_expiry:critical":
		return days()
	case "license_grace":
		return "льготный период"
	case "license_restricted":
		return "изменения конфигурации запрещены"
	case "license_invalid":
		return "подпись не прошла проверку"
	case "license_clock":
		return "часы сервера отстают"
	}
	return code
}
