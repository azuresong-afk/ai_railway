package integrity

import "slices"

// Отозванные номера заверений рабочих ключей (ADR-0022, п. 2: отзыв —
// новым выпуском). Один список на назначение: каталог теневого ИИ и база
// требований подписаны ключами одного назначения service_db, и номер
// вносится один раз (ревью 4.r4). Выпуск с номером в списке перестаёт
// принимать файлы, подписанные этим ключом, в том числе уже загруженные.
var (
	// revokedServiceDB — назначение service_db (ADR-0027, п. 2).
	revokedServiceDB = []uint64{}
	// revokedLicense — назначение license (ADR-0026, п. 2): отзыв ключа
	// лицензий не задевает служебные базы, и наоборот.
	revokedLicense = []uint64{}
)

// RevokedServiceDB сообщает, отозвано ли заверение рабочего ключа служебных
// баз с номером serial.
func RevokedServiceDB(serial uint64) bool { return slices.Contains(revokedServiceDB, serial) }

// RevokedLicense сообщает, отозвано ли заверение рабочего ключа лицензий с
// номером serial.
func RevokedLicense(serial uint64) bool { return slices.Contains(revokedLicense, serial) }
