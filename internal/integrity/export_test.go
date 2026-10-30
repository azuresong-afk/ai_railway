package integrity

// SetRevoked подменяет списки отозванных номеров на время теста
// (тесты пакета integrity_test с базами разных видов).
func SetRevoked(serviceDB, license []uint64) (restore func()) {
	s, l := revokedServiceDB, revokedLicense
	revokedServiceDB, revokedLicense = serviceDB, license
	return func() { revokedServiceDB, revokedLicense = s, l }
}
