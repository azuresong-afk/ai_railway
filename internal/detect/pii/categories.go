package pii

// Categories — все категории находок детектора (detect.Categorizer).
func (Detector) Categories() []string {
	return []string{CatSNILS, CatINN, CatOGRN, CatOGRNIP, CatCard, CatPassport, CatPhone, CatEmail, CatBirthdate, CatAccount}
}
