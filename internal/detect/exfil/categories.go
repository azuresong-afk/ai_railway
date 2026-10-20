package exfil

// Categories — все категории находок детектора (detect.Categorizer).
func (Detector) Categories() []string {
	return []string{CatImage, CatLink, CatDataURI, CatActive}
}
