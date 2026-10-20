package injection

// Categories — все категории находок детектора (detect.Categorizer).
func (Detector) Categories() []string {
	return []string{CatOverride, CatRole, CatLeak, CatStructure, CatObfuscation}
}
