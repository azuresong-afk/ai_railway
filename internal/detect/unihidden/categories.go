package unihidden

// Categories — все категории находок детектора (detect.Categorizer).
func (Detector) Categories() []string {
	return []string{CatTag, CatBidi, CatInvisible, CatHomoglyph}
}
