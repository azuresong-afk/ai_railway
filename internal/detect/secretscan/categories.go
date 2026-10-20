package secretscan

// Categories — все категории находок детектора (detect.Categorizer).
func (Detector) Categories() []string {
	return []string{CatPrivateKey, CatAPIKey, CatJWT, CatConnString, CatPassword, CatToken}
}
