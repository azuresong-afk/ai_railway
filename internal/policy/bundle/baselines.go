package bundle

import (
	"errors"
	"fmt"
)

// Эталоны системного промпта (ТЗ 5.4, DM-26; задача 4.14 этапа 4).
// Раздел prompt_baselines: хеш нормализованного текста эталона
// (session.PromptHash) и режим контроля приложения. Сам текст в пакет не
// попадает: он хранится только на сервере, зашифрованным ключом данных.
// Приложения с выключенным контролем в разделе нет.

// Режимы контроля эталона в пакете.
const (
	PromptModeAlert = "alert"
	PromptModeBlock = "block"
)

// PromptBaseline — эталон приложения в пакете.
type PromptBaseline struct {
	App  string `json:"app"`
	Hash string `json:"hash"`
	Mode string `json:"mode"`
}

// validateBaselines — эталон только у приложения пакета (не исключённого),
// один на приложение, хеш — 64 hex, режим — alert или block.
func validateBaselines(bs []PromptBaseline, apps map[string]bool) []error {
	if len(bs) > MaxApplications {
		return []error{fmt.Errorf("prompt_baselines: больше %d эталонов", MaxApplications)}
	}
	var errs []error
	seen := map[string]bool{}
	for i, b := range bs {
		at := fmt.Sprintf("prompt_baselines[%d] (%s)", i, short(b.App))
		if !apps[b.App] || seen[b.App] {
			errs = append(errs, fmt.Errorf("%s: приложения нет в пакете или эталон указан дважды", at))
		}
		seen[b.App] = true
		if !sha256Re.MatchString(b.Hash) {
			errs = append(errs, fmt.Errorf("%s: hash — 64 шестнадцатеричные цифры", at))
		}
		if b.Mode != PromptModeAlert && b.Mode != PromptModeBlock {
			errs = append(errs, errors.New(at+": mode — alert или block"))
		}
	}
	return errs
}
