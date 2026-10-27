package gateway

import (
	"fmt"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Эталон системного промпта и prompt.integrity (ТЗ 5.4, 5.16; задача 4.14
// этапа 4, DM-26). Эталон регистрирует владелец в карточке приложения; в
// пакет конфигурации попадают только хеш нормализованного текста
// (session.PromptHash) и режим контроля: alert — находка и оповещение,
// block — блокировка запроса. Режим «выключен» в пакет не попадает.
//
// Системный промпт запроса — начальные сообщения с ролью system или
// developer подряд: их текстовые части склеиваются через пробел, затем
// пробельные символы нормализуются (session.Normalize). Поэтому
// приложение может разбить промпт на части или сообщения по границам слов,
// поменять переводы строк и отступы — хеш тот же; любое другое изменение,
// в том числе невидимые символы, — расхождение. Системные сообщения
// посреди диалога не сравниваются: их добавляют приложения с RAG.
//
// Режим контроля превращается в служебное правило app.prompt_integrity в
// конце политики приложения: решение, режимы monitor и enforce, исключения
// и трассировка работают как у правил политики, а правило самой политики
// с prompt.integrity может только усилить действие.

// Режимы контроля эталона в пакете.
const (
	PromptModeAlert = "alert"
	PromptModeBlock = "block"
)

// RuleAppPrompt — служебное правило режима контроля эталона.
const RuleAppPrompt = "app.prompt_integrity"

// Места находки prompt.integrity в событии.
const (
	promptLocation        = "messages[0].content"
	promptMissingLocation = "messages"
)

// PromptBaseline — эталон приложения в шлюзе.
type PromptBaseline struct {
	// Hash — session.PromptHash эталона, 64 hex.
	Hash string
	// Mode — alert или block.
	Mode string
}

// promptCheck — сверка системного промпта приложения с эталоном.
type promptCheck struct {
	hash   string
	hasher aisecCrypto.Hasher
}

// SetPromptBaselines задаёт эталоны приложений (ID → эталон) и добавляет
// к их политикам служебное правило. Эталон неизвестного приложения или с
// неизвестным режимом — ошибка: пакет с ним не применяется. Вызывается до
// начала обслуживания запросов.
func (rt *Router) SetPromptBaselines(h aisecCrypto.Hasher, baselines map[string]PromptBaseline) error {
	if len(baselines) > 0 && h == nil {
		return fmt.Errorf("эталоны системного промпта: нет хеша криптопрофиля")
	}
	for id, b := range baselines {
		a, ok := rt.apps[id]
		if !ok {
			// Приложение исключено из пакета или его нет: эталон не нужен.
			continue
		}
		action := policy.Log
		switch b.Mode {
		case PromptModeAlert:
		case PromptModeBlock:
			action = policy.Block
		default:
			return fmt.Errorf("приложение %s: режим эталона системного промпта %q", id, b.Mode)
		}
		if !validHexHash(b.Hash) {
			return fmt.Errorf("приложение %s: хеш эталона системного промпта", id)
		}
		pol, err := a.Policy.WithRule(a.Detectors, policy.RuleSpec{ID: RuleAppPrompt, Detector: session.PromptID,
			Directions: []detect.Direction{detect.Input}, Action: action, Severity: policy.High})
		if err != nil {
			return fmt.Errorf("приложение %s: %w", id, err)
		}
		a.Policy, a.prompt = pol, &promptCheck{hash: b.Hash, hasher: h}
	}
	return nil
}

// validHexHash — 64 шестнадцатеричные цифры в нижнем регистре.
func validHexHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// systemPrompt — системный промпт запроса и есть ли он вообще.
func systemPrompt(req *chat.Request) (string, bool) {
	var parts []string
	for i := range req.Messages {
		m := &req.Messages[i]
		if m.Role != "system" && m.Role != "developer" {
			break
		}
		parts = append(parts, messageText(m, " "))
	}
	return strings.Join(parts, " "), len(parts) > 0
}

// promptFinding — находка prompt.integrity, если у приложения есть эталон
// и системный промпт запроса с ним расходится или его нет.
func (a *App) promptFinding(req *chat.Request) []locatedFinding {
	pc := a.prompt
	if pc == nil {
		return nil
	}
	text, ok := systemPrompt(req)
	f := locatedFinding{Finding: detect.Finding{Detector: session.PromptID, Version: session.PromptVersion,
		Threat: session.ThreatPrompt, Score: 1}, Text: -1, Location: promptLocation, Src: detect.SourceUser}
	switch {
	case !ok:
		f.Category, f.Location = session.CatPromptMissing, promptMissingLocation
	case session.PromptHash(pc.hasher, text) != pc.hash:
		f.Category = session.CatPromptChanged
	default:
		return nil
	}
	return []locatedFinding{f}
}
