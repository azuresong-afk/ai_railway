// Пакет session — детекторы уровня запроса и сессии (ТЗ 5.2, этап 4;
// задачи 4.13 и 4.14): session.risk (DM-06), prompt.integrity (DM-26) и
// history.integrity (DM-03).
//
// Отдельный текст они не проверяют: находку session.risk и
// prompt.integrity даёт конвейер шлюза по состоянию сессии и эталону
// системного промпта приложения (internal/gateway, session.go и
// integrity.go), находку history.integrity — сервер при приёме событий по
// хешам ответов, выданных в сессии (internal/events, history.go). Здесь —
// их описания для реестра детекторов: политика называет их в правилах, а
// Compile проверяет направления, категории и допустимые действия.
//
// Здесь же — нормализация текста для сравнения по хешу (Normalize):
// эталон системного промпта и реплики ассистента сравниваются без учёта
// пробельных символов по краям и длины их последовательностей.
package session

import (
	"context"
	"encoding/hex"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect"
)

// ID, версии и категории детекторов.
const (
	RiskID      = "session.risk"
	RiskVersion = "1.0.0"
	// CatEscalation — накопленная оценка находок сессии (DM-06).
	CatEscalation = "session.escalation"

	PromptID      = "prompt.integrity"
	PromptVersion = "1.0.0"
	// CatPromptChanged — системный промпт запроса отличается от эталона;
	// CatPromptMissing — у приложения есть эталон, а системного промпта в
	// запросе нет (DM-26).
	CatPromptChanged = "prompt.changed"
	CatPromptMissing = "prompt.missing"

	HistoryID      = "history.integrity"
	HistoryVersion = "1.0.0"
	// CatHistoryForged — реплика ассистента в истории, которой шлюз в этой
	// сессии не выдавал (DM-03).
	CatHistoryForged = "history.forged"
)

// Строки матрицы обнаружения (ТЗ 5.16).
const (
	ThreatRisk    = "DM-06"
	ThreatPrompt  = "DM-26"
	ThreatHistory = "DM-03"
)

// Detector — описание детектора уровня запроса или сессии для реестра.
// Detect находок не даёт: Registry.Run его не запускает (RequestLevel).
type Detector struct {
	id, version string
	categories  []string
	actions     []string
}

// Risk — session.risk: оповещение или блокировка сессии по накопленной
// оценке (ТЗ 5.16, DM-06). Маскировать нечего: у находки нет позиций в
// тексте.
func Risk() Detector {
	return Detector{id: RiskID, version: RiskVersion, categories: []string{CatEscalation},
		actions: []string{"allow", "log", "block"}}
}

// Prompt — prompt.integrity: оповещение или блокировка при расхождении с
// эталоном (ТЗ 5.4, DM-26).
func Prompt() Detector {
	return Detector{id: PromptID, version: PromptVersion, categories: []string{CatPromptChanged, CatPromptMissing},
		actions: []string{"allow", "log", "block"}}
}

// History — history.integrity: проверка идёт на сервере после ответа
// приложению, поэтому правило только отмечает находку в событии (и
// поднимает оповещение), но не блокирует (ТЗ 5.16, DM-03).
func History() Detector {
	return Detector{id: HistoryID, version: HistoryVersion, categories: []string{CatHistoryForged},
		actions: []string{"allow", "log"}}
}

// All — детекторы пакета в порядке регистрации.
func All() []detect.Detector {
	return []detect.Detector{Risk(), Prompt(), History()}
}

// ID — идентификатор детектора.
func (d Detector) ID() string { return d.id }

// Version — версия детектора.
func (d Detector) Version() string { return d.version }

// Directions — только вход: сессия и эталон относятся к запросу.
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Input} }

// Categories — категории находок (detect.Categorizer).
func (d Detector) Categories() []string { return append([]string(nil), d.categories...) }

// Actions — допустимые действия правил (detect.ActionLimiter).
func (d Detector) Actions() []string { return append([]string(nil), d.actions...) }

// RequestLevel — детектор уровня запроса (detect.RequestLevel).
func (Detector) RequestLevel() bool { return true }

// Detect по отдельному тексту находок не даёт.
func (Detector) Detect(context.Context, detect.Text) ([]detect.Finding, error) { return nil, nil }

// MaxPrompt — предел эталона системного промпта, байт.
const MaxPrompt = 128 << 10

// promptDomain — разделитель назначения хеша эталона: хеш системного
// промпта не совпадает с хешем того же текста в другом назначении.
const promptDomain = "\x00aisec-prompt-baseline/1\x00"

// PromptHash — хеш эталона системного промпта для пакета конфигурации и
// сравнения в шлюзе: хеш криптопрофиля (SHA-256 или «Стрибог») от
// нормализованного текста (Normalize), 64 hex. Хеш не скрывает текст от
// перебора по словарю: сам текст хранится только зашифрованным, а хеш —
// в карточке приложения и в подписанном пакете шлюзов.
func PromptHash(h aisecCrypto.Hasher, text string) string {
	return hex.EncodeToString(h.Sum([]byte(promptDomain + Normalize(text))))
}

// Normalize приводит пробельные символы текста к одному виду: убирает их
// по краям, а каждую последовательность внутри заменяет одним пробелом
// U+0020. Пробельный символ — unicode.IsSpace: пробелы, табуляции,
// переводы строки и возврат каретки, неразрывный пробел и пробелы Unicode
// категории Zs. Прочие символы, в том числе невидимые (U+200B) и
// управление направлением текста, сохраняются: их появление меняет хеш.
func Normalize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	n := NewNormalizer(&b)
	n.WriteString(s)
	n.Flush()
	return b.String()
}

// Normalizer — Normalize потоком: текст ответа модели приходит частями, и
// часть может кончаться посреди символа UTF-8. Неполный символ ждёт
// продолжения; в конце (Flush) пишется как есть.
type Normalizer struct {
	w io.Writer
	// space — перед следующим символом нужен пробел; started — хотя бы
	// один символ уже записан (пробелы в начале не пишутся).
	space, started bool
	part           []byte
	buf            []byte
}

// NewNormalizer пишет нормализованный текст в w (обычно hash.Hash или
// strings.Builder: их запись не возвращает ошибок).
func NewNormalizer(w io.Writer) *Normalizer { return &Normalizer{w: w} }

// WriteString дописывает часть текста.
func (n *Normalizer) WriteString(s string) {
	if len(n.part) > 0 {
		// Неполный символ с конца прошлой части (до 3 байт) — перед новой
		// частью: разбор тот же, что у текста целиком.
		s = string(n.part) + s
		n.part = n.part[:0]
	}
	n.write(s)
	n.out()
}

// write нормализует s; неполный символ в конце откладывает в part.
func (n *Normalizer) write(s string) {
	for i := 0; i < len(s); {
		if !utf8.FullRuneInString(s[i:]) {
			n.part = append(n.part, s[i:]...)
			return
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if size == 1 && r == utf8.RuneError {
			// Неверный байт — как есть, отдельным символом.
			n.put(s[i : i+1])
		} else if unicode.IsSpace(r) {
			n.space = n.started
		} else {
			n.put(s[i : i+size])
		}
		i += size
	}
}

func (n *Normalizer) put(c string) {
	if n.space {
		n.buf = append(n.buf, ' ')
		n.space = false
	}
	n.buf = append(n.buf, c...)
	n.started = true
}

// out передаёт накопленное в w.
func (n *Normalizer) out() {
	if len(n.buf) > 0 {
		_, _ = n.w.Write(n.buf) //nolint:gosec // G104: запись в хеш и strings.Builder не возвращает ошибок
		n.buf = n.buf[:0]
	}
}

// Flush дописывает отложенный неполный символ как есть. Пробелы в конце
// не пишутся.
func (n *Normalizer) Flush() {
	if len(n.part) > 0 {
		for i := range n.part {
			n.put(string(n.part[i : i+1]))
		}
		n.part = n.part[:0]
	}
	n.out()
}
