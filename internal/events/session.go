package events

import (
	"errors"
	"fmt"
	"math"
	"regexp"
)

// Сессия запроса чата (ТЗ 5.1, 5.5; задачи 4.13 и 4.14 этапа 4). Шлюз
// пишет в событие псевдоним сессии — HMAC идентификатора из заголовка
// X-AISec-Session или отпечатка начала диалога на ключе шлюза, не исходное
// значение, — и оценку session.risk. Для history.integrity (DM-03) шлюз
// добавляет хеши реплик ассистента из истории запроса и хеши ответов,
// выданных приложению; сервер сверяет их при приёме (history.go) и в
// хранимые метаданные хешей не пишет: хеш — HMAC текста реплики.

// Источники идентификатора сессии.
const (
	SessionHeader      = "header"      // заголовок X-AISec-Session
	SessionFingerprint = "fingerprint" // отпечаток начала диалога
)

// Пределы сессии в событии.
const (
	// MaxHistoryReplies — хешей реплик ассистента из истории запроса:
	// последние по порядку диалога.
	MaxHistoryReplies = 64
	// MaxIssuedReplies — хешей ответов, выданных приложению (варианты n).
	MaxIssuedReplies = 16
)

// Session — сессия события gateway_request.
type Session struct {
	// ID — псевдоним сессии: 32 hex.
	ID string `json:"id"`
	// Source — откуда идентификатор: header или fingerprint.
	Source string `json:"source"`
	// Risk — оценка session.risk после этого хода, 0–1; Turns — ходов
	// сессии с учётом этого. Нули — политика без session.risk.
	Risk  float64 `json:"risk,omitempty"`
	Turns int     `json:"turns,omitempty"`
	// History — хеши реплик ассистента из истории запроса; хеши реплик
	// (History, Issued) есть, только если в политике приложения есть
	// правило history.integrity (HistoryRule, его действие и серьёзность).
	History         []Reply `json:"history,omitempty"`
	HistoryRule     string  `json:"history_rule,omitempty"`
	HistoryAction   string  `json:"history_action,omitempty"`
	HistorySeverity string  `json:"history_severity,omitempty"`
	// Issued — хеши ответов, выданных приложению в этом запросе.
	Issued []string `json:"issued,omitempty"`
}

// Reply — реплика ассистента из истории запроса: номер сообщения и хеш
// нормализованного текста (32 hex).
type Reply struct {
	Message int    `json:"message"`
	Hash    string `json:"hash"`
}

var (
	// historyActions — действия правила history.integrity: проверка идёт
	// после ответа, блокировать нечего (internal/detect/session).
	historyActions = map[string]bool{"allow": true, "log": true}
	severities     = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}
	sessionIDRe    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	ruleNameRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// validate проверяет сессию события.
func (s *Session) validate() []error {
	var errs []error
	if !sessionIDRe.MatchString(s.ID) {
		errs = append(errs, errors.New("session.id — 32 шестнадцатеричные цифры"))
	}
	if s.Source != SessionHeader && s.Source != SessionFingerprint {
		errs = append(errs, errors.New("session.source — header или fingerprint"))
	}
	if math.IsNaN(s.Risk) || s.Risk < 0 || s.Risk > 1 || s.Turns < 0 {
		errs = append(errs, errors.New("session.risk — от 0 до 1, session.turns — не меньше 0"))
	}
	if len(s.History) > MaxHistoryReplies || len(s.Issued) > MaxIssuedReplies {
		errs = append(errs, fmt.Errorf("session: не больше %d реплик истории и %d выданных ответов", MaxHistoryReplies, MaxIssuedReplies))
	}
	for _, r := range s.History {
		if r.Message < 0 || !sessionIDRe.MatchString(r.Hash) {
			errs = append(errs, errors.New("session.history: номер сообщения и хеш из 32 шестнадцатеричных цифр"))
			break
		}
	}
	for _, h := range s.Issued {
		if !sessionIDRe.MatchString(h) {
			errs = append(errs, errors.New("session.issued: хеш из 32 шестнадцатеричных цифр"))
			break
		}
	}
	switch {
	case s.HistoryRule != "" && (!ruleNameRe.MatchString(s.HistoryRule) || !historyActions[s.HistoryAction] || !severities[s.HistorySeverity]):
		errs = append(errs, errors.New("session: нужны правило, действие (allow или log) и серьёзность history.integrity"))
	case s.HistoryRule == "" && (len(s.History) > 0 || len(s.Issued) > 0 || s.HistoryAction != "" || s.HistorySeverity != ""):
		errs = append(errs, errors.New("session: хеши реплик — только с правилом history.integrity"))
	}
	return errs
}

// stored — сессия для хранимых метаданных: без хешей реплик.
func (s *Session) stored() *Session {
	if s == nil {
		return nil
	}
	return &Session{ID: s.ID, Source: s.Source, Risk: s.Risk, Turns: s.Turns}
}
