package incidents

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/alerting"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// InputError — ошибки проверки ввода; текст каждой начинается с имени поля.
type InputError struct{ Errs []error }

func (e *InputError) Error() string { return errors.Join(e.Errs...).Error() }

func inputErr(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return &InputError{Errs: errs}
}

// textField проверяет длину текста в символах и отсутствие управляющих
// символов, кроме перевода строки и табуляции в многострочных полях.
func textField(errs *[]error, field, v string, lo, hi int, multiline bool) {
	if !utf8.ValidString(v) {
		*errs = append(*errs, fmt.Errorf("%s: текст не в UTF-8", field))
		return
	}
	n := utf8.RuneCountInString(v)
	switch {
	case n < lo && lo == 1:
		*errs = append(*errs, fmt.Errorf("%s: заполните поле", field))
		return
	case n > hi:
		*errs = append(*errs, fmt.Errorf("%s: не больше %d символов", field, hi))
		return
	}
	for _, r := range v {
		allowed := multiline && (r == '\n' || r == '\t' || r == '\r')
		if r < 0x20 && !allowed || r == 0x7f {
			*errs = append(*errs, fmt.Errorf("%s: недопустимый управляющий символ", field))
			return
		}
	}
}

// validID — UUID в канонической записи нижнего регистра (как ID в путях API).
func validID(s string) bool {
	_, err := store.ParseUUID(s)
	return err == nil
}

func validSeverity(s string) bool { return slices.Contains(alerting.Severities(), s) }

// CreateInput — тело создания инцидента. С AlertID название, серьёзность
// и категория по умолчанию берутся из оповещения; с ReopenOf — из
// закрытого инцидента.
type CreateInput struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	AlertID  string `json:"alert_id"`
	ReopenOf string `json:"reopen_of"`
}

// parseCreate проверяет тело создания; required — название, серьёзность и
// категория обязательны (создание без оповещения и прежнего инцидента).
func parseCreate(in CreateInput) error {
	var errs []error
	required := in.AlertID == "" && in.ReopenOf == ""
	if in.AlertID != "" && in.ReopenOf != "" {
		errs = append(errs, errors.New("reopen_of: укажите либо оповещение, либо закрытый инцидент"))
	}
	if in.AlertID != "" && !validID(in.AlertID) {
		errs = append(errs, errors.New("alert_id: укажите ID оповещения (UUID)"))
	}
	if in.ReopenOf != "" && !validID(in.ReopenOf) {
		errs = append(errs, errors.New("reopen_of: укажите ID инцидента (UUID)"))
	}
	if required || in.Title != "" {
		textField(&errs, "title", in.Title, 1, MaxTitle, false)
	}
	if (required || in.Severity != "") && !validSeverity(in.Severity) {
		errs = append(errs, errors.New("severity: одно из значений info, low, medium, high, critical"))
	}
	if required || in.Category != "" {
		if _, ok := LookupCategory(in.Category); !ok {
			errs = append(errs, errors.New("category: категория из справочника GET /api/v1/incident-categories"))
		}
	}
	return inputErr(errs)
}

// StatusInput — тело смены статуса: при закрытии резолюция обязательна.
type StatusInput struct {
	Status     string `json:"status"`
	Resolution string `json:"resolution"`
	Comment    string `json:"comment"`
}

// ParseStatusInput проверяет тело смены статуса.
func ParseStatusInput(in StatusInput) error {
	var errs []error
	if !slices.Contains([]string{StatusInProgress, StatusContained, StatusClosed}, in.Status) {
		errs = append(errs, errors.New("status: одно из значений in_progress, contained, closed"))
	}
	switch {
	case in.Status == StatusClosed && !slices.Contains(Resolutions(), in.Resolution):
		errs = append(errs, errors.New("resolution: при закрытии укажите resolved, false_positive или risk_accepted"))
	case in.Status != StatusClosed && in.Resolution != "":
		errs = append(errs, errors.New("resolution: резолюция указывается только при закрытии"))
	}
	textField(&errs, "comment", in.Comment, 0, MaxResolutionComment, true)
	return inputErr(errs)
}

// AssignInput — тело назначения: пустой user_id снимает ответственного.
type AssignInput struct {
	UserID *string `json:"user_id"`
}

func parseAssign(in AssignInput) error {
	if in.UserID == nil {
		return inputErr([]error{errors.New("user_id: укажите ID пользователя или пустую строку")})
	}
	if *in.UserID != "" && !validID(*in.UserID) {
		return inputErr([]error{errors.New("user_id: укажите ID пользователя (UUID)")})
	}
	return nil
}

// CommentInput — новый комментарий или правка (Replaces — ID прежней версии).
type CommentInput struct {
	Body     string `json:"body"`
	Replaces string `json:"replaces"`
}

func parseComment(in CommentInput) error {
	var errs []error
	textField(&errs, "body", in.Body, 1, MaxComment, true)
	if strings.TrimSpace(in.Body) == "" && len(errs) == 0 {
		errs = append(errs, errors.New("body: заполните поле"))
	}
	if in.Replaces != "" && !validID(in.Replaces) {
		errs = append(errs, errors.New("replaces: укажите ID комментария (UUID)"))
	}
	return inputErr(errs)
}

// StageInput — отметка этапа реагирования.
type StageInput struct {
	Note string `json:"note"`
}

func parseStage(key string, in StageInput) error {
	var errs []error
	if !slices.ContainsFunc(stageTemplate, func(s StageDef) bool { return s.Key == key }) {
		errs = append(errs, errors.New("stage: этап из шаблона intake, triage, containment, investigation"))
	}
	textField(&errs, "note", in.Note, 0, MaxStageNote, true)
	return inputErr(errs)
}

// LinkInput — связь оповещения с существующим инцидентом.
type LinkInput struct {
	AlertID string `json:"alert_id"`
}

func parseLink(in LinkInput) error {
	if !validID(in.AlertID) {
		return inputErr([]error{errors.New("alert_id: укажите ID оповещения (UUID)")})
	}
	return nil
}

// InstructionsInput — новая инструкция категории; Version — версия,
// которую открыли для правки (устаревшая — ErrVersionConflict).
type InstructionsInput struct {
	Body    string `json:"body"`
	Version int    `json:"version"`
}

func parseInstructions(in InstructionsInput) error {
	var errs []error
	textField(&errs, "body", in.Body, 0, MaxInstructions, true)
	if in.Version < 1 {
		errs = append(errs, errors.New("version: укажите версию, открытую для правки"))
	}
	return inputErr(errs)
}

// ParseQuery разбирает фильтры списка: каждый параметр не больше одного
// раза; status — статус или open (все незакрытые). Прочие параметры
// (limit, cursor) разбирает API.
func ParseQuery(v url.Values) (Query, error) {
	var q Query
	var errs []error
	one := func(name string, valid func(string) bool, detail string) string {
		vs, ok := v[name]
		if !ok {
			return ""
		}
		if len(vs) != 1 || !valid(vs[0]) {
			errs = append(errs, fmt.Errorf("%s: %s", name, detail))
			return ""
		}
		return vs[0]
	}
	q.Status = one("status", func(s string) bool { return s == StatusOpen || slices.Contains(Statuses(), s) },
		"одно из значений new, in_progress, contained, closed, open")
	q.Severity = one("severity", validSeverity, "одно из значений info, low, medium, high, critical")
	q.Category = one("category", func(s string) bool { _, ok := LookupCategory(s); return ok }, "категория из справочника")
	q.AssigneeID = one("assignee_id", validID, "ID пользователя (UUID)")
	q.Source = one("source", func(s string) bool {
		return slices.Contains([]string{SourceManual, SourceAlert, SourceAuto, SourceReopen}, s)
	}, "одно из значений manual, alert, auto, reopen")
	if len(errs) > 0 {
		return Query{}, &InputError{Errs: errs}
	}
	return q, nil
}
