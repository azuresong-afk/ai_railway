package shadowai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Исключения (задача 4.23, ADR-0027, дополнение 1): пользователи и сервисы,
// которые не учитываются в сводках и оповещениях. Типичный случай —
// учётная запись самого шлюза, которая ходит к провайдерам через прокси
// заказчика (ADR-0027, «Последствия»). Пользователь хранится только
// псевдонимом; логин, который ввёл администратор, нигде не сохраняется.

// Виды исключений.
const (
	ExcludeUser    = "user"
	ExcludeService = "service"
)

// Пределы исключений.
const (
	MaxExclusions       = 1000
	MaxExclusionComment = 200
)

// Ошибки исключений.
var (
	ErrNoUserKey         = errors.New("ключ псевдонимов пользователей не задан: пользователи не учитываются, исключать некого")
	ErrExclusionExists   = errors.New("такое исключение уже есть")
	ErrExclusionNotFound = errors.New("исключение не найдено")
	ErrTooManyExclusions = errors.New("исключений больше допустимого")
)

// weakeningExclusion — причина ослабления в аудите (DM-40).
const weakeningExclusion = "shadow_ai_exclusion"

// Exclusion — исключение. Value — псевдоним пользователя (32 hex) или ID
// сервиса каталога.
type Exclusion struct {
	Kind      string    `json:"kind"`
	Value     string    `json:"value"`
	Comment   string    `json:"comment"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
}

// ExclusionInput — новое исключение. Пользователь задаётся логином (или
// адресом клиента) из журнала — сервер сразу заменяет его псевдонимом — или
// готовым псевдонимом со страницы пользователей сервиса.
type ExclusionInput struct {
	Kind    string `json:"kind"`
	Login   string `json:"login,omitempty"`
	Alias   string `json:"alias,omitempty"`
	Service string `json:"service,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// Exclusions — множество исключённых псевдонимов и сервисов.
type Exclusions struct {
	users    map[string]struct{}
	services map[string]struct{}
}

// ExclusionsOf — множество по списку.
func ExclusionsOf(list []Exclusion) Exclusions {
	e := Exclusions{users: map[string]struct{}{}, services: map[string]struct{}{}}
	for _, x := range list {
		switch x.Kind {
		case ExcludeUser:
			e.users[x.Value] = struct{}{}
		case ExcludeService:
			e.services[x.Value] = struct{}{}
		}
	}
	return e
}

// Excludes — строка сервиса service от пользователя alias не учитывается.
func (e Exclusions) Excludes(service, alias string) bool {
	if _, ok := e.services[service]; ok {
		return true
	}
	if alias == "" {
		return false
	}
	_, ok := e.users[alias]
	return ok
}

// validAlias — псевдоним: 32 строчные шестнадцатеричные цифры.
func validAlias(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// validComment — до MaxExclusionComment символов UTF-8 без управляющих.
func validComment(s string) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > MaxExclusionComment {
		return false
	}
	for _, r := range s {
		if r < 0x20 || (r >= 0x7f && r < 0xa0) {
			return false
		}
	}
	return true
}

// exclusionOf проверяет ввод и возвращает исключение без автора.
func (s *Service) exclusionOf(in ExclusionInput) (Exclusion, error) {
	ex := Exclusion{Kind: in.Kind, Comment: strings.TrimSpace(in.Comment)}
	if !validComment(ex.Comment) {
		return Exclusion{}, &QueryError{fmt.Sprintf("comment — до %d символов без управляющих", MaxExclusionComment)}
	}
	switch in.Kind {
	case ExcludeService:
		if in.Login != "" || in.Alias != "" || !validServiceID(in.Service) {
			return Exclusion{}, &QueryError{"service — ID сервиса каталога, login и alias не задаются"}
		}
		ex.Value = in.Service
	case ExcludeUser:
		if in.Service != "" || (in.Login == "") == (in.Alias == "") {
			return Exclusion{}, &QueryError{"для пользователя задаётся ровно одно из login и alias"}
		}
		if s.o.UserMAC == nil {
			return Exclusion{}, ErrNoUserKey
		}
		if in.Alias != "" {
			if !validAlias(in.Alias) {
				return Exclusion{}, &QueryError{"alias — псевдоним пользователя, 32 шестнадцатеричные цифры"}
			}
			ex.Value = in.Alias
			break
		}
		// Тот же разбор, что у строк журнала: псевдоним совпадёт со сводками.
		login, err := cleanUser(in.Login)
		if err != nil || login == "" {
			return Exclusion{}, &QueryError{fmt.Sprintf("login — логин или адрес из журнала, до %d байт без управляющих", maxUserLen)}
		}
		ex.Value = pseudonym(s.o.UserMAC, login)
	default:
		return Exclusion{}, &QueryError{"kind — user или service"}
	}
	return ex, nil
}

// ListExclusions — исключения по виду и значению.
func (s *Service) ListExclusions(ctx context.Context) ([]Exclusion, error) {
	return s.o.Store.Exclusions(ctx, s.o.OrgID)
}

// exclusions — действующее множество исключений (кэш сервиса).
func (s *Service) exclusions(ctx context.Context) (Exclusions, error) {
	s.mu.Lock()
	ex, ok, gen := s.excl, s.exclLoaded, s.exclGen
	s.mu.Unlock()
	if ok {
		return ex, nil
	}
	list, err := s.o.Store.Exclusions(ctx, s.o.OrgID)
	if err != nil {
		return Exclusions{}, err
	}
	ex = ExclusionsOf(list)
	s.mu.Lock()
	// Список изменился, пока читали: в кэш не кладём, следующий вызов
	// перечитает (4.23-3).
	if s.exclGen == gen {
		s.excl, s.exclLoaded = ex, true
	}
	s.mu.Unlock()
	return ex, nil
}

func (s *Service) dropExclusionCache() {
	s.mu.Lock()
	s.excl, s.exclLoaded = Exclusions{}, false
	s.exclGen++
	s.mu.Unlock()
}

// AddExclusion добавляет исключение. Накопленные сводки исключённого
// пользователя или сервиса удаляются той же транзакцией: исключение
// скрывает данные от анализа и оповещений, поэтому это ослабление (DM-40) —
// с повторной проверкой паролем или кодом и weakening в аудите.
func (s *Service) AddExclusion(ctx context.Context, by By, in ExclusionInput) (Exclusion, error) {
	ex, err := s.exclusionOf(in)
	if err != nil {
		return Exclusion{}, err
	}
	if by.Confirm == nil {
		return Exclusion{}, ErrConfirmNeeded
	}
	if err := by.Confirm(ctx); err != nil {
		return Exclusion{}, err
	}
	ex.CreatedAt, ex.CreatedBy = s.o.Clock().UTC(), by.ref()
	err = s.o.Store.AddExclusion(ctx, s.o.OrgID, ex, func(deleted int64) audit.Entry {
		d := map[string]any{"kind": ex.Kind, "value": ex.Value, "deleted_rows": deleted,
			"weakening": true, "weakening_reasons": []string{weakeningExclusion}}
		if ex.Comment != "" {
			d["comment"] = ex.Comment
		}
		return by.entry("shadow_ai.exclusion_added", audit.Object{Type: "shadow_ai_exclusion", ID: ex.Kind + ":" + ex.Value}, d)
	})
	s.dropExclusionCache()
	if err != nil {
		return Exclusion{}, err
	}
	s.refreshSyslog(ctx)
	return ex, nil
}

// RemoveExclusion снимает исключение: следующие строки снова учитываются,
// удалённые при добавлении сводки не возвращаются.
func (s *Service) RemoveExclusion(ctx context.Context, by By, kind, value string) error {
	switch {
	case kind == ExcludeUser && validAlias(value):
	case kind == ExcludeService && validServiceID(value):
	default:
		return ErrExclusionNotFound
	}
	rec := by.entry("shadow_ai.exclusion_removed", audit.Object{Type: "shadow_ai_exclusion", ID: kind + ":" + value},
		map[string]any{"kind": kind, "value": value})
	err := s.o.Store.RemoveExclusion(ctx, s.o.OrgID, kind, value, rec)
	s.dropExclusionCache()
	if err == nil {
		s.refreshSyslog(ctx)
	}
	return err
}
