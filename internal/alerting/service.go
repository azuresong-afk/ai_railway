package alerting

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// Ошибки.
var (
	ErrNotFound = errors.New("не найдено")
	// ErrExists — встроенное правило с этим ключом уже создано.
	ErrExists = errors.New("правило уже существует")
	// ErrVersionConflict — правило изменили после того, как его прочитал
	// автор запроса.
	ErrVersionConflict = errors.New("правило изменено другим пользователем")
	// ErrTransition — недопустимый переход статуса оповещения.
	ErrTransition = errors.New("недопустимый переход статуса")
	// ErrLocked — у встроенного правила безопасности меняются только получатели.
	ErrLocked = errors.New("у встроенного правила безопасности меняются только получатели")
	// ErrTooMany — достигнут предел числа правил.
	ErrTooMany = errors.New("достигнут предел числа правил")
	// ErrConfirmRequired — ослабление без повторной проверки субъекта.
	ErrConfirmRequired = errors.New("ослабление правила требует повторной проверки")
	// errNoBuiltin — встроенного правила нет (сервер не создал встроенные).
	errNoBuiltin = errors.New("оповещения: встроенное правило не создано")
	// errUnchanged — изменение ничего не меняет: записи нет.
	errUnchanged = errors.New("без изменений")
)

// Store — хранилище правил и оповещений. Рабочая реализация — PGStore,
// для тестов без PostgreSQL — Memory. Изменения пишутся одной транзакцией
// вместе с записью аудита.
type Store interface {
	Rules(ctx context.Context, orgID string) ([]Rule, error)
	Rule(ctx context.Context, orgID, id string) (Rule, error)
	// CountRules — правил администратора (без встроенных).
	CountRules(ctx context.Context, orgID string) (int, error)
	// CreateRule создаёт правило; встроенное с уже занятым ключом — ErrExists.
	CreateRule(ctx context.Context, r Rule, rec audit.Entry) error
	// UpdateRule меняет правило под блокировкой строки: fn получает текущее
	// правило и возвращает запись аудита и срабатывания встроенных правил.
	UpdateRule(ctx context.Context, orgID, id string, fn func(*Rule) (audit.Entry, []Raise, error)) (Rule, error)
	Alerts(ctx context.Context, orgID string, q AlertQuery) ([]Alert, error)
	Alert(ctx context.Context, orgID, id string) (Alert, error)
	AlertEvents(ctx context.Context, orgID, id string) ([]EventRef, error)
	AlertHistory(ctx context.Context, orgID, id string) ([]History, error)
	// UpdateAlert меняет оповещение под блокировкой строки и добавляет
	// переход в историю.
	UpdateAlert(ctx context.Context, orgID, id string, fn func(*Alert) (History, audit.Entry, error)) (Alert, error)
}

// Options — зависимости сервиса.
type Options struct {
	Store    Store
	Provider aisecCrypto.Provider
	OrgID    string
	Clock    func() time.Time
	// UserCheck — пользователь-получатель существует и активен; nil — не проверяется.
	UserCheck func(ctx context.Context, id string) error
	// RoleCheck — роль-получатель существует; nil — не проверяется.
	RoleCheck func(ctx context.Context, id string) error
	// Retention — срок хранения оповещений (PGStore); nil — по умолчанию,
	// без изменения.
	Retention RetentionStore
}

// Service — правила и оповещения для API консоли.
type Service struct {
	store     Store
	orgID     string
	clock     func() time.Time
	ids       *ids.Generator
	userCheck func(ctx context.Context, id string) error
	roleCheck func(ctx context.Context, id string) error
	retention RetentionStore
}

// New создаёт сервис.
func New(o Options) (*Service, error) {
	if o.Store == nil || o.Provider == nil {
		return nil, errors.New("оповещения: нет хранилища или криптопрофиля")
	}
	r, err := o.Provider.Random()
	if err != nil {
		return nil, err
	}
	if o.OrgID == "" {
		o.OrgID = audit.DefaultOrgID
	}
	if o.Clock == nil {
		o.Clock = time.Now
	}
	return &Service{store: o.Store, orgID: o.OrgID, clock: o.Clock, ids: ids.NewGenerator(r),
		userCheck: o.UserCheck, roleCheck: o.RoleCheck, retention: o.Retention}, nil
}

// By — субъект действия.
type By struct {
	Actor audit.Actor
	IP    netip.Addr
	// UserID — пользователь субъекта (у токена — его владелец): исполнитель
	// оповещения, принятого в работу.
	UserID string
	// Confirm — повторная проверка паролем или кодом TOTP перед ослаблением
	// правила (DM-40); nil — ослабление отклоняется с ErrConfirmRequired.
	Confirm func(ctx context.Context) error
}

func (b By) entry(action, objType, objID string, details any) audit.Entry {
	return audit.Entry{Actor: b.Actor, SourceIP: b.IP, Action: action, Object: audit.Object{Type: objType, ID: objID},
		Result: audit.ResultSuccess, Details: details}
}

// ref — субъект в полях created_by, closed_by и истории.
func (b By) ref() string {
	s := string(b.Actor.Type) + ":" + b.Actor.ID
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

func (b By) confirm(ctx context.Context) error {
	if b.Confirm == nil {
		return ErrConfirmRequired
	}
	return b.Confirm(ctx)
}

func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Microsecond) }

func (s *Service) newID() (string, error) {
	id, err := s.ids.New()
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

// Rules — все правила организации: встроенные и администратора.
func (s *Service) Rules(ctx context.Context) ([]Rule, error) { return s.store.Rules(ctx, s.orgID) }

// Rule — правило по ID.
func (s *Service) Rule(ctx context.Context, id string) (Rule, error) {
	return s.store.Rule(ctx, s.orgID, id)
}

// checkRecipients — получатели существуют (роли и активные пользователи).
func (s *Service) checkRecipients(ctx context.Context, rc Recipients) error {
	var errs []error
	if s.roleCheck != nil {
		for _, r := range rc.Roles {
			if err := s.roleCheck(ctx, r); err != nil {
				errs = append(errs, fmt.Errorf("recipients.roles: роли %s нет", r))
			}
		}
	}
	if s.userCheck != nil {
		for _, u := range rc.Users {
			if err := s.userCheck(ctx, u); err != nil {
				errs = append(errs, fmt.Errorf("recipients.users: пользователь %s не найден или не активен", u))
			}
		}
	}
	if len(errs) > 0 {
		return &InputError{Errs: errs}
	}
	return nil
}

// ruleDetails — правило в записи аудита.
func ruleDetails(r *Rule) map[string]any {
	return map[string]any{"name": r.Name, "kind": r.Kind, "enabled": r.Enabled, "severity": r.Severity,
		"condition": r.Condition, "group_by": r.GroupBy, "suppress_minutes": r.SuppressMinutes,
		"group_minutes": r.GroupMinutes, "recipients": r.Recipients, "version": r.Version}
}

// CreateRule создаёт правило «порог» или «новое» (право alert_rules.manage).
func (s *Service) CreateRule(ctx context.Context, by By, in RuleInput) (Rule, error) {
	r, err := ParseRuleInput(in, "")
	if err != nil {
		return Rule{}, err
	}
	if err := s.checkRecipients(ctx, r.Recipients); err != nil {
		return Rule{}, err
	}
	n, err := s.store.CountRules(ctx, s.orgID)
	if err != nil {
		return Rule{}, err
	}
	if n >= MaxRules {
		return Rule{}, ErrTooMany
	}
	if r.ID, err = s.newID(); err != nil {
		return Rule{}, err
	}
	now := s.now()
	r.OrgID, r.Version, r.CreatedAt, r.CreatedBy, r.UpdatedAt, r.UpdatedBy = s.orgID, 1, now, by.ref(), now, by.ref()
	rec := by.entry("alert_rule.create", "alert_rule", r.ID, ruleDetails(&r))
	if err := s.store.CreateRule(ctx, r, rec); err != nil {
		return Rule{}, err
	}
	return r, nil
}

// UpdateRule заменяет настройки правила (право alert_rules.manage).
// Ослабление (DM-40) пишется с weakening и требует повторной проверки;
// изменение получателей порождает оповещение (ТЗ 5.6).
func (s *Service) UpdateRule(ctx context.Context, by By, id string, in RuleInput) (Rule, error) {
	cur, err := s.store.Rule(ctx, s.orgID, id)
	if err != nil {
		return Rule{}, err
	}
	var next Rule
	if Locked(cur.Kind) {
		// У системных правил и правил безопасности меняются только получатели.
		rc, errs := parseRecipients(in.Recipients)
		if len(errs) > 0 {
			return Rule{}, &InputError{Errs: errs}
		}
		next = cur.clone()
		next.Recipients = rc
	} else if next, err = ParseRuleInput(in, cur.Kind); err != nil {
		return Rule{}, err
	}
	if err := s.checkRecipients(ctx, next.Recipients); err != nil {
		return Rule{}, err
	}
	r, err := s.store.UpdateRule(ctx, s.orgID, id, func(r *Rule) (audit.Entry, []Raise, error) {
		if in.Version != r.Version {
			return audit.Entry{}, nil, ErrVersionConflict
		}
		if Locked(r.Kind) {
			if lockedConflict(&in, r) {
				return audit.Entry{}, nil, ErrLocked
			}
			next = r.clone()
			rc, _ := parseRecipients(in.Recipients)
			next.Recipients = rc
		} else {
			next.GroupMinutes = r.GroupMinutes
		}
		recipientsChanged := !next.Recipients.equal(r.Recipients)
		if sameSettings(r, &next) && !recipientsChanged {
			return audit.Entry{}, nil, errUnchanged
		}
		reasons := Weakening(r, &next)
		if len(reasons) > 0 {
			if err := by.confirm(ctx); err != nil {
				return audit.Entry{}, nil, err
			}
		}
		before, beforeRecipients := ruleDetails(r), r.Recipients
		r.Name, r.Description, r.Enabled, r.Severity = next.Name, next.Description, next.Enabled, next.Severity
		r.Condition, r.GroupBy, r.SuppressMinutes, r.GroupMinutes = next.Condition, next.GroupBy, next.SuppressMinutes, next.GroupMinutes
		r.Recipients = next.Recipients
		r.Version++
		r.UpdatedAt, r.UpdatedBy = s.now(), by.ref()
		if reasons == nil {
			reasons = []string{}
		}
		rec := by.entry("alert_rule.update", "alert_rule", r.ID, map[string]any{"before": before, "after": ruleDetails(r),
			"weakening": len(reasons) > 0, "weakening_reasons": reasons, "recipients_changed": recipientsChanged})
		var raises []Raise
		if recipientsChanged {
			raises = append(raises, s.recipientsRaise(by, r, beforeRecipients))
		}
		return rec, raises, nil
	})
	if errors.Is(err, errUnchanged) {
		return s.store.Rule(ctx, s.orgID, id)
	}
	return r, err
}

// lockedConflict — запрос к правилу безопасности или системному меняет
// что-то кроме получателей: переданные поля должны совпадать с текущими.
func lockedConflict(in *RuleInput, r *Rule) bool {
	return in.Kind != "" && in.Kind != r.Kind || in.Name != "" && in.Name != r.Name ||
		in.Description != "" && in.Description != r.Description || in.Enabled != nil && *in.Enabled != r.Enabled ||
		in.Severity != "" && in.Severity != r.Severity || in.Condition != (Condition{}) && in.Condition != r.Condition ||
		len(in.GroupBy) > 0 && !slices.Equal(in.GroupBy, r.GroupBy) ||
		in.SuppressMinutes != nil && *in.SuppressMinutes != r.SuppressMinutes
}

// recipientsRaise — срабатывание правила «изменены получатели»: ключ —
// автор изменения, в подробностях — правило и списки до и после.
func (s *Service) recipientsRaise(by By, r *Rule, before Recipients) Raise {
	actor := by.Actor.Name
	if actor == "" {
		actor = by.Actor.ID
	}
	values := map[string]string{"actor": actor}
	item := map[string]any{"rule_id": r.ID, "rule_name": r.Name, "before": before, "after": r.Recipients,
		"at": r.UpdatedAt.Format(time.RFC3339Nano)}
	return Raise{Key: BuiltinRecipientsChanged, Trigger: Trigger{Key: "actor=" + by.ref(), Values: values, Count: 1,
		Details: map[string]any{"items": []any{item}}}}
}

// Alerts — страница оповещений от новых к старым.
func (s *Service) Alerts(ctx context.Context, q AlertQuery) ([]Alert, error) {
	return s.store.Alerts(ctx, s.orgID, q)
}

// AlertCard — оповещение со ссылками на события и историей.
type AlertCard struct {
	Alert   Alert
	Events  []EventRef
	History []History
}

// Alert — карточка оповещения.
func (s *Service) Alert(ctx context.Context, id string) (AlertCard, error) {
	a, err := s.store.Alert(ctx, s.orgID, id)
	if err != nil {
		return AlertCard{}, err
	}
	evs, err := s.store.AlertEvents(ctx, s.orgID, id)
	if err != nil {
		return AlertCard{}, err
	}
	h, err := s.store.AlertHistory(ctx, s.orgID, id)
	if err != nil {
		return AlertCard{}, err
	}
	return AlertCard{Alert: a, Events: evs, History: h}, nil
}

// SetStatus переводит оповещение: принять в работу или закрыть (право
// alerts.manage). Пишет историю и alert.status_changed.
func (s *Service) SetStatus(ctx context.Context, by By, id, to, comment string) (Alert, error) {
	var errs []error
	if to != StatusInProgress && to != StatusClosed {
		errs = append(errs, errors.New("status: in_progress или closed"))
	}
	textField(&errs, "comment", comment, 0, MaxComment)
	if len(errs) > 0 {
		return Alert{}, &InputError{Errs: errs}
	}
	hid, err := s.newID()
	if err != nil {
		return Alert{}, err
	}
	return s.store.UpdateAlert(ctx, s.orgID, id, func(a *Alert) (History, audit.Entry, error) {
		from := a.Status
		if !transitionAllowed(from, to) {
			return History{}, audit.Entry{}, ErrTransition
		}
		now := s.now()
		a.Status, a.UpdatedAt = to, now
		switch to {
		case StatusInProgress:
			a.AssigneeID = by.UserID
		case StatusClosed:
			a.ClosedAt, a.ClosedBy, a.Open = now, by.ref(), false
		}
		h := History{ID: hid, AlertID: a.ID, At: now, Actor: by.ref(), From: from, To: to, Comment: comment}
		rec := by.entry("alert.status_changed", "alert", a.ID, map[string]any{"from": from, "to": to,
			"rule_id": a.RuleID, "severity": a.Severity, "comment": comment != ""})
		return h, rec, nil
	})
}

// systemBy — субъект действий сервера (встроенные правила).
var systemBy = By{Actor: audit.Actor{Type: audit.ActorSystem, ID: "aisec-server", Name: "Сервер управления"}}

// EnsureBuiltins создаёт недостающие встроенные правила с записью
// alert_rule.create от имени сервера. Возвращает число созданных.
func (s *Service) EnsureBuiltins(ctx context.Context) (int, error) {
	have, err := s.store.Rules(ctx, s.orgID)
	if err != nil {
		return 0, err
	}
	created := 0
	for _, r := range builtinRules() {
		if slices.ContainsFunc(have, func(h Rule) bool { return h.BuiltinKey == r.BuiltinKey }) {
			continue
		}
		if r.ID, err = s.newID(); err != nil {
			return created, err
		}
		now := s.now()
		r.OrgID, r.Version, r.CreatedAt, r.CreatedBy, r.UpdatedAt, r.UpdatedBy = s.orgID, 1, now, systemBy.ref(), now, systemBy.ref()
		d := ruleDetails(&r)
		d["builtin"] = r.BuiltinKey
		err := s.store.CreateRule(ctx, r, systemBy.entry("alert_rule.create", "alert_rule", r.ID, d))
		switch {
		case errors.Is(err, ErrExists):
		case err != nil:
			return created, err
		default:
			created++
		}
	}
	return created, nil
}
