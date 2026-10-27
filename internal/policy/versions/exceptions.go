package versions

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/policy"
)

// Исключения в версиях политик (ТЗ 5.3; решение Р8 этапа 3, задача 3.22).
// Исключение живёт в YAML версии (policy.ExceptionSpec), поэтому каждое
// добавление, продление и удаление — новая неизменяемая версия с записью в
// журнал аудита той же транзакцией. Добавление, продление и изменение
// условия ослабляют защиту: повторная проверка паролем или кодом и признак
// weakening (правило DM-40). Автора и время изменения ставит сервер, срок
// считается от момента сохранения: подставить чужого автора или растянуть
// срок датой создания из YAML нельзя.

// Ошибки исключений.
var (
	ErrExceptionNotFound = errors.New("исключение не найдено")
)

// Действия журнала аудита для исключений.
const (
	ActionExceptionAdd    = "policy.exception_add"
	ActionExceptionExtend = "policy.exception_extend"
	ActionExceptionDelete = "policy.exception_delete"
)

// MaxExceptionInput — байт условия исключения в теле запроса (без пароля
// и комментария).
const MaxExceptionInput = 8 << 10

// ExceptionInput — условие и срок нового исключения (из API или
// черновика по событию).
type ExceptionInput struct {
	Detector string `json:"detector"`
	Category string `json:"category,omitempty"`
	Pattern  string `json:"pattern,omitempty"`
	Fragment string `json:"fragment,omitempty"`
	App      string `json:"app,omitempty"`
	User     string `json:"user,omitempty"`
	Source   string `json:"source,omitempty"`
	Reason   string `json:"reason"`
	// ExpiresInDays — срок в сутках от сохранения (1–365); 0 — ExpiresAt
	// или 30 суток.
	ExpiresInDays int `json:"expires_in_days,omitempty"`
	// ExpiresAt — точный конец действия; не вместе с ExpiresInDays.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// EventID — событие, по отметке которого создаётся исключение.
	EventID string `json:"event_id,omitempty"`
}

// Check проверяет условие, причину и форму срока; сам срок от текущего
// времени проверяется при сохранении.
func (in ExceptionInput) Check() error {
	if in.ExpiresInDays != 0 && in.ExpiresAt != nil {
		return invalidf("expires_in_days — не вместе с expires_at")
	}
	if limit := limitDays(in.Detector); in.ExpiresInDays < 0 || in.ExpiresInDays > limit {
		return invalidf("expires_in_days — от 1 до %d суток", limit)
	}
	// Срок от текущего времени проверяется при сохранении; здесь — условие
	// и причина тем же Validate, что у YAML политики.
	probe := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	e := policy.ExceptionSpec{ID: "exc-probe", Detector: in.Detector, Category: in.Category, Pattern: in.Pattern,
		Fragment: in.Fragment, App: in.App, User: in.User, Source: detect.Source(in.Source), Reason: in.Reason,
		Author: "user:probe", CreatedAt: probe, ExpiresAt: probe.Add(policy.DefaultExceptionTTL), Event: in.EventID}
	if err := (&policy.Spec{ID: "probe", Name: "probe", Version: 1, Mode: policy.Monitor,
		Exceptions: []policy.ExceptionSpec{e}}).Validate(); err != nil {
		return invalid(err)
	}
	return nil
}

// spec — исключение id с автором author, созданное в момент now.
func (in ExceptionInput) spec(id, author string, now time.Time) (policy.ExceptionSpec, error) {
	exp, err := expiry(in.ExpiresInDays, in.ExpiresAt, now, in.Detector)
	if err != nil {
		return policy.ExceptionSpec{}, err
	}
	return policy.ExceptionSpec{ID: id, Detector: in.Detector, Category: in.Category, Pattern: in.Pattern,
		Fragment: in.Fragment, App: in.App, User: in.User, Source: detect.Source(in.Source), Reason: in.Reason,
		Author: author, CreatedAt: now, ExpiresAt: exp, Event: in.EventID}, nil
}

// limitDays — наибольший срок исключения детектора в сутках.
func limitDays(detector string) int { return int(policy.ExceptionTTLLimit(detector).Hours() / 24) }

// expiry — конец действия: days суток от now или at; ни того ни другого —
// policy.DefaultExceptionTTL, но не дальше предела детектора. Срок — от 1
// секунды до policy.ExceptionTTLLimit (у канарейки — 7 суток, 3Н49 ревью 3.r4).
func expiry(days int, at *time.Time, now time.Time, detector string) (time.Time, error) {
	limit := policy.ExceptionTTLLimit(detector)
	switch {
	case days != 0 && at != nil:
		return time.Time{}, invalidf("expires_in_days — не вместе с expires_at")
	case days < 0 || days > limitDays(detector):
		return time.Time{}, invalidf("expires_in_days — от 1 до %d суток", limitDays(detector))
	case days > 0:
		return now.Add(time.Duration(days) * 24 * time.Hour), nil
	case at == nil:
		return now.Add(min(policy.DefaultExceptionTTL, limit)), nil
	}
	exp := at.UTC().Truncate(time.Second)
	if !exp.After(now) || exp.Sub(now) > limit {
		return time.Time{}, invalidf("expires_at — в будущем, не дальше %d суток от сохранения", limitDays(detector))
	}
	return exp, nil
}

// stampExceptions ставит автора и время сохранения новым и изменённым
// исключениям spec относительно prev (nil — новой политики): автор — by,
// created_at — now, срок проверяется от now. Неизменённые исключения и
// исключения отката (их содержимое уже сохранял сервер) остаются как есть.
// keep — список исключений не передан: переносятся исключения prev.
func stampExceptions(spec, prev *policy.Spec, by By, now time.Time, source string, keep bool) error {
	if keep && spec.Exceptions == nil && prev != nil {
		spec.Exceptions = slices.Clone(prev.Exceptions)
		return nil
	}
	old := map[string]policy.ExceptionSpec{}
	if prev != nil {
		for _, e := range prev.Exceptions {
			old[e.ID] = e
		}
	}
	for i := range spec.Exceptions {
		e := &spec.Exceptions[i]
		if p, ok := old[e.ID]; ok && sameException(p, *e) || source == SourceRollback {
			continue
		}
		exp := e.ExpiresAt
		var at *time.Time
		if !exp.IsZero() {
			at = &exp
		}
		end, err := expiry(0, at, now, e.Detector)
		if err != nil {
			return &InputError{Errs: []error{fmt.Errorf("exceptions[%d] (%s): %w", i, e.ID, err)}}
		}
		e.Author, e.CreatedAt, e.ExpiresAt = by.ref(), now, end
	}
	return nil
}

// sameException — исключения совпадают целиком (время — с точностью до
// секунды, в UTC).
func sameException(a, b policy.ExceptionSpec) bool {
	return a.Condition() == b.Condition() && a.Reason == b.Reason && a.Author == b.Author && a.Event == b.Event &&
		a.CreatedAt.Equal(b.CreatedAt) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// cloneSpec — копия спецификации, которую можно менять.
func cloneSpec(s *policy.Spec) *policy.Spec {
	c := *s
	c.Rules = slices.Clone(s.Rules)
	c.Exceptions = slices.Clone(s.Exceptions)
	c.Tools = s.Tools.Clone()
	return &c
}

// newExceptionID — ID исключения: exc- и 12 шестнадцатеричных цифр.
func (s *Service) newExceptionID() (string, error) {
	b := make([]byte, 6)
	if err := s.rnd.Read(b); err != nil {
		return "", err
	}
	return "exc-" + hex.EncodeToString(b), nil
}

// ExceptionStatus — исключение и его состояние в момент запроса.
type ExceptionStatus struct {
	policy.ExceptionSpec
	// Expired — срок истёк: шлюз исключение не применяет, хотя оно ещё в
	// версии политики.
	Expired bool
}

// Exceptions — исключения версии n политики slug (0 — текущая) с
// состоянием на сейчас.
func (s *Service) Exceptions(ctx context.Context, slug string, n int) (Doc, []ExceptionStatus, error) {
	d, err := s.Get(ctx, slug, n)
	if err != nil {
		return Doc{}, nil, err
	}
	now := s.now()
	out := make([]ExceptionStatus, 0, len(d.Spec.Exceptions))
	for _, e := range d.Spec.Exceptions {
		out = append(out, ExceptionStatus{ExceptionSpec: e, Expired: !e.Active(now)})
	}
	return d, out, nil
}

// AddException — новая версия политики slug поверх base с исключением in.
// Ослабление: нужна повторная проверка by.Confirm.
func (s *Service) AddException(ctx context.Context, by By, slug string, base int, in ExceptionInput, comment string) (Doc, policy.ExceptionSpec, error) {
	id, err := s.newExceptionID()
	if err != nil {
		return Doc{}, policy.ExceptionSpec{}, err
	}
	var added policy.ExceptionSpec
	d, err := s.mutate(ctx, by, slug, base, comment, ActionExceptionAdd, id, func(sp *policy.Spec, now time.Time) error {
		if len(sp.Exceptions) >= policy.MaxExceptions {
			return invalidf("не больше %d исключений в политике", policy.MaxExceptions)
		}
		e, err := in.spec(id, by.ref(), now)
		if err != nil {
			return err
		}
		sp.Exceptions = append(sp.Exceptions, e)
		added = e
		return nil
	})
	return d, added, err
}

// ExtendException — новая версия с другим сроком исключения id: days суток
// от сохранения или at. Продление — ослабление (повторная проверка), сокращение
// срока — нет. reason — новая причина; пусто — прежняя.
func (s *Service) ExtendException(ctx context.Context, by By, slug string, base int, id string, days int, at *time.Time,
	reason, comment string) (Doc, policy.ExceptionSpec, error) {
	var changed policy.ExceptionSpec
	d, err := s.mutate(ctx, by, slug, base, comment, ActionExceptionExtend, id, func(sp *policy.Spec, now time.Time) error {
		i := slices.IndexFunc(sp.Exceptions, func(e policy.ExceptionSpec) bool { return e.ID == id })
		if i < 0 {
			return ErrExceptionNotFound
		}
		e := &sp.Exceptions[i]
		exp, err := expiry(days, at, now, e.Detector)
		if err != nil {
			return err
		}
		e.ExpiresAt, e.CreatedAt, e.Author = exp, now, by.ref()
		if reason != "" {
			e.Reason = reason
		}
		changed = *e
		return nil
	})
	return d, changed, err
}

// DeleteException — новая версия без исключения id (усиление защиты:
// повторная проверка не нужна).
func (s *Service) DeleteException(ctx context.Context, by By, slug string, base int, id, comment string) (Doc, error) {
	return s.mutate(ctx, by, slug, base, comment, ActionExceptionDelete, id, func(sp *policy.Spec, _ time.Time) error {
		i := slices.IndexFunc(sp.Exceptions, func(e policy.ExceptionSpec) bool { return e.ID == id })
		if i < 0 {
			return ErrExceptionNotFound
		}
		sp.Exceptions = slices.Delete(sp.Exceptions, i, i+1)
		return nil
	})
}

// mutate — новая версия политики slug поверх base: fn меняет копию текущей
// спецификации под блокировкой политики. Запись аудита action с объектом
// политики и ID исключения, сводкой изменений и признаком weakening.
func (s *Service) mutate(ctx context.Context, by By, slug string, base int, comment, action, excID string,
	fn func(sp *policy.Spec, now time.Time) error) (Doc, error) {
	if policy.IsTemplate(slug) {
		return Doc{}, ErrTemplate
	}
	if base < 1 {
		return Doc{}, invalidf("base_version — номер версии, поверх которой сохраняется изменение")
	}
	if err := checkComment(comment); err != nil {
		return Doc{}, err
	}
	now := s.now().Truncate(time.Second)
	var out Doc
	p, v, err := s.store.AddVersion(ctx, s.orgID, slug, base, func(p Policy, cur Version) (Version, audit.Entry, error) {
		prev, err := cur.Spec()
		if err != nil {
			return Version{}, audit.Entry{}, fmt.Errorf("политики: текущая версия %s/%d не разбирается: %w", slug, cur.Version, err)
		}
		sp := cloneSpec(prev)
		if err := fn(sp, now); err != nil {
			return Version{}, audit.Entry{}, err
		}
		n := cur.Version + 1
		y, err := s.prepare(sp, slug, n, Defaults{NonText: prev.NonText})
		if err != nil {
			return Version{}, audit.Entry{}, err
		}
		v := s.newVersion(p.ID, n, y, SourceAPI, comment, by, s.now())
		diff := Compare(prev, sp)
		if diff.Weakened() {
			if err := by.confirm(ctx); err != nil {
				return Version{}, audit.Entry{}, err
			}
		}
		details := diff.details()
		details["slug"], details["from_version"], details["to_version"] = slug, cur.Version, n
		details["source"], details["spec_hash"], details["exception"] = SourceAPI, hex.EncodeToString(v.Hash), excID
		out.Spec = sp
		return v, by.entry(action, p.ID, details), nil
	})
	if err != nil {
		return Doc{}, err
	}
	out.Policy, out.Version = p, v
	return out, nil
}
