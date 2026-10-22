package audit

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Просмотр журнала аудита в консоли (ТЗ 6.3 п. 11, задача 2.4a): выборка с
// фильтрами по белому списку полей. Записи только читаются; маскирование
// секретов сделано при записи (record.go), исходных значений в БД нет.

// Пределы выборки.
const (
	// MaxQueryRange — наибольший период выборки.
	MaxQueryRange = 31 * 24 * time.Hour
	// MaxQueryLimit — наибольшее число записей за запрос.
	MaxQueryLimit = 1000
	// MaxQueryActions — наибольшее число кодов и групп в фильтре.
	MaxQueryActions = 20
	// QueryTimeout — предел на выборку, если у контекста нет своего срока.
	QueryTimeout = 10 * time.Second
)

// ErrBadQuery — параметры выборки неверны (ошибка вызывающего кода: API
// проверяет их раньше и отвечает 400 с полями).
var ErrBadQuery = errors.New("журнал аудита: неверные параметры выборки")

// actionCode — код события, как в CHECK таблицы audit_log.
var actionCode = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// actionGroup — группа кодов без завершающей точки: «auth», «api_token».
var actionGroup = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// ValidAction — строка имеет вид кода события (не обязательно из перечня:
// в журнале есть и коды прежних версий).
func ValidAction(s string) bool { return len(s) <= 64 && actionCode.MatchString(s) }

// ValidActionGroup — строка имеет вид группы кодов без «.*».
func ValidActionGroup(s string) bool { return len(s) < 64 && actionGroup.MatchString(s) }

// Query — выборка записей журнала от новых к старым.
type Query struct {
	OrgID string    // пусто — организация по умолчанию
	From  time.Time // включительно
	To    time.Time // не включительно
	// Actions — точные коды; Groups — группы кодов: «auth» отбирает
	// auth.login и auth.mfa_failed. Запись подходит, если совпала с любым.
	Actions []string
	Groups  []string
	// ActorType — тип субъекта; пусто — любой.
	ActorType ActorType
	// Actor — точное совпадение с ID или именем субъекта (логином).
	Actor      string
	ObjectType string
	ObjectID   string
	// Result — итог; пусто — любой.
	Result Result
	// After — курсор: последняя запись предыдущей страницы; nil — с начала.
	After *Position
	Limit int
}

// Position — место записи в выборке. Записи идут от новых к старым по
// (TS, Seq); записи с не конечным временем (подмена в обход CHECK) — в
// начале выборки по Seq, у них TS нулевое.
type Position struct {
	TS  time.Time
	Seq int64
}

// Validate проверяет период, пределы и значения из белых списков.
func (q *Query) Validate() error {
	switch {
	case q.From.IsZero() || q.To.IsZero() || !q.From.Before(q.To) || q.To.Sub(q.From) > MaxQueryRange:
		return fmt.Errorf("%w: период", ErrBadQuery)
	case q.Limit < 1 || q.Limit > MaxQueryLimit:
		return fmt.Errorf("%w: limit", ErrBadQuery)
	case len(q.Actions)+len(q.Groups) > MaxQueryActions:
		return fmt.Errorf("%w: коды событий", ErrBadQuery)
	case q.After != nil && q.After.Seq < 1:
		return fmt.Errorf("%w: курсор", ErrBadQuery)
	case utf8.RuneCountInString(q.Actor) > maxActorName || utf8.RuneCountInString(q.ObjectType) > maxObjectType ||
		utf8.RuneCountInString(q.ObjectID) > maxObjectID:
		return fmt.Errorf("%w: длина значения", ErrBadQuery)
	}
	for _, a := range q.Actions {
		if !ValidAction(a) {
			return fmt.Errorf("%w: код события", ErrBadQuery)
		}
	}
	for _, g := range q.Groups {
		if !ValidActionGroup(g) {
			return fmt.Errorf("%w: группа событий", ErrBadQuery)
		}
	}
	switch q.ActorType {
	case "", ActorUser, ActorAPIToken, ActorSystem, ActorGateway, ActorCLI:
	default:
		return fmt.Errorf("%w: тип субъекта", ErrBadQuery)
	}
	switch q.Result {
	case "", ResultSuccess, ResultFailure, ResultDenied:
	default:
		return fmt.Errorf("%w: результат", ErrBadQuery)
	}
	return nil
}

// listColumns — столбцы записи в частях выборки и во внешнем SELECT.
const (
	listInner = `seq, id, org_id, ts, actor_type, actor_id, actor_name, source_ip, action,
		object_type, object_id, result, details, hash_alg, prev_hash, hash`
	listOuter = `seq, id::text, org_id::text, CASE WHEN isfinite(ts) THEN ts END, actor_type, actor_id, actor_name,
		host(source_ip), action, object_type, object_id, result, details::text, hash_alg, prev_hash, hash`
)

// buildList — SELECT выборки. Текст запроса собирается только из констант;
// значения пользователя — параметрами.
//
// Две части UNION ALL (В17 ревью 2.r3b): записи с не конечным временем — по
// частичному индексу audit_log_not_finite (обычно пусто), и период
// ts >= $2 AND ts < $3 по индексу (org_id, ts) с порядком (ts, seq) от
// новых к старым. Условие «период или не конечное время» в одной части не
// позволяло применить индекс: выборка шла назад по seq через весь журнал.
func buildList(q *Query) (string, []any) {
	org := q.OrgID
	if org == "" {
		org = DefaultOrgID
	}
	args := []any{org, q.From.UTC(), q.To.UTC()}
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	var f strings.Builder
	if len(q.Actions) > 0 || len(q.Groups) > 0 {
		// Группа сравнивается через starts_with, а не LIKE: «_» в кодах
		// был бы шаблоном.
		groups := make([]string, len(q.Groups))
		for i, g := range q.Groups {
			groups[i] = g + "."
		}
		actions := append([]string{}, q.Actions...)
		f.WriteString(" AND (action = ANY(" + arg(actions) + "::text[]) OR EXISTS (SELECT 1 FROM unnest(" +
			arg(groups) + "::text[]) AS g(p) WHERE starts_with(action, g.p)))")
	}
	if q.ActorType != "" {
		f.WriteString(" AND actor_type = " + arg(string(q.ActorType)))
	}
	if q.Actor != "" {
		p := arg(q.Actor)
		f.WriteString(" AND (actor_id = " + p + " OR actor_name = " + p + ")")
	}
	if q.ObjectType != "" {
		f.WriteString(" AND object_type = " + arg(q.ObjectType))
	}
	if q.ObjectID != "" {
		f.WriteString(" AND object_id = " + arg(q.ObjectID))
	}
	if q.Result != "" {
		f.WriteString(" AND result = " + arg(string(q.Result)))
	}
	filter := f.String()
	limit := arg(q.Limit)
	var b strings.Builder
	b.WriteString("SELECT " + listOuter + " FROM (")
	// Курсор в первой части (не конечное время) — продолжаем её по seq;
	// курсор во второй — первая часть уже выдана.
	if q.After == nil || q.After.TS.IsZero() {
		b.WriteString("(SELECT 0 AS part, " + listInner + " FROM audit_log WHERE org_id = $1::uuid AND NOT isfinite(ts)" + filter)
		if q.After != nil {
			b.WriteString(" AND seq < " + arg(q.After.Seq))
		}
		b.WriteString(" ORDER BY seq DESC LIMIT " + limit + ") UNION ALL ")
	}
	b.WriteString("(SELECT 1 AS part, " + listInner + " FROM audit_log WHERE org_id = $1::uuid AND ts >= $2 AND ts < $3" + filter)
	if q.After != nil && !q.After.TS.IsZero() {
		b.WriteString(" AND (ts, seq) < (" + arg(q.After.TS.UTC()) + ", " + arg(q.After.Seq) + ")")
	}
	b.WriteString(" ORDER BY ts DESC, seq DESC LIMIT " + limit + ")")
	b.WriteString(") AS q ORDER BY part, CASE WHEN part = 1 THEN ts END DESC, seq DESC LIMIT " + limit)
	return b.String(), args
}

// List возвращает записи выборки q от новых к старым. Запись, которой в
// обход CHECK записали не конечное время, попадает в любой период (в начале
// выборки) и возвращается с нулевым TS: просмотр не скрывает следы подмены,
// их находит проверка. Читает через пул чтения (WithReadDB), если он задан.
func (l *Log) List(ctx context.Context, q Query) ([]Record, error) {
	if err := q.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := withTimeout(ctx, QueryTimeout)
	defer cancel()
	sql, args := buildList(&q)
	rows, err := l.reader().Query(ctx, sql, args...)
	if err != nil {
		return nil, fmt.Errorf("журнал аудита: выборка: %w", err)
	}
	defer rows.Close()
	out := make([]Record, 0, min(q.Limit, 256))
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("журнал аудита: выборка: %w", err)
	}
	return out, nil
}
