package audit

import (
	"strings"
	"testing"
	"time"
)

func validQuery() Query {
	to := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return Query{From: to.Add(-24 * time.Hour), To: to, Limit: 51}
}

func TestQueryValidate(t *testing.T) {
	ok := []func(*Query){
		func(*Query) {},
		func(q *Query) { q.From = q.To.Add(-MaxQueryRange) },
		func(q *Query) { q.Limit = MaxQueryLimit },
		func(q *Query) {
			q.Actions, q.Groups = make([]string, 10), make([]string, 10)
			for i := range q.Actions {
				q.Actions[i], q.Groups[i] = "auth.login", "api_token"
			}
		},
		func(q *Query) { q.ActorType, q.Result, q.Actor = ActorCLI, ResultDenied, strings.Repeat("я", 128) },
	}
	for i, f := range ok {
		q := validQuery()
		f(&q)
		if err := q.Validate(); err != nil {
			t.Errorf("допустимая выборка %d отклонена: %v", i, err)
		}
	}
	bad := map[string]func(*Query){
		"нет периода":       func(q *Query) { q.From = time.Time{} },
		"from = to":         func(q *Query) { q.From = q.To },
		"длиннее 31 суток":  func(q *Query) { q.From = q.To.Add(-MaxQueryRange - time.Second) },
		"limit 0":           func(q *Query) { q.Limit = 0 },
		"limit больше":      func(q *Query) { q.Limit = MaxQueryLimit + 1 },
		"21 код":            func(q *Query) { q.Actions = make([]string, 21) },
		"код с шаблоном":    func(q *Query) { q.Actions = []string{"auth.%"} },
		"код без точки":     func(q *Query) { q.Actions = []string{"auth"} },
		"группа с точкой":   func(q *Query) { q.Groups = []string{"auth."} },
		"группа с _ в нач.": func(q *Query) { q.Groups = []string{"_auth"} },
		"тип субъекта":      func(q *Query) { q.ActorType = "root" },
		"результат":         func(q *Query) { q.Result = "ok" },
		"курсор":            func(q *Query) { q.After = &Position{Seq: 0} },
		"длинный объект":    func(q *Query) { q.ObjectID = strings.Repeat("x", maxObjectID+1) },
	}
	for name, f := range bad {
		q := validQuery()
		f(&q)
		if err := q.Validate(); err == nil {
			t.Errorf("%s: выборка принята", name)
		}
	}
}

// Значения пользователя не попадают в текст SQL: только параметры.
func TestBuildListParameterized(t *testing.T) {
	q := validQuery()
	q.Actions, q.Groups = []string{"auth.login"}, []string{"user"}
	q.ActorType, q.Actor, q.ObjectType, q.ObjectID, q.Result = ActorUser, "x' OR '1'='1", "role", "sec_admin", ResultDenied
	q.After = &Position{TS: q.To.Add(-time.Hour), Seq: 42}
	sql, args := buildList(&q)
	for _, v := range []string{"x' OR", "sec_admin", "auth.login", "user.", "42"} {
		if strings.Contains(sql, v) {
			t.Errorf("значение %q в тексте SQL: %s", v, sql)
		}
	}
	// Курсор в периоде: части с не конечным временем нет, (ts, seq) — параметрами.
	if len(args) != 13 || strings.Contains(sql, "NOT isfinite") || !strings.Contains(sql, "(ts, seq) < ($12, $13)") ||
		!strings.HasSuffix(sql, "seq DESC LIMIT $11") {
		t.Errorf("параметров %d: %s", len(args), sql)
	}
	if g, ok := args[4].([]string); !ok || len(g) != 1 || g[0] != "user." {
		t.Errorf("группа: %#v", args[4])
	}
	// Без курсора и с курсором в части с не конечным временем — обе части,
	// период — без «OR» (В17 ревью 2.r3b).
	for _, after := range []*Position{nil, {Seq: 7}} {
		q.After = after
		sql, _ = buildList(&q)
		if strings.Count(sql, "NOT isfinite(ts)") != 1 || !strings.Contains(sql, "UNION ALL") || strings.Contains(sql, " OR NOT") ||
			!strings.Contains(sql, "ts >= $2 AND ts < $3") || (after != nil) != strings.Contains(sql, "AND seq < $12") {
			t.Errorf("курсор %v: %s", after, sql)
		}
	}
}
