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
		"курсор":            func(q *Query) { q.BeforeSeq = -1 },
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
	q.ActorType, q.Actor, q.ObjectType, q.ObjectID, q.Result, q.BeforeSeq = ActorUser, "x' OR '1'='1", "role", "sec_admin", ResultDenied, 42
	sql, args := buildList(&q)
	for _, v := range []string{"x' OR", "sec_admin", "auth.login", "user.", "42"} {
		if strings.Contains(sql, v) {
			t.Errorf("значение %q в тексте SQL: %s", v, sql)
		}
	}
	if len(args) != 12 || !strings.HasSuffix(sql, "ORDER BY seq DESC LIMIT $12") {
		t.Errorf("параметров %d: %s", len(args), sql)
	}
	if g, ok := args[4].([]string); !ok || len(g) != 1 || g[0] != "user." {
		t.Errorf("группа: %#v", args[4])
	}
}
