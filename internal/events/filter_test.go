package events

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestParseFilterPositive(t *testing.T) {
	for in, want := range map[string]string{
		"":                "",
		"   ":             "",
		`app = "crm-bot"`: `app = "crm-bot"`,
		`app="a" and severity in ("high","critical")`:                               `app = "a" and severity in ("high", "critical")`,
		`stream = true and has_content = false`:                                     `stream = true and has_content = false`,
		`threat in ("DM-05") and model != "x"`:                                      `threat = "DM-05" and model != "x"`,
		`action not in ("allow", "allow")`:                                          `action != "allow"`,
		`user not in ("a", "b")`:                                                    `user not in ("a", "b")`,
		"app = \"с \\\"кавычкой\\\" и \\\\\"":                                       "app = \"с \\\"кавычкой\\\" и \\\\\"",
		`detector = "pii.inn" and gateway = "01900000-0000-7000-8000-0000000000e1"`: `detector = "pii.inn" and gateway = "01900000-0000-7000-8000-0000000000e1"`,
		"type = \"check\"\n\tand storage = \"full\"":                                `type = "check" and storage = "full"`,
		`app = "Приложение 1"`:                                                      `app = "Приложение 1"`,
	} {
		f, err := ParseFilter(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := f.String(); got != want {
			t.Errorf("%q: каноническая запись %q, ожидалась %q", in, got, want)
		}
	}
}

func TestParseFilterNegative(t *testing.T) {
	for _, in := range []string{
		`app`, `app =`, `app = crm`, `= "x"`, `nope = "x"`, `App = "x"`,
		`app = "x" or env = "y"`, `app = "x" and`, `app = "x" env = "y"`,
		`app == "x"`, `app ! "x"`, `app in "x"`, `app in ()`, `app in ("x"`, `app in ("x" "y")`,
		`app not ("x")`, `app = "x`, `app = "\n"`, `app = "\t"`, "app = \"\x7f\"", "app = \"\xff\"",
		`app = "a\b"`, `app = ""`, `stream = "true"`, `stream != true`, `stream in (true)`, `stream = yes`,
		`type = "other"`, `storage = "plain"`, `policy_mode = "audit"`, `threat = "DM-5"`, `threat = "dm-05"`,
		`gateway = "not-a-uuid"`, `gateway = "01900000-0000-7000-8000-0000000000E1"`, `detector = "Pii"`,
		`app = "x";`, `(app = "x")`, `app = 'x'`,
	} {
		if f, err := ParseFilter(in); err == nil {
			t.Errorf("%q принят: %v", in, f)
		}
	}
}

func TestParseFilterLimits(t *testing.T) {
	cond := `app = "x"`
	many := strings.Repeat(cond+" and ", MaxFilterConds-1) + cond
	if _, err := ParseFilter(many); err != nil {
		t.Fatalf("%d условий: %v", MaxFilterConds, err)
	}
	if _, err := ParseFilter(many + " and " + cond); err == nil {
		t.Fatal("условий больше предела")
	}
	vals := make([]string, MaxFilterValues)
	for i := range vals {
		vals[i] = strconv.Quote("v" + strconv.Itoa(i))
	}
	list := "app in (" + strings.Join(vals, ",") + ")"
	if _, err := ParseFilter(list); err != nil {
		t.Fatalf("%d значений: %v", MaxFilterValues, err)
	}
	if _, err := ParseFilter("app in (" + strings.Join(vals, ",") + `,"extra")`); err == nil {
		t.Fatal("значений больше предела")
	}
	// Повторы не считаются в предел и убираются.
	if f, err := ParseFilter("app in (" + strings.Join(vals, ",") + `,"v0")`); err != nil || len(f.Conds[0].Values) != MaxFilterValues {
		t.Fatalf("повтор: %v %v", f, err)
	}
	long := `app = "` + strings.Repeat("я", MaxFilterValue/2) + `"`
	if _, err := ParseFilter(long); err != nil {
		t.Fatalf("значение %d байт: %v", MaxFilterValue, err)
	}
	if _, err := ParseFilter(`app = "` + strings.Repeat("a", MaxFilterValue+1) + `"`); err == nil {
		t.Fatal("значение длиннее предела")
	}
	if _, err := ParseFilter(strings.Repeat(" ", MaxFilterLen+1)); !errors.Is(err, ErrFilterTooLong) {
		t.Fatalf("длина: %v", err)
	}
}

func TestFilterErrorPosition(t *testing.T) {
	_, err := ParseFilter(`app = "x" and nope = "y"`)
	var fe *FilterError
	if !errors.As(err, &fe) || fe.Pos != 14 || !strings.Contains(fe.Error(), "позиция 14") {
		t.Fatalf("ошибка %v", err)
	}
	// Текст ошибки не повторяет ввод пользователя.
	if strings.Contains(fe.Error(), "nope") {
		t.Fatalf("ошибка повторяет ввод: %v", fe)
	}
}

// SQL содержит только константы кода и ссылки $N; значения — в параметрах.
func TestFilterSQLParameterized(t *testing.T) {
	evil := `x'); DROP TABLE events; --`
	f, err := ParseFilter(`app = "` + evil + `" and threat not in ("DM-01","DM-02") and stream = true and ` +
		`detector != "pii.inn" and gateway in ("01900000-0000-7000-8000-0000000000e1", "01900000-0000-7000-8000-0000000000e2") and env != "p"`)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	a := &sqlArgs{args: []any{"org"}}
	f.appendSQL(&b, a)
	sql := b.String()
	if strings.Contains(sql, "DROP") || strings.Contains(sql, "DM-01") || strings.Contains(sql, "pii.inn") || strings.Contains(sql, "'p'") {
		t.Fatalf("значение пользователя в SQL: %s", sql)
	}
	want := ` AND e.app = ANY($2::text[]) AND NOT (e.threats && $3::text[]) AND e.stream = $4 AND ` +
		`NOT EXISTS (SELECT 1 FROM jsonb_array_elements(COALESCE(e.details->'findings', '[]'::jsonb)) AS f WHERE f->>'detector' = ANY($5::text[])) AND ` +
		`e.gateway_id = ANY($6::uuid[]) AND (e.env IS NULL OR e.env <> ALL($7::text[]))`
	if sql != want {
		t.Fatalf("SQL:\n%s\nожидался:\n%s", sql, want)
	}
	if !reflect.DeepEqual(a.args[1], []string{evil}) || a.args[3] != true || len(a.args) != 7 {
		t.Fatalf("параметры %v", a.args)
	}

	// Значение, совпадающее с частью SQL (корпус fuzz value-substring-of-sql),
	// тоже уходит только параметром.
	f, err = ParseFilter(`app = "p = "`)
	if err != nil {
		t.Fatal(err)
	}
	b.Reset()
	a = &sqlArgs{}
	f.appendSQL(&b, a)
	if b.String() != ` AND e.app = ANY($1::text[])` || !reflect.DeepEqual(a.args, []any{[]string{"p = "}}) {
		t.Fatalf("SQL %q, параметры %v", b.String(), a.args)
	}
}

func TestBuildQueryShape(t *testing.T) {
	s := &PGStore{orgID: "org"}
	f, err := ParseFilter(`app = "x"`)
	if err != nil {
		t.Fatal(err)
	}
	q := Query{From: eventsT0, To: eventsT0.Add(MaxQueryRange), Filter: f, After: &Position{TS: eventsT0, ID: "id"}, Limit: 51}
	sql, args := s.buildQuery(&q, 0)
	for _, part := range []string{"LEFT JOIN event_marks m ON m.event_id = e.id AND m.event_ts = e.ts AND m.org_id = e.org_id WHERE e.org_id = $1", "e.ts >= $2 AND e.ts < $3", "(e.ts, e.id) < ($4, $5::uuid)",
		"e.app = ANY($6::text[])", "ORDER BY e.ts DESC, e.id DESC LIMIT $7"} {
		if !strings.Contains(sql, part) {
			t.Errorf("нет %q в %s", part, sql)
		}
	}
	if strings.Contains(sql, "event_content") || strings.Contains(sql, "details") {
		t.Errorf("список читает содержимое или details: %s", sql)
	}
	if len(args) != 7 {
		t.Fatalf("параметров %d", len(args))
	}
	q.After, q.ReceivedBefore = nil, eventsT0
	sql, _ = s.buildQuery(&q, MaxExportRows)
	if !strings.HasPrefix(sql, "SELECT count(*) FROM (SELECT 1 FROM events e") || !strings.Contains(sql, "e.received_at <= $4") ||
		!strings.HasSuffix(sql, "LIMIT $6) AS s") {
		t.Fatalf("подсчёт: %s", sql)
	}
	q.WithDetails = true
	if sql, _ = s.buildQuery(&q, 0); !strings.Contains(sql, ", e.details FROM events e") || strings.Contains(sql, "event_content") {
		t.Fatalf("выгрузка JSON: %s", sql)
	}
}

func TestFilterMatch(t *testing.T) {
	r := &Record{App: "crm", Type: TypeCheck, Threats: []string{"DM-05", "DM-13"}, Stream: true,
		Details: &Details{Findings: []Finding{{Detector: "pii.inn"}}}}
	for in, want := range map[string]bool{
		``:                                 true,
		`app = "crm"`:                      true,
		`app != "crm"`:                     false,
		`env != "prod"`:                    true, // нет значения — «не равно»
		`env = "prod"`:                     false,
		`threat = "DM-13"`:                 true,
		`threat not in ("DM-01", "DM-05")`: false,
		`detector = "pii.inn"`:             true,
		`detector != "secret.aws"`:         true,
		`stream = true and type = "check"`: true,
		`stream = false`:                   false,
		`has_content = false`:              true,
	} {
		f, err := ParseFilter(in)
		if err != nil {
			t.Fatal(in, err)
		}
		if got := f.Match(r); got != want {
			t.Errorf("%q: %v", in, got)
		}
	}
}

func FuzzParseFilter(f *testing.F) {
	for _, s := range []string{``, `app = "x"`, `severity in ("high", "critical") and stream = true`,
		`threat not in ("DM-01","DM-02")`, `app = "\"\\"`, `app in (`, `detector = "pii.inn"`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		flt, err := ParseFilter(s)
		if err != nil {
			return
		}
		if len(flt.Conds) > MaxFilterConds {
			t.Fatalf("условий %d", len(flt.Conds))
		}
		for _, c := range flt.Conds {
			if len(c.Values) == 0 || len(c.Values) > MaxFilterValues {
				t.Fatalf("значений %d", len(c.Values))
			}
			for _, v := range c.Values {
				if len(v) > MaxFilterValue || !utf8.ValidString(v) {
					t.Fatalf("значение %q", v)
				}
			}
		}
		// Каноническая запись разбирается в тот же фильтр.
		canon := flt.String()
		again, err := ParseFilter(canon)
		if err != nil {
			t.Fatalf("каноническая запись %q не разбирается: %v", canon, err)
		}
		if !reflect.DeepEqual(again, flt) || again.String() != canon {
			t.Fatalf("круг: %q → %q", canon, again.String())
		}
		// SQL — только константы и ссылки на параметры: тот же фильтр с
		// другими значениями даёт ту же строку SQL, а значения целиком
		// уходят параметрами. Поиск значения подстрокой в SQL здесь не
		// годится: «p = » — часть константы «e.app = ANY(».
		var b strings.Builder
		a := &sqlArgs{}
		flt.appendSQL(&b, a)
		probe := Filter{Conds: make([]Cond, len(flt.Conds))}
		for i, c := range flt.Conds {
			probe.Conds[i] = c
			if filterFields[c.Field].kind == kindBool {
				continue
			}
			probe.Conds[i].Values = make([]string, len(c.Values))
			for j := range c.Values {
				probe.Conds[i].Values[j] = "probe" + strconv.Itoa(i) + "_" + strconv.Itoa(j)
			}
		}
		var pb strings.Builder
		pa := &sqlArgs{}
		probe.appendSQL(&pb, pa)
		if pb.String() != b.String() {
			t.Fatalf("SQL зависит от значений:\n%s\n%s", b.String(), pb.String())
		}
		if len(a.args) != len(flt.Conds) {
			t.Fatalf("параметров %d, условий %d", len(a.args), len(flt.Conds))
		}
		for i, c := range flt.Conds {
			if filterFields[c.Field].kind == kindBool {
				if a.args[i] != (c.Values[0] == "true") {
					t.Fatalf("параметр %d: %v", i, a.args[i])
				}
			} else if !reflect.DeepEqual(a.args[i], c.Values) {
				t.Fatalf("параметр %d: %v, значения %q", i, a.args[i], c.Values)
			}
		}
	})
}

// ml_unavailable (задача 4.19): признак решения в details, значение — только
// параметром; без признака — false.
func TestFilterMLUnavailableSQL(t *testing.T) {
	f, err := ParseFilter(`ml_unavailable = true and app = "crm"`)
	if err != nil {
		t.Fatal(err)
	}
	if f.String() != `ml_unavailable = true and app = "crm"` {
		t.Fatalf("запись: %s", f.String())
	}
	var b strings.Builder
	a := &sqlArgs{}
	f.appendSQL(&b, a)
	want := ` AND COALESCE((e.details->'decision'->>'ml_unavailable')::boolean, false) = $1 AND e.app = ANY($2::text[])`
	if b.String() != want || a.args[0] != true {
		t.Fatalf("SQL %q, параметры %v", b.String(), a.args)
	}
	for _, bad := range []string{`ml_unavailable != true`, `ml_unavailable = "yes"`, `ml_unavailable in (true)`} {
		if _, err := ParseFilter(bad); err == nil {
			t.Errorf("%q: принято", bad)
		}
	}
	r := &Record{Details: &Details{Decision: &Decision{MLUnavailable: true}}}
	g, err := ParseFilter(`ml_unavailable = false`)
	if err != nil {
		t.Fatal(err)
	}
	if g.Match(r) || !g.Match(&Record{}) {
		t.Fatal("Match ml_unavailable = false")
	}
}
