package policy

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/canary"
)

// Исключения в политике (задача 3.22 этапа 3).

var (
	excCreated = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	excExpires = excCreated.Add(DefaultExceptionTTL)
	excFrag    = strings.Repeat("ab", 16)
	excUser    = strings.Repeat("cd", 16)
)

func exceptionSpec(e ExceptionSpec) ExceptionSpec {
	if e.ID == "" {
		e.ID = "exc-1"
	}
	if e.Detector == "" {
		e.Detector = detInjection
	}
	if e.Reason == "" {
		e.Reason = "ложное срабатывание на инструкции поддержки"
	}
	if e.Author == "" {
		e.Author = "user:u1"
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = excCreated
	}
	if e.ExpiresAt.IsZero() {
		e.ExpiresAt = excExpires
	}
	return e
}

// blockingSpec — политика enforce, блокирующая инъекцию, с исключениями.
func blockingSpec(exc ...ExceptionSpec) *Spec {
	return &Spec{ID: "p", Name: "П", Version: 1, Mode: Enforce, Rules: []RuleSpec{
		{ID: "inj", Detector: detInjection, Directions: in, Action: Block, Severity: High},
	}, Exceptions: exc}
}

func injHit(rule, frag string) Hit {
	h := inj
	h.Finding.Rule = rule
	h.Fragment = frag
	return h
}

func TestExceptionApplied(t *testing.T) {
	now := excCreated.Add(time.Hour)
	cases := []struct {
		name    string
		exc     ExceptionSpec
		hit     Hit
		req     Request
		skipped bool
	}{
		{"совпадение по шаблону и приложению", ExceptionSpec{Pattern: "persona_removal", App: "support"},
			injHit("persona_removal", ""), Request{App: "support"}, true},
		{"совпадение по хешу фрагмента", ExceptionSpec{Fragment: excFrag},
			injHit("persona_removal", excFrag), Request{App: "any"}, true},
		{"совпадение по пользователю", ExceptionSpec{User: excUser, Category: "injection.override"},
			injHit("x", ""), Request{User: excUser}, true},
		{"другой шаблон", ExceptionSpec{Pattern: "persona_removal"},
			injHit("ignore_previous", ""), Request{}, false},
		{"другой фрагмент", ExceptionSpec{Fragment: excFrag},
			injHit("persona_removal", strings.Repeat("ef", 16)), Request{}, false},
		{"фрагмент без хеша в находке", ExceptionSpec{Fragment: excFrag},
			injHit("persona_removal", ""), Request{}, false},
		{"другое приложение", ExceptionSpec{App: "support"},
			injHit("persona_removal", ""), Request{App: "billing"}, false},
		{"другой пользователь", ExceptionSpec{User: excUser},
			injHit("persona_removal", ""), Request{User: excFrag}, false},
		{"другая категория", ExceptionSpec{App: "support", Category: "injection.persona"},
			injHit("x", ""), Request{App: "support"}, false},
		{"другой источник", ExceptionSpec{App: "support", Source: detect.SourceRAG},
			injHit("x", ""), Request{App: "support"}, false},
		{"другой детектор", ExceptionSpec{App: "support", Detector: detSecrets},
			injHit("x", ""), Request{App: "support"}, false},
		{"истёкшее", ExceptionSpec{App: "support", ExpiresAt: excCreated.Add(time.Minute)},
			injHit("x", ""), Request{App: "support"}, false},
		{"ровно в момент истечения", ExceptionSpec{App: "support", ExpiresAt: now},
			injHit("x", ""), Request{App: "support"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := exceptionSpec(c.exc)
			p := compile(t, blockingSpec(e))
			req := c.req
			req.Endpoint, req.Direction, req.Hits, req.Now = EndpointChat, detect.Input, []Hit{c.hit}, now
			d := p.Evaluate(req)
			if c.skipped {
				if d.Block || len(d.Excepted) != 1 || d.Excepted[0] != (Excepted{Hit: 0, Exception: e.ID}) || len(d.Matches) != 0 {
					t.Fatalf("находка должна быть пропущена: %+v", d)
				}
				return
			}
			if !d.Block || len(d.Excepted) != 0 {
				t.Fatalf("исключение не должно применяться: %+v", d)
			}
		})
	}
}

// Исключение пропускает только свою находку: другие находки запроса
// по-прежнему дают решение.
func TestExceptionSkipsOnlyItsHit(t *testing.T) {
	s := blockingSpec(exceptionSpec(ExceptionSpec{App: "support"}))
	s.Rules = append(s.Rules, RuleSpec{ID: "cards", Detector: detPII, Directions: in, Action: Redact, Severity: Medium})
	d := compile(t, s).Evaluate(Request{Endpoint: EndpointChat, Direction: detect.Input, App: "support",
		Hits: []Hit{injHit("x", ""), pii}, Now: excCreated})
	if d.Block || d.Action != Redact || len(d.Excepted) != 1 || d.Excepted[0].Hit != 0 || len(d.Matches) != 1 {
		t.Fatalf("решение: %+v", d)
	}
}

func TestExceptionTooBroadRejected(t *testing.T) {
	for _, e := range []ExceptionSpec{
		exceptionSpec(ExceptionSpec{}),
		exceptionSpec(ExceptionSpec{Category: "injection.override"}),
		exceptionSpec(ExceptionSpec{Source: detect.SourceRAG}),
	} {
		err := blockingSpec(e).Validate()
		if err == nil || !strings.Contains(err.Error(), ErrExceptionTooBroad.Error()) {
			t.Fatalf("слишком широкое исключение %+v принято: %v", e, err)
		}
	}
}

func TestExceptionValidate(t *testing.T) {
	long := func(n int) string { return strings.Repeat("я", n) }
	cases := map[string]ExceptionSpec{
		"id":                  {ID: "Exc 1", App: "a"},
		"detector":            {Detector: "Injection", App: "a"},
		"category":            {Category: "PII", App: "a"},
		"pattern пробел":      {Pattern: "a b"},
		"pattern длинный":     {Pattern: strings.Repeat("a", 129)},
		"fragment":            {Fragment: "abc"},
		"fragment регистр":    {Fragment: strings.ToUpper(excFrag)},
		"user":                {User: "user-1"},
		"app":                 {App: "Support"},
		"source":              {App: "a", Source: "web"},
		"причина пустая":      {App: "a", Reason: " "},
		"причина длинная":     {App: "a", Reason: long(MaxExceptionReason + 1)},
		"причина управляющий": {App: "a", Reason: "a\u0007"},
		"автор длинный":       {App: "a", Author: strings.Repeat("u", MaxExceptionAuthor+1)},
		"доли секунды":        {App: "a", ExpiresAt: excExpires.Add(time.Millisecond)},
		"истекает раньше":     {App: "a", ExpiresAt: excCreated},
		"больше 365 суток":    {App: "a", ExpiresAt: excCreated.Add(MaxExceptionTTL + time.Second)},
		"год":                 {App: "a", CreatedAt: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(1999, 2, 1, 0, 0, 0, 0, time.UTC)},
		"event":               {App: "a", Event: "not-a-uuid"},
	}
	for name, e := range cases {
		t.Run(name, func(t *testing.T) {
			if err := blockingSpec(exceptionSpec(e)).Validate(); err == nil {
				t.Fatalf("исключение %+v принято", e)
			}
		})
	}
	// Граница: ровно 365 суток — допустимо.
	ok := exceptionSpec(ExceptionSpec{App: "a", ExpiresAt: excCreated.Add(MaxExceptionTTL)})
	if err := blockingSpec(ok).Validate(); err != nil {
		t.Fatal(err)
	}
	// Повтор ID.
	if err := blockingSpec(ok, ok).Validate(); err == nil || !strings.Contains(err.Error(), "дважды") {
		t.Fatalf("повтор ID: %v", err)
	}
}

func TestExceptionMaxCount(t *testing.T) {
	list := make([]ExceptionSpec, MaxExceptions+1)
	for i := range list {
		list[i] = exceptionSpec(ExceptionSpec{ID: "e-" + strconv.Itoa(i), App: "a"})
	}
	if err := blockingSpec(list...).Validate(); err == nil || !strings.Contains(err.Error(), "не больше") {
		t.Fatalf("предел числа исключений: %v", err)
	}
}

// Неизвестный детектор в исключении — ошибка компиляции, как у правил.
func TestExceptionUnknownDetector(t *testing.T) {
	s := blockingSpec(exceptionSpec(ExceptionSpec{App: "a", Detector: "judge.llm"}))
	if _, err := Compile(s, catalog(t)); err == nil {
		t.Fatal("исключение с незарегистрированным детектором принято")
	}
}

// Разбор и выгрузка: время приводится к UTC, запись однозначна.
func TestExceptionRoundTrip(t *testing.T) {
	data := sample + `exceptions:
  - id: exc-support
    detector: injection.heuristic
    pattern: persona_removal
    app: support
    reason: ложное срабатывание
    author: user:u1
    created_at: 2026-10-01T03:00:00+03:00
    expires_at: 2026-10-31T00:00:00Z
`
	s, err := Parse(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	e := s.Exceptions[0]
	if !e.CreatedAt.Equal(excCreated) || e.CreatedAt.Location() != time.UTC || e.Pattern != "persona_removal" {
		t.Fatalf("исключение: %+v", e)
	}
	out, err := Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte("created_at: 2026-10-01T00:00:00Z")) {
		t.Fatalf("выгрузка:\n%s", out)
	}
	p, err := Compile(s, catalog(t))
	if err != nil || p.Exceptions() != 1 {
		t.Fatalf("компиляция: %v", err)
	}
	// Пустой раздел — как отсутствующий.
	s2, err := Parse(strings.NewReader(sample + "exceptions: []\n"))
	if err != nil || s2.Exceptions != nil {
		t.Fatalf("пустой раздел: %v %+v", err, s2.Exceptions)
	}
}

func TestValidPattern(t *testing.T) {
	if !ValidPattern("list.words-1.word") || ValidPattern("") || ValidPattern("a b") || ValidPattern("шаблон") {
		t.Fatal("ValidPattern")
	}
}

// 3Н42 ревью 3.r3: исключение для канарейки — только с хешем фрагмента;
// по правилу и приложению DM-08 для приложения не выключается.
func TestExceptionCanaryRequiresFragment(t *testing.T) {
	for _, e := range []ExceptionSpec{
		exceptionSpec(ExceptionSpec{Detector: canary.ID, App: "support-bot"}),
		exceptionSpec(ExceptionSpec{Detector: canary.ID, App: "support-bot", Pattern: "marker"}),
	} {
		err := blockingSpec(e).Validate()
		if err == nil || !strings.Contains(err.Error(), ErrExceptionCanaryFragment.Error()) {
			t.Fatalf("исключение канарейки без фрагмента %+v: %v", e, err)
		}
	}
	if err := blockingSpec(exceptionSpec(ExceptionSpec{Detector: canary.ID, App: "support-bot", Fragment: excFrag})).Validate(); err != nil {
		t.Fatalf("исключение канарейки с фрагментом: %v", err)
	}
}
