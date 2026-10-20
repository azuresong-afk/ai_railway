package api

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCursorRoundTrip(t *testing.T) {
	c := Cursor{TimeMicro: 1760000000123456, ID: "0190a1b2-c3d4"}
	got, err := DecodeCursor(c.Encode())
	if err != nil || got != c {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestDecodeCursorRejects(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	for name, in := range map[string]string{
		"пустой":           "",
		"слишком длинный":  strings.Repeat("A", MaxCursorLen+1),
		"не base64":        "!!!!",
		"с паддингом":      "MTox=",
		"нет двоеточия":    enc("123abc"),
		"минус":            enc("-1:abc"),
		"ведущий ноль":     enc("012:abc"),
		"не число":         enc("1x:abc"),
		"пустой id":        enc("1:"),
		"плохой символ id": enc("1:a b"),
		"длинный id":       enc("1:" + strings.Repeat("a", 65)),
		"переполнение":     enc("99999999999999999999:a"),
	} {
		if _, err := DecodeCursor(in); err == nil {
			t.Errorf("%s: принят %q", name, in)
		}
	}
}

func FuzzDecodeCursor(f *testing.F) {
	f.Add(Cursor{TimeMicro: 5, ID: "x"}.Encode())
	f.Add("")
	f.Add("MTox")
	f.Fuzz(func(t *testing.T, s string) {
		c, err := DecodeCursor(s)
		if err != nil {
			return
		}
		// Принятый курсор канонически перекодируется в ту же строку.
		if c.Encode() != s {
			t.Fatalf("курсор %q не канонический: %+v", s, c)
		}
	})
}

func TestParsePage(t *testing.T) {
	good := Cursor{TimeMicro: 7, ID: "a"}.Encode()
	p, prob := ParsePage(httptest.NewRequest("GET", "/x?limit=10&cursor="+good, nil))
	if prob != nil || p.Limit != 10 || p.Cursor == nil || p.Cursor.ID != "a" {
		t.Fatalf("%+v %v", p, prob)
	}
	p, prob = ParsePage(httptest.NewRequest("GET", "/x", nil))
	if prob != nil || p.Limit != DefaultPageLimit || p.Cursor != nil {
		t.Fatalf("умолчания: %+v %v", p, prob)
	}
	for _, q := range []string{"limit=0", "limit=201", "limit=abc", "limit=1&limit=2", "cursor=%21", "cursor=" + good + "&cursor=" + good, "limit=-5"} {
		if _, prob := ParsePage(httptest.NewRequest("GET", "/x?"+q, nil)); prob == nil || prob.Status != 400 || len(prob.Errors) == 0 {
			t.Errorf("%s: принято", q)
		}
	}
}
