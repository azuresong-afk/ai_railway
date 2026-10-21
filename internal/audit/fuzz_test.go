package audit

import (
	"bytes"
	"encoding/json"
	"testing"
)

// Разбор подробностей: без паники, результат — объект JSON, повторная
// канонизация его не меняет.
func FuzzCanonicalJSON(f *testing.F) {
	for _, s := range []string{
		`{}`, `{"b":1,"a":2}`, `{"a":{"b":[1,2.50,"x",null,true]}}`, `{"x":"<&> "}`,
		`{"a":1}{"b":2}`, `[1]`, `{"password":"x"}`, `{"a":"\xff"}`, `{"n":1e400}`, `{"a":1,"a":2}`,
		// Маскирование значений (В4 ревью 2.r1).
		`{"r":"Bearer abc def"}`, `{"r":["basic  x","bearer bearer y"]}`, `{"u":"p://a:b:c@d/e ftp://x:y@z"}`,
		`{"r":"Bearer [скрыто]"}`, `{"u":"p://a:[скрыто]@d"}`, `{"r":"bearer\t"}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, in []byte) {
		out, err := CanonicalJSON(in)
		if err != nil {
			return
		}
		if len(out) > maxDetailsSize {
			t.Fatalf("больше лимита: %d", len(out))
		}
		if !json.Valid(out) || out[0] != '{' {
			t.Fatalf("результат не объект JSON: %s", out)
		}
		again, err := CanonicalJSON(out)
		if err != nil || !bytes.Equal(again, out) {
			t.Fatalf("неидемпотентно: %s → %s (%v)", out, again, err)
		}
	})
}

// Любое изменение одного байта подробностей любой записи цепочки, которое
// оставляет запись разбираемой, обнаруживается (DM-43).
func FuzzChainDetectsTamper(f *testing.F) {
	f.Add(uint8(0), uint8(5), byte('7'))
	f.Add(uint8(2), uint8(1), byte('x'))
	f.Fuzz(func(t *testing.T, rec, pos uint8, b byte) {
		h := hasher(t)
		g := Anchor{Hash: genesis(h)}
		rs := buildChain(t, h, g, 4)
		r := &rs[int(rec)%len(rs)]
		d := append([]byte(nil), r.Details...)
		i := int(pos) % len(d)
		if d[i] == b {
			return
		}
		d[i] = b
		r.Details = d
		if _, brk := VerifyRecords(h, g, nil, rs); brk == nil {
			t.Fatalf("изменение %q не обнаружено", d)
		}
	})
}
