package audit

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// buildChain строит n связанных записей от точки anchor.
func buildChain(t testing.TB, h crypto.Hasher, anchor Anchor, n int) []Record {
	t.Helper()
	out := make([]Record, 0, n)
	prev := anchor.Hash
	for i := 0; i < n; i++ {
		r := goldenRecord(h)
		r.Seq = anchor.Seq + int64(i) + 1
		r.ID = fmt.Sprintf("0192f3a0-0000-7000-8000-%012d", r.Seq)
		r.TS = r.TS.Add(time.Duration(i) * time.Second)
		r.Details = json.RawMessage(fmt.Sprintf(`{"n":%d}`, i))
		r.PrevHash = prev
		sum, err := r.ComputeHash(h)
		if err != nil {
			t.Fatal(err)
		}
		r.Hash = sum
		prev = sum
		out = append(out, r)
	}
	return out
}

// rehash пересчитывает хеши начиная с записи i — так действовал бы
// злоумышленник, знающий алгоритм.
func rehash(t testing.TB, h crypto.Hasher, rs []Record, i int) {
	t.Helper()
	for ; i < len(rs); i++ {
		if i > 0 {
			rs[i].PrevHash = rs[i-1].Hash
		}
		sum, err := rs[i].ComputeHash(h)
		if err != nil {
			t.Fatal(err)
		}
		rs[i].Hash = sum
	}
}

func cloneRecords(rs []Record) []Record {
	out := make([]Record, len(rs))
	copy(out, rs)
	return out
}

func TestChainValid(t *testing.T) {
	h := hasher(t)
	g := Anchor{Hash: genesis(h)}
	rs := buildChain(t, h, g, 5)
	if n, b := VerifyRecords(h, g, nil, rs); b != nil || n != 5 {
		t.Fatalf("%d, %v", n, b)
	}
	// Пустой журнал без прошлых проверок — цел.
	if n, b := VerifyRecords(h, g, nil, nil); b != nil || n != 0 {
		t.Fatalf("пустой: %d, %v", n, b)
	}
	// Продолжение от контрольной точки архивации.
	cp := Anchor{Seq: 100, Hash: h.Sum([]byte("контрольная точка"))}
	if _, b := VerifyRecords(h, cp, nil, buildChain(t, h, cp, 3)); b != nil {
		t.Fatalf("от контрольной точки: %v", b)
	}
	// Прошлая проверка видела запись 3 — она на месте.
	known := []Anchor{{Seq: 3, Hash: rs[2].Hash}, {Seq: 5, Hash: rs[4].Hash}}
	if _, b := VerifyRecords(h, g, known, rs); b != nil {
		t.Fatalf("с прошлой проверкой: %v", b)
	}
}

// DM-43: правка или удаление записей аудита в обход продукта обнаруживается
// проверкой цепочки хешей (РСБ.4).
func TestDM43_ChainBroken(t *testing.T) {
	h := hasher(t)
	g := Anchor{Hash: genesis(h)}
	base := buildChain(t, h, g, 6)
	cases := []struct {
		name   string
		mutate func([]Record) ([]Record, []Anchor)
		seq    int64
		reason Reason
	}{
		{"правка субъекта", func(rs []Record) ([]Record, []Anchor) {
			rs[2].Actor.Name = "кто-то другой"
			return rs, nil
		}, 3, ReasonHashMismatch},
		{"правка результата", func(rs []Record) ([]Record, []Anchor) {
			rs[1].Result = ResultSuccess + "x"
			return rs, nil
		}, 2, ReasonHashMismatch},
		{"правка подробностей", func(rs []Record) ([]Record, []Anchor) {
			rs[3].Details = json.RawMessage(`{"n":42}`)
			return rs, nil
		}, 4, ReasonHashMismatch},
		{"правка времени", func(rs []Record) ([]Record, []Anchor) {
			rs[0].TS = rs[0].TS.Add(time.Microsecond)
			return rs, nil
		}, 1, ReasonHashMismatch},
		{"правка адреса", func(rs []Record) ([]Record, []Anchor) {
			rs[4].SourceIP = rs[4].SourceIP.Next()
			return rs, nil
		}, 5, ReasonHashMismatch},
		{"правка с пересчётом хеша одной записи", func(rs []Record) ([]Record, []Anchor) {
			rs[2].Action = "auth.logout"
			rehash(t, h, rs[2:3], 0)
			return rs, nil
		}, 4, ReasonPrevMismatch},
		{"удаление из середины", func(rs []Record) ([]Record, []Anchor) {
			return append(rs[:2], rs[3:]...), nil
		}, 4, ReasonGap},
		{"удаление начала", func(rs []Record) ([]Record, []Anchor) {
			return rs[2:], nil
		}, 3, ReasonHeadMissing},
		{"удаление начала с перенумерацией", func(rs []Record) ([]Record, []Anchor) {
			rs = rs[2:]
			for i := range rs {
				rs[i].Seq = int64(i + 1)
			}
			rs[0].PrevHash = genesis(h)
			rehash(t, h, rs, 0)
			return rs, []Anchor{{Seq: 6, Hash: base[5].Hash}}
		}, 0, ReasonRewritten},
		// Обрезка и обрезка с дописыванием — одна причина (задача 2.4a).
		{"удаление хвоста", func(rs []Record) ([]Record, []Anchor) {
			known := []Anchor{{Seq: 6, Hash: rs[5].Hash}}
			return rs[:4], known
		}, 5, ReasonRewritten},
		{"удаление хвоста и дописывание новых записей", func(rs []Record) ([]Record, []Anchor) {
			known := []Anchor{{Seq: 6, Hash: rs[5].Hash}}
			rs = rs[:4]
			rs = append(rs, buildChain(t, h, Anchor{Seq: 4, Hash: rs[3].Hash}, 3)...)
			rs[4].Details = json.RawMessage(`{"forged":true}`)
			rehash(t, h, rs, 4)
			return rs, known
		}, 6, ReasonRewritten},
		{"пересчёт всей цепочки после проверки", func(rs []Record) ([]Record, []Anchor) {
			known := []Anchor{{Seq: 6, Hash: rs[5].Hash}}
			rs[1].Actor.ID = "u-2"
			rehash(t, h, rs, 1)
			return rs, known
		}, 6, ReasonRewritten},
		{"перестановка записей", func(rs []Record) ([]Record, []Anchor) {
			rs[1], rs[2] = rs[2], rs[1]
			rs[1].Seq, rs[2].Seq = 2, 3
			return rs, nil
		}, 2, ReasonPrevMismatch},
		{"пересчёт и подложная строка проверки дальше точки в памяти", func(rs []Record) ([]Record, []Anchor) {
			// В памяти — запись 4; нарушитель пересчитал цепочку с записи 2 и
			// добавил «успешную проверку» записи 6 с новым хешем.
			mem := Anchor{Seq: 4, Hash: rs[3].Hash}
			rs[1].Object.ID = "подмена"
			rehash(t, h, rs, 1)
			return rs, []Anchor{mem, {Seq: 6, Hash: rs[5].Hash}}
		}, 4, ReasonRewritten},
		{"подробности не в канонической форме", func(rs []Record) ([]Record, []Anchor) {
			rs[2].Details = json.RawMessage(`{"n": 2}`)
			return rs, nil
		}, 3, ReasonInvalid},
		{"нечитаемая запись", func(rs []Record) ([]Record, []Anchor) {
			rs[3].unreadable = true
			return rs, nil
		}, 4, ReasonInvalid},
		{"чужой алгоритм", func(rs []Record) ([]Record, []Anchor) {
			rs[0].HashAlg = "MD5"
			return rs, nil
		}, 1, ReasonAlgMismatch},
		{"неканонические подробности", func(rs []Record) ([]Record, []Anchor) {
			rs[0].Details = json.RawMessage(`{не json`)
			return rs, nil
		}, 1, ReasonInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rs, known := tc.mutate(cloneRecords(base))
			_, b := VerifyRecords(h, g, known, rs)
			if b == nil {
				t.Fatal("нарушение не обнаружено")
			}
			if b.Reason != tc.reason || (tc.seq != 0 && b.Seq != tc.seq) {
				t.Fatalf("обнаружено %v, ожидалось %s на записи %d", b, tc.reason, tc.seq)
			}
		})
	}
}
