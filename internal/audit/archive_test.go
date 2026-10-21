package audit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// signerPair — ключ подписи аудита и его открытый ключ.
func signerPair(t testing.TB) (crypto.Signer, crypto.Verifier) {
	t.Helper()
	p := provider(t)
	s, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return s, v
}

// writeArchive собирает файл архива из записей так же, как Archive.
func writeArchive(t testing.TB, h crypto.Hasher, s crypto.Signer, anchor Anchor, rs []Record) ([]byte, *Checkpoint) {
	t.Helper()
	var buf bytes.Buffer
	fw := newFileWriter(&buf, h)
	last := rs[len(rs)-1]
	if err := fw.line(fileHeader{
		Format: archiveFormat, V: formatVersion, OrgID: DefaultOrgID, HashAlg: h.Name(),
		PrevSeq: anchor.Seq, PrevHash: hex.EncodeToString(anchor.Hash), FromSeq: anchor.Seq + 1, ToSeq: last.Seq,
		CreatedAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC).Format(tsLayout),
	}, true); err != nil {
		t.Fatal(err)
	}
	for i := range rs {
		if err := fw.line(toFileRecord(&rs[i]), true); err != nil {
			t.Fatal(err)
		}
	}
	cp := &Checkpoint{
		ID: "0192f3a0-0000-7000-8000-00000000c001", OrgID: DefaultOrgID, Seq: last.Seq, Hash: last.Hash,
		HashAlg: h.Name(), PrevSeq: anchor.Seq, PrevHash: anchor.Hash, Records: int64(len(rs)),
		ArchiveName: "audit-2026.jsonl", ArchiveHash: fw.bodyHash(), CreatedAt: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if err := cp.Sign(s); err != nil {
		t.Fatal(err)
	}
	if err := fw.line(fileTrailer{Checkpoint: cp.payload(), SigAlg: cp.SigAlg, Signature: cp.Signature, PublicKey: cp.PublicKey}, false); err != nil {
		t.Fatal(err)
	}
	if err := fw.flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), cp
}

func TestArchiveFileRoundTrip(t *testing.T) {
	h := hasher(t)
	s, v := signerPair(t)
	g := Anchor{Hash: genesis(h)}
	rs := buildChain(t, h, g, 7)
	data, want := writeArchive(t, h, s, g, rs)
	cp, err := VerifyArchive(bytes.NewReader(data), h, v)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Seq != 7 || cp.Records != 7 || !bytes.Equal(cp.Hash, rs[6].Hash) || !bytes.Equal(cp.ArchiveHash, want.ArchiveHash) {
		t.Fatalf("точка: %+v", cp)
	}
	// Второй архив продолжает первую точку.
	next := buildChain(t, h, cp.Anchor(), 3)
	data2, cp2 := writeArchive(t, h, s, cp.Anchor(), next)
	if _, err := VerifyArchive(bytes.NewReader(data2), h, v); err != nil {
		t.Fatal(err)
	}
	if a, err := VerifyCheckpoints(h, v, []Checkpoint{*cp, *cp2}); err != nil || a.Seq != 10 {
		t.Fatalf("последовательность точек: %v %v", a, err)
	}
}

// DM-43: подмена архива на внешнем носителе обнаруживается без БД.
func TestDM43_ArchiveTampered(t *testing.T) {
	h := hasher(t)
	s, v := signerPair(t)
	_, other := signerPair(t)
	g := Anchor{Hash: genesis(h)}
	rs := buildChain(t, h, g, 5)
	data, _ := writeArchive(t, h, s, g, rs)
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	join := func(ls []string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }
	replaced := func(i int, old, repl string) []byte {
		ls := append([]string(nil), lines...)
		ls[i] = strings.Replace(ls[i], old, repl, 1)
		return join(ls)
	}
	without := func(i int) []byte {
		ls := append([]string(nil), lines[:i]...)
		return join(append(ls, lines[i+1:]...))
	}
	// Правка записи с пересчётом цепочки: хеши записей сходятся, тело — нет.
	recomputed := cloneRecords(rs)
	recomputed[2].Actor.Name = "другой"
	rehash(t, h, recomputed, 2)
	forged, _ := writeArchive(t, h, s, g, recomputed)
	forgedLines := strings.Split(strings.TrimSuffix(string(forged), "\n"), "\n")
	swapped := append(append([]string(nil), forgedLines[:len(forgedLines)-1]...), lines[len(lines)-1])

	cases := map[string][]byte{
		"правка записи":                  replaced(3, `"name":"Иванов`, `"name":"Петров`),
		"удаление записи из середины":    without(2),
		"удаление последней записи":      without(len(lines) - 2),
		"пересчёт цепочки, старая точка": join(swapped),
		"правка заголовка":               replaced(0, `"from_seq":1`, `"from_seq":2`),
		"правка точки":                   replaced(len(lines)-1, `"records":5`, `"records":4`),
		"нет точки":                      join(lines[:len(lines)-1]),
		"пустой файл":                    nil,
		"только заголовок":               join(lines[:1]),
		"лишнее поле в записи":           replaced(1, `{"v":1,`, `{"v":1,"x":1,`),
	}
	for name, d := range cases {
		if _, err := VerifyArchive(bytes.NewReader(d), h, v); !errors.Is(err, ErrArchiveInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := VerifyArchive(bytes.NewReader(data), h, other); !errors.Is(err, ErrArchiveInvalid) {
		t.Errorf("чужой открытый ключ: %v", err)
	}
}

// DM-43: подмена, удаление или чужая подпись контрольной точки.
func TestDM43_CheckpointForged(t *testing.T) {
	h := hasher(t)
	s, v := signerPair(t)
	other, _ := signerPair(t)
	g := Anchor{Hash: genesis(h)}
	_, cp1 := writeArchive(t, h, s, g, buildChain(t, h, g, 4))
	_, cp2 := writeArchive(t, h, s, cp1.Anchor(), buildChain(t, h, cp1.Anchor(), 2))
	if a, err := VerifyCheckpoints(h, v, []Checkpoint{*cp1, *cp2}); err != nil || a.Seq != 6 {
		t.Fatalf("исходные точки: %v %v", a, err)
	}
	mod := func(f func(c *Checkpoint)) Checkpoint {
		c := *cp2
		f(&c)
		return c
	}
	resigned := mod(func(c *Checkpoint) { c.Seq, c.Records = 7, 3 })
	if err := resigned.Sign(other); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]Checkpoint{
		"удалена первая точка":            {*cp2},
		"номер изменён без подписи":       {*cp1, mod(func(c *Checkpoint) { c.Seq, c.Records = 7, 3 })},
		"хеш изменён без подписи":         {*cp1, mod(func(c *Checkpoint) { c.Hash = bytes.Repeat([]byte{1}, 32) })},
		"подписана чужим ключом":          {*cp1, resigned},
		"не продолжает предыдущую":        {*cp1, mod(func(c *Checkpoint) { c.PrevSeq = 3 })},
		"число записей не сходится":       {*cp1, mod(func(c *Checkpoint) { c.Records = 5 })},
		"имя архива изменено без подписи": {*cp1, mod(func(c *Checkpoint) { c.ArchiveName = "x" })},
		"чужой алгоритм":                  {*cp1, mod(func(c *Checkpoint) { c.HashAlg = "SHA-1" })},
	}
	for name, cps := range cases {
		if _, err := VerifyCheckpoints(h, v, cps); !errors.Is(err, ErrCheckpointInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Без открытого ключа проверяется только связность: подмена с
	// сохранением связей не видна, удаление точки — видно.
	if _, err := VerifyCheckpoints(h, nil, []Checkpoint{*cp1, resigned}); err != nil {
		t.Errorf("без ключа связность цела, но получена ошибка: %v", err)
	}
	if _, err := VerifyCheckpoints(h, nil, []Checkpoint{*cp2}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Errorf("без ключа удаление первой точки не обнаружено: %v", err)
	}
}

func FuzzVerifyArchive(f *testing.F) {
	h := hasher(f)
	s, v := signerPair(f)
	g := Anchor{Hash: genesis(h)}
	data, _ := writeArchive(f, h, s, g, buildChain(f, h, g, 3))
	f.Add(data)
	f.Add([]byte(`{"format":"aisec-audit-archive","v":1}` + "\n"))
	f.Fuzz(func(t *testing.T, in []byte) {
		cp, err := VerifyArchive(bytes.NewReader(in), h, v)
		if err != nil {
			if !errors.Is(err, ErrArchiveInvalid) {
				t.Fatalf("ошибка без ErrArchiveInvalid: %v", err)
			}
			return
		}
		// Принятый архив подписан нашим ключом и описывает непустой диапазон.
		if !cp.VerifySignature(v) || cp.Records <= 0 || cp.Seq != cp.PrevSeq+cp.Records {
			t.Fatalf("принят некорректный архив: %+v", cp)
		}
	})
}
