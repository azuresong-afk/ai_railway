package audit

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// rotation — подписанная смена ключа prev → next после точки cpSeq.
func rotation(t *testing.T, seq int, prev, next crypto.Signer, cpSeq int64) KeyRotation {
	t.Helper()
	r := KeyRotation{OrgID: DefaultOrgID, Seq: seq, CheckpointSeq: cpSeq, RotatedAt: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)}
	if err := SignKeyRotation(hasher(t), prev, next, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// ОЦЛ.3, ADR-0018, п. 5: точки до смены проверяются прежним ключом,
// после — новым; архив после смены проверяется новым открытым ключом.
func TestKeyScheduleCheckpoints(t *testing.T) {
	h := hasher(t)
	p := provider(t)
	s1, v1 := signerPair(t)
	s2, v2 := signerPair(t)
	s3, _ := signerPair(t)
	g := Anchor{Hash: genesis(h)}
	_, cp1 := writeArchive(t, h, s1, g, buildChain(t, h, g, 4))
	data2, cp2 := writeArchive(t, h, s2, cp1.Anchor(), buildChain(t, h, cp1.Anchor(), 3))

	r1 := rotation(t, 1, s1, s2, cp1.Seq)
	ks, err := NewKeySchedule(p, v1, []KeyRotation{r1})
	if err != nil {
		t.Fatal(err)
	}
	if ks.Rotations() != 1 || ks.LatestID() != KeyID(h, s2.PublicKey()) || !bytes.Equal(ks.Latest().PublicKey(), v2.PublicKey()) {
		t.Fatalf("расписание: %d смен, действующий %s", ks.Rotations(), ks.LatestID())
	}
	if a, err := VerifyCheckpoints(h, ks, []Checkpoint{*cp1, *cp2}); err != nil || a.Seq != 7 {
		t.Fatalf("точки по расписанию: %v %v", a, err)
	}
	if _, err := VerifyArchive(bytes.NewReader(data2), h, ks); err != nil {
		t.Fatalf("архив после смены по расписанию: %v", err)
	}
	if _, err := VerifyArchive(bytes.NewReader(data2), h, SingleKey(v1)); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("архив после смены только с прежним ключом: %v", err)
	}

	// Точка после смены, подписанная прежним ключом, и точка до смены,
	// подписанная новым, — отказ.
	oldAfterData, oldAfter := writeArchive(t, h, s1, cp1.Anchor(), buildChain(t, h, cp1.Anchor(), 3))
	if _, err := VerifyCheckpoints(h, ks, []Checkpoint{*cp1, *oldAfter}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("точка после смены прежним ключом: %v", err)
	}
	// 3В3 ревью 3.r1: и офлайн-проверка архива — по расписанию: архив с
	// точкой после смены, подписанной прежним (скомпрометированным) ключом,
	// отклоняется, хотя открытый ключ прежнего лежит в каталоге.
	if _, err := VerifyArchive(bytes.NewReader(oldAfterData), h, ks); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("архив после смены, подписанный прежним ключом: %v", err)
	}
	data1, _ := writeArchive(t, h, s1, g, buildChain(t, h, g, 4))
	if _, err := VerifyArchive(bytes.NewReader(data1), h, ks); err != nil {
		t.Fatalf("архив до смены прежним ключом: %v", err)
	}
	newBeforeData, newBefore := writeArchive(t, h, s2, g, buildChain(t, h, g, 4))
	if _, err := VerifyArchive(bytes.NewReader(newBeforeData), h, ks); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("архив до смены, подписанный новым ключом: %v", err)
	}
	if _, err := VerifyCheckpoints(h, ks, []Checkpoint{*newBefore, *cp2}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("точка до смены новым ключом: %v", err)
	}
	// Подпись верна, но public_key точки называет другой ключ.
	named := *cp2
	named.PublicKey = s3.PublicKey()
	if _, err := VerifyCheckpoints(h, ks, []Checkpoint{*cp1, named}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("чужой public_key в точке: %v", err)
	}
}

// Подменённая или не продолжающая расписание смена ключа отклоняется.
func TestKeyScheduleRejected(t *testing.T) {
	p := provider(t)
	s1, v1 := signerPair(t)
	s2, _ := signerPair(t)
	s3, _ := signerPair(t)
	good := rotation(t, 1, s1, s2, 10)
	second := rotation(t, 2, s2, s3, 20)
	mod := func(r KeyRotation, f func(*KeyRotation)) KeyRotation {
		f(&r)
		return r
	}
	cases := map[string][]KeyRotation{
		"смена не от действующего ключа": {rotation(t, 1, s3, s2, 10)},
		"номер не с 1":             {mod(good, func(r *KeyRotation) { r.Seq = 2 })},
		"пропуск номера":           {good, mod(second, func(r *KeyRotation) { r.Seq = 3 })},
		"номер точки убывает":      {good, rotation(t, 2, s2, s3, 5)},
		"подменён открытый ключ":   {mod(good, func(r *KeyRotation) { r.PublicKey = s3.PublicKey() })},
		"подменён номер точки":     {mod(good, func(r *KeyRotation) { r.CheckpointSeq = 11 })},
		"нет подписи новым ключом": {mod(good, func(r *KeyRotation) { r.Signature = r.PrevSignature })},
		"чужой алгоритм":           {mod(good, func(r *KeyRotation) { r.SigAlg = "other" })},
		"вторая смена от якоря":    {good, rotation(t, 2, s1, s3, 20)},
	}
	for name, rots := range cases {
		if _, err := NewKeySchedule(p, v1, rots); !errors.Is(err, ErrKeyRotationInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	ks, err := NewKeySchedule(p, v1, []KeyRotation{good, second})
	if err != nil {
		t.Fatal(err)
	}
	for seq, want := range map[int64]crypto.Signer{1: s1, 10: s1, 11: s2, 20: s2, 21: s3} {
		if !bytes.Equal(ks.CheckpointKey(seq).PublicKey(), want.PublicKey()) {
			t.Errorf("ключ точки %d не по расписанию", seq)
		}
	}
}

// Файл смены (3В3 ревью 3.r1): разбор воспроизводит подписанную смену, она
// проходит расписание; подмена любого поля — отказ разбора или расписания.
func TestKeyRotationFile(t *testing.T) {
	p := provider(t)
	s1, v1 := signerPair(t)
	s2, _ := signerPair(t)
	r := rotation(t, 1, s1, s2, 10)
	data, err := MarshalKeyRotation(&r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseKeyRotation(data)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewKeySchedule(p, v1, []KeyRotation{got}); err != nil {
		t.Fatalf("разобранная смена не проходит расписание: %v", err)
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"номер точки": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"checkpoint_seq":10`), []byte(`"checkpoint_seq":11`), 1)
		},
		"формат":      func(b []byte) []byte { return bytes.Replace(b, []byte(keyRotationFormat), []byte("other"), 1) },
		"лишнее поле": func(b []byte) []byte { return bytes.Replace(b, []byte(`{`), []byte(`{"x":1,`), 1) },
		"время": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`2027-01-02T00:00:00`), []byte(`2027-01-02T00:00:01`), 1)
		},
	} {
		m := mutate(append([]byte(nil), data...))
		if bytes.Equal(m, data) {
			t.Fatalf("%s: подмена не применилась", name)
		}
		r2, err := ParseKeyRotation(m)
		if err == nil {
			_, err = NewKeySchedule(p, v1, []KeyRotation{r2})
		}
		if !errors.Is(err, ErrKeyRotationInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ParseKeyRotation(bytes.Repeat([]byte{' '}, MaxKeyRotationFile+1)); !errors.Is(err, ErrKeyRotationInvalid) {
		t.Errorf("большой файл: %v", err)
	}
}

// FuzzParseKeyRotation — разбор недоверенного файла смены ключа аудита:
// без паники, разобранное воспроизводится.
func FuzzParseKeyRotation(f *testing.F) {
	s1, _ := signerPair(f)
	s2, _ := signerPair(f)
	r := KeyRotation{OrgID: DefaultOrgID, Seq: 1, CheckpointSeq: 3, RotatedAt: time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)}
	h, err := provider(f).Hasher()
	if err != nil {
		f.Fatal(err)
	}
	if err := SignKeyRotation(h, s1, s2, &r); err != nil {
		f.Fatal(err)
	}
	seed, err := MarshalKeyRotation(&r)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"format":"aisec-audit-key-rotation","v":1}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		got, err := ParseKeyRotation(in)
		if err != nil {
			if !errors.Is(err, ErrKeyRotationInvalid) {
				t.Fatalf("ошибка без ErrKeyRotationInvalid: %v", err)
			}
			return
		}
		out, err := MarshalKeyRotation(&got)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseKeyRotation(out)
		if err != nil {
			t.Fatalf("повторный разбор: %v", err)
		}
		a, _ := got.SignedBytes()   //nolint:gosec // тест: подписанные байты сравниваются ниже
		b, _ := again.SignedBytes() //nolint:gosec // тест: подписанные байты сравниваются ниже
		if !bytes.Equal(a, b) {
			t.Fatal("подписанная форма не воспроизводится")
		}
	})
}
