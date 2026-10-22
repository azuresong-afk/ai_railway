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
	if _, err := VerifyArchive(bytes.NewReader(data2), h, v1, v2); err != nil {
		t.Fatalf("архив после смены с обоими ключами: %v", err)
	}
	if _, err := VerifyArchive(bytes.NewReader(data2), h, v1); !errors.Is(err, ErrArchiveInvalid) {
		t.Fatalf("архив после смены только с прежним ключом: %v", err)
	}

	// Точка после смены, подписанная прежним ключом, и точка до смены,
	// подписанная новым, — отказ.
	_, oldAfter := writeArchive(t, h, s1, cp1.Anchor(), buildChain(t, h, cp1.Anchor(), 3))
	if _, err := VerifyCheckpoints(h, ks, []Checkpoint{*cp1, *oldAfter}); !errors.Is(err, ErrCheckpointInvalid) {
		t.Fatalf("точка после смены прежним ключом: %v", err)
	}
	_, newBefore := writeArchive(t, h, s2, g, buildChain(t, h, g, 4))
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
