package audit

import (
	"bytes"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/crypto"
)

// testHeadMAC — имитовставка головы на постоянном ключе (в сервере ключ
// выводится из ключа данных, keyring.Box.MAC).
func testHeadMAC(t *testing.T, fill byte) HeadMAC {
	t.Helper()
	m, err := provider(t).NewMAC(bytes.Repeat([]byte{fill}, crypto.MinMACKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return HeadMAC{KeyID: "0192f3a0-0000-7000-8000-00000000000a", MAC: m}
}

// rewriteChain переписывает запись seq и пересчитывает цепочку до конца —
// как владелец таблиц, отключивший триггеры (замечание В2 ревью 2.r1).
// Затем добавляет «успешную» проверку новой головы с имитовставкой tag
// (nil — без неё, как строка, которую добавил бы нарушитель без ключа).
func rewriteChain(t *testing.T, env *testEnv, seq int64, tag func(Anchor) []byte) {
	t.Helper()
	ctx := ctxT(t)
	h := hasher(t)
	recs, err := NewVerifier(env.log).readBatch(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := env.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }() //nolint:gosec // G104: откат после коммита безвреден
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Skipf("нужен суперпользователь: %v", err)
	}
	var prev []byte
	for i := range recs {
		r := &recs[i]
		if r.Seq == seq {
			r.Actor.Name = "другой"
		}
		if r.Seq >= seq {
			r.PrevHash = prev
			if r.Hash, err = r.ComputeHash(h); err != nil {
				t.Fatal(err)
			}
			if _, err := tx.Exec(ctx, "UPDATE audit_log SET actor_name = $2, prev_hash = $3, hash = $4 WHERE seq = $1",
				r.Seq, r.Actor.Name, r.PrevHash, r.Hash); err != nil {
				t.Fatal(err)
			}
		}
		prev = r.Hash
	}
	head := Anchor{Seq: recs[len(recs)-1].Seq, Hash: prev}
	var mac []byte
	var keyID *string
	if tag != nil {
		mac = tag(head)
		k := testHeadMAC(t, 1).KeyID
		keyID = &k
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_verifications (id, ts, ok, checked, last_seq, last_hash, reason, head_mac, mac_key_id)
		VALUES ('0192f3a0-0000-7000-8000-0000000000ff', now() + interval '1 second', true, $1, $1, $2, 'ok', $3, $4::uuid)`,
		head.Seq, head.Hash, mac, keyID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

// В2: после переписывания журнала и пересчёта цепочки новый процесс
// находит подмену по имитовставке головы прошлой проверки.
func TestHeadMACRewriteDetected(t *testing.T) {
	cases := []struct {
		name   string
		tag    func(Anchor) []byte
		reason Reason
	}{
		{"строка проверки без имитовставки", nil, ReasonRewritten},
		{"имитовставка чужим ключом", func(a Anchor) []byte { return testHeadMAC(t, 2).MAC.Sum(headMessage(a)) }, ReasonAnchorForged},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := setupDB(t)
			ctx := ctxT(t)
			record(t, env.log, 5)
			if res := verify(t, NewVerifier(env.log, WithHeadMAC(testHeadMAC(t, 1)))); !res.OK() {
				t.Fatalf("до вмешательства: %v", res.Break)
			}
			var mac []byte
			if err := env.owner.QueryRow(ctx, "SELECT head_mac FROM audit_verifications WHERE ok ORDER BY ts DESC LIMIT 1").
				Scan(&mac); err != nil || len(mac) == 0 {
				t.Fatalf("имитовставка головы не сохранена: %v", err)
			}
			rewriteChain(t, env, 3, tc.tag)
			// Новый процесс: в памяти прошлых проверок нет.
			res := verify(t, NewVerifier(env.log, WithHeadMAC(testHeadMAC(t, 1))))
			if res.OK() || res.Break.Reason != tc.reason {
				t.Fatalf("итог %+v, ожидалось %s", res.Break, tc.reason)
			}
		})
	}
}

// Без имитовставки та же подмена вместе с «успешной» строкой проверки не
// видна: так было до исправления В2, остаётся для aisec-cli без ключей.
func TestHeadMACAbsentRewriteHidden(t *testing.T) {
	env := setupDB(t)
	record(t, env.log, 5)
	if res := verify(t, NewVerifier(env.log)); !res.OK() {
		t.Fatalf("до вмешательства: %v", res.Break)
	}
	rewriteChain(t, env, 3, nil)
	if res := verify(t, NewVerifier(env.log)); !res.OK() {
		t.Fatalf("без имитовставки ожидался пропуск подмены: %v", res.Break)
	}
}

// Строки прежнего ключа данных и строки без имитовставки опорой не служат,
// но и нарушением не считаются: ротация ключа не даёт ложной тревоги.
func TestHeadMACOtherKeyIgnored(t *testing.T) {
	env := setupDB(t)
	record(t, env.log, 3)
	old := testHeadMAC(t, 1)
	if res := verify(t, NewVerifier(env.log, WithHeadMAC(old))); !res.OK() {
		t.Fatal(res.Break)
	}
	rotated := testHeadMAC(t, 3)
	rotated.KeyID = "0192f3a0-0000-7000-8000-00000000000b"
	for range 2 {
		if res := verify(t, NewVerifier(env.log, WithHeadMAC(rotated))); !res.OK() {
			t.Fatalf("после ротации: %v", res.Break)
		}
	}
}
