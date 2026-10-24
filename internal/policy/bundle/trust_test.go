package bundle_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/bundletest"
)

var trustNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

// trustFixture — якорь (ключ фикстуры f), новый ключ и корень УЦ.
type trustFixture struct {
	f, next *bundletest.Fixture
	h       aisecCrypto.Hasher
	root    []byte
}

func newTrustFixture(t *testing.T) *trustFixture {
	t.Helper()
	f := bundletest.New(t)
	next := bundletest.New(t)
	next.Recipient = f.Recipient
	h, err := f.Provider.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := aisecCrypto.NewCA("aisec test CA", 24*time.Hour, trustNow)
	if err != nil {
		t.Fatal(err)
	}
	return &trustFixture{f: f, next: next, h: h, root: ca.CertDER()}
}

func ptr(t time.Time) *time.Time { return &t }

func (x *trustFixture) key(s aisecCrypto.Signer, notAfter *time.Time) bundle.TrustKey {
	return bundle.TrustKey{PublicKey: s.PublicKey(), NotAfter: notAfter}
}

// rotation — заявление 1: якорь до конца перекрытия, новый ключ действует.
func (x *trustFixture) rotation(t *testing.T, overlap time.Duration) []byte {
	t.Helper()
	raw, err := bundle.SignTrust(x.f.Provider, x.f.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: trustNow,
		Keys:  []bundle.TrustKey{x.key(x.f.Signer, ptr(trustNow.Add(overlap))), x.key(x.next.Signer, nil)},
		Roots: []bundle.TrustRoot{{DER: x.root}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// opener — проверка от якоря f с цепочкой и часами clock.
func (x *trustFixture) opener(t *testing.T, clock func() time.Time) (*bundle.Opener, *bundle.TrustChain) {
	t.Helper()
	o := x.f.Opener(t)
	c, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.f.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	o.SetTrust(c, clock)
	return o, c
}

func (x *trustFixture) sealer(t *testing.T, s aisecCrypto.Signer, stmts ...[]byte) *bundle.Sealer {
	t.Helper()
	sl, err := bundle.NewSealer(x.f.Provider, s)
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.f.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range stmts {
		if _, err := c.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	sl.SetTrust(c)
	return sl
}

func (x *trustFixture) seal(t *testing.T, sl *bundle.Sealer, version int64) []byte {
	t.Helper()
	c, err := x.f.Content(t).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sl.Seal(bundle.SealInput{Version: version, IssuedAt: trustNow, GatewayID: bundletest.GatewayID,
		Content: c, Secrets: bundle.Secrets{"llm": bundletest.Credential}, RecipientKey: x.f.Recipient.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestTrustRotationAccepted — шлюз узнаёт новый ключ из заявления в пакете
// и до конца перекрытия принимает пакеты, подписанные обоими ключами.
func TestTrustRotationAccepted(t *testing.T) {
	x := newTrustFixture(t)
	stmt := x.rotation(t, 30*24*time.Hour)
	now := trustNow
	o, c := x.opener(t, func() time.Time { return now })
	// Пакет без заявлений, подписанный якорем.
	if _, err := o.Open(x.f.Seal(t, x.f.Content(t), 1), 0); err != nil {
		t.Fatal(err)
	}
	// Пакет новым ключом с заявлением.
	b, err := o.Open(x.seal(t, x.sealer(t, x.next.Signer, stmt), 2), 0)
	if err != nil {
		t.Fatal(err)
	}
	if b.KeyID != x.next.Sealer.KeyID() || o.TrustSeq() != 1 || c.ActiveKeyID() != x.next.Sealer.KeyID() {
		t.Fatalf("ключ %s, номер %d", b.KeyID, o.TrustSeq())
	}
	// Прежний ключ — до конца перекрытия, в том числе с тем же заявлением.
	if _, err := o.Open(x.seal(t, x.sealer(t, x.f.Signer, stmt), 3), 0); err != nil {
		t.Fatalf("прежний ключ в перекрытии: %v", err)
	}
	if roots := o.TrustRoots(); len(roots) != 1 || string(roots[0]) != string(x.root) {
		t.Fatal("корни УЦ из заявления не получены")
	}
	if got := c.KnownKeyIDs(); len(got) != 2 {
		t.Fatalf("известные ключи: %v", got)
	}
	// Повтор того же заявления ничего не меняет.
	if added, err := c.Append(stmt); added || err != nil {
		t.Fatalf("повтор: %v %v", added, err)
	}
	// Цепочка восстанавливается из сохранённых заявлений (trust.json).
	c2, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.f.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range o.TrustRaw() {
		if _, err := c2.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	if c2.Seq() != 1 || c2.ActiveKeyID() != x.next.Sealer.KeyID() {
		t.Fatal("цепочка не восстановлена")
	}
}

// TestDM42_TrustRotationRejected — отказы ротации ключа подписи (DM-42,
// ОЦЛ.3; ADR-0018, п. 4): пакет прежним ключом после перекрытия, подмена
// ключа в заявлении, заявление чужим ключом, пропуск и перестановка
// заявлений.
func TestDM42_TrustRotationRejected(t *testing.T) {
	x := newTrustFixture(t)
	stmt := x.rotation(t, time.Hour)
	now := trustNow
	o, _ := x.opener(t, func() time.Time { return now })
	if _, err := o.Open(x.seal(t, x.sealer(t, x.next.Signer, stmt), 1), 0); err != nil {
		t.Fatal(err)
	}
	reason := func(data []byte) string {
		_, err := o.Open(data, 0)
		return bundle.Reason(err)
	}
	// Перекрытие истекло: пакет прежним ключом, даже с заявлением, — отказ.
	now = trustNow.Add(time.Hour)
	old := x.seal(t, x.sealer(t, x.f.Signer, stmt), 2)
	if r := reason(old); r != bundle.ReasonSignature {
		t.Fatalf("прежний ключ после перекрытия: %s", r)
	}
	if _, err := o.Open(x.seal(t, x.sealer(t, x.next.Signer, stmt), 3), 0); err != nil {
		t.Fatalf("новый ключ после перекрытия: %v", err)
	}

	// Подмена ключа в заявлении: подпись заявления не сходится.
	evil := bundletest.New(t)
	forged := swapTrustKey(t, stmt, x.next.Signer.PublicKey(), evil.Signer.PublicKey())
	fresh, _ := x.opener(t, nil)
	bad := x.seal(t, x.sealer(t, x.next.Signer, stmt), 4)
	bad = replaceTrust(t, bad, forged)
	if _, err := fresh.Open(bad, 0); bundle.Reason(err) != bundle.ReasonSignature || fresh.TrustSeq() != 0 {
		t.Fatalf("подмена ключа: %v", err)
	}
	// Заявление, подписанное чужим ключом от имени якоря.
	alien, err := bundle.SignTrust(x.f.Provider, evil.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: trustNow,
		Keys: []bundle.TrustKey{x.key(evil.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Open(replaceTrust(t, bad, alien), 0); bundle.Reason(err) != bundle.ReasonSignature {
		t.Fatalf("чужой ключ: %v", err)
	}
	// Пакет злоумышленника с его же «заявлением» не принимается.
	if _, err := fresh.Open(x.seal(t, x.sealer(t, evil.Signer), 5), 0); bundle.Reason(err) != bundle.ReasonSignature {
		t.Fatalf("пакет чужим ключом: %v", err)
	}

	// Пропуск: заявление 2 без заявления 1.
	third := bundletest.New(t)
	stmt2, err := bundle.SignTrust(x.f.Provider, x.next.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: trustNow.Add(time.Minute),
		Keys: []bundle.TrustKey{x.key(x.next.Signer, ptr(trustNow.Add(2*time.Hour))), x.key(third.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	gap, _ := x.opener(t, nil)
	if _, err := gap.Open(replaceTrust(t, bad, stmt2), 0); bundle.Reason(err) != bundle.ReasonSignature {
		t.Fatalf("пропуск: %v", err)
	}
	// Заявление 2, подписанное прежним (уже не действующим) ключом.
	byOld, err := bundle.SignTrust(x.f.Provider, x.f.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: trustNow.Add(time.Minute),
		Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.f.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(stmt); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(byOld); err == nil {
		t.Fatal("заявление прежним ключом принято")
	}
	// Заявление, убирающее ключ, которым подписано.
	drops, err := bundle.SignTrust(x.f.Provider, x.next.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: trustNow.Add(time.Minute),
		Keys: []bundle.TrustKey{x.key(third.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Append(drops); err == nil {
		t.Fatal("заявление без ключа подписи принято")
	}
	// Другое заявление с уже принятым номером.
	other := x.rotation(t, 2*time.Hour)
	if _, err := c.Append(other); err == nil {
		t.Fatal("подменённое заявление 1 принято")
	}
	// Без цепочки заявления в пакете не ожидаются.
	if _, err := x.f.Opener(t).Open(x.seal(t, x.sealer(t, x.f.Signer, stmt), 6), 0); bundle.Reason(err) != bundle.ReasonFormat {
		t.Fatalf("без цепочки: %v", err)
	}
	if _, err := c.Append(stmt2); err != nil {
		t.Fatalf("законное заявление 2: %v", err)
	}
}

func TestTrustStatementInvalid(t *testing.T) {
	x := newTrustFixture(t)
	p := x.f.Provider
	cases := map[string]bundle.TrustDraft{
		"номер 0":           {Seq: 0, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}},
		"без времени":       {Seq: 1, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}},
		"без ключей":        {Seq: 1, IssuedAt: trustNow},
		"два действующих":   {Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil), x.key(x.next.Signer, nil)}},
		"нет действующего":  {Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, ptr(trustNow))}},
		"ключ дважды":       {Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil), x.key(x.f.Signer, ptr(trustNow))}},
		"корень не УЦ":      {Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}, Roots: []bundle.TrustRoot{{DER: []byte{1, 2}}}},
		"корни без действ.": {Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}, Roots: []bundle.TrustRoot{{DER: x.root, NotAfter: ptr(trustNow)}}},
	}
	five := bundle.TrustDraft{Seq: 1, IssuedAt: trustNow, Keys: []bundle.TrustKey{x.key(x.f.Signer, nil)}}
	for range bundle.MaxTrustKeys {
		five.Keys = append(five.Keys, x.key(bundletest.New(t).Signer, ptr(trustNow)))
	}
	cases["пять ключей"] = five
	for name, d := range cases {
		if _, err := bundle.SignTrust(p, x.f.Signer, d); err == nil {
			t.Errorf("%s: заявление выпущено", name)
		}
	}
}

// swapTrustKey заменяет открытый ключ в теле заявления, не меняя подписи.
func swapTrustKey(t *testing.T, raw, from, to []byte) []byte {
	t.Helper()
	var env map[string]string
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	body, err := base64.StdEncoding.DecodeString(env["statement"])
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(body), base64.StdEncoding.EncodeToString(from), base64.StdEncoding.EncodeToString(to), 1)
	if s == string(body) {
		t.Fatal("ключ в заявлении не найден")
	}
	env["statement"] = base64.StdEncoding.EncodeToString([]byte(s))
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// replaceTrust заменяет заявления в конверте пакета.
func replaceTrust(t *testing.T, raw []byte, stmts ...[]byte) []byte {
	t.Helper()
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	var items []string
	for _, s := range stmts {
		items = append(items, base64.StdEncoding.EncodeToString(s))
	}
	env["trust"] = items
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// FuzzParseTrust — заявление в пакете — недоверенный вход: Append не
// паникует и принимает только исходное заявление.
func FuzzParseTrust(f *testing.F) {
	fx := bundletest.New(f)
	next := bundletest.New(f)
	raw, err := bundle.SignTrust(fx.Provider, fx.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: trustNow,
		Keys: []bundle.TrustKey{{PublicKey: fx.Signer.PublicKey(), NotAfter: ptr(trustNow)}, {PublicKey: next.Signer.PublicKey()}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"statement":"","key_id":"0000000000000000","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := bundle.NewTrustChain(fx.Provider, []aisecCrypto.Verifier{fx.Verifier(t)})
		if err != nil {
			t.Fatal(err)
		}
		added, err := c.Append(data)
		if err == nil && added && c.ActiveKeyID() != next.Sealer.KeyID() {
			t.Fatal("принято чужое заявление")
		}
		if err != nil && errors.Is(err, bundle.ErrTrustGap) && c.Seq() != 0 {
			t.Fatal("пропуск изменил цепочку")
		}
	})
}

// TestDM42_TrustReanchor — якорь шлюза на ключе не первого заявления (DM-42,
// ОЦЛ.3; ADR-0018, п. 4.4; 3В9 ревью 3.r1): при компрометации ключа подписи
// администратор переносит -bundle-pub на новый ключ. Заявления до него
// пропускаются и доверия не дают, цепочка начинается с первого подписанного
// якорем; прежний ключ и его «заявления» не принимаются. Сервер строг.
func TestDM42_TrustReanchor(t *testing.T) {
	x := newTrustFixture(t)
	third := bundletest.New(t)
	third.Recipient = x.f.Recipient
	stmt1 := x.rotation(t, 0) // f → next, f сразу не действует
	stmt2, err := bundle.SignTrust(x.f.Provider, x.next.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: trustNow.Add(time.Minute),
		Keys: []bundle.TrustKey{x.key(x.next.Signer, ptr(trustNow.Add(time.Minute))), x.key(third.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	now := trustNow.Add(time.Hour)
	reanchored := func(t *testing.T) (*bundle.Opener, *bundle.TrustChain) {
		t.Helper()
		o := x.next.Opener(t)
		c, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.next.Verifier(t)})
		if err != nil {
			t.Fatal(err)
		}
		c.AllowReanchor()
		o.SetTrust(c, func() time.Time { return now })
		return o, c
	}

	// Сервер после первой ротации: заявление №1 пропускается, пакет новым
	// ключом-якорем принимается, шлюз сообщает номер 1 (сервер не шлёт пакет
	// заново ради заявления).
	o, c := reanchored(t)
	if _, err := o.Open(x.seal(t, x.sealer(t, x.next.Signer, stmt1), 1), 0); err != nil {
		t.Fatalf("якорь на ключе заявления 1: %v", err)
	}
	if o.TrustSeq() != 1 || len(o.TrustRaw()) != 0 || c.ActiveKeyID() != x.next.Sealer.KeyID() {
		t.Fatalf("номер %d, сохраняемых %d", o.TrustSeq(), len(o.TrustRaw()))
	}
	// Следующая ротация: заявление №2 подписано якорем и начинает цепочку.
	if _, err := o.Open(x.seal(t, x.sealer(t, third.Signer, stmt1, stmt2), 2), 0); err != nil {
		t.Fatalf("заявление 2 от якоря: %v", err)
	}
	if raw := o.TrustRaw(); o.TrustSeq() != 2 || len(raw) != 1 || string(raw[0]) != string(stmt2) {
		t.Fatalf("номер %d, сохраняемых %d", o.TrustSeq(), len(raw))
	}
	if _, err := o.Open(x.seal(t, x.sealer(t, third.Signer, stmt1, stmt2), 3), 0); err != nil {
		t.Fatalf("повтор заявлений: %v", err)
	}
	// Скомпрометированный первый ключ не принимается ни пакетом, ни своим
	// заявлением №2 с ключом нарушителя.
	evil := bundletest.New(t)
	branch, err := bundle.SignTrust(x.f.Provider, x.f.Signer, bundle.TrustDraft{Seq: 2, IssuedAt: trustNow.Add(time.Minute),
		Keys: []bundle.TrustKey{x.key(x.f.Signer, ptr(trustNow.Add(48*time.Hour))), x.key(evil.Signer, nil)}})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := reanchored(t)
	if _, err := fresh.Open(x.seal(t, x.sealer(t, x.f.Signer), 4), 0); bundle.Reason(err) != bundle.ReasonSignature {
		t.Fatalf("пакет прежним ключом: %v", err)
	}
	bad := replaceTrust(t, x.seal(t, x.sealer(t, evil.Signer, stmt1), 5), branch)
	if _, err := fresh.Open(bad, 0); bundle.Reason(err) != bundle.ReasonSignature || fresh.TrustSeq() != 2 {
		t.Fatalf("ответвление прежним ключом: %v, номер %d", err, fresh.TrustSeq())
	}

	// Перезапуск шлюза: из trust.json приходит только заявление №2.
	_, restart := reanchored(t)
	if _, err := restart.Append(stmt2); err != nil || restart.Seq() != 2 || restart.ActiveKeyID() != third.Sealer.KeyID() {
		t.Fatalf("восстановление: %v, номер %d", err, restart.Seq())
	}
	if added, err := restart.Append(stmt1); added || err != nil {
		t.Fatalf("заявление до начала цепочки: %v %v", added, err)
	}

	// Без AllowReanchor (сервер) — прежняя строгость.
	strict, err := bundle.NewTrustChain(x.f.Provider, []aisecCrypto.Verifier{x.next.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strict.Append(stmt1); err == nil || errors.Is(err, bundle.ErrTrustBeforeAnchor) {
		t.Fatalf("строгая цепочка: %v", err)
	}
	if _, err := strict.Append(stmt2); !errors.Is(err, bundle.ErrTrustGap) {
		t.Fatalf("строгая цепочка с №2: %v", err)
	}
}
