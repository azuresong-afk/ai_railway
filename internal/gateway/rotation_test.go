package gateway_test

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Ротация ключа подписи пакетов и корня УЦ на стороне шлюза (задача 3.3,
// ADR-0018, п. 4 и 6).

// trustOpener — проверка пакетов с цепочкой доверия от ключа фикстуры и
// заявлениями из каталога состояния, часы — clock.
func (e *bundleEnv) trustOpener(t *testing.T, clock func() time.Time) *bundle.Opener {
	t.Helper()
	o := e.fx.Opener(t)
	chain, err := bundle.NewTrustChain(e.fx.Provider, []aisecCrypto.Verifier{e.fx.Verifier(t)})
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := e.fx.Provider.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(e.dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }() //nolint:gosec // G104: каталог открыт только для чтения заявлений
	raws, err := st.LoadTrust()
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range raws {
		if _, err := chain.Append(raw); err != nil {
			t.Fatal(err)
		}
	}
	o.SetTrust(chain, clock)
	return o
}

// DM-42, ОЦЛ.3: шлюз узнаёт новый ключ подписи из заявления в пакете,
// сохраняет заявление и тот же пакет, подписанный новым ключом; после
// перезапуска цепочка восстанавливается; после перекрытия пакет прежним
// ключом отклоняется; заявление чужим ключом не принимается.
func TestDM42_BundleClientTrustRotation(t *testing.T) {
	e := newBundleEnv(t)
	p := e.fx.Provider
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c := e.clientWith(t, e.trustOpener(t, nil))
	v100 := e.fx.Seal(t, e.fx.Content(t), 100)
	e.srv.set(v100, "100")
	e.poll(t, c)
	if e.srv.seqs[len(e.srv.seqs)-1] != "0" {
		t.Fatalf("номер цепочки в запросе: %q", e.srv.seqs)
	}

	// Ротация: заявление №1 подписано ключом-якорем, новый ключ действует,
	// прежний — ещё час.
	s2, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	anchor := e.fx.Verifier(t)
	until := now.Add(time.Hour).UTC().Truncate(time.Second)
	raw, err := bundle.SignTrust(p, e.fx.Signer, bundle.TrustDraft{Seq: 1, IssuedAt: now, Keys: []bundle.TrustKey{
		{ID: bundle.KeyID(h, anchor.PublicKey()), PublicKey: anchor.PublicKey(), NotAfter: &until},
		{ID: bundle.KeyID(h, s2.PublicKey()), PublicKey: s2.PublicKey()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	server, err := bundle.NewTrustChain(p, []aisecCrypto.Verifier{anchor})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Append(raw); err != nil {
		t.Fatal(err)
	}
	sealer2, err := bundle.NewSealer(p, s2)
	if err != nil {
		t.Fatal(err)
	}
	sealer2.SetTrust(server)
	same := sealWith(t, e, sealer2, 100)
	e.srv.set(same, "100-rotated")
	e.poll(t, c)
	if len(e.applied) != 1 || !bytes.Equal(e.saved(t), same) {
		t.Fatalf("тот же пакет новым ключом: применений %d, на диске новый %v", len(e.applied), bytes.Equal(e.saved(t), same))
	}
	data, err := os.ReadFile(filepath.Join(e.dir, gateway.TrustFile))
	if err != nil {
		t.Fatalf("trust.json: %v", err)
	}
	if info, err := os.Stat(filepath.Join(e.dir, gateway.TrustFile)); err != nil || info.Mode().Perm() != 0o600 || len(data) == 0 {
		t.Fatalf("права trust.json: %v", info.Mode())
	}

	// Перезапуск через два часа: цепочка из trust.json, пакет на диске
	// подписан новым ключом и проверяется, прежний ключ уже не действует.
	later := func() time.Time { return now.Add(2 * time.Hour) }
	o := e.trustOpener(t, later)
	if o.TrustSeq() != 1 {
		t.Fatalf("цепочка после перезапуска: %d", o.TrustSeq())
	}
	c2 := e.clientWith(t, o)
	if !c2.LoadSaved() {
		t.Fatal("сохранённый пакет нового ключа не принят после перезапуска")
	}
	e.srv.set(e.fx.Seal(t, e.fx.Content(t), 101), "101")
	e.poll(t, c2)
	if c2.ETag() != `"100"` {
		t.Fatalf("пакет прежним ключом после перекрытия принят: %q", c2.ETag())
	}
	wantReport(t, e.srv.lastReport(), "rejected", 101, bundle.ReasonSignature)
	if e.srv.seqs[len(e.srv.seqs)-1] != "1" {
		t.Fatalf("номер цепочки после ротации: %q", e.srv.seqs[len(e.srv.seqs)-1])
	}

	// Подмена ключа: заявление №2 подписано чужим ключом и объявляет его
	// действующим — пакет отклоняется, цепочка не меняется.
	stranger, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	forged, err := bundle.SignTrust(p, stranger, bundle.TrustDraft{Seq: 2, IssuedAt: now.Add(time.Minute), Keys: []bundle.TrustKey{
		{ID: bundle.KeyID(h, s2.PublicKey()), PublicKey: s2.PublicKey(), NotAfter: &until},
		{ID: bundle.KeyID(h, stranger.PublicKey()), PublicKey: stranger.PublicKey()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	evil, err := bundle.NewTrustChain(p, []aisecCrypto.Verifier{anchor})
	if err != nil {
		t.Fatal(err)
	}
	evil.Append(raw)    //nolint:errcheck,gosec // заявление проверено выше
	evil.Append(forged) //nolint:errcheck,gosec // чужая цепочка: сервер злоумышленника её не проверяет
	evilSealer, err := bundle.NewSealer(p, stranger)
	if err != nil {
		t.Fatal(err)
	}
	evilSealer.SetTrust(evil)
	e.srv.set(sealWith(t, e, evilSealer, 102), "102")
	e.poll(t, c2)
	if c2.ETag() != `"100"` {
		t.Fatalf("пакет с подменённым ключом принят: %q", c2.ETag())
	}
	wantReport(t, e.srv.lastReport(), "rejected", 102, bundle.ReasonSignature)
	if o.TrustSeq() != 1 {
		t.Fatalf("цепочка после подмены: %d", o.TrustSeq())
	}
	e.srv.set(sealWith(t, e, sealer2, 103), "103")
	e.poll(t, c2)
	if c2.ETag() != `"103"` {
		t.Fatalf("пакет новым ключом после отказов: %q", c2.ETag())
	}
}

// sealWith — содержимое фикстуры версии version, подписанное s.
func sealWith(t *testing.T, e *bundleEnv, s *bundle.Sealer, version int64) []byte {
	t.Helper()
	orig := e.fx.Sealer
	e.fx.Sealer = s
	defer func() { e.fx.Sealer = orig }()
	return e.fx.Seal(t, e.fx.Content(t), version)
}

// trust.json хранит последние 64 заявления; повреждённый файл — ошибка.
func TestBundleStateTrustFile(t *testing.T) {
	dir := stateDir(t)
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(dir, rnd)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }() //nolint:gosec // G104: тест
	if raws, err := st.LoadTrust(); err != nil || raws != nil {
		t.Fatalf("без файла: %v %v", raws, err)
	}
	var raws [][]byte
	for i := range 70 {
		raws = append(raws, []byte{byte(i)})
	}
	if err := st.SaveTrust(raws); err != nil {
		t.Fatal(err)
	}
	got, err := st.LoadTrust()
	if err != nil || len(got) != 64 || got[0][0] != 6 || got[63][0] != 69 {
		t.Fatalf("сохранено %d, %v", len(got), err)
	}
	path := filepath.Join(dir, gateway.TrustFile)
	for name, data := range map[string]string{
		"не JSON":      "x",
		"чужой формат": `{"format":"other","statements":[]}`,
		"лишнее поле":  `{"format":"aisec-gateway-trust/1","statements":[],"x":1}`,
		"не base64":    `{"format":"aisec-gateway-trust/1","statements":["!"]}`,
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := st.LoadTrust(); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

// reissueEnv — шлюз с переключаемым сертификатом и перевыпуском с
// корнями roots.
func reissueEnv(t *testing.T, e *mtlsEnv, reg gateway.Registration, roots [][]byte) (*http.Client, *gateway.BundleState, *gateway.Reissuer) {
	t.Helper()
	sw, err := aisecCrypto.NewClientCertSwitch(reg.CertPEM, reg.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := gateway.ControlTransportSwitch(e.tp, e.ca.CertPEM(), sw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &http.Client{Transport: tr}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	rnd, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	st, err := gateway.OpenBundleState(stateDir(t), rnd)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() }) //nolint:gosec // G104: закрытие каталога в очистке теста
	r, err := gateway.NewReissuer(gateway.ReissueConfig{Client: client, Transport: tr, Server: e.internal, GatewayID: reg.GatewayID,
		Switch: sw, State: st, Roots: func() [][]byte { return roots }, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	return client, st, r
}

// ИАФ.10, ADR-0018, п. 6.3: шлюз перевыпускает сертификат по признаку из
// heartbeat, сохраняет пару в client.pem и переходит на неё без
// перезапуска; сервер после первого запроса с новым сертификатом
// прежний не принимает.
func TestReissueOverMTLS(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")
	client, st, r := reissueEnv(t, e, reg, [][]byte{e.ca.CertDER()})
	// УЦ теста действует сутки: heartbeat требует перевыпуск.
	calls := 0
	gateway.RunHeartbeat(context.Background(), gateway.HeartbeatConfig{Client: client, Server: e.internal, Version: "2.0.0", Logger: quiet(),
		Reissue: func(ctx context.Context) error {
			calls++
			return r.Reissue(ctx)
		},
		Sleep: func(context.Context, time.Duration) bool { return false }})
	if calls != 1 {
		t.Fatalf("перевыпуск из heartbeat: вызовов %d", calls)
	}
	certPEM, _, err := st.LoadClientPair()
	if err != nil || certPEM == nil {
		t.Fatalf("client.pem: %v", err)
	}
	next, err := aisecCrypto.ParseCertInfo(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Следующий запрос идёт с новым сертификатом: сервер делает его
	// действующим (heartbeat ответит 429 по частоте, но после проверки).
	if _, err := post(t, client, e.internal, "/internal/v1/heartbeat", `{"version":"2.0.0"}`); err != nil {
		t.Fatal(err)
	}
	list, err := e.svc.List(context.Background())
	if err != nil || len(list) != 1 || list[0].CertSerial != next.Serial || list[0].NextCertSerial != "" {
		t.Fatalf("реестр после перехода: %+v %v", list, err)
	}
	resp, err := post(t, e.client(t, reg.CertPEM, reg.KeyPEM), e.internal, "/internal/v1/heartbeat", `{"version":"2.0.0"}`)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("прежний сертификат после перехода: %v %v", resp, err)
	}
}

// Сертификат не от корня из заявления о доверии шлюз не принимает:
// client.pem не создаётся, прежний сертификат действует.
func TestReissueRejectsForeignRoot(t *testing.T) {
	e := newMTLSEnv(t)
	reg := e.registerGateway(t, "gw-1")
	stranger, err := aisecCrypto.NewCA("stranger", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client, st, r := reissueEnv(t, e, reg, [][]byte{stranger.CertDER()})
	if err := r.Reissue(context.Background()); err == nil {
		t.Fatal("сертификат не от корня из заявления принят")
	}
	if cert, _, err := st.LoadClientPair(); err != nil || cert != nil {
		t.Fatalf("client.pem после отказа: %v", err)
	}
	resp, err := post(t, client, e.internal, "/internal/v1/events:batch", `{}`)
	if err != nil || resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("прежний сертификат после отказа: %v %v", resp, err)
	}
}
