package bundle

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Заявление о доверии (ADR-0018, п. 4): подписанный список ключей подписи
// пакетов и корней внутреннего УЦ со сроками перекрытия. Заявления образуют
// цепочку от файла-якоря bundle-signing.pub: заявление N подписано
// действующим ключом заявления N−1 (для первого — якорем). Подменённое,
// переставленное или пропущенное заявление цепочка не принимает.

// TrustFormat — формат заявления; он же разделитель домена подписи.
const TrustFormat = "aisec-trust/1"

// Пределы заявлений.
const (
	// MaxTrustStatement — предел подписанного заявления, байт.
	MaxTrustStatement = 16 << 10
	// MaxTrustKeys и MaxTrustRoots — ключей подписи и корней в заявлении.
	MaxTrustKeys  = 4
	MaxTrustRoots = 4
	// MaxTrustInBundle — заявлений в конверте пакета (последние).
	MaxTrustInBundle = 8
)

// TrustKey — ключ подписи пакетов в заявлении. NotAfter — конец
// перекрытия; nil — действующий ключ (ровно один в заявлении).
type TrustKey struct {
	ID        string
	PublicKey []byte
	NotAfter  *time.Time
	verifier  aisecCrypto.Verifier
}

// TrustRoot — корень внутреннего УЦ в заявлении. NotAfter — конец
// перекрытия; nil — действующий корень.
type TrustRoot struct {
	ID       string
	DER      []byte
	NotAfter *time.Time
}

// TrustStatement — проверенное заявление.
type TrustStatement struct {
	Seq      int64
	IssuedAt time.Time
	Keys     []TrustKey
	Roots    []TrustRoot
	// SignedBy — KeyID ключа, которым подписано заявление.
	SignedBy string
	// Raw — подписанное заявление как получено (хранится и пересылается).
	Raw []byte
}

// ActiveKey — действующий ключ заявления.
func (s *TrustStatement) ActiveKey() TrustKey {
	for _, k := range s.Keys {
		if k.NotAfter == nil {
			return k
		}
	}
	return TrustKey{}
}

// ActiveRoot — действующий корень; ok = false — корни не заданы.
func (s *TrustStatement) ActiveRoot() (TrustRoot, bool) {
	for _, r := range s.Roots {
		if r.NotAfter == nil {
			return r, true
		}
	}
	return TrustRoot{}, false
}

// Valid — срок перекрытия не истёк на момент now.
func valid(notAfter *time.Time, now time.Time) bool {
	return notAfter == nil || now.Before(*notAfter)
}

// Внешний вид заявления: части в стандартном base64, сроки — RFC 3339.
type trustKeyJSON struct {
	PublicKey string     `json:"public_key"`
	NotAfter  *time.Time `json:"not_after,omitempty"`
}

type trustRootJSON struct {
	Cert     string     `json:"cert"`
	NotAfter *time.Time `json:"not_after,omitempty"`
}

type trustBody struct {
	Format      string          `json:"format"`
	Seq         int64           `json:"seq"`
	IssuedAt    time.Time       `json:"issued_at"`
	SigningKeys []trustKeyJSON  `json:"signing_keys"`
	CARoots     []trustRootJSON `json:"ca_roots,omitempty"`
}

type signedTrust struct {
	Statement string `json:"statement"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

// trustMessage — подписываемые байты: домен и тело заявления.
func trustMessage(body []byte) []byte {
	msg := make([]byte, 0, len(TrustFormat)+1+len(body))
	msg = append(msg, TrustFormat...)
	msg = append(msg, 0)
	return append(msg, body...)
}

// TrustDraft — новое заявление для подписи (aisec-cli keys).
type TrustDraft struct {
	Seq      int64
	IssuedAt time.Time
	Keys     []TrustKey
	Roots    []TrustRoot
}

// SignTrust подписывает заявление ключом signer. Результат проверяется
// разбором: заявление, которое шлюз не примет, не выпускается.
func SignTrust(p aisecCrypto.Provider, signer aisecCrypto.Signer, d TrustDraft) ([]byte, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	b := trustBody{Format: TrustFormat, Seq: d.Seq, IssuedAt: d.IssuedAt.UTC()}
	for _, k := range d.Keys {
		b.SigningKeys = append(b.SigningKeys, trustKeyJSON{PublicKey: encodeB64(k.PublicKey), NotAfter: utcPtr(k.NotAfter)})
	}
	for _, r := range d.Roots {
		b.CARoots = append(b.CARoots, trustRootJSON{Cert: encodeB64(r.DER), NotAfter: utcPtr(r.NotAfter)})
	}
	body, err := json.Marshal(b)
	if err != nil {
		return nil, err
	}
	sig, err := signer.Sign(trustMessage(body))
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(signedTrust{Statement: encodeB64(body), KeyID: KeyID(h, signer.PublicKey()), Signature: encodeB64(sig)})
	if err != nil {
		return nil, err
	}
	if len(out) > MaxTrustStatement {
		return nil, fmt.Errorf("заявление о доверии больше %d байт", MaxTrustStatement)
	}
	if _, _, err := parseTrust(p, h, out); err != nil {
		return nil, err
	}
	return out, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// RootID — идентификатор корня УЦ: первые 8 байт хеша сертификата (DER).
func RootID(h aisecCrypto.Hasher, der []byte) string { return hex.EncodeToString(h.Sum(der)[:8]) }

// parseTrust строго разбирает подписанное заявление без проверки подписи:
// возвращает заявление и байты тела для проверки. Подпись проверяет
// TrustChain по ключу из цепочки. Покрыт fuzz-тестом FuzzParseTrust.
func parseTrust(p aisecCrypto.Provider, h aisecCrypto.Hasher, raw []byte) (*TrustStatement, []byte, error) {
	if len(raw) > MaxTrustStatement {
		return nil, nil, fmt.Errorf("заявление о доверии больше %d байт", MaxTrustStatement)
	}
	var env signedTrust
	if err := decodeStrict(raw, &env); err != nil {
		return nil, nil, fmt.Errorf("заявление о доверии: %w", err)
	}
	body, err := decodeB64(env.Statement, MaxTrustStatement)
	if err != nil {
		return nil, nil, fmt.Errorf("заявление о доверии: %w", err)
	}
	if _, err := decodeB64(env.Signature, aisecCrypto.SignatureSize); err != nil {
		return nil, nil, fmt.Errorf("заявление о доверии: подпись: %w", err)
	}
	if !keyIDValid(env.KeyID) {
		return nil, nil, errors.New("заявление о доверии: неверный key_id")
	}
	var b trustBody
	if err := decodeStrict(body, &b); err != nil {
		return nil, nil, fmt.Errorf("заявление о доверии: %w", err)
	}
	switch {
	case b.Format != TrustFormat:
		return nil, nil, errors.New("заявление о доверии: неизвестный формат")
	case b.Seq < 1:
		return nil, nil, errors.New("заявление о доверии: номер меньше 1")
	case b.IssuedAt.IsZero():
		return nil, nil, errors.New("заявление о доверии: нет времени")
	case len(b.SigningKeys) == 0 || len(b.SigningKeys) > MaxTrustKeys:
		return nil, nil, fmt.Errorf("заявление о доверии: ключей подписи от 1 до %d", MaxTrustKeys)
	case len(b.CARoots) > MaxTrustRoots:
		return nil, nil, fmt.Errorf("заявление о доверии: корней УЦ не больше %d", MaxTrustRoots)
	}
	st := &TrustStatement{Seq: b.Seq, IssuedAt: b.IssuedAt.UTC(), SignedBy: env.KeyID, Raw: raw}
	active := 0
	for _, k := range b.SigningKeys {
		pub, err := decodeB64(k.PublicKey, aisecCrypto.PublicKeySize)
		if err != nil {
			return nil, nil, fmt.Errorf("заявление о доверии: ключ: %w", err)
		}
		v, err := p.NewVerifier(pub)
		if err != nil {
			return nil, nil, fmt.Errorf("заявление о доверии: ключ: %w", err)
		}
		id := KeyID(h, pub)
		if slices.ContainsFunc(st.Keys, func(x TrustKey) bool { return x.ID == id }) {
			return nil, nil, errors.New("заявление о доверии: ключ указан дважды")
		}
		if k.NotAfter == nil {
			active++
		}
		st.Keys = append(st.Keys, TrustKey{ID: id, PublicKey: pub, NotAfter: utcPtr(k.NotAfter), verifier: v})
	}
	if active != 1 {
		return nil, nil, errors.New("заявление о доверии: действующий ключ подписи (без not_after) должен быть ровно один")
	}
	active = 0
	for _, r := range b.CARoots {
		der, err := decodeB64(r.Cert, aisecCrypto.MaxRootDER)
		if err != nil {
			return nil, nil, fmt.Errorf("заявление о доверии: корень: %w", err)
		}
		if _, err := aisecCrypto.CheckRootDER(der); err != nil {
			return nil, nil, fmt.Errorf("заявление о доверии: %w", err)
		}
		id := RootID(h, der)
		if slices.ContainsFunc(st.Roots, func(x TrustRoot) bool { return x.ID == id }) {
			return nil, nil, errors.New("заявление о доверии: корень указан дважды")
		}
		if r.NotAfter == nil {
			active++
		}
		st.Roots = append(st.Roots, TrustRoot{ID: id, DER: der, NotAfter: utcPtr(r.NotAfter)})
	}
	if len(st.Roots) > 0 && active != 1 {
		return nil, nil, errors.New("заявление о доверии: действующий корень (без not_after) должен быть ровно один")
	}
	return st, body, nil
}

func keyIDValid(id string) bool {
	if len(id) != 16 {
		return false
	}
	for i := 0; i < len(id); i++ {
		if c := id[i]; (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// TrustChain — проверенная цепочка заявлений от якорей. Не потокобезопасна:
// шлюз меняет её под блокировкой BundleClient, сервер — только при запуске.
type TrustChain struct {
	provider aisecCrypto.Provider
	hasher   aisecCrypto.Hasher
	anchors  []TrustKey
	stmts    []*TrustStatement
	// base — номер заявления перед первым в stmts: у сервера всегда 0, у
	// шлюза с якорем на более позднем ключе — номер, с которого начат его
	// отсчёт (AllowReanchor).
	base int64
	// reanchor — режим шлюза (AllowReanchor); skipped — наибольший номер
	// заявления, пропущенного до якоря, пока stmts пусто.
	reanchor bool
	skipped  int64
}

// NewTrustChain — цепочка от якорей (ключей файлов bundle-signing.pub или
// -bundle-pub шлюза).
func NewTrustChain(p aisecCrypto.Provider, anchors []aisecCrypto.Verifier) (*TrustChain, error) {
	if p == nil || len(anchors) == 0 || len(anchors) > MaxVerifiers {
		return nil, fmt.Errorf("цепочка доверия: нужно от 1 до %d ключей-якорей", MaxVerifiers)
	}
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	c := &TrustChain{provider: p, hasher: h}
	for _, v := range anchors {
		id := KeyID(h, v.PublicKey())
		if slices.ContainsFunc(c.anchors, func(x TrustKey) bool { return x.ID == id }) {
			return nil, errors.New("цепочка доверия: один и тот же ключ-якорь указан дважды")
		}
		c.anchors = append(c.anchors, TrustKey{ID: id, PublicKey: v.PublicKey(), verifier: v})
	}
	return c, nil
}

// ErrTrustGap — заявление не продолжает цепочку: пропущены промежуточные.
var ErrTrustGap = errors.New("заявление о доверии не продолжает известную цепочку: пропущены промежуточные заявления")

// ErrTrustBeforeAnchor — заявление выпущено до ключа-якоря шлюза (якорь
// перенесён на более поздний ключ, AllowReanchor): оно не проверяется и не
// даёт доверия, его пропускают.
var ErrTrustBeforeAnchor = errors.New("заявление о доверии выпущено до ключа-якоря шлюза и пропущено")

// AllowReanchor — режим шлюза (ADR-0018, п. 4.4; 3В9 ревью 3.r1): якорь
// (-bundle-pub) может быть ключом, введённым не первым заявлением, — так
// администратор отсекает у шлюза скомпрометированный ключ подписи. Пока
// принятых заявлений нет, заявление, подписанное не якорем, пропускается
// (ErrTrustBeforeAnchor), а первое подписанное якорем начинает цепочку с
// любого номера. Сервер режим не включает: его цепочка — строго от №1.
func (c *TrustChain) AllowReanchor() { c.reanchor = true }

// Append проверяет и добавляет заявление. Уже известное (тот же номер и те
// же байты) пропускается: added = false. Правила (ADR-0018, п. 4.4):
// номер — следующий за последним; подписано действующим ключом последнего
// заявления (для первого — якорем); ключ, которым подписано, остаётся в
// списке нового заявления.
func (c *TrustChain) Append(raw []byte) (added bool, err error) {
	st, body, err := parseTrust(c.provider, c.hasher, raw)
	if err != nil {
		return false, err
	}
	base := c.base
	var signers []TrustKey
	if len(c.stmts) == 0 && c.reanchor {
		if !slices.ContainsFunc(c.anchors, func(k TrustKey) bool { return k.ID == st.SignedBy }) {
			c.skipped = max(c.skipped, st.Seq)
			return false, ErrTrustBeforeAnchor
		}
		base, signers = st.Seq-1, c.anchors
	} else {
		last := c.Seq()
		if st.Seq <= base {
			// До начала цепочки шлюза: такие заявления ему не нужны.
			return false, nil
		}
		if st.Seq <= last {
			if string(c.stmts[st.Seq-base-1].Raw) == string(raw) {
				return false, nil
			}
			return false, fmt.Errorf("заявление о доверии %d отличается от уже принятого", st.Seq)
		}
		if st.Seq != last+1 {
			return false, ErrTrustGap
		}
		if prev := c.Latest(); prev == nil {
			signers = c.anchors
		} else {
			signers = []TrustKey{prev.ActiveKey()}
		}
	}
	i := slices.IndexFunc(signers, func(k TrustKey) bool { return k.ID == st.SignedBy })
	if i < 0 {
		return false, errors.New("заявление о доверии подписано не действующим ключом цепочки")
	}
	var env signedTrust
	if err := decodeStrict(raw, &env); err != nil {
		return false, err
	}
	sig, err := decodeB64(env.Signature, aisecCrypto.SignatureSize)
	if err != nil {
		return false, err
	}
	if !signers[i].verifier.Verify(trustMessage(body), sig) {
		return false, errors.New("подпись заявления о доверии не сходится")
	}
	if !slices.ContainsFunc(st.Keys, func(k TrustKey) bool { return k.ID == st.SignedBy }) {
		return false, errors.New("заявление о доверии убирает ключ, которым подписано")
	}
	if prev := c.Latest(); prev != nil && st.IssuedAt.Before(prev.IssuedAt) {
		return false, errors.New("заявление о доверии выпущено раньше предыдущего")
	}
	c.base = base
	c.stmts = append(c.stmts, st)
	return true, nil
}

// Seq — номер последнего заявления; 0 — заявлений нет. У шлюза с якорем на
// более позднем ключе, пока своих заявлений нет, — номер последнего
// пропущенного: всё до него шлюзу не нужно, и сервер не присылает пакет
// заново ради этих заявлений.
func (c *TrustChain) Seq() int64 {
	if len(c.stmts) == 0 {
		return c.skipped
	}
	return c.base + int64(len(c.stmts))
}

// Latest — последнее заявление; nil — заявлений нет.
func (c *TrustChain) Latest() *TrustStatement {
	if len(c.stmts) == 0 {
		return nil
	}
	return c.stmts[len(c.stmts)-1]
}

// Raw — подписанные заявления начиная с номера from (с 1), по порядку;
// у шлюза с якорем на более позднем ключе — только принятые им.
func (c *TrustChain) Raw(from int64) [][]byte {
	from = max(from-c.base, 1)
	var out [][]byte
	for _, st := range c.stmts[min(int(from-1), len(c.stmts)):] {
		out = append(out, st.Raw)
	}
	return out
}

// Verifiers — ключи, которыми можно подписывать пакеты на момент now: до
// первого заявления — якоря, затем ключи последнего заявления с
// неистёкшим перекрытием.
func (c *TrustChain) Verifiers(now time.Time) map[string]aisecCrypto.Verifier {
	out := map[string]aisecCrypto.Verifier{}
	st := c.Latest()
	if st == nil {
		for _, k := range c.anchors {
			out[k.ID] = k.verifier
		}
		return out
	}
	for _, k := range st.Keys {
		if valid(k.NotAfter, now) {
			out[k.ID] = k.verifier
		}
	}
	return out
}

// ActiveKeyID — ключ, которым сервер подписывает пакеты: действующий ключ
// последнего заявления или первый якорь.
func (c *TrustChain) ActiveKeyID() string {
	if st := c.Latest(); st != nil {
		return st.ActiveKey().ID
	}
	return c.anchors[0].ID
}

// KnownKeyIDs — все ключи цепочки: якоря и ключи любого заявления. По ним
// сервер сверяет ключи проверки шлюза (В19 ревью 2.r4).
func (c *TrustChain) KnownKeyIDs() []string {
	var out []string
	add := func(id string) {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	for _, k := range c.anchors {
		add(k.ID)
	}
	for _, st := range c.stmts {
		for _, k := range st.Keys {
			add(k.ID)
		}
	}
	slices.Sort(out)
	return out
}

// Roots — корни УЦ последнего заявления; пусто — корни не менялись и
// действует корень из файла -ca-cert.
func (c *TrustChain) Roots() []TrustRoot {
	if st := c.Latest(); st != nil {
		return st.Roots
	}
	return nil
}

// ValidRoots — корни с неистёкшим перекрытием на момент now (DER).
func (c *TrustChain) ValidRoots(now time.Time) [][]byte {
	var out [][]byte
	for _, r := range c.Roots() {
		if valid(r.NotAfter, now) {
			out = append(out, r.DER)
		}
	}
	return out
}
