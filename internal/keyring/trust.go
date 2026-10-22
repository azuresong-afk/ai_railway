package keyring

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Ротация ключа подписи пакетов, корня внутреннего УЦ и ключа аудита
// (ADR-0018, п. 4–6; задача 3.3 этапа 3). Файлы aisec-cli init — якоря и не
// меняются; новые ключи пишутся рядом с ID в имени, доверие к ним — по
// подписанной цепочке в БД (trust_statements, audit_key_rotations).

// Файлы каталога ключей aisec-cli init (ADR-0007).
const (
	SigningKeyFile = "bundle-signing.key"
	SigningPubFile = "bundle-signing.pub"
	AuditKeyFile   = "audit-signing.key"
	AuditPubFile   = "audit-signing.pub"
	CACertFile     = "ca.crt"
	CAKeyFile      = "ca.key"
)

// Права новых файлов: закрытые ключи — 0400, открытые и сертификаты — 0444.
const (
	permSecret = 0o400
	permPublic = 0o444
)

// DefaultOverlap — перекрытие прежнего ключа подписи и корня по умолчанию.
const DefaultOverlap = 30 * 24 * time.Hour

// caCommonName — имя УЦ, как у aisec-cli init.
const caCommonName = "AISec internal CA"

// SigningFiles — файлы ключа подписи пакетов id: якорь — файлы init,
// остальные — bundle-signing.<id>.key и .pub.
func SigningFiles(id, anchorID string) (key, pub string) {
	if id == anchorID {
		return SigningKeyFile, SigningPubFile
	}
	return "bundle-signing." + id + ".key", "bundle-signing." + id + ".pub"
}

// AuditFiles — файлы ключа аудита id.
func AuditFiles(id, anchorID string) (key, pub string) {
	if id == anchorID {
		return AuditKeyFile, AuditPubFile
	}
	return "audit-signing." + id + ".key", "audit-signing." + id + ".pub"
}

// CAFiles — файлы корня УЦ id (сертификат и ключ).
func CAFiles(id, anchorID string) (crt, key string) {
	if id == anchorID {
		return CACertFile, CAKeyFile
	}
	return "ca." + id + ".crt", "ca." + id + ".key"
}

// maxKeyDirFile — предел файла ключа или сертификата.
const maxKeyDirFile = 64 << 10

// ReadKeyDirFile читает обычный файл каталога ключей через os.Root.
// Закрытый ключ (secret) — только с правами 0400 или 0600.
func ReadKeyDirFile(root *os.Root, name string, secret bool) (data []byte, err error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	switch {
	case !info.Mode().IsRegular():
		return nil, fmt.Errorf("%s: не обычный файл", name)
	case secret && !aisecCrypto.KeyFilePermsOK(info):
		return nil, fmt.Errorf("%s: файл доступен группе или остальным (права %o); нужно 0400", name, info.Mode().Perm())
	case info.Size() > maxKeyDirFile:
		return nil, fmt.Errorf("%s: файл больше %d байт", name, maxKeyDirFile)
	}
	data, err = io.ReadAll(io.LimitReader(f, maxKeyDirFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyDirFile {
		return nil, fmt.Errorf("%s: файл больше %d байт", name, maxKeyDirFile)
	}
	return data, nil
}

// ReadSigner — закрытый ключ подписи вида kind из файла name каталога.
func ReadSigner(root *os.Root, p aisecCrypto.Provider, name, kind string) (aisecCrypto.Signer, error) {
	data, err := ReadKeyDirFile(root, name, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, kind)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	defer clear(seed)
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, а установка — %s", name, profile, p.Name())
	}
	return p.NewSigner(seed)
}

// ReadVerifier — открытый ключ вида kind из файла name каталога.
func ReadVerifier(root *os.Root, p aisecCrypto.Provider, name, kind string) (aisecCrypto.Verifier, error) {
	data, err := ReadKeyDirFile(root, name, false)
	if err != nil {
		return nil, err
	}
	return aisecCrypto.ParseVerifierPEM(p, name, data, kind)
}

// maxTrustStatements — предел числа заявлений при чтении.
const maxTrustStatements = 10000

// LoadTrust читает заявления о доверии организации и проверяет цепочку от
// якорей. Заявление, которое цепочка не принимает, — ошибка: доверие в БД
// подменено (DM-42).
func LoadTrust(ctx context.Context, q Querier, p aisecCrypto.Provider, orgID string, anchors []aisecCrypto.Verifier) (*bundle.TrustChain, error) {
	chain, err := bundle.NewTrustChain(p, anchors)
	if err != nil {
		return nil, err
	}
	qctx, cancel := dbCtx(ctx)
	defer cancel()
	rows, err := q.Query(qctx, `SELECT seq, statement FROM trust_statements WHERE org_id = $1 ORDER BY seq LIMIT $2`,
		orgID, maxTrustStatements+1)
	if err != nil {
		return nil, fmt.Errorf("заявления о доверии: %w", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var seq int64
		var raw []byte
		if err := rows.Scan(&seq, &raw); err != nil {
			return nil, fmt.Errorf("заявления о доверии: %w", err)
		}
		if n++; n > maxTrustStatements {
			return nil, fmt.Errorf("заявлений о доверии больше %d", maxTrustStatements)
		}
		if _, err := chain.Append(raw); err != nil {
			return nil, fmt.Errorf("заявление о доверии %d не проверяется по цепочке от %s: %w", seq, SigningPubFile, err)
		}
		if chain.Seq() != seq {
			return nil, fmt.Errorf("заявление о доверии %d: номер в строке не совпадает с номером в заявлении", seq)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("заявления о доверии: %w", err)
	}
	return chain, nil
}

// TrustRotation — итог rotate-signing или rotate-ca.
type TrustRotation struct {
	Seq          int64
	OldID, NewID string
	// OverlapUntil — до какого времени действует прежний ключ или корень.
	OverlapUntil time.Time
	// Files — созданные файлы в каталоге ключей.
	Files []string
}

// trustEnv — общее для rotate-signing и rotate-ca: якорь, цепочка и
// действующий ключ подписи.
type trustEnv struct {
	root     *os.Root
	hasher   aisecCrypto.Hasher
	anchorID string
	chain    *bundle.TrustChain
	signer   aisecCrypto.Signer
}

func openTrustEnv(ctx context.Context, tx pgx.Tx, root *os.Root, p aisecCrypto.Provider, orgID string) (*trustEnv, error) {
	h, err := p.Hasher()
	if err != nil {
		return nil, err
	}
	anchor, err := ReadVerifier(root, p, SigningPubFile, aisecCrypto.KeyKindSigningPublic)
	if err != nil {
		return nil, fmt.Errorf("ключ-якорь подписи пакетов: %w", err)
	}
	chain, err := LoadTrust(ctx, tx, p, orgID, []aisecCrypto.Verifier{anchor})
	if err != nil {
		return nil, err
	}
	env := &trustEnv{root: root, hasher: h, anchorID: bundle.KeyID(h, anchor.PublicKey()), chain: chain}
	active := chain.ActiveKeyID()
	keyFile, _ := SigningFiles(active, env.anchorID)
	if env.signer, err = ReadSigner(root, p, keyFile, aisecCrypto.KeyKindSigning); err != nil {
		return nil, fmt.Errorf("действующий ключ подписи пакетов: %w", err)
	}
	if bundle.KeyID(h, env.signer.PublicKey()) != active {
		return nil, fmt.Errorf("%s не соответствует действующему ключу подписи %s", keyFile, active)
	}
	return env, nil
}

// draft — новое заявление: ключи и корни последнего заявления (до первой
// ротации — якоря) без истёкших.
func (e *trustEnv) draft(now time.Time) (bundle.TrustDraft, error) {
	d := bundle.TrustDraft{Seq: e.chain.Seq() + 1, IssuedAt: now}
	if st := e.chain.Latest(); st != nil {
		for _, k := range st.Keys {
			if k.NotAfter == nil || now.Before(*k.NotAfter) {
				d.Keys = append(d.Keys, bundle.TrustKey{ID: k.ID, PublicKey: k.PublicKey, NotAfter: k.NotAfter})
			}
		}
		for _, r := range st.Roots {
			if r.NotAfter == nil || now.Before(*r.NotAfter) {
				d.Roots = append(d.Roots, bundle.TrustRoot{ID: r.ID, DER: r.DER, NotAfter: r.NotAfter})
			}
		}
		return d, nil
	}
	d.Keys = []bundle.TrustKey{{ID: e.anchorID, PublicKey: e.signer.PublicKey()}}
	// Корень из ca.crt — первым корнем цепочки; без УЦ корней нет.
	der, err := readCACertDER(e.root, CACertFile)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return d, nil
	case err != nil:
		return d, err
	}
	d.Roots = []bundle.TrustRoot{{ID: bundle.RootID(e.hasher, der), DER: der}}
	return d, nil
}

func readCACertDER(root *os.Root, name string) ([]byte, error) {
	data, err := ReadKeyDirFile(root, name, false)
	if err != nil {
		return nil, err
	}
	der, err := aisecCrypto.CertDER(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return der, nil
}

// AnchorRootID — ID корня из ca.crt (файла init): его файлы не переименовываются.
func AnchorRootID(root *os.Root, h aisecCrypto.Hasher) (string, error) {
	der, err := readCACertDER(root, CACertFile)
	if err != nil {
		return "", fmt.Errorf("корень УЦ: %w", err)
	}
	return bundle.RootID(h, der), nil
}

// commit подписывает заявление действующим ключом, проверяет его цепочкой и
// записывает вместе с записью аудита. *sent — запись отправлена в БД: после
// этого исход фиксации может быть неизвестен, и файлы не удаляются.
func (e *trustEnv) commit(ctx context.Context, tx pgx.Tx, sent *bool, rec Recorder, p aisecCrypto.Provider, d bundle.TrustDraft,
	orgID string, actor audit.Actor, action string, details map[string]any) (int64, error) {
	if len(d.Keys) > bundle.MaxTrustKeys || len(d.Roots) > bundle.MaxTrustRoots {
		return 0, fmt.Errorf("в перекрытии уже %d ключей и %d корней (предел %d): дождитесь конца перекрытия прежних",
			len(d.Keys)-1, len(d.Roots)-1, bundle.MaxTrustKeys)
	}
	raw, err := bundle.SignTrust(p, e.signer, d)
	if err != nil {
		return 0, err
	}
	if _, err := e.chain.Append(raw); err != nil {
		return 0, fmt.Errorf("новое заявление не проверяется цепочкой: %w", err)
	}
	*sent = true
	if _, err := tx.Exec(ctx, `INSERT INTO trust_statements (org_id, seq, statement, signed_by, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`, orgID, d.Seq, raw, bundle.KeyID(e.hasher, e.signer.PublicKey()), d.IssuedAt,
		actorRef(actor)); err != nil {
		return 0, fmt.Errorf("заявление о доверии: запись: %w", err)
	}
	details["seq"] = d.Seq
	return d.Seq, rec.RecordTx(ctx, tx, audit.Entry{OrgID: orgID, Actor: actor, Action: action,
		Object: audit.Object{Type: "trust_statement", ID: fmt.Sprint(d.Seq)}, Result: audit.ResultSuccess, Details: details})
}

func actorRef(a audit.Actor) string {
	ref := string(a.Type) + ":" + a.ID
	if len(ref) > 128 {
		ref = ref[:128]
	}
	return ref
}

// overlapUntil — конец перекрытия; при overlap = 0 прежний ключ перестаёт
// приниматься сразу (компрометация).
func overlapUntil(now time.Time, overlap time.Duration) *time.Time {
	t := now.Add(overlap).UTC().Truncate(time.Second)
	return &t
}

// writeKeyPair пишет новые файлы (O_EXCL) и сбрасывает каталог.
func writeKeyPair(root *os.Root, files map[string][]byte, perms map[string]fs.FileMode) ([]string, error) {
	var created []string
	for name, data := range files {
		if err := WriteNewFile(root, name, data, perms[name]); err != nil {
			for _, c := range created {
				_ = root.Remove(c) //nolint:gosec // G104: уборка неудавшейся записи; важна исходная ошибка
			}
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, syncRoot(root)
}

// RotateSigning — keys rotate-signing (ADR-0018, п. 4.2): новый ключ
// подписи пакетов и заявление, в котором прежний ключ действует ещё overlap.
func RotateSigning(ctx context.Context, db Owner, rec Recorder, p aisecCrypto.Provider, dir, orgID string,
	actor audit.Actor, now time.Time, overlap time.Duration) (TrustRotation, error) {
	if overlap < 0 {
		return TrustRotation{}, errors.New("перекрытие не может быть отрицательным")
	}
	root, err := OpenKeyDir(dir)
	if err != nil {
		return TrustRotation{}, err
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: файлы записаны и синхронизированы раньше
	now = now.UTC().Truncate(time.Second)
	var out TrustRotation
	sent := false
	err = InTx(ctx, db, func(tx pgx.Tx) error {
		env, err := openTrustEnv(ctx, tx, root, p, orgID)
		if err != nil {
			return err
		}
		d, err := env.draft(now)
		if err != nil {
			return err
		}
		next, err := p.GenerateSigner()
		if err != nil {
			return err
		}
		out.OldID, out.NewID = env.chain.ActiveKeyID(), bundle.KeyID(env.hasher, next.PublicKey())
		until := overlapUntil(now, overlap)
		for i := range d.Keys {
			if d.Keys[i].ID == out.OldID {
				d.Keys[i].NotAfter = until
			}
		}
		d.Keys = append(d.Keys, bundle.TrustKey{ID: out.NewID, PublicKey: next.PublicKey()})
		out.OverlapUntil = *until
		seed := next.Seed()
		defer clear(seed)
		keyPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigning, p.Name(), seed)
		if err != nil {
			return err
		}
		defer clear(keyPEM)
		pubPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindSigningPublic, p.Name(), next.PublicKey())
		if err != nil {
			return err
		}
		keyName, pubName := SigningFiles(out.NewID, env.anchorID)
		if out.Files, err = writeKeyPair(root, map[string][]byte{keyName: keyPEM, pubName: pubPEM},
			map[string]fs.FileMode{keyName: permSecret, pubName: permPublic}); err != nil {
			return err
		}
		out.Seq, err = env.commit(ctx, tx, &sent, rec, p, d, orgID, actor, "keys.signing_rotated", map[string]any{
			"previous_key_id": out.OldID, "key_id": out.NewID, "overlap_until": out.OverlapUntil.Format(time.RFC3339)})
		return err
	})
	if err != nil {
		return TrustRotation{}, cleanup(root, out.Files, sent, err)
	}
	return out, nil
}

// RotateCA — keys rotate-ca (ADR-0018, п. 6.1): новый корень внутреннего
// УЦ и заявление, в котором прежний корень действует ещё overlap.
func RotateCA(ctx context.Context, db Owner, rec Recorder, p aisecCrypto.Provider, dir, orgID string,
	actor audit.Actor, now time.Time, overlap time.Duration) (TrustRotation, error) {
	if overlap < 0 {
		return TrustRotation{}, errors.New("перекрытие не может быть отрицательным")
	}
	root, err := OpenKeyDir(dir)
	if err != nil {
		return TrustRotation{}, err
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: файлы записаны и синхронизированы раньше
	now = now.UTC().Truncate(time.Second)
	var out TrustRotation
	sent := false
	err = InTx(ctx, db, func(tx pgx.Tx) error {
		env, err := openTrustEnv(ctx, tx, root, p, orgID)
		if err != nil {
			return err
		}
		d, err := env.draft(now)
		if err != nil {
			return err
		}
		if len(d.Roots) == 0 {
			return fmt.Errorf("в каталоге нет %s: внутренний УЦ не создан, ротировать нечего", CACertFile)
		}
		ca, err := aisecCrypto.NewCA(caCommonName, aisecCrypto.MaxCertValidity, now)
		if err != nil {
			return err
		}
		der := ca.CertDER()
		out.NewID = bundle.RootID(env.hasher, der)
		until := overlapUntil(now, overlap)
		for i := range d.Roots {
			if d.Roots[i].NotAfter == nil {
				out.OldID = d.Roots[i].ID
				d.Roots[i].NotAfter = until
			}
		}
		d.Roots = append(d.Roots, bundle.TrustRoot{ID: out.NewID, DER: der})
		out.OverlapUntil = *until
		keyPEM, err := ca.KeyPEM()
		if err != nil {
			return err
		}
		defer clear(keyPEM)
		anchorRoot, err := AnchorRootID(root, env.hasher)
		if err != nil {
			return err
		}
		crtName, keyName := CAFiles(out.NewID, anchorRoot)
		if out.Files, err = writeKeyPair(root, map[string][]byte{crtName: ca.CertPEM(), keyName: keyPEM},
			map[string]fs.FileMode{crtName: permPublic, keyName: permSecret}); err != nil {
			return err
		}
		out.Seq, err = env.commit(ctx, tx, &sent, rec, p, d, orgID, actor, "keys.ca_rotated", map[string]any{
			"previous_root_id": out.OldID, "root_id": out.NewID, "overlap_until": out.OverlapUntil.Format(time.RFC3339),
			"root_not_after": ca.NotAfter().UTC().Format(time.RFC3339)})
		return err
	})
	if err != nil {
		return TrustRotation{}, cleanup(root, out.Files, sent, err)
	}
	return out, nil
}

// cleanup удаляет файлы несостоявшейся ротации, если запись в БД не
// отправлялась: новый ключ никто не примет. После отправки исход фиксации
// может быть неизвестен — файлы остаются, решает keys status.
func cleanup(root *os.Root, files []string, sent bool, err error) error {
	if !sent {
		for _, name := range files {
			_ = root.Remove(name) //nolint:gosec // G104: файл без записи в БД безвреден, повторный запуск создаст новый
		}
		return err
	}
	if len(files) > 0 {
		return fmt.Errorf("%w; новые файлы %v сохранены: если keys status не показывает ротацию, удалите их", err, files)
	}
	return err
}

// AuditRotation — итог keys rotate-audit.
type AuditRotation struct {
	Seq           int
	OldID, NewID  string
	CheckpointSeq int64
	Files         []string
}

// RotateAudit — keys rotate-audit (ADR-0018, п. 5): новый ключ подписи
// контрольных точек и смена в audit_key_rotations, подписанная прежним и
// новым ключом. Блокировка архивации держится до конца транзакции: новая
// точка не ляжет между чтением номера последней точки и записью смены.
func RotateAudit(ctx context.Context, db Owner, rec Recorder, p aisecCrypto.Provider, dir, orgID string,
	actor audit.Actor, now time.Time) (AuditRotation, error) {
	root, err := OpenKeyDir(dir)
	if err != nil {
		return AuditRotation{}, err
	}
	defer func() { _ = root.Close() }() //nolint:gosec // G104: файлы записаны и синхронизированы раньше
	h, err := p.Hasher()
	if err != nil {
		return AuditRotation{}, err
	}
	var out AuditRotation
	sent := false
	err = InTx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", audit.ArchiveLockID); err != nil {
			return fmt.Errorf("блокировка архивации: %w", err)
		}
		anchor, err := ReadVerifier(root, p, AuditPubFile, aisecCrypto.KeyKindAuditSigningPublic)
		if err != nil {
			return fmt.Errorf("ключ-якорь аудита: %w", err)
		}
		rots, err := audit.LoadKeyRotations(ctx, tx)
		if err != nil {
			return err
		}
		ks, err := audit.NewKeySchedule(p, anchor, rots)
		if err != nil {
			return err
		}
		anchorID := audit.KeyID(h, anchor.PublicKey())
		out.OldID = ks.LatestID()
		keyFile, _ := AuditFiles(out.OldID, anchorID)
		prev, err := ReadSigner(root, p, keyFile, aisecCrypto.KeyKindAuditSigning)
		if err != nil {
			return fmt.Errorf("действующий ключ аудита: %w", err)
		}
		if !aisecCrypto.Equal(prev.PublicKey(), ks.Latest().PublicKey()) {
			return fmt.Errorf("%s не соответствует действующему ключу аудита %s", keyFile, out.OldID)
		}
		next, err := p.GenerateSigner()
		if err != nil {
			return err
		}
		out.NewID = audit.KeyID(h, next.PublicKey())
		if out.CheckpointSeq, err = audit.LatestCheckpointSeq(ctx, tx); err != nil {
			return err
		}
		r := audit.KeyRotation{OrgID: orgID, Seq: ks.Rotations() + 1, CheckpointSeq: out.CheckpointSeq, RotatedAt: now}
		if err := audit.SignKeyRotation(h, prev, next, &r); err != nil {
			return err
		}
		if _, err := audit.NewKeySchedule(p, anchor, append(rots, r)); err != nil {
			return fmt.Errorf("смена ключа не проверяется расписанием: %w", err)
		}
		out.Seq = r.Seq
		seed := next.Seed()
		defer clear(seed)
		keyPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindAuditSigning, p.Name(), seed)
		if err != nil {
			return err
		}
		defer clear(keyPEM)
		pubPEM, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindAuditSigningPublic, p.Name(), next.PublicKey())
		if err != nil {
			return err
		}
		keyName, pubName := AuditFiles(out.NewID, anchorID)
		if out.Files, err = writeKeyPair(root, map[string][]byte{keyName: keyPEM, pubName: pubPEM},
			map[string]fs.FileMode{keyName: permSecret, pubName: permPublic}); err != nil {
			return err
		}
		sent = true
		if err := audit.InsertKeyRotation(ctx, tx, &r); err != nil {
			return err
		}
		return rec.RecordTx(ctx, tx, audit.Entry{OrgID: orgID, Actor: actor, Action: "keys.audit_rotated",
			Object: audit.Object{Type: "key_file", ID: pubName}, Result: audit.ResultSuccess,
			Details: map[string]any{"seq": r.Seq, "previous_key_id": out.OldID, "key_id": out.NewID,
				"checkpoint_seq": out.CheckpointSeq}})
	})
	if err != nil {
		return AuditRotation{}, cleanup(root, out.Files, sent, err)
	}
	return out, nil
}
