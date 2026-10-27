package auth_test

import (
	"context"
	"encoding/hex"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/auth/authtest"
	"github.com/azuresong-afk/ai_railway/internal/auth/ldap"
	"github.com/azuresong-afk/ai_railway/internal/auth/oidc"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/keyring"
	"github.com/azuresong-afk/ai_railway/internal/keyring/keyringtest"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// Тесты на живой БД: AISEC_TEST_DATABASE_URL (make dev, postgres на
// 127.0.0.1:5432; пользователь стенда — владелец БД). Без переменной
// пропускаются. Каждый тест — в своей схеме; приложение работает под ролью
// aisec_app, как в рабочей установке.

type pgEnv struct {
	owner *pgxpool.Pool
	app   *pgxpool.Pool
	log   *audit.Log
	store *auth.PGStore
	svc   *auth.Service
	clock *clock
	mfa   *mfaKeys
	// keyID — ID ключа данных установки (data_keys).
	keyID string
	// oidc — клиент IdP сервиса (вход через IdP, ADR-0025): loopback
	// разрешён для синтетического IdP на 127.0.0.1.
	oidc *oidc.Client
	// ldap — клиент каталога сервиса (вход через LDAP, ADR-0025, 2):
	// loopback разрешён для синтетического каталога на 127.0.0.1.
	ldap *ldap.Client
	// dir и box — каталог ключей установки и ключ данных сервиса (ротация).
	dir string
	box *keyring.Box
}

func pgCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	return ctx
}

func newPool(t *testing.T, dsn, schema, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 16
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	if role != "" {
		cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
			_, err := c.Exec(ctx, "SELECT set_config('role', $1, false)", role)
			return err
		}
	}
	p, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

type poolExec struct{ p *pgxpool.Pool }

func (e poolExec) InTx(ctx context.Context, fn func(store.Tx) error) error {
	tx, err := e.p.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }() //nolint:gosec // G104: откат после коммита безвреден
	if err := fn(poolTx{tx}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type poolTx struct{ tx pgx.Tx }

func (t poolTx) Exec(ctx context.Context, sql string, args ...any) error {
	_, err := t.tx.Exec(ctx, sql, args...)
	return err
}

func (t poolTx) Applied(ctx context.Context) ([]store.Applied, error) {
	rows, err := t.tx.Query(ctx, "SELECT version, name, checksum FROM schema_migrations ORDER BY version")
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (store.Applied, error) {
		var a store.Applied
		err := r.Scan(&a.Version, &a.Name, &a.Checksum)
		return a, err
	})
}

func setupPG(t *testing.T) *pgEnv {
	t.Helper()
	dsn := os.Getenv("AISEC_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AISEC_TEST_DATABASE_URL не задан")
	}
	ctx := pgCtx(t)
	p := provider(t)
	r, err := p.Random()
	if err != nil {
		t.Fatal(err)
	}
	b, err := aisecCrypto.RandomBytes(r, 6)
	if err != nil {
		t.Fatal(err)
	}
	schema := "auth_test_" + hex.EncodeToString(b)
	admin := newPool(t, dsn, "public", "")
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE") //nolint:gosec // G104: уборка тестовой схемы
	})
	owner := newPool(t, dsn, schema, "")
	ms, err := store.LoadMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	h, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&store.Migrator{Exec: poolExec{owner}, Hasher: h, Migrations: ms}).Up(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, "GRANT USAGE ON SCHEMA "+pgx.Identifier{schema}.Sanitize()+" TO aisec_app"); err != nil {
		t.Fatal(err)
	}
	e := &pgEnv{owner: owner, app: newPool(t, dsn, schema, "aisec_app"), clock: &clock{t: time.Now().UTC().Truncate(time.Microsecond)}}
	if e.log, err = audit.New(e.app, p); err != nil {
		t.Fatal(err)
	}
	if e.store, err = auth.NewPGStore(e.app, e.log); err != nil {
		t.Fatal(err)
	}
	// Ключи установки — как после aisec-cli init; сервер загружает их так же.
	dir, keyID := keyringtest.Install(t, ctx, owner, p, audit.DefaultOrgID)
	box, err := keyring.Load(ctx, e.app, p, dir, audit.DefaultOrgID)
	if err != nil {
		t.Fatal(err)
	}
	e.keyID, e.dir, e.box = keyID, dir, box
	roles, err := auth.NewPGRoles(e.app, e.log)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.NewPGAPITokens(e.app, e.log)
	if err != nil {
		t.Fatal(err)
	}
	if e.oidc, err = oidc.New(p); err != nil {
		t.Fatal(err)
	}
	e.oidc.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if e.ldap, err = ldap.New(p); err != nil {
		t.Fatal(err)
	}
	e.ldap.AllowNetworks([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})
	if e.svc, err = auth.NewService(ctx, e.store, e.log, p, auth.WithClock(e.clock.now), auth.WithPasswordHasher(&authtest.Hasher{}),
		auth.WithSecretBox(box), auth.WithRoleStore(roles), auth.WithAPITokenStore(tokens), auth.WithOIDC(e.store, e.oidc),
		auth.WithLDAP(e.store, e.ldap)); err != nil {
		t.Fatal(err)
	}
	e.mfa = newMFAKeys(e.svc, e.store, e.clock)
	return e
}

func (e *pgEnv) addUser(t *testing.T, id, login string, role auth.Role) {
	t.Helper()
	now := e.clock.now()
	u := auth.User{ID: id, OrgID: audit.DefaultOrgID, Login: login, DisplayName: "Тест " + login, Role: role,
		Status: auth.StatusActive, PasswordHash: authtest.HashOf(phrase), PasswordChangedAt: now, CreatedAt: now, CreatedBy: "test"}
	rec := audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "user.create",
		Object: audit.Object{Type: "user", ID: id}, Result: audit.ResultSuccess}
	if err := e.store.CreateUser(pgCtx(t), u, rec); err != nil {
		t.Fatal(err)
	}
}

func (e *pgEnv) login(t *testing.T, login, password string) (auth.LoginResult, error) {
	t.Helper()
	return e.svc.Login(pgCtx(t), auth.LoginInput{Login: login, Password: password, SourceIP: testIP, UserAgent: "test"})
}

func sqlState(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

func auditCount(t *testing.T, e *pgEnv, action string) int {
	t.Helper()
	var n int
	if err := e.owner.QueryRow(pgCtx(t), "SELECT count(*) FROM audit_log WHERE action = $1", action).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Полный путь на PostgreSQL: вход, сессия, смена пароля, деактивация;
// записи аудита в цепочке, цепочка цела.
func TestPGFlow(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	u, temp, err := e.svc.CreateUser(ctx, admin, auth.NewUser{Login: "ivanov", DisplayName: "Иванов", Role: auth.RoleAnalyst})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.CreateUser(ctx, admin, auth.NewUser{Login: "IVANOV", DisplayName: "Дубль", Role: auth.RoleAnalyst}); !errors.Is(err, auth.ErrLoginTaken) {
		t.Fatalf("занятый логин: %v", err)
	}
	r1, err := e.login(t, "ivanov", temp)
	if err != nil || r1.Caller.Session.State != auth.SessionPasswordChange {
		t.Fatalf("вход с временным паролем: %v", err)
	}
	r2, err := e.login(t, "ivanov", temp)
	if err != nil {
		t.Fatal(err)
	}
	c, err := e.svc.Authenticate(ctx, r2.Token, testIP)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ChangePassword(ctx, c, temp, phrase2); err != nil {
		t.Fatal(err)
	}
	if c, err = e.svc.Authenticate(ctx, r2.Token, testIP); err != nil || c.Session.State != auth.SessionActive {
		t.Fatalf("после смены пароля: %v %s", err, c.Session.State)
	}
	if _, err := e.svc.Authenticate(ctx, r1.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("другая сессия жива: %v", err)
	}
	hist, err := e.store.PasswordHistory(ctx, u.ID, 10)
	if err != nil || len(hist) != 1 || hist[0] != authtest.HashOf(temp) {
		t.Fatalf("история: %v %v", hist, err)
	}
	if err := e.svc.SetStatus(ctx, admin, u.ID, auth.StatusDeactivated); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authenticate(ctx, r2.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("сессия деактивированного: %v", err)
	}
	if err := e.svc.SetStatus(ctx, admin, adminID, auth.StatusDeactivated); !errors.Is(err, auth.ErrSelf) {
		t.Fatal(err)
	}
	users, err := e.svc.Users(ctx, nil, 10)
	if err != nil || len(users) != 2 {
		t.Fatalf("список: %d %v", len(users), err)
	}
	page, err := e.svc.Users(ctx, &auth.UserCursor{CreatedAt: users[0].CreatedAt, ID: users[0].ID}, 10)
	if err != nil || len(page) != 1 || page[0].ID != users[1].ID {
		t.Fatalf("вторая страница: %v %v", page, err)
	}
	p := auth.DefaultPolicy()
	p.SessionIdleMinutes = 10
	if err := e.svc.SetPolicy(ctx, admin, p, "", ""); err != nil {
		t.Fatal(err)
	}
	if got, err := e.svc.Policy(ctx); err != nil || got != p {
		t.Fatalf("политика: %+v", got)
	}
	for _, a := range []string{"auth.login", "user.create", "auth.password_changed", "user.deactivate", "auth.policy_changed"} {
		if auditCount(t, e, a) == 0 {
			t.Errorf("нет записи %s в audit_log", a)
		}
	}
	v, err := audit.NewVerifier(e.log).Verify(ctx)
	if err != nil || !v.OK() {
		t.Fatalf("цепочка аудита: %v %+v", err, v.Break)
	}
}

// DM-39 на PostgreSQL: параллельные неудачи считаются все, блокировка
// наступает ровно один раз.
func TestPGConcurrentFailures(t *testing.T) {
	e := setupPG(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	const n = 20
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.login(t, "ivanov", wrongPhrase); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	u, err := e.store.UserByID(pgCtx(t), audit.DefaultOrgID, userID)
	if err != nil {
		t.Fatal(err)
	}
	threshold := auth.DefaultPolicy().LockoutThreshold
	if !u.Locked(e.clock.now()) || u.FailedAttempts < threshold {
		t.Fatalf("блокировка: %v, неудач %d", u.Locked(e.clock.now()), u.FailedAttempts)
	}
	if got := auditCount(t, e, "auth.locked"); got != 1 {
		t.Fatalf("auth.locked записан %d раз", got)
	}
	if got := auditCount(t, e, "auth.login_failed"); got != n {
		t.Fatalf("auth.login_failed: %d из %d", got, n)
	}
	if _, err := e.login(t, "ivanov", phrase); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("вход во время блокировки: %v", err)
	}
}

// Встречная деактивация двух администраторов не оставляет систему без
// активного администратора безопасности.
func TestPGLastAdminConcurrent(t *testing.T) {
	e := setupPG(t)
	const second = "01900000-0000-7000-8000-00000000a002"
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, second, "admin2", auth.RoleSecurityAdmin)
	r1, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := e.login(t, "admin2", phrase)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, pair := range [][2]any{{e.mfa.complete(t, r1), second}, {e.mfa.complete(t, r2), adminID}} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = e.svc.SetStatus(pgCtx(t), pair[0].(auth.Caller), pair[1].(string), auth.StatusDeactivated)
		}()
	}
	wg.Wait()
	var active int
	if err := e.owner.QueryRow(pgCtx(t), "SELECT count(*) FROM users WHERE status = 'active'").Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 || (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("активных %d, ошибки %v", active, errs)
	}
}

// УПД.4 на PostgreSQL: параллельные входы не превышают лимит сессий.
func TestPGSessionLimitConcurrent(t *testing.T) {
	e := setupPG(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := e.login(t, "ivanov", phrase); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	list, err := e.store.ListSessions(pgCtx(t), userID)
	if err != nil || len(list) != auth.DefaultPolicy().SessionMaxPerUser {
		t.Fatalf("сессий %d: %v", len(list), err)
	}
}

// УПД.5: учётные записи не удаляются ни ролью приложения, ни владельцем;
// роль приложения не удаляет сессии.
func TestPGNoDelete(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	if _, err := e.login(t, "ivanov", phrase); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DELETE FROM users", "TRUNCATE users CASCADE", "DELETE FROM sessions", "DELETE FROM auth_settings"} {
		if _, err := e.app.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("%s под aisec_app: %v", q, err)
		}
	}
	if _, err := e.owner.Exec(ctx, "DELETE FROM users"); sqlState(err) != "42501" {
		t.Errorf("DELETE FROM users владельцем: %v", err)
	}
}

// Токен хранится только хешем: по значению из cookie строку не найти.
func TestPGTokenStoredHashed(t *testing.T) {
	e := setupPG(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	res, err := e.login(t, "ivanov", phrase)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	err = e.owner.QueryRow(pgCtx(t), "SELECT count(*) FROM sessions WHERE position($1::bytea in token_hash) > 0 OR position($1::bytea in csrf_hash) > 0",
		[]byte(res.Token)).Scan(&n)
	if err != nil || n != 0 {
		t.Fatalf("токен в БД открыто: %d %v", n, err)
	}
	// Бездействие завершает сессию с причиной idle.
	e.clock.add(16 * time.Minute)
	if _, err := e.svc.Authenticate(pgCtx(t), res.Token, testIP); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatal(err)
	}
	var reason string
	if err := e.owner.QueryRow(pgCtx(t), "SELECT revoke_reason FROM sessions").Scan(&reason); err != nil || reason != auth.RevokeIdle {
		t.Fatalf("причина: %q %v", reason, err)
	}
}

// addSetupToken кладёт токен первичной настройки, как aisec-cli init.
func (e *pgEnv) addSetupToken(t *testing.T, id, token string) {
	t.Helper()
	h, err := provider(t).Hasher()
	if err != nil {
		t.Fatal(err)
	}
	now := e.clock.now()
	if _, err := e.owner.Exec(pgCtx(t), `INSERT INTO setup_tokens (id, org_id, hash_alg, token_hash, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, id, audit.DefaultOrgID, h.Name(), h.Sum([]byte(token)), now, now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
}

// ЗИ.4 на PostgreSQL: параллельные настройки — с одним токеном и с двумя
// разными — создают ровно одного администратора; токен гасится, запись
// аудита ссылается на него.
func TestPGSetupConcurrent(t *testing.T) {
	e := setupPG(t)
	tokens := []string{setupToken(0x10), setupToken(0x40)}
	e.addSetupToken(t, "01900000-0000-7000-8000-0000000c0001", tokens[0])
	e.addSetupToken(t, "01900000-0000-7000-8000-0000000c0002", tokens[1])
	const n = 8
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = e.svc.Setup(pgCtx(t), auth.SetupInput{Token: tokens[i%2], Login: "admin" + strconv.Itoa(i),
				DisplayName: "Администратор", Password: phrase, SourceIP: testIP})
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, auth.ErrSetupUnavailable):
			t.Fatal(err)
		}
	}
	var users, used int
	ctx := pgCtx(t)
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM users").Scan(&users); err != nil {
		t.Fatal(err)
	}
	if err := e.owner.QueryRow(ctx, "SELECT count(*) FROM setup_tokens WHERE used_at IS NOT NULL").Scan(&used); err != nil {
		t.Fatal(err)
	}
	if ok != 1 || users != 1 || used != 1 {
		t.Fatalf("успешных %d, пользователей %d, погашено токенов %d", ok, users, used)
	}
	var detail string
	if err := e.owner.QueryRow(ctx, `SELECT details->>'setup_record_id' FROM audit_log
		WHERE action = 'setup.completed' AND result = 'success'`).Scan(&detail); err != nil || !strings.HasPrefix(detail, "01900000-0000-7000-8000-0000000c000") {
		t.Fatalf("аудит: %q %v", detail, err)
	}
	if got := auditCount(t, e, "setup.completed"); got != n {
		t.Fatalf("записей setup.completed %d, ожидалось %d", got, n)
	}
	// Настройки установки записаны той же транзакцией, что и администратор (H-Р4).
	var tz, mode string
	if err := e.owner.QueryRow(ctx, "SELECT timezone, retention_mode FROM install_settings").Scan(&tz, &mode); err != nil ||
		tz != "Europe/Moscow" || mode != "masked" {
		t.Fatalf("настройки установки: %q %q %v", tz, mode, err)
	}
	// Изменение в «Администрировании» под aisec_app (миграция 0024, В26 ревью 2.r5).
	if err := e.store.SetInstallSettings(ctx, audit.DefaultOrgID, auth.InstallSettings{Timezone: "Asia/Omsk", RetentionMode: "none"},
		e.clock.now(), audit.Entry{Actor: audit.Actor{Type: audit.ActorCLI, ID: "test"}, Action: "setup.settings_changed",
			Object: audit.Object{Type: "install_settings", ID: audit.DefaultOrgID}, Result: audit.ResultSuccess}); err != nil {
		t.Fatal(err)
	}
	if cfg, ok, err := e.store.InstallSettings(ctx, audit.DefaultOrgID); err != nil || !ok || cfg.Timezone != "Asia/Omsk" || cfg.RetentionMode != "none" {
		t.Fatalf("после изменения: %+v %v %v", cfg, ok, err)
	}
	if got := auditCount(t, e, "setup.settings_changed"); got != 1 {
		t.Fatalf("записей setup.settings_changed %d", got)
	}
}

// Роль приложения меняет только «живые» столбцы: логин, роль, хеши токенов
// и привязку сессии не переписать; завершённую сессию не оживить даже владельцем.
func TestPGColumnGrants(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	res, err := e.login(t, "ivanov", phrase)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		// Роль меняется (назначение, задача 2.9): её проверяет TestPGRoleGuards.
		"UPDATE users SET login = 'x'", "UPDATE users SET org_id = org_id",
		"UPDATE sessions SET token_hash = csrf_hash", "UPDATE sessions SET user_id = user_id", "UPDATE sessions SET expires_at = now()",
		"UPDATE setup_tokens SET expires_at = now()",
	} {
		if _, err := e.app.Exec(ctx, q); sqlState(err) != "42501" {
			t.Errorf("%s под aisec_app: %v", q, err)
		}
	}
	if err := e.svc.Logout(ctx, res.Caller); err != nil {
		t.Fatal(err)
	}
	if _, err := e.owner.Exec(ctx, "UPDATE sessions SET revoked_at = NULL, revoke_reason = NULL"); sqlState(err) != "23514" {
		t.Errorf("оживление сессии владельцем: %v", err)
	}
}

// В7 ревью 2.r2 на PostgreSQL: последний незаблокированный администратор
// безопасности при бессрочной блокировке в настройках блокируется на 15 минут.
func TestPGLastAdminLockoutCapped(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	e.addUser(t, userID, "ivanov", auth.RoleAnalyst)
	admin := e.mfa.complete(t, mustPGLogin(t, e, "admin"))
	p := auth.DefaultPolicy()
	p.LockoutMinutes = 0
	if err := e.svc.SetPolicy(ctx, admin, p, "", ""); err != nil {
		t.Fatal(err)
	}
	for _, login := range []string{"admin", "ivanov"} {
		for range p.LockoutThreshold {
			if _, err := e.login(t, login, wrongPhrase); !errors.Is(err, auth.ErrInvalidCredentials) {
				t.Fatal(err)
			}
		}
	}
	var (
		adminFor *time.Duration
		until    *time.Time
	)
	if err := e.owner.QueryRow(ctx, "SELECT locked_until - locked_at FROM users WHERE id = $1", adminID).Scan(&adminFor); err != nil {
		t.Fatal(err)
	}
	if adminFor == nil || *adminFor != 15*time.Minute {
		t.Fatalf("блокировка последнего администратора: %v", adminFor)
	}
	if err := e.owner.QueryRow(ctx, "SELECT locked_until FROM users WHERE id = $1 AND locked_at IS NOT NULL", userID).Scan(&until); err != nil || until != nil {
		t.Fatalf("бессрочная блокировка пользователя: %v %v", until, err)
	}
}

// Задача 4.6: e-mail в PostgreSQL — значение сохраняется и убирается, запись
// аудита в той же транзакции без самого адреса, неизвестная запись — ErrNotFound.
func TestPGEmail(t *testing.T) {
	e := setupPG(t)
	ctx := pgCtx(t)
	e.addUser(t, adminID, "admin", auth.RoleSecurityAdmin)
	res, err := e.login(t, "admin", phrase)
	if err != nil {
		t.Fatal(err)
	}
	admin := e.mfa.complete(t, res)
	u, _, err := e.svc.CreateUser(ctx, admin, auth.NewUser{Login: "ivanov", DisplayName: "Иванов", Role: auth.RoleAnalyst})
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "" {
		t.Fatalf("новая запись с адресом: %q", u.Email)
	}
	if err := e.svc.SetEmail(ctx, admin, u.ID, "ivanov@example.ru"); err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.User(ctx, u.ID)
	if err != nil || got.Email != "ivanov@example.ru" {
		t.Fatalf("после задания: %+v %v", got, err)
	}
	list, err := e.svc.Users(ctx, nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range list {
		found = found || (x.ID == u.ID && x.Email == "ivanov@example.ru")
	}
	if !found {
		t.Fatal("адрес не виден в списке")
	}
	if err := e.svc.SetEmail(ctx, admin, u.ID, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ = e.svc.User(ctx, u.ID); got.Email != "" {
		t.Fatalf("адрес не убран: %q", got.Email)
	}
	if err := e.svc.SetEmail(ctx, admin, "01900000-0000-7000-8000-0000000000ff", "a@example.ru"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("несуществующая запись: %v", err)
	}
	if err := e.store.SetEmail(ctx, audit.DefaultOrgID, u.ID, strings.Repeat("a", 255), audit.Entry{}); err == nil {
		t.Fatal("адрес длиннее 254 принят базой")
	}
}
