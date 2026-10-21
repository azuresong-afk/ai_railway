package auth_test

import (
	"context"
	"encoding/hex"
	"errors"
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
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
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
	if e.svc, err = auth.NewService(ctx, e.store, e.log, p, auth.WithClock(e.clock.now), auth.WithPasswordHasher(&authtest.Hasher{})); err != nil {
		t.Fatal(err)
	}
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
	admin := res.Caller
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
	p.SessionIdleMinutes = 30
	if err := e.svc.SetPolicy(ctx, admin, p); err != nil {
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
	for i, pair := range [][2]any{{r1.Caller, second}, {r2.Caller, adminID}} {
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
		"UPDATE users SET login = 'x'", "UPDATE users SET role = 'security_admin'", "UPDATE users SET org_id = org_id",
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
