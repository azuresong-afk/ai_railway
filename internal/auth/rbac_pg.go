package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// PGRoles — RoleStore на PostgreSQL (миграция 0009_rbac). Записи аудита
// изменений пишутся в той же транзакции.
type PGRoles struct {
	pg *PGStore
}

// NewPGRoles создаёт хранилище ролей; журнал должен работать через тот же пул.
func NewPGRoles(db PGDB, a *audit.Log) (*PGRoles, error) {
	s, err := NewPGStore(db, a)
	if err != nil {
		return nil, fmt.Errorf("роли: %w", err)
	}
	return &PGRoles{pg: s}, nil
}

// pgQuerier — общее у пула и транзакции для чтения.
type pgQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// pgForeignKeyViolation — SQLSTATE нарушения внешнего ключа.
const pgForeignKeyViolation = "23503"

func sqlStateOf(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

const roleCols = `id, display_name, description, builtin, mfa_required, created_at, created_by, updated_at`

func scanRole(row pgx.Row) (RoleDef, error) {
	var (
		r  RoleDef
		id string
	)
	err := row.Scan(&id, &r.DisplayName, &r.Description, &r.Builtin, &r.MFARequired, &r.CreatedAt, &r.CreatedBy, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return RoleDef{}, ErrRoleNotFound
	}
	if err != nil {
		return RoleDef{}, fmt.Errorf("роли: разбор: %w", err)
	}
	r.ID = Role(id)
	return r, nil
}

// addGrant добавляет разрешение из БД. Разрешения, которых больше нет в
// каталоге, и неизвестные области пропускаются: прав они не дают.
func addGrant(g Grants, perm, scope string) {
	p, ok := LookupPermission(perm)
	sc, okScope := ParseScope(scope)
	if !ok || !okScope || (sc == ScopeOwn && !p.Ownable) {
		return
	}
	g[perm] = sc
}

// loadRole читает свою роль с разрешениями; lock — «FOR UPDATE», «FOR SHARE» или пусто.
func loadRole(ctx context.Context, q pgQuerier, orgID string, id Role, lock string) (RoleDef, error) {
	r, err := scanRole(q.QueryRow(ctx, "SELECT "+roleCols+" FROM roles WHERE org_id = $1 AND id = $2 "+lock, orgID, string(id)))
	if err != nil {
		return RoleDef{}, err
	}
	if r.Builtin {
		b, ok := LookupBuiltinRole(id)
		if !ok {
			// Строка предустановленной роли, которой нет в этой версии кода: прав нет.
			r.Grants = Grants{}
			return r, nil
		}
		return b, nil
	}
	rows, err := q.Query(ctx, "SELECT permission, scope FROM role_permissions WHERE org_id = $1 AND role_id = $2", orgID, string(id))
	if err != nil {
		return RoleDef{}, fmt.Errorf("роли: разрешения: %w", err)
	}
	defer rows.Close()
	r.Grants = Grants{}
	for rows.Next() {
		var perm, scope string
		if err := rows.Scan(&perm, &scope); err != nil {
			return RoleDef{}, fmt.Errorf("роли: разрешения: %w", err)
		}
		addGrant(r.Grants, perm, scope)
	}
	if err := rows.Err(); err != nil {
		return RoleDef{}, fmt.Errorf("роли: разрешения: %w", err)
	}
	return r, nil
}

// CustomRole — своя роль; предустановленная или отсутствующая — ErrRoleNotFound.
func (s *PGRoles) CustomRole(ctx context.Context, orgID string, id Role) (RoleDef, error) {
	if !id.Valid() || id.Builtin() {
		return RoleDef{}, ErrRoleNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	r, err := loadRole(ctx, s.pg.db, orgID, id, "")
	if err != nil {
		return RoleDef{}, err
	}
	if r.Builtin {
		return RoleDef{}, ErrRoleNotFound
	}
	return r, nil
}

// ListCustomRoles — свои роли по ID (не больше MaxCustomRoles).
func (s *PGRoles) ListCustomRoles(ctx context.Context, orgID string) ([]RoleDef, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.pg.db.Query(ctx, "SELECT "+roleCols+" FROM roles WHERE org_id = $1 AND NOT builtin ORDER BY id LIMIT $2",
		orgID, MaxCustomRoles+1)
	if err != nil {
		return nil, fmt.Errorf("роли: список: %w", err)
	}
	defs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (RoleDef, error) { return scanRole(r) })
	if err != nil {
		return nil, fmt.Errorf("роли: список: %w", err)
	}
	if len(defs) == 0 {
		return defs, nil
	}
	idx := make(map[Role]int, len(defs))
	for i := range defs {
		defs[i].Grants = Grants{}
		idx[defs[i].ID] = i
	}
	prow, err := s.pg.db.Query(ctx, `SELECT p.role_id, p.permission, p.scope FROM role_permissions p
		JOIN roles r ON r.org_id = p.org_id AND r.id = p.role_id WHERE p.org_id = $1 AND NOT r.builtin`, orgID)
	if err != nil {
		return nil, fmt.Errorf("роли: разрешения: %w", err)
	}
	defer prow.Close()
	for prow.Next() {
		var role, perm, scope string
		if err := prow.Scan(&role, &perm, &scope); err != nil {
			return nil, fmt.Errorf("роли: разрешения: %w", err)
		}
		if i, ok := idx[Role(role)]; ok {
			addGrant(defs[i].Grants, perm, scope)
		}
	}
	if err := prow.Err(); err != nil {
		return nil, fmt.Errorf("роли: разрешения: %w", err)
	}
	return defs, nil
}

// RoleUsers — число учётных записей по ролям.
func (s *PGRoles) RoleUsers(ctx context.Context, orgID string) (map[Role]int, error) {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	rows, err := s.pg.db.Query(ctx, "SELECT role, count(*) FROM users WHERE org_id = $1 GROUP BY role", orgID)
	if err != nil {
		return nil, fmt.Errorf("роли: пользователи: %w", err)
	}
	defer rows.Close()
	out := map[Role]int{}
	for rows.Next() {
		var (
			role string
			n    int
		)
		if err := rows.Scan(&role, &n); err != nil {
			return nil, fmt.Errorf("роли: пользователи: %w", err)
		}
		out[Role(role)] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("роли: пользователи: %w", err)
	}
	return out, nil
}

func insertGrants(ctx context.Context, tx pgx.Tx, orgID string, id Role, g Grants) error {
	for _, p := range g.Names() {
		if _, err := tx.Exec(ctx, "INSERT INTO role_permissions (org_id, role_id, permission, scope) VALUES ($1, $2, $3, $4)",
			orgID, string(id), p, g.Scope(p).String()); err != nil {
			return fmt.Errorf("роли: разрешение: %w", err)
		}
	}
	return nil
}

// CreateRole сохраняет свою роль и запись аудита одной транзакцией.
// Создания в организации идут по очереди (рекомендательная блокировка),
// чтобы предел MaxCustomRoles нельзя было обойти параллельными запросами.
func (s *PGRoles) CreateRole(ctx context.Context, orgID, actorID string, r RoleDef, fn func(actor Actor) (audit.Entry, error)) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.pg.inTx(ctx, func(tx pgx.Tx) error {
		actor, err := loadActor(ctx, tx, orgID, actorID, true)
		if err != nil {
			return err
		}
		rec, err := fn(actor)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('aisec.roles'), hashtext($1))", orgID); err != nil {
			return fmt.Errorf("роли: блокировка: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM roles WHERE org_id = $1 AND NOT builtin", orgID).Scan(&n); err != nil {
			return fmt.Errorf("роли: число: %w", err)
		}
		if n >= MaxCustomRoles {
			return ErrTooManyRoles
		}
		tag, err := tx.Exec(ctx, `INSERT INTO roles (org_id, id, display_name, description, mfa_required, created_at, created_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (org_id, id) DO NOTHING`,
			orgID, string(r.ID), r.DisplayName, r.Description, r.MFARequired, r.CreatedAt, r.CreatedBy, r.UpdatedAt)
		if err != nil {
			return fmt.Errorf("роли: создание: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrRoleTaken
		}
		if err := insertGrants(ctx, tx, orgID, r.ID, r.Grants); err != nil {
			return err
		}
		return s.pg.record(ctx, tx, rec)
	})
}

func validUUID(s string) bool {
	_, err := store.ParseUUID(s)
	return err == nil
}

// noActor — действующий не найден: прав нет.
var noActor = Actor{Role: RoleDef{Grants: Grants{}}}

// loadActor перечитывает действующего в транзакции: строку пользователя
// (с lockUser — FOR SHARE, иначе она уже заблокирована вызывающим) и его
// роль. Порядок блокировок везде один: пользователи, затем роли.
func loadActor(ctx context.Context, tx pgx.Tx, orgID, actorID string, lockUser bool) (Actor, error) {
	if !validUUID(actorID) {
		return noActor, nil
	}
	q := "SELECT role, status FROM users WHERE org_id = $1 AND id = $2"
	if lockUser {
		q += " FOR SHARE"
	}
	var role, status string
	err := tx.QueryRow(ctx, q, orgID, actorID).Scan(&role, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return noActor, nil
	}
	if err != nil {
		return Actor{}, fmt.Errorf("роли: действующий: %w", err)
	}
	r, err := roleForAssign(ctx, tx, orgID, Role(role))
	if errors.Is(err, ErrRoleNotFound) {
		r = RoleDef{ID: Role(role), Grants: Grants{}}
	} else if err != nil {
		return Actor{}, err
	}
	return Actor{Role: r, Active: Status(status) == StatusActive}, nil
}

// lockCustom блокирует свою роль; предустановленная — ErrRoleBuiltin.
func lockCustom(ctx context.Context, tx pgx.Tx, orgID string, id Role) (RoleDef, error) {
	if !id.Valid() {
		return RoleDef{}, ErrRoleNotFound
	}
	cur, err := loadRole(ctx, tx, orgID, id, "FOR UPDATE")
	if err != nil {
		return RoleDef{}, err
	}
	if cur.Builtin {
		return RoleDef{}, ErrRoleBuiltin
	}
	return cur, nil
}

// UpdateRole меняет свою роль под блокировкой строки.
func (s *PGRoles) UpdateRole(ctx context.Context, orgID, actorID string, id Role,
	fn func(actor Actor, cur RoleDef) (RoleDef, audit.Entry, error)) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.pg.inTx(ctx, func(tx pgx.Tx) error {
		actor, err := loadActor(ctx, tx, orgID, actorID, true)
		if err != nil {
			return err
		}
		if actor.Role.ID == id {
			// Своя роль: отказ до блокировки FOR UPDATE поверх FOR SHARE.
			_, _, err := fn(actor, RoleDef{ID: id, Grants: Grants{}})
			return err
		}
		cur, err := lockCustom(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		next, rec, err := fn(actor, cur)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE roles SET display_name = $3, description = $4, mfa_required = $5, updated_at = $6
			WHERE org_id = $1 AND id = $2`, orgID, string(id), next.DisplayName, next.Description, next.MFARequired, next.UpdatedAt); err != nil {
			return fmt.Errorf("роли: изменение: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM role_permissions WHERE org_id = $1 AND role_id = $2", orgID, string(id)); err != nil {
			return fmt.Errorf("роли: разрешения: %w", err)
		}
		if err := insertGrants(ctx, tx, orgID, id, next.Grants); err != nil {
			return err
		}
		return s.pg.record(ctx, tx, rec)
	})
}

// DeleteRole удаляет свою роль без пользователей.
func (s *PGRoles) DeleteRole(ctx context.Context, orgID, actorID string, id Role, fn func(actor Actor, cur RoleDef) (audit.Entry, error)) error {
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	return s.pg.inTx(ctx, func(tx pgx.Tx) error {
		actor, err := loadActor(ctx, tx, orgID, actorID, true)
		if err != nil {
			return err
		}
		if actor.Role.ID == id {
			_, err := fn(actor, RoleDef{ID: id, Grants: Grants{}})
			return err
		}
		cur, err := lockCustom(ctx, tx, orgID, id)
		if err != nil {
			return err
		}
		rec, err := fn(actor, cur)
		if err != nil {
			return err
		}
		var used bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM users WHERE org_id = $1 AND role = $2)", orgID, string(id)).
			Scan(&used); err != nil {
			return fmt.Errorf("роли: пользователи: %w", err)
		}
		if used {
			return ErrRoleInUse
		}
		if _, err := tx.Exec(ctx, "DELETE FROM role_permissions WHERE org_id = $1 AND role_id = $2", orgID, string(id)); err != nil {
			return fmt.Errorf("роли: разрешения: %w", err)
		}
		if _, err := tx.Exec(ctx, "DELETE FROM roles WHERE org_id = $1 AND id = $2", orgID, string(id)); err != nil {
			if sqlStateOf(err) == pgForeignKeyViolation {
				return ErrRoleInUse
			}
			return fmt.Errorf("роли: удаление: %w", err)
		}
		return s.pg.record(ctx, tx, rec)
	})
}

// roleForAssign — роль для назначения: предустановленная из кода, своя —
// под блокировкой FOR SHARE (параллельное удаление или изменение ждёт).
func roleForAssign(ctx context.Context, tx pgx.Tx, orgID string, id Role) (RoleDef, error) {
	if r, ok := LookupBuiltinRole(id); ok {
		return r, nil
	}
	if !id.Valid() {
		return RoleDef{}, ErrRoleNotFound
	}
	return loadRole(ctx, tx, orgID, id, "FOR SHARE")
}

// AssignRole назначает роль. Строки администраторов безопасности
// блокируются в порядке ID до строк действующего и цели — так же, как при
// деактивации: встречные действия не оставят систему без администратора.
// Действующий и цель блокируются одним запросом в порядке ID, поэтому
// встречные назначения двух пользователей друг другу не взаимоблокируются.
func (s *PGRoles) AssignRole(ctx context.Context, orgID, actorID, userID string, role Role, now time.Time,
	fn func(actor Actor, u User, cur, next RoleDef) (audit.Entry, error)) (int, error) {
	if _, err := store.ParseUUID(userID); err != nil {
		return 0, ErrNotFound
	}
	ctx, cancel := pgCtx(ctx)
	defer cancel()
	var n int
	err := s.pg.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id::text FROM users WHERE org_id = $1 AND role = $2 AND status = $3
			ORDER BY id FOR UPDATE`, orgID, string(RoleSecurityAdmin), string(StatusActive))
		if err != nil {
			return fmt.Errorf("роли: администраторы: %w", err)
		}
		admins, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("роли: администраторы: %w", err)
		}
		ids := []string{userID}
		if validUUID(actorID) {
			ids = append(ids, actorID)
		}
		if _, err := tx.Exec(ctx, "SELECT 1 FROM users WHERE org_id = $1 AND id = ANY($2::uuid[]) ORDER BY id FOR UPDATE",
			orgID, ids); err != nil {
			return fmt.Errorf("роли: блокировка пользователей: %w", err)
		}
		u, err := scanUser(tx.QueryRow(ctx, "SELECT "+userCols+" FROM users u WHERE u.org_id = $1 AND u.id = $2", orgID, userID))
		if err != nil {
			return err
		}
		actor, err := loadActor(ctx, tx, orgID, actorID, false)
		if err != nil {
			return err
		}
		cur, err := roleForAssign(ctx, tx, orgID, u.Role)
		if errors.Is(err, ErrRoleNotFound) {
			cur = RoleDef{ID: u.Role, Grants: Grants{}}
		} else if err != nil {
			return err
		}
		next, err := roleForAssign(ctx, tx, orgID, role)
		if err != nil {
			return err
		}
		// Сначала права назначающего: отказ по ним не раскрывает, последний ли это администратор.
		rec, err := fn(actor, u, cur, next)
		if err != nil {
			return err
		}
		if u.Role == RoleSecurityAdmin && u.Status == StatusActive && role != RoleSecurityAdmin && len(admins) <= 1 {
			return ErrLastAdmin
		}
		if u.Role == role {
			return ErrRoleUnchanged
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET role = $2 WHERE id = $1", userID, string(role)); err != nil {
			if sqlStateOf(err) == pgForeignKeyViolation {
				return ErrRoleNotFound
			}
			return fmt.Errorf("роли: назначение: %w", err)
		}
		tag, err := tx.Exec(ctx, `UPDATE sessions SET revoked_at = $2, revoke_reason = $3
			WHERE user_id = $1 AND revoked_at IS NULL`, userID, now, RevokeAdmin)
		if err != nil {
			return fmt.Errorf("роли: завершение сессий: %w", err)
		}
		n = int(tag.RowsAffected())
		AddDetail(&rec, "revoked_sessions", n)
		return s.pg.record(ctx, tx, rec)
	})
	return n, err
}

var _ RoleStore = (*PGRoles)(nil)
