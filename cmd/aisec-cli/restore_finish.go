package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// restoreFinishTimeout — предел шага целиком: четыре правки и одна запись.
const restoreFinishTimeout = 2 * time.Minute

// copyDirRe — имя каталога копии backup.sh (aisec-20261022T101500Z) или
// другое короткое имя без путей.
var copyDirRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// restoreFinish — aisec-cli restore-finish: шаг после восстановления
// полной копии пилота (restore.sh; В2 ревью B1 этапа 3, РВ.2). Копия
// возвращает сессии консоли, токены API, токены регистрации шлюзов и токен
// первичной настройки в состояние на момент копии, в том числе отозванные и
// погашенные позже, поэтому одной транзакцией все они завершаются (3В21
// ревью 3.r3) и пишется запись system.restored. Давность копии — по
// последней записи журнала аудита восстановленной БД: её не подделать, не
// нарушив цепочку (restore.sh проверяет её следом); свои прежние записи
// system.restored не в счёт, иначе повтор обнулил бы давность. Шаг выполняется до
// запуска сервера, иначе его записи сдвинут оценку. Проверки «сервер
// остановлен» по свежим сессиям нет: копию, снятую минуты назад, она
// отвергла бы, а отзыв безопасен и при работающем сервере. Копия старше 7 суток —
// только предупреждение: БД уже восстановлена, отказ оставил бы сессии в
// силе (решение владельца 25.10.2026). Без -confirm команда ничего не
// делает (3Н53 ревью 3.r4): на работающей установке случайный запуск
// завершил бы все сессии, отозвал токены и записал ложное system.restored.
func restoreFinish(args []string, dsn string, stdout, stderr io.Writer, now time.Time) error {
	fset := flag.NewFlagSet("restore-finish", flag.ContinueOnError)
	fset.SetOutput(stderr)
	copyDir := fset.String("copy-dir", "", "имя каталога копии для записи аудита (только для сверки, на расчёт не влияет)")
	confirm := fset.Bool("confirm", false, "подтверждение: БД только что восстановлена из копии, сервер не запущен")
	if err := fset.Parse(args); err != nil {
		return err
	}
	if fset.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fset.NArg())
	}
	if !*confirm {
		return errors.New("команда завершает все сессии консоли и отзывает все токены API; выполняйте её только после " +
			"восстановления копии и до запуска сервера, с флагом -confirm (restore.sh передаёт его сам)")
	}
	if *copyDir != "" && !copyDirRe.MatchString(*copyDir) {
		return errors.New("-copy-dir: имя каталога без пути, до 128 символов A–Z, a–z, 0–9, «.», «_», «-»")
	}
	if dsn == "" {
		return errors.New("задайте AISEC_DATABASE_URL (postgres://пользователь@хост:порт/база)")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), restoreFinishTimeout)
	defer cancel()
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return err
	}
	defer db.Close()
	l, err := openAuditLog(db, p, nil)
	if err != nil {
		return err
	}
	res, err := restoreFinishTx(ctx, db, l, cliActor(), *copyDir, now)
	if err != nil {
		return err
	}
	say(stdout, "Восстановление завершено: сессий консоли завершено %d, токенов API отозвано %d, токенов регистрации шлюзов погашено %d, "+
		"токенов первичной настройки погашено %d. Запись system.restored в журнале аудита.\n",
		res.revoked.Sessions, res.revoked.APITokens, res.gatewayTokens, res.setupTokens)
	if res.gatewayTokens > 0 {
		say(stdout, "Шлюзы, зарегистрированные после копии, и шлюзы с невыданным токеном зарегистрируйте заново новым токеном "+
			"(aisec-cli gateway token, для зарегистрированных — с -reregister).\n")
	}
	say(stdout, "Последняя запись журнала аудита копии — %s (%d ч назад).\n", res.lastAudit.UTC().Format("2006-01-02 15:04 UTC"), res.ageHours)
	// Напоминание о сверке — при любой давности (3В34 ревью 3.r4): шлюз,
	// отозванный или перерегистрированный после копии, снова действует со
	// старым сертификатом и получает пакеты с учётными данными провайдеров.
	say(stdout, "Действующих шлюзов в копии: %d.", res.activeGateways)
	for _, g := range res.gateways {
		say(stdout, " %s (зарегистрирован %s);", g.name, g.registeredAt.UTC().Format("2006-01-02 15:04 UTC"))
	}
	if int64(len(res.gateways)) < res.activeGateways {
		say(stdout, " …")
	}
	say(stdout, "\nСверьте с журналом аудита прежней установки (руководство администратора, раздел 12.2, шаг 6): шлюз, отозванный "+
		"или перерегистрированный после %s, отзовите снова (aisec-cli gateway revoke) или зарегистрируйте заново с -reregister; "+
		"деактивацию пользователей, отзыв ключей приложений и сброс второго фактора повторите.\n", res.lastAudit.UTC().Format("2006-01-02 15:04 UTC"))
	if res.stale {
		say(stderr, "ВНИМАНИЕ: копия старше 7 суток. Всё, что отозвали, деактивировали и сменили после %s, снова в силе: "+
			"ключи приложений, учётные записи, блокировки, пароли, сбросы второго фактора и коды восстановления, регистрации шлюзов. Сверьте с журналом аудита прежней установки "+
			"(руководство администратора, раздел 12.2, шаг 6).\n", res.lastAudit.UTC().Format("2006-01-02 15:04 UTC"))
	}
	return nil
}

type restoreFinishResult struct {
	revoked       auth.RestoreRevoked
	gatewayTokens int64
	setupTokens   int64
	lastAudit     time.Time
	ageHours      int64
	stale         bool
	// activeGateways — действующих шлюзов в копии; gateways — первые из них.
	activeGateways int64
	gateways       []restoredGateway
}

// restoredGateway — действующий шлюз восстановленной копии.
type restoredGateway struct {
	name         string
	registeredAt time.Time
}

// maxListedGateways — шлюзов в выводе restore-finish.
const maxListedGateways = 20

// restoreFinishTx — отзыв и запись аудита одной транзакцией под
// блокировкой восстановления.
func restoreFinishTx(ctx context.Context, db *store.DB, l *audit.Log, actor audit.Actor, copyDir string,
	now time.Time) (restoreFinishResult, error) {
	var res restoreFinishResult
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		return res, err
	}
	defer rollbackQuietly(ctx, tx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(restoreLockID)); err != nil {
		return res, err
	}
	var last *time.Time
	if err := tx.QueryRow(ctx, "SELECT max(ts) FROM audit_log WHERE org_id = $1 AND action <> 'system.restored'",
		audit.DefaultOrgID).Scan(&last); err != nil {
		return res, err
	}
	if last == nil {
		return res, errors.New("журнал аудита пуст: это не восстановленная установка")
	}
	res.lastAudit = *last
	age := max(now.Sub(*last), 0)
	res.ageHours = int64(age / time.Hour)
	res.stale = age > maxCopyAge
	if res.revoked, err = auth.RevokeAllForRestoreTx(ctx, tx, audit.DefaultOrgID, now); err != nil {
		return res, err
	}
	if res.gatewayTokens, err = gwregistry.ExpireTokensForRestoreTx(ctx, tx, audit.DefaultOrgID, now); err != nil {
		return res, err
	}
	// Токен первичной настройки: копия, снятая до init, возвращает его
	// непогашенным. Триггер setup_tokens_guard разрешает только погашение.
	tag, err := tx.Exec(ctx, "UPDATE setup_tokens SET used_at = greatest($2::timestamptz, created_at) WHERE org_id = $1 AND used_at IS NULL",
		audit.DefaultOrgID, now)
	if err != nil {
		return res, fmt.Errorf("токен первичной настройки: погашение: %w", err)
	}
	res.setupTokens = tag.RowsAffected()
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM gateways WHERE org_id = $1 AND status = 'active'",
		audit.DefaultOrgID).Scan(&res.activeGateways); err != nil {
		return res, err
	}
	rows, err := tx.Query(ctx, "SELECT name, registered_at FROM gateways WHERE org_id = $1 AND status = 'active' ORDER BY name LIMIT $2",
		audit.DefaultOrgID, maxListedGateways)
	if err != nil {
		return res, err
	}
	res.gateways, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (restoredGateway, error) {
		var g restoredGateway
		err := r.Scan(&g.name, &g.registeredAt)
		return g, err
	})
	if err != nil {
		return res, err
	}
	details := map[string]any{
		"last_audit_at":          res.lastAudit.UTC().Format(time.RFC3339),
		"copy_age_hours":         res.ageHours,
		"stale_copy":             res.stale,
		"revoked_sessions":       res.revoked.Sessions,
		"revoked_api_tokens":     res.revoked.APITokens,
		"expired_gateway_tokens": res.gatewayTokens,
		"expired_setup_tokens":   res.setupTokens,
		"active_gateways":        res.activeGateways,
	}
	if copyDir != "" {
		details["copy_dir"] = copyDir
	}
	rec := audit.Entry{OrgID: audit.DefaultOrgID, Actor: actor, Action: "system.restored",
		Object: audit.Object{Type: "installation", ID: audit.DefaultOrgID}, Result: audit.ResultSuccess, Details: details}
	if err := l.RecordTx(ctx, tx, rec); err != nil {
		return res, err
	}
	if err := tx.Commit(ctx); err != nil {
		if errors.Is(err, pgx.ErrTxCommitRollback) {
			return res, err
		}
		return res, fmt.Errorf("фиксация: %w — исход неизвестен: проверьте запись system.restored в журнале аудита, при её отсутствии повторите", err)
	}
	return res, nil
}
