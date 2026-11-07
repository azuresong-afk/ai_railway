package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// aisec-cli update check | apply | status — обновление установки без
// Docker с локального каталога или носителя (ТЗ 7.6, ОБН.1–ОБН.3;
// ADR-0036): проверка подписи до действий, копия БД, остановка служб,
// каталог версии и атомарное переключение, миграции новым aisec-cli,
// запуск с закрытым приёмом событий, проверка здоровья, при сбое на любом
// шаге — откат; журнал шагов переживает прерывание.

var (
	// errUpdateRolledBack — обновление не удалось и откачено (код 4).
	errUpdateRolledBack = errors.New("обновление откачено")
	// errUpdateInterrupted — получен сигнал остановки.
	errUpdateInterrupted = errors.New("обновление прервано сигналом")
)

// updateEnvMarker — переменная обёртки /usr/sbin/aisec-cli: обновление
// запускается только на установке без Docker и только через неё.
const updateEnvMarker = "AISEC_UPDATE_HOST"

// updater — обновление одного компонента.
type updater struct {
	p      aisecCrypto.Provider
	host   updateHost
	db     updateDB // nil — узел без сервера (только шлюз или анализаторы)
	state  *stateStore
	roots  map[string]string // компонент → корень
	owner  int
	out    io.Writer
	now    func() time.Time
	settle time.Duration
	// healthTimeout — сколько ждать /readyz после запуска.
	healthTimeout time.Duration
	poll          time.Duration
	// stopFlag — получен SIGINT или SIGTERM: после текущего шага — откат.
	stopFlag *atomic.Bool
	// free — свободное место; в тестах — подмена.
	free func(dir string) (int64, error)
}

func (u *updater) freeSpace(dir string) (int64, error) {
	if u.free != nil {
		return u.free(dir)
	}
	return freeBytes(dir)
}

func (u *updater) say(format string, a ...any) { say(u.out, format+"\n", a...) }

func (u *updater) layout(component string) layout {
	return layout{Root: u.roots[component], OwnerUID: u.owner}
}

// unitsOf — службы компонента в порядке остановки.
func unitsOf(component string) []string {
	switch component {
	case componentML:
		return []string{unitML}
	case componentMedia:
		return []string{unitMedia}
	}
	// Сначала шлюз: его очередь в памяти уходит на ещё работающий сервер.
	return []string{unitGateway, unitServer}
}

// plan — итог проверки: всё, что нужно шагам.
type plan struct {
	rel, cur   *releaseInfo
	component  string
	adopt      bool
	units      []string
	db         bool
	applied    int
	pending    int
	allowOlder bool
	older      bool
}

// check — раздел 2 ADR-0036: только чтение, без изменений.
func (u *updater) check(ctx context.Context, dir string, allowOlder bool) (*plan, error) {
	if err := checkSourceDir(dir); err != nil {
		return nil, rejected(err)
	}
	rel, err := readManifestPair(u.p, dir)
	if err != nil {
		return nil, rejected(err)
	}
	if rel.TestSigned {
		u.say("ВНИМАНИЕ: сборка с тестовым ключом манифеста — не для поставки.")
	}
	if rel.Component, err = componentOf(rel.Manifest); err != nil {
		return nil, rejected(err)
	}
	if rel.Bytes, err = releaseBytes(rel.Manifest); err != nil {
		return nil, rejected(err)
	}
	if err := copyRelease(ctx, u.p, rel, ""); err != nil {
		return nil, rejected(err)
	}
	pl := &plan{rel: rel, component: rel.Component, allowOlder: allowOlder}
	l := u.layout(rel.Component)
	if l.Root == "" {
		return nil, errors.New("корень компонента не задан")
	}
	if owned, err := u.host.PackageOwned(ctx); err != nil {
		return nil, err
	} else if owned {
		return nil, errors.New("установка из пакета deb или rpm: обновляйте её пакетом; aisec-cli update для пакетов — после задачи 6.15")
	}
	if err := l.checkDirs(); err != nil {
		return nil, err
	}
	curID, isDir, err := l.installed()
	if err != nil {
		return nil, err
	}
	if pl.cur, err = l.installedRelease(u.p); err != nil {
		return nil, fmt.Errorf("установленный выпуск: %w", err)
	}
	if !isDir && curID != pl.cur.ID {
		return nil, fmt.Errorf("каталог версии %s не соответствует своему манифесту (%s)", curID, pl.cur.ID)
	}
	pl.adopt = isDir
	if pl.cur.SHA256 == rel.SHA256 {
		return nil, errAlreadyInstalled
	}
	if pl.cur.ID == rel.ID {
		return nil, rejected(errors.New("каталог версии с этим именем уже занят другим манифестом"))
	}
	if rel.Manifest.Created.Before(pl.cur.Manifest.Created) {
		if !allowOlder {
			return nil, rejected(fmt.Errorf("выпуск %s собран раньше установленного %s (откат); намеренный откат — -allow-older", rel.Manifest.Version, pl.cur.Manifest.Version))
		}
		pl.older = true
	}
	if rel.Component != componentMain {
		// Шлюз обновляется раньше анализаторов (ADR-0032, дополнение 03.11.2026).
		main, err := u.layout(componentMain).installedRelease(u.p)
		if err != nil {
			return nil, fmt.Errorf("основной выпуск: %w", err)
		}
		if rel.Manifest.Created.After(main.Manifest.Created) {
			return nil, rejected(fmt.Errorf("выпуск %s новее основного выпуска %s: сначала обновите aisec (шлюз раньше анализаторов)", rel.Manifest.Version, main.Manifest.Version))
		}
	}
	free, err := u.freeSpace(l.optDir())
	if err != nil {
		return nil, err
	}
	if free < rel.Bytes+spaceMargin {
		return nil, fmt.Errorf("мало места в %s: нужно %d МиБ, свободно %d МиБ", l.optDir(), (rel.Bytes+spaceMargin)>>20, free>>20)
	}
	for _, unit := range unitsOf(rel.Component) {
		st, err := u.host.State(ctx, unit)
		if err != nil {
			return nil, err
		}
		if st.Active {
			pl.units = append(pl.units, unit)
		}
		if unit == unitServer && (st.Active || st.Enabled) {
			pl.db = true
		}
	}
	if pl.db {
		if u.db == nil {
			return nil, errors.New("на узле сервера нужна строка подключения владельца схемы (AISEC_DATABASE_URL в /etc/aisec/aisec-cli.env)")
		}
		applied, err := u.db.Applied(ctx)
		if err != nil {
			return nil, err
		}
		pl.applied = len(applied)
		if pl.pending, err = checkSchema(applied, rel.Manifest); err != nil {
			return nil, rejected(err)
		}
		size, err := u.db.Size(ctx)
		if err != nil {
			return nil, err
		}
		free, err := u.freeSpace(u.state.dir)
		if err != nil {
			return nil, err
		}
		if free < size/2+spaceMargin {
			return nil, fmt.Errorf("мало места под копию БД в %s: нужно не меньше %d МиБ, свободно %d МиБ", u.state.dir, (size/2+spaceMargin)>>20, free>>20)
		}
	}
	if contains(pl.units, unitServer) {
		// Проверка здоровья настроена верно — до остановки служб.
		if err := u.host.Ready(ctx); err != nil {
			return nil, fmt.Errorf("проверка здоровья не настроена: работающий сервер не ответил (%w); задайте -health-url и -health-ca", err)
		}
	}
	return pl, nil
}

var errAlreadyInstalled = errors.New("этот выпуск уже установлен")

func rejected(err error) error { return fmt.Errorf("%w: %w", errReleaseRejected, err) }

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// apply выполняет шаги раздела 3 ADR-0036. Сбой после первого изменения —
// откат (rollback) и errUpdateRolledBack.
func (u *updater) apply(ctx context.Context, pl *plan) error {
	st := u.newState(pl)
	if err := u.state.save(st); err != nil {
		return err
	}
	u.say("Обновление %s: %s → %s. Службы: %s. Миграций к применению: %d.", pl.component, pl.cur.Manifest.Version, pl.rel.Manifest.Version, joinUnits(pl.units), pl.pending)
	if err := u.record(ctx, u.entry("update.started", audit.ResultSuccess, st, map[string]any{"migrations_pending": pl.pending})); err != nil {
		if st.DB {
			_ = u.state.remove() //nolint:gosec // G104: ничего не изменено
			return fmt.Errorf("запись update.started в журнал аудита: %w", err)
		}
		u.say("Запись update.started не удалась: %v", err)
	}
	if err := u.forward(ctx, st, pl); err != nil {
		return u.fail(ctx, st, err)
	}
	return u.conclude(ctx, st)
}

// fail — сбой шага до итога: откат (раздел 4 ADR-0036).
func (u *updater) fail(ctx context.Context, st *updateState, cause error) error {
	u.say("Сбой: %v", cause)
	u.say("Откат на %s.", st.FromVersion)
	if err := u.rollback(ctx, st, cause); err != nil {
		return fmt.Errorf("откат не завершён: %w; повторите aisec-cli update apply — он продолжит откат", err)
	}
	return errUpdateRolledBack
}

// conclude — после проверки здоровья: открыть приём (сбой — откат: сервер
// нового выпуска не работает), затем итог. Сбой записи итога не
// откатывает работающий выпуск: повторный запуск его допишет.
func (u *updater) conclude(ctx context.Context, st *updateState) error {
	if !stepAfter(st.Step, stepOpened) {
		if err := u.open(ctx, st); err != nil {
			return u.fail(ctx, st, err)
		}
	}
	if err := u.complete(ctx, st); err != nil {
		return fmt.Errorf("новый выпуск работает, но итог обновления не записан: %w; повторите aisec-cli update apply — он завершит обновление", err)
	}
	return nil
}

// record — запись в журнал аудита, если БД доступна; иначе (узел без
// строки подключения) — в journald.
func (u *updater) record(ctx context.Context, e audit.Entry) error {
	if u.db != nil {
		return u.db.Audit(ctx, e)
	}
	return u.host.Journal(ctx, journalText(e))
}

// journalText — запись для journald: код, итог и подробности без секретов.
func journalText(e audit.Entry) string {
	d, err := json.Marshal(e.Details)
	if err != nil {
		d = []byte("{}")
	}
	return fmt.Sprintf("%s %s release=%s %s", e.Action, e.Result, e.Object.ID, d)
}

// newState — журнал нового обновления на шаге «проверка».
func (u *updater) newState(pl *plan) *updateState {
	return &updateState{
		Format: updateStateFormat, ID: newUpdateID(u.now()), Component: pl.component, StartedAt: u.now().UTC().Truncate(time.Second),
		Step: stepChecked, FromID: pl.cur.ID, FromVersion: pl.cur.Manifest.Version, FromSHA: pl.cur.SHA256,
		ToID: pl.rel.ID, ToVersion: pl.rel.Manifest.Version, ToSHA: pl.rel.SHA256, Adopt: pl.adopt, Units: pl.units,
		DB: pl.db, AppliedBefore: pl.applied, AllowOlder: pl.allowOlder,
	}
}

// advance записывает пройденный шаг; сигнал остановки до проверки
// здоровья — ошибка, после которой обновление откатывается. После неё
// обновление доводится, как при повторном запуске (recover).
func (u *updater) advance(st *updateState, step string) error {
	st.Step = step
	if err := u.state.save(st); err != nil {
		return err
	}
	if u.stopFlag != nil && u.stopFlag.Load() && !stepAfter(step, stepHealthy) {
		return errUpdateInterrupted
	}
	return nil
}

func (u *updater) forward(ctx context.Context, st *updateState, pl *plan) error {
	l := u.layout(st.Component)
	if st.DB {
		// Приём закрывается до остановки: сервер, запущенный кем угодно
		// (перезагрузка, systemd) до итога или отката, не примет событий,
		// которые стёр бы откат с восстановлением копии.
		st.Gated = true
		if err := u.state.save(st); err != nil {
			return err
		}
		if err := u.host.Gate(ctx, true); err != nil {
			return fmt.Errorf("закрытие приёма событий: %w", err)
		}
	}
	for _, unit := range st.Units {
		u.say("Остановка %s…", unit)
		if err := u.host.Stop(ctx, unit); err != nil {
			return fmt.Errorf("остановка %s: %w", unit, err)
		}
	}
	if err := u.advance(st, stepStopped); err != nil {
		return err
	}
	if st.DB {
		// Копия — после остановки шлюза и сервера: после неё в БД ничего
		// не пишется до проверки здоровья нового выпуска.
		u.say("Резервная копия БД…")
		dir := u.state.dumpDir(st.ID)
		if err := ensureOwnedDir(dir, 0o700, u.owner); err != nil {
			return err
		}
		if err := u.db.Dump(ctx, filepath.Join(dir, dumpFile)); err != nil {
			return fmt.Errorf("резервная копия БД: %w", err)
		}
	}
	if err := u.advance(st, stepBackedUp); err != nil {
		return err
	}
	if st.Adopt {
		if err := l.adopt(st.FromID); err != nil {
			return fmt.Errorf("переход на каталоги версий: %w", err)
		}
	}
	if err := u.advance(st, stepAdopted); err != nil {
		return err
	}
	u.say("Копирование выпуска в %s со сверкой хешей…", l.release(st.ToID))
	if err := l.stage(ctx, u.p, pl.rel); err != nil {
		return fmt.Errorf("копирование выпуска: %w", err)
	}
	if err := u.advance(st, stepStaged); err != nil {
		return err
	}
	if err := l.switchTo(st.ToID); err != nil {
		return fmt.Errorf("переключение на новый выпуск: %w", err)
	}
	if err := u.advance(st, stepSwitched); err != nil {
		return err
	}
	if st.DB {
		u.say("Миграции…")
		out, err := u.host.RunCLI(ctx, u.newCLI(st), "migrate")
		if err != nil {
			return fmt.Errorf("миграции: %w", err)
		}
		if out != "" {
			u.say("  %s", lastLine(out))
		}
	}
	if err := u.advance(st, stepMigrated); err != nil {
		return err
	}
	if err := u.startUnits(ctx, st); err != nil {
		return err
	}
	if err := u.advance(st, stepStarted); err != nil {
		return err
	}
	u.say("Проверка здоровья…")
	if err := u.health(ctx, st, false); err != nil {
		return fmt.Errorf("проверка здоровья: %w", err)
	}
	return u.advance(st, stepHealthy)
}

// newCLI — aisec-cli нового выпуска по пути каталога версии (не через
// ссылку): его хеш сверен при копировании.
func (u *updater) newCLI(st *updateState) string {
	return filepath.Join(u.layout(st.Component).release(st.ToID), "bin", "aisec-cli")
}

// startUnits запускает службы в порядке «шлюз → сервер» (анализаторы —
// свои); приём событий сервером закрыт с шага остановки.
func (u *updater) startUnits(ctx context.Context, st *updateState) error {
	for _, unit := range []string{unitGateway, unitServer, unitML, unitMedia} {
		if !contains(st.Units, unit) {
			continue
		}
		u.say("Запуск %s…", unit)
		if err := u.host.Start(ctx, unit); err != nil {
			return fmt.Errorf("запуск %s: %w", unit, err)
		}
	}
	return nil
}

// health — раздел 4 ADR-0036: службы устойчивы, сервер готов, целостность.
func (u *updater) health(ctx context.Context, st *updateState, rollback bool) error {
	base := map[string]int{}
	for _, unit := range st.Units {
		s, err := u.host.State(ctx, unit)
		if err != nil {
			return err
		}
		if !s.Active {
			return fmt.Errorf("служба %s не работает", unit)
		}
		base[unit] = s.Restarts
	}
	if contains(st.Units, unitServer) {
		if err := u.waitReady(ctx); err != nil {
			return err
		}
	}
	if err := sleepCtx(ctx, u.settle); err != nil {
		return err
	}
	for _, unit := range st.Units {
		s, err := u.host.State(ctx, unit)
		if err != nil {
			return err
		}
		if !s.Active || s.Restarts != base[unit] {
			return fmt.Errorf("служба %s не устойчива: перезапускалась или остановилась", unit)
		}
	}
	if rollback {
		return nil
	}
	if st.Component == componentMain {
		args := []string{"verify"}
		if st.AllowOlder && st.DB {
			args = append(args, "-accept-rollback")
		}
		out, err := u.host.RunCLI(ctx, u.newCLI(st), args...)
		if err != nil {
			return fmt.Errorf("контроль целостности: %w", err)
		}
		u.say("  %s", lastLine(out))
		return nil
	}
	installed, err := u.layout(st.Component).installedRelease(u.p)
	if err != nil {
		return fmt.Errorf("контроль целостности: %w", err)
	}
	if installed.SHA256 != st.ToSHA {
		return errors.New("контроль целостности: установлен не тот выпуск")
	}
	checker, err := integrity.NewChecker(integrity.Config{Component: "cli", Provider: u.p,
		ManifestPath: filepath.Join(u.layout(st.Component).link(), integrity.ManifestFile), AllFiles: true})
	if err != nil {
		return err
	}
	res, err := checker.Check(ctx, integrity.TriggerManual)
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("контроль целостности: %s", reasonText(res.Reason))
	}
	return nil
}

func (u *updater) waitReady(ctx context.Context) error {
	deadline := u.now().Add(u.healthTimeout)
	for {
		err := u.host.Ready(ctx)
		if err == nil {
			return nil
		}
		if !u.now().Before(deadline) {
			return err
		}
		if err := sleepCtx(ctx, u.poll); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// open — шаг 10: открыть приём, перезапустить сервер и проверить снова.
func (u *updater) open(ctx context.Context, st *updateState) error {
	if st.Gated {
		if err := u.host.Gate(ctx, false); err != nil {
			return fmt.Errorf("открытие приёма событий: %w", err)
		}
		if contains(st.Units, unitServer) {
			u.say("Приём событий открыт, перезапуск aisec-server…")
			if err := u.host.Restart(ctx, unitServer); err != nil {
				return fmt.Errorf("перезапуск aisec-server: %w", err)
			}
		}
		st.Gated = false
		if err := u.state.save(st); err != nil {
			return err
		}
		if contains(st.Units, unitServer) {
			if err := u.health(ctx, st, true); err != nil {
				return fmt.Errorf("проверка после открытия приёма: %w", err)
			}
		}
	}
	return u.advance(st, stepOpened)
}

// complete — шаг 11: итог в журнал аудита, уборка, удаление журнала шагов.
func (u *updater) complete(ctx context.Context, st *updateState) error {
	details := map[string]any{}
	if st.DB {
		applied, err := u.db.Applied(ctx)
		if err != nil {
			return err
		}
		details["migrations_applied"] = len(applied) - st.AppliedBefore
	}
	if err := u.record(ctx, u.entry("update.install", audit.ResultSuccess, st, details)); err != nil {
		return fmt.Errorf("запись update.install: %w", err)
	}
	u.cleanup(st, false)
	if err := u.state.remove(); err != nil {
		return err
	}
	u.say("Обновление завершено: установлен выпуск %s. Прежний выпуск %s оставлен для отката.", st.ToVersion, st.FromVersion)
	return nil
}

// cleanup — уборка после итога: после обновления — выпуски кроме нового и
// предыдущего, после отката — только каталог несостоявшегося выпуска;
// копии БД кроме последней. Ошибка уборки не меняет итога, только
// сообщается.
func (u *updater) cleanup(st *updateState, rolledBack bool) {
	l := u.layout(st.Component)
	var err error
	if rolledBack {
		err = l.drop(st.ToID)
	} else {
		err = l.prune(st.ToID, st.FromID)
	}
	if err != nil {
		u.say("Не удалось удалить старые каталоги версий: %v", err)
	}
	entries, err := os.ReadDir(u.state.dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() && updateIDRe.MatchString(e.Name()) && e.Name() != st.ID {
			if err := os.RemoveAll(filepath.Join(u.state.dir, e.Name())); err != nil {
				u.say("Не удалось удалить прежнюю копию БД %s: %v", e.Name(), err)
			}
		}
	}
}

// rollback — раздел 4 ADR-0036. Каждый шаг повторяем: прерванный откат
// продолжает следующий запуск.
func (u *updater) rollback(ctx context.Context, st *updateState, cause error) error {
	ctx = context.WithoutCancel(ctx)
	l := u.layout(st.Component)
	// Службы могли быть остановлены частично или запущены новым выпуском:
	// остановить все (повтор безопасен).
	for _, unit := range reversed(st.Units) {
		if err := u.host.Stop(ctx, unit); err != nil {
			return fmt.Errorf("остановка %s: %w", unit, err)
		}
	}
	// Дополнение могло остаться, даже если сбой случился внутри Gate:
	// удаление повторяемо.
	if st.DB || st.Gated {
		if err := u.host.Gate(ctx, false); err != nil {
			return fmt.Errorf("открытие приёма событий: %w", err)
		}
		st.Gated = false
		if err := u.state.save(st); err != nil {
			return err
		}
	}
	restored := false
	if st.DB {
		applied, err := u.db.Applied(ctx)
		if err != nil {
			return err
		}
		if len(applied) > st.AppliedBefore {
			u.say("Миграции нового выпуска применились: восстановление БД из копии…")
			if err := u.db.Restore(ctx, filepath.Join(u.state.dumpDir(st.ID), dumpFile)); err != nil {
				return fmt.Errorf("восстановление БД: %w", err)
			}
			restored = true
		}
	}
	// Прежний выпуск: ссылка пропала посреди перехода на каталоги версий —
	// довести переход; ссылка на новый выпуск — вернуть на прежний.
	id, isDir, err := l.installed()
	switch {
	case err != nil && st.Adopt:
		if err := l.adopt(st.FromID); err != nil {
			return fmt.Errorf("возврат прежнего выпуска: %w", err)
		}
	case err != nil:
		return fmt.Errorf("возврат прежнего выпуска: %w", err)
	case !isDir && id != st.FromID:
		if err := l.switchTo(st.FromID); err != nil {
			return fmt.Errorf("возврат прежнего выпуска: %w", err)
		}
	}
	if id, isDir, err := l.installed(); err != nil || (!isDir && id != st.FromID) {
		return errors.New("прежний выпуск не установлен")
	}
	for _, unit := range []string{unitGateway, unitServer, unitML, unitMedia} {
		if !contains(st.Units, unit) {
			continue
		}
		if err := u.host.Start(ctx, unit); err != nil {
			u.say("Не удалось запустить %s прежнего выпуска: %v", unit, err)
		}
	}
	healthErr := u.health(ctx, st, true)
	if healthErr != nil {
		u.say("Прежний выпуск после отката: %v", healthErr)
	}
	details := map[string]any{"failed_after": st.Step, "reason": shortReason(cause), "db_restored": restored}
	if restored && stepAfter(st.Step, stepHealthy) {
		details["events_window"] = "события, принятые сервером после открытия приёма и до отката, потеряны"
		u.say("Внимание: события, принятые после открытия приёма и до отката, не сохранились — сверьте журналы шлюзов.")
	} else if restored {
		details["events_window"] = "приём событий был закрыт до проверки здоровья"
	}
	if err := u.record(ctx, u.entry("update.rollback", audit.ResultFailure, st, details)); err != nil {
		u.say("Запись update.rollback не удалась: %v", err)
	}
	u.cleanup(st, true)
	if err := u.state.remove(); err != nil {
		return err
	}
	if restored {
		u.say("Откат выполнен: работает выпуск %s, БД восстановлена из копии; шлюзы досылают события из буфера.", st.FromVersion)
	} else {
		u.say("Откат выполнен: работает выпуск %s, БД не менялась; шлюзы досылают события из буфера.", st.FromVersion)
	}
	return nil
}

func reversed(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[len(s)-1-i] = v
	}
	return out
}

// recover — незавершённое обновление по журналу: проверка здоровья пройдена
// — довести, иначе — откатить (ADR-0036, раздел 5).
func (u *updater) recover(ctx context.Context, st *updateState) error {
	if stepAfter(st.Step, stepHealthy) {
		u.say("Незавершённое обновление %s → %s прошло проверку здоровья: завершение.", st.FromVersion, st.ToVersion)
		return u.conclude(ctx, st)
	}
	u.say("Незавершённое обновление %s → %s (последний шаг — %s): откат.", st.FromVersion, st.ToVersion, st.Step)
	if err := u.rollback(ctx, st, errUpdateInterrupted); err != nil {
		return fmt.Errorf("откат не завершён: %w; повторите aisec-cli update apply", err)
	}
	return errUpdateRolledBack
}

func (u *updater) entry(action string, result audit.Result, st *updateState, extra map[string]any) audit.Entry {
	d := map[string]any{"component": st.Component, "from": st.FromID, "to": st.ToID, "version": st.ToVersion, "update_id": st.ID}
	for k, v := range extra {
		d[k] = v
	}
	return audit.Entry{OrgID: audit.DefaultOrgID, Actor: cliActor(), Action: action,
		Object: audit.Object{Type: "release", ID: st.ToID}, Result: result, Details: d}
}

// dsnHasPassword — пароль в строке подключения (URL или «ключ=значение»).
func dsnHasPassword(dsn string) bool {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return true // не разобрать — не рисковать
		}
		_, set := u.User.Password()
		return set || u.Query().Has("password")
	}
	return dsnPasswordRe.MatchString(dsn)
}

var dsnPasswordRe = regexp.MustCompile(`(?i)(^|\s)password\s*=`)

// updateFlags — флаги apply и check.
type updateFlags struct {
	allowOlder    bool
	healthURL     string
	healthCA      string
	settle        time.Duration
	healthTimeout time.Duration
}

// updateCmd — разбор подкоманды и сборка updater для хоста с systemd.
func updateCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("подкоманда: check, apply или status")
	}
	sub := args[0]
	fl := flag.NewFlagSet("update "+sub, flag.ContinueOnError)
	fl.SetOutput(stderr)
	var f updateFlags
	if sub == "check" || sub == "apply" {
		fl.BoolVar(&f.allowOlder, "allow-older", false, "принять выпуск, собранный раньше установленного (намеренный откат)")
		fl.StringVar(&f.healthURL, "health-url", "", "адрес /readyz сервера; по умолчанию https://AISEC_SERVER_LISTEN/readyz из /etc/aisec/aisec-server.env")
		fl.StringVar(&f.healthCA, "health-ca", healthCAPath, "корень, которому доверяет проверка /readyz")
		fl.DurationVar(&f.settle, "settle", 30*time.Second, "сколько службы должны проработать без перезапуска")
		fl.DurationVar(&f.healthTimeout, "health-timeout", 2*time.Minute, "сколько ждать готовности сервера после запуска")
	}
	if sub != "check" && sub != "apply" && sub != "status" {
		return errors.New("подкоманда: check, apply или status")
	}
	if err := fl.Parse(args[1:]); err != nil {
		return err
	}
	if sub != "status" && (f.settle < 0 || f.settle > 30*time.Minute || f.healthTimeout < time.Second || f.healthTimeout > time.Hour) {
		return errors.New("settle — от 0 до 30m, health-timeout — от 1s до 1h")
	}
	dir := ""
	switch {
	case sub == "status" && fl.NArg() == 0:
	case sub == "apply" && fl.NArg() <= 1:
		dir = fl.Arg(0)
	case sub == "check" && fl.NArg() == 1:
		dir = fl.Arg(0)
	default:
		return errors.New("ожидается один каталог выпуска: aisec-cli update " + sub + " КАТАЛОГ")
	}
	if os.Getenv(updateEnvMarker) != "systemd" {
		return errors.New("aisec-cli update работает на установке без Docker через /usr/sbin/aisec-cli (ADR-0036); для compose — задача 6.21")
	}
	if os.Geteuid() != 0 {
		return errors.New("обновление устанавливает только администратор системы: запустите от root (sudo aisec-cli update …)")
	}
	u, closeFn, err := newSystemdUpdater(f, stdout)
	if err != nil {
		return err
	}
	defer closeFn()
	return u.run(sub, dir, f.allowOlder)
}

// run — общая часть команд для хоста и тестов.
func (u *updater) run(sub, dir string, allowOlder bool) error {
	ctx := context.Background()
	if err := u.state.open(); err != nil {
		return err
	}
	defer u.state.close()
	st, err := u.state.load()
	if err != nil {
		return fmt.Errorf("журнал обновления %s: %w; разберите его вручную (руководство, «Обновление и откат»)", u.state.dir, err)
	}
	switch sub {
	case "status":
		if st == nil {
			u.say("Незавершённых обновлений нет.")
			return nil
		}
		action := "откат"
		if stepAfter(st.Step, stepHealthy) {
			action = "завершение"
		}
		u.say("Незавершённое обновление %s: %s → %s, начато %s, последний шаг — %s. Повторный aisec-cli update apply выполнит: %s.",
			st.Component, st.FromVersion, st.ToVersion, st.StartedAt.Format(time.RFC3339), st.Step, action)
		return nil
	case "check":
		if st != nil {
			return errors.New("есть незавершённое обновление: сначала aisec-cli update apply (доведёт или откатит его)")
		}
		pl, err := u.check(ctx, dir, allowOlder)
		if err != nil {
			return u.reportCheck(err)
		}
		u.say("Выпуск %s (%s) прошёл проверку: подпись верна, файлов %d, миграций к применению %d, службы: %s. Изменений не сделано.",
			pl.rel.Manifest.Version, pl.component, countDisk(pl.rel), pl.pending, joinUnits(pl.units))
		return nil
	}
	if st != nil {
		return u.recover(ctx, st)
	}
	if dir == "" {
		return errors.New("укажите каталог выпуска: aisec-cli update apply КАТАЛОГ")
	}
	pl, err := u.check(ctx, dir, allowOlder)
	if err != nil {
		if errors.Is(err, errReleaseRejected) {
			_ = u.record(ctx, audit.Entry{OrgID: audit.DefaultOrgID, Actor: cliActor(), Action: "update.install", //nolint:gosec // G104: отказ выпуска важнее записи
				Object: audit.Object{Type: "release", ID: "rejected"}, Result: audit.ResultFailure, Details: map[string]any{"reason": shortReason(err)}})
		}
		return u.reportCheck(err)
	}
	stop := make(chan os.Signal, 2)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP) //nolint:forbidigo // ADR-0036, раздел 5: обрыв сеанса (SIGHUP) — откат после текущего шага, а не гибель посреди шага
	defer signal.Stop(stop)
	var stopped atomic.Bool
	u.stopFlag = &stopped
	go func() {
		for range stop {
			stopped.Store(true)
		}
	}()
	return u.apply(ctx, pl)
}

func (u *updater) reportCheck(err error) error {
	if errors.Is(err, errAlreadyInstalled) {
		u.say("Этот выпуск уже установлен: изменений не нужно.")
		return nil
	}
	if errors.Is(err, errReleaseRejected) {
		u.say("Выпуск не прошёл проверку: %s", strings.TrimPrefix(err.Error(), errReleaseRejected.Error()+": "))
		return errReleaseRejected
	}
	return err
}

func countDisk(rel *releaseInfo) int {
	n := 0
	for _, e := range rel.Manifest.Files {
		if !e.Kind.Embedded() {
			n++
		}
	}
	return n
}

// newSystemdUpdater — updater для хоста с systemd: настройки из
// /etc/aisec, БД — если задана строка подключения.
func newSystemdUpdater(f updateFlags, out io.Writer) (*updater, func(), error) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, nil, err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return nil, nil, err
	}
	cliEnv, err := readEnvFileIfExists(cliEnvPath)
	if err != nil {
		return nil, nil, err
	}
	serverEnv, err := readEnvFileIfExists(serverEnvPath)
	if err != nil {
		return nil, nil, err
	}
	rawHealth := f.healthURL
	if rawHealth == "" {
		if rawHealth, err = healthURLFromEnv(serverEnv); err != nil {
			return nil, nil, err
		}
	}
	healthURL, err := healthURL(rawHealth)
	if err != nil {
		return nil, nil, err
	}
	dsn := cliEnv["AISEC_DATABASE_URL"]
	if dsnHasPassword(dsn) {
		// pg_dump и psql получают строку в аргументах, видимых в /proc.
		return nil, nil, errors.New("AISEC_DATABASE_URL в /etc/aisec/aisec-cli.env содержит пароль: уберите его, пароль владельца схемы читается из PGPASSFILE (ADR-0034)")
	}
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "PGCONNECT_TIMEOUT=10"}
	if dsn != "" {
		env = append(env, "AISEC_DATABASE_URL="+dsn)
	}
	if _, err := os.Lstat(ownerPGPassPath); err == nil {
		env = append(env, "PGPASSFILE="+ownerPGPassPath)
	}
	u := &updater{
		p: p, host: &systemdHost{p: p, env: env, healthURL: healthURL, healthCA: f.healthCA},
		state: &stateStore{dir: "/var/lib/aisec/update", ownerUID: 0},
		roots: map[string]string{componentMain: "/", componentML: "/opt/aisec-ml", componentMedia: "/opt/aisec-media"},
		out:   out, now: func() time.Time { return time.Now() }, settle: f.settle, healthTimeout: f.healthTimeout, poll: 2 * time.Second,
	}
	closeFn := func() {}
	if dsn != "" {
		// Пароль из PGPASSFILE читает pgx так же, как pg_dump и psql.
		if err := os.Setenv("PGPASSFILE", ownerPGPassPath); err != nil {
			return nil, nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		db, err := openUpdateDB(ctx, p, dsn, dsn, env, defaultPGTools)
		if err != nil {
			// Узел без СУБД (только шлюз): БД не нужна, если сервер здесь не
			// работает; check это проверит.
			u.say("БД недоступна (%v): шаги с БД будут недоступны.", shortReason(err))
		} else {
			u.db = db
			closeFn = db.Close
		}
	}
	return u, closeFn, nil
}

func readEnvFileIfExists(name string) (map[string]string, error) {
	data, err := readSmallFile(name, maxEnvFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	m, err := parseEnvFile(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return m, nil
}
