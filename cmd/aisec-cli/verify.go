package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/store"
	"github.com/azuresong-afk/ai_railway/migrations"
)

// errIntegrityViolated — нарушение целостности: код возврата 3 отличает его
// (DM-42) от ошибки выполнения.
var errIntegrityViolated = errors.New("целостность установки нарушена")

// executable — путь запущенного aisec-cli; в тестах подменяется.
var executable = os.Executable

// verifyTimeout — предел проверки: хеширование всех файлов установки.
const verifyTimeout = 10 * time.Minute

// verifyCmd проверяет целостность установки по подписанному манифесту по
// команде администратора (ОЦЛ.2): все файлы манифеста на диске, встроенные
// в aisec-cli миграции и сам aisec-cli. Сервер не нужен. С AISEC_DATABASE_URL
// итог пишется в integrity_checks и журнал аудита (integrity.check), а
// манифест старше последней успешной проверки — откат выпуска
// (manifest_rollback, В20 ревью 2.r4). Намеренный откат принимается флагом
// -accept-rollback; с -gateway ИМЯ — откат шлюза по его heartbeat.
// -release КАТАЛОГ — проверка нового выпуска перед обновлением (ОБН.1,
// verifyRelease).
func verifyCmd(args []string, dsn string, stdout, stderr io.Writer) error {
	fl := flag.NewFlagSet("verify", flag.ContinueOnError)
	fl.SetOutput(stderr)
	manifest := fl.String("manifest", "", "манифест целостности; по умолчанию ../aisec-manifest.json от каталога aisec-cli")
	accept := fl.Bool("accept-rollback", false, "принять намеренный откат на более старый выпуск (нужен AISEC_DATABASE_URL)")
	gw := fl.String("gateway", "", "с -accept-rollback: принять откат шлюза с этим именем (файлы на этом хосте не проверяются)")
	release := fl.String("release", "", "каталог нового выпуска: проверить подпись ключом этой версии и все его файлы (ОБН.1)")
	allowOlder := fl.Bool("allow-older", false, "с -release: принять выпуск, собранный раньше установленного (намеренный откат)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fl.NArg())
	}
	if *release != "" {
		if *manifest != "" || *accept || *gw != "" {
			return errors.New("release: не сочетается с -manifest, -accept-rollback и -gateway")
		}
		return verifyRelease(*release, *allowOlder, stdout)
	}
	if *allowOlder {
		return errors.New("allow-older: задаётся только с -release")
	}
	if *accept && dsn == "" {
		return errors.New("accept-rollback: нужен AISEC_DATABASE_URL — откат принимается по истории проверок в БД")
	}
	if *gw != "" {
		if !*accept {
			return errors.New("gateway: задаётся только с -accept-rollback")
		}
		return acceptGatewayRollback(dsn, *gw, stdout)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	exe, err := executable()
	if err != nil {
		exe = "" // проверка отметит исполняемый файл как нечитаемый
	}
	path := *manifest
	if path == "" {
		path = integrity.DefaultManifestPath(exe)
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "cli", Provider: p, ManifestPath: path,
		Executable: exe, BinaryName: "bin/aisec-cli",
		Embedded: map[string]fs.FS{"migrations": migrations.FS},
		AllFiles: true,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	res, err := checker.Check(ctx, integrity.TriggerManual)
	if err != nil {
		return err
	}
	if dsn != "" {
		saved, err := recordResult(ctx, dsn, p, res, *accept)
		if errors.Is(err, integrity.ErrNoRollback) {
			printResult(stdout, path, res)
			return err
		}
		if err != nil {
			printResult(stdout, path, res)
			return fmt.Errorf("итог проверки не записан в журнал: %w", err)
		}
		res = saved
		if *accept && res.OK() {
			say(stdout, "Откат на выпуск %s принят: запись integrity.rollback_accepted в журнале аудита.\n", res.ManifestVersion)
		}
	}
	printResult(stdout, path, res)
	if !res.OK() {
		return errIntegrityViolated
	}
	return nil
}

// errReleaseRejected — новый выпуск не прошёл проверку (код возврата 3, как
// у нарушения целостности).
var errReleaseRejected = errors.New("выпуск не прошёл проверку")

// verifyRelease проверяет каталог нового выпуска до обновления (ОБН.1,
// ADR-0019): подпись манифеста — ключом, встроенным в этот, установленный
// aisec-cli, и все невстроенные файлы манифеста на диске каталога (через
// os.Root, ссылки не проходят). Манифест и подпись — только обычные файлы,
// не ссылки. Сам aisec-cli и его встроенные миграции с новым манифестом не
// сверяются: версия вшита в бинарник, и сверка себя отвергала бы любой другой
// выпуск. Встроенные наборы нового выпуска входят в его бинарники, а те
// сверяются целиком. Выпуск, собранный раньше установленного (откат),
// отвергается без allowOlder. Итог в БД не пишется: это не проверка
// установки.
func verifyRelease(dir string, allowOlder bool, stdout io.Writer) error {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	if err := aisecCrypto.SelfTest(p); err != nil {
		return err
	}
	path := filepath.Join(dir, integrity.ManifestFile)
	reject := func(format string, a ...any) error {
		say(stdout, "Выпуск не прошёл проверку: "+format+"\n", a...)
		return errReleaseRejected
	}
	for _, f := range []string{path, filepath.Join(dir, integrity.SignatureFile)} {
		if info, err := os.Lstat(f); err == nil && !info.Mode().IsRegular() {
			return reject("%s — не обычный файл (ссылка или каталог).", f)
		}
	}
	checker, err := integrity.NewChecker(integrity.Config{
		Component: "cli", Provider: p, ManifestPath: path, AllFiles: true,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	res, err := checker.Check(ctx, integrity.TriggerManual)
	if err != nil {
		return err
	}
	if res.TestSigned {
		say(stdout, "ВНИМАНИЕ: сборка с тестовым ключом манифеста — не для поставки.\n")
	}
	if !res.OK() {
		say(stdout, "Выпуск не прошёл проверку: %s. Манифест %s, проверено файлов: %d.\n", reasonText(res.Reason), path, res.Checked)
		for _, f := range res.Failures {
			say(stdout, "  %s — %s\n", f.Path, problemText(f.Problem))
		}
		if res.Omitted > 0 {
			say(stdout, "  и ещё нарушений: %d\n", res.Omitted)
		}
		return errReleaseRejected
	}
	if res.Checked == 0 {
		return reject("в манифесте %s нет ни одного файла на диске.", path)
	}
	if !allowOlder {
		installed, err := installedManifest(ctx, p)
		if err != nil {
			return fmt.Errorf("манифест установленной версии: %w; без него откат не определить (-allow-older — проверить без сравнения)", err)
		}
		if res.ManifestCreated.Before(installed.ManifestCreated) {
			return reject("выпуск %s собран раньше установленного %s (откат). Намеренный откат — -allow-older.", res.ManifestVersion, installed.ManifestVersion)
		}
	}
	say(stdout, "Выпуск %s проверен ключом установленной версии %s: подпись верна, файлов: %d.\n", res.ManifestVersion, version, res.Checked)
	return nil
}

// installedManifest — подписанный манифест установки, в которой работает этот
// aisec-cli (над каталогом bin/): по его времени сборки определяется откат.
func installedManifest(ctx context.Context, p aisecCrypto.Provider) (integrity.Result, error) {
	exe, err := executable()
	if err != nil {
		return integrity.Result{}, err
	}
	path := integrity.DefaultManifestPath(exe)
	checker, err := integrity.NewChecker(integrity.Config{Component: "cli", Provider: p, ManifestPath: path})
	if err != nil {
		return integrity.Result{}, err
	}
	res, err := checker.Check(ctx, integrity.TriggerManual)
	if err != nil {
		return integrity.Result{}, err
	}
	if !res.OK() {
		return integrity.Result{}, fmt.Errorf("%s: %s", path, reasonText(res.Reason))
	}
	return res, nil
}

func recordResult(ctx context.Context, dsn string, p aisecCrypto.Provider, res integrity.Result, accept bool) (integrity.Result, error) {
	db, err := store.Open(ctx, dsn, 2)
	if err != nil {
		return res, err
	}
	defer db.Close()
	l, err := audit.New(db.Pool(), p)
	if err != nil {
		return res, err
	}
	pg, err := integrity.NewPGStore(db.Pool(), l, p)
	if err != nil {
		return res, err
	}
	// Нарушение файлов откатом не принимается: оно пишется как обычно.
	if accept && res.OK() {
		return pg.AcceptRollback(ctx, res, cliActor())
	}
	return pg.Record(ctx, res, cliActor(), netip.Addr{})
}

// acceptGatewayRollback — намеренный откат шлюза: максимум манифеста шлюза
// становится текущим, условие ОЦЛ.5 по шлюзу снимается (В20 ревью 2.r4).
func acceptGatewayRollback(dsn, name string, stdout io.Writer) error {
	if !gwregistry.ValidName(name) {
		return errors.New("gateway: неверное имя шлюза")
	}
	ctx := context.Background()
	svc, closeDB, err := openRegistry(ctx, dsn)
	if err != nil {
		return err
	}
	defer closeDB()
	g, err := svc.AcceptRollback(ctx, name, cliActor())
	if err != nil {
		return err
	}
	say(stdout, "Откат шлюза %s на выпуск %s принят: запись integrity.rollback_accepted в журнале аудита.\n", g.Name,
		g.Integrity.ManifestVersion)
	return nil
}

func printResult(w io.Writer, path string, res integrity.Result) {
	if res.TestSigned {
		say(w, "ВНИМАНИЕ: сборка с тестовым ключом манифеста — не для поставки.\n")
	}
	if res.OK() {
		say(w, "Целостность не нарушена. Манифест %s, версия %s, проверено файлов: %d.\n", path, res.ManifestVersion, res.Checked)
		return
	}
	say(w, "Целостность нарушена: %s. Манифест %s, проверено файлов: %d.\n", reasonText(res.Reason), path, res.Checked)
	for _, f := range res.Failures {
		say(w, "  %s — %s\n", f.Path, problemText(f.Problem))
	}
	if res.Omitted > 0 {
		say(w, "  и ещё нарушений: %d\n", res.Omitted)
	}
}

func reasonText(r integrity.Reason) string {
	switch r {
	case integrity.ReasonManifestMissing:
		return "нет файла манифеста"
	case integrity.ReasonManifestInvalid:
		return "манифест не разобран или не для этого криптопрофиля"
	case integrity.ReasonSignatureInvalid:
		return "подпись манифеста неверна или её нет"
	case integrity.ReasonFilesMismatch:
		return "файлы не совпадают с манифестом"
	case integrity.ReasonManifestRollback:
		return "установлен выпуск старше уже проверенного (откат); намеренный откат — aisec-cli verify -accept-rollback"
	}
	return string(r)
}

func problemText(p integrity.Problem) string {
	switch p {
	case integrity.ProblemModified:
		return "содержимое изменено"
	case integrity.ProblemSize:
		return "размер не совпадает"
	case integrity.ProblemMissing:
		return "файл отсутствует"
	case integrity.ProblemExtra:
		return "лишний файл"
	case integrity.ProblemNotRegular:
		return "не обычный файл (ссылка или каталог)"
	case integrity.ProblemUnreadable:
		return "не удалось прочитать"
	case integrity.ProblemNoEntry:
		return "нет в манифесте"
	case integrity.ProblemChanged:
		return "изменён после запуска"
	}
	return string(p)
}
