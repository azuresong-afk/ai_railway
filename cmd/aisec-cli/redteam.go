package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/cliclient"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/store"
)

// Запуск тестирования устойчивости из CI (ТЗ 5.13; задача 5.33 этапа 5,
// ADR-0031): команда запускает цель на сервере управления токеном API с
// правами redteam.run и redteam.read, ждёт завершения и печатает итоги.
// Код выхода 3 — доля удавшихся атак выше порога. Выводятся только ID
// сценариев, строки матрицы, категории и счётчики: промптов атак и ответов
// цели в выводе нет. Отчёт с выдержками — в консоли или GET
// /api/v1/redteam/runs/{id}/report.

// errRedteamThreshold — доля удавшихся атак выше порога (код выхода 3).
var errRedteamThreshold = errors.New("доля удавшихся атак выше порога")

// Пределы команды.
const (
	redteamRunPath   = "/api/v1/redteam/runs"
	redteamMaxWait   = 130 * time.Minute
	redteamDefWait   = 125 * time.Minute
	redteamMaxAuth   = 4096
	redteamMaxFilter = 64
	redteamMaxIDs    = 1000
	redteamMaxCard   = 8 << 20
	// redteamCancelWait — срок запроса отмены при прерывании команды.
	redteamCancelWait = 15 * time.Second
)

var (
	redteamThreatRe   = regexp.MustCompile(`^DM-(0[1-9]|[1-9][0-9])$`)
	redteamScenarioRe = regexp.MustCompile(`^[A-Z][A-Z0-9-]{2,63}$`)
)

// redteamRunCard — поля ответа сервера, которые нужны команде.
type redteamRunCard struct {
	ID         string         `json:"id"`
	TargetName string         `json:"target_name"`
	Status     string         `json:"status"`
	Reason     string         `json:"reason"`
	Scenarios  int            `json:"scenarios"`
	Counts     map[string]int `json:"counts"`
	DBVersion  uint64         `json:"db_version"`
	Results    []struct {
		ScenarioID string   `json:"scenario_id"`
		Lang       string   `json:"lang"`
		Threat     string   `json:"threat"`
		Category   string   `json:"category"`
		Verdict    string   `json:"verdict"`
		Step       int      `json:"step"`
		Matched    []string `json:"matched"`
		ErrorCode  string   `json:"error_code"`
	} `json:"results"`
}

type redteamFlags struct {
	server, ca, tokenFile, profile, target, lang, authFile, out string
	scenarios, threats                                          string
	threshold                                                   float64
	timeout, wait, poll                                         time.Duration
}

// redteamCmd — aisec-cli redteam run.
func redteamCmd(args []string, stdout, stderr io.Writer) error {
	if len(args) > 0 && args[0] == "run" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return redteamRun(ctx, args[1:], stdout, stderr)
	}
	return errors.New("подкоманда: run")
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func redteamRun(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("redteam run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var f redteamFlags
	fs.StringVar(&f.server, "server", "", "адрес сервера управления: https://хост[:порт]")
	fs.StringVar(&f.ca, "ca", "", "корневой сертификат сервера (PEM): доверие — только ему")
	fs.StringVar(&f.tokenFile, "token-file", "", "файл с токеном API с правами redteam.run и redteam.read (права 0600 или 0400)")
	fs.StringVar(&f.target, "target", "", "ID цели тестирования устойчивости")
	fs.Float64Var(&f.threshold, "threshold", 0, "допустимая доля удавшихся атак среди проверенных сценариев, % (0 — не допускается ни одной)")
	fs.StringVar(&f.scenarios, "scenarios", "", "ID сценариев через запятую; пусто — все")
	fs.StringVar(&f.threats, "threats", "", "строки матрицы DM-NN через запятую; пусто — все")
	fs.StringVar(&f.lang, "lang", "", "язык сценариев: ru или en; пусто — оба")
	fs.StringVar(&f.authFile, "auth-value-file", "", "файл со значением секретного заголовка цели (права 0600 или 0400); значение уходит на сервер только на время запуска")
	fs.StringVar(&f.out, "out", "", "файл для итогов запуска в JSON (без промптов и ответов); создаётся с правами 0600")
	fs.StringVar(&f.profile, "crypto-profile", aisecCrypto.ProfileStandard, "криптопрофиль TLS: standard или gost")
	fs.DurationVar(&f.timeout, "timeout", cliclient.DefaultTimeout, "срок одного запроса к серверу")
	fs.DurationVar(&f.wait, "wait", redteamDefWait, "сколько ждать завершения запуска")
	fs.DurationVar(&f.poll, "poll", 5*time.Second, "как часто спрашивать сервер о запуске")
	if err := fs.Parse(args); err != nil {
		return err
	}
	in, err := f.check(fs)
	if err != nil {
		return err
	}
	p, err := aisecCrypto.New(f.profile)
	if err != nil {
		return fmt.Errorf("-crypto-profile: %w", err)
	}
	c, err := cliclient.New(cliclient.Options{Server: f.server, CAFile: f.ca, TokenFile: f.tokenFile, Provider: p, Timeout: f.timeout,
		MaxResponse: redteamMaxCard})
	if err != nil {
		return err
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	var started redteamRunCard
	if err := c.Do(ctx, "POST", redteamRunPath, body, "application/json", &started); err != nil {
		return fmt.Errorf("запуск не начат: %w", err)
	}
	if _, err := store.ParseUUID(started.ID); err != nil {
		return errors.New("сервер вернул запуск без ID")
	}
	say(stdout, "Запуск %s начат, сценариев: %d, база сценариев версии %d.\n", started.ID, started.Scenarios, started.DBVersion)
	card, err := waitRedteamRun(ctx, c, started.ID, f.wait, f.poll)
	if err != nil {
		return err
	}
	return finishRedteam(stdout, card, f)
}

// redteamStart — тело запроса запуска.
type redteamStart struct {
	TargetID  string   `json:"target_id"`
	Scenarios []string `json:"scenarios,omitempty"`
	Threats   []string `json:"threats,omitempty"`
	Lang      string   `json:"lang,omitempty"`
	AuthValue string   `json:"auth_value,omitempty"` //nolint:gosec // G117: значение заголовка цели уходит в запрос запуска и нигде не сохраняется
}

func (f *redteamFlags) check(fs *flag.FlagSet) (redteamStart, error) {
	var in redteamStart
	switch {
	case fs.NArg() != 0:
		return in, errors.New("лишние аргументы: все параметры — флаги")
	case f.server == "" || f.ca == "" || f.tokenFile == "" || f.target == "":
		return in, errors.New("обязательны -server, -ca, -token-file и -target")
	case math.IsNaN(f.threshold) || f.threshold < 0 || f.threshold > 100:
		return in, errors.New("-threshold: от 0 до 100 процентов")
	case f.lang != "" && f.lang != "ru" && f.lang != "en":
		return in, errors.New("-lang: ru или en")
	case f.timeout <= 0 || f.timeout > 10*time.Minute:
		return in, errors.New("-timeout: от 1 с до 10 мин")
	case f.wait < time.Minute || f.wait > redteamMaxWait:
		return in, errors.New("-wait: от 1 мин до 2 ч 10 мин")
	case f.poll < 100*time.Millisecond || f.poll > time.Minute:
		return in, errors.New("-poll: от 100 мс до 1 мин")
	}
	if _, err := store.ParseUUID(f.target); err != nil {
		return in, errors.New("-target: ID цели (UUID)")
	}
	in = redteamStart{TargetID: f.target, Scenarios: splitList(f.scenarios), Threats: splitList(f.threats), Lang: f.lang}
	if len(in.Scenarios) > redteamMaxIDs {
		return in, fmt.Errorf("-scenarios: не больше %d ID", redteamMaxIDs)
	}
	for _, id := range in.Scenarios {
		if !redteamScenarioRe.MatchString(id) {
			return in, errors.New("-scenarios: ID сценария, например RT-DM08-001")
		}
	}
	if len(in.Threats) > redteamMaxFilter {
		return in, fmt.Errorf("-threats: не больше %d строк", redteamMaxFilter)
	}
	for _, th := range in.Threats {
		if !redteamThreatRe.MatchString(th) {
			return in, errors.New("-threats: строки матрицы DM-NN, например DM-08")
		}
	}
	if f.authFile != "" {
		data, err := aisecCrypto.ReadKeyFile(f.authFile)
		if err != nil {
			return in, fmt.Errorf("-auth-value-file: %w", err)
		}
		v := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
		if v == "" || len(v) > redteamMaxAuth || !utf8.ValidString(v) || strings.IndexFunc(v, unicode.IsControl) >= 0 {
			return in, fmt.Errorf("-auth-value-file: одна строка до %d байт без управляющих символов", redteamMaxAuth)
		}
		in.AuthValue = v
	}
	return in, nil
}

// waitRedteamRun ждёт завершения запуска. Прерывание команды (Ctrl+C,
// SIGTERM) отменяет запуск на сервере: атаки не должны продолжаться после
// остановки CI-задачи.
func waitRedteamRun(ctx context.Context, c *cliclient.Client, id string, wait, poll time.Duration) (redteamRunCard, error) {
	deadline := time.NewTimer(wait)
	defer deadline.Stop()
	tick := time.NewTicker(poll)
	defer tick.Stop()
	cancel := func(why error) (redteamRunCard, error) {
		cctx, stop := context.WithTimeout(context.WithoutCancel(ctx), redteamCancelWait)
		defer stop()
		if err := c.Do(cctx, "POST", redteamRunPath+"/"+id+"/cancel", []byte("{}"), "application/json", nil); err != nil {
			return redteamRunCard{}, fmt.Errorf("%w; отменить запуск %s не удалось: %w", why, id, err)
		}
		return redteamRunCard{}, fmt.Errorf("%w; запуск %s отменён", why, id)
	}
	for {
		var card redteamRunCard
		if err := c.Do(ctx, "GET", redteamRunPath+"/"+id, nil, "", &card); err != nil {
			if ctx.Err() != nil {
				return cancel(errors.New("команда прервана"))
			}
			return redteamRunCard{}, fmt.Errorf("состояние запуска %s: %w", id, err)
		}
		if card.ID != id {
			return redteamRunCard{}, errors.New("сервер вернул другой запуск")
		}
		switch card.Status {
		case "done", "failed", "cancelled":
			return card, nil
		case "queued", "running":
		default:
			return redteamRunCard{}, fmt.Errorf("неизвестное состояние запуска: %q", card.Status)
		}
		select {
		case <-ctx.Done():
			return cancel(errors.New("команда прервана"))
		case <-deadline.C:
			return cancel(fmt.Errorf("запуск не завершился за %s (-wait)", wait))
		case <-tick.C:
		}
	}
}

// Названия итогов в выводе.
var redteamVerdicts = []struct{ key, title string }{
	{"succeeded", "атака удалась"}, {"blocked", "заблокировано защитой"}, {"defended", "отражено"},
	{"unchecked", "не проверено"}, {"error", "ошибка"}, {"skipped", "пропущено"},
}

func finishRedteam(stdout io.Writer, card redteamRunCard, f redteamFlags) error {
	if f.out != "" {
		if err := writeRedteamOut(f.out, card); err != nil {
			return err
		}
	}
	parts := make([]string, 0, len(redteamVerdicts))
	for _, v := range redteamVerdicts {
		parts = append(parts, fmt.Sprintf("%s — %d", v.title, card.Counts[v.key]))
	}
	say(stdout, "Запуск %s завершён: %s.\n", card.ID, card.Status)
	say(stdout, "Итоги: %s.\n", strings.Join(parts, "; "))
	if card.Status != "done" {
		reason := card.Reason
		if reason == "" {
			reason = "причина не указана"
		}
		return fmt.Errorf("запуск не доведён до конца (%s: %s): итоги неполные", card.Status, reason)
	}
	evaluated := card.Counts["succeeded"] + card.Counts["blocked"] + card.Counts["defended"]
	if evaluated == 0 {
		return errors.New("ни один сценарий не дал вердикта защиты (все с ошибкой, пропущены или без оценщика): цель не проверена")
	}
	won := card.Counts["succeeded"]
	pct := float64(won) * 100 / float64(evaluated)
	if bad := card.Counts["error"] + card.Counts["unchecked"] + card.Counts["skipped"]; bad > 0 {
		say(stdout, "ВНИМАНИЕ: сценариев без вердикта защиты: %d (ошибки цели, пропуски, условие judge без оценщика).\n", bad)
	}
	if won > 0 {
		say(stdout, "Удавшиеся атаки (%d из %d проверенных, %s %%):\n", won, evaluated, formatPercent(pct))
		type row struct{ id, line string }
		var rows []row
		for _, r := range card.Results {
			if r.Verdict == "succeeded" {
				rows = append(rows, row{r.ScenarioID, fmt.Sprintf("  %s\t%s\t%s\t%s\tшаг %d\tусловия: %s", r.ScenarioID, r.Lang, r.Threat,
					r.Category, r.Step, strings.Join(r.Matched, ", "))})
			}
		}
		sort.Slice(rows, func(i, j int) bool { return rows[i].id < rows[j].id })
		for _, r := range rows {
			say(stdout, "%s\n", r.line)
		}
	}
	if pct > f.threshold {
		say(stdout, "Доля удавшихся атак %s %% выше порога %s %%.\n", formatPercent(pct), formatPercent(f.threshold))
		return errRedteamThreshold
	}
	say(stdout, "Доля удавшихся атак %s %% не выше порога %s %%.\n", formatPercent(pct), formatPercent(f.threshold))
	return nil
}

func formatPercent(v float64) string {
	return strings.Replace(fmt.Sprintf("%.1f", v), ".", ",", 1)
}

// writeRedteamOut записывает итоги запуска: новый файл с правами 0600,
// существующий не перезаписывается.
func writeRedteamOut(path string, card redteamRunCard) error {
	data, err := json.MarshalIndent(card, "", "  ")
	if err != nil {
		return err
	}
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: путь задаёт администратор
	if err != nil {
		return fmt.Errorf("-out: %w", err)
	}
	if _, err := fh.Write(append(data, '\n')); err != nil {
		_ = fh.Close() //nolint:gosec // G104: ошибка записи важнее
		return fmt.Errorf("-out: %w", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("-out: %w", err)
	}
	return nil
}
