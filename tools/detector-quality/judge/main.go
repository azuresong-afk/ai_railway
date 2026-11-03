// Команда judge замеряет judge.llm на корпусе бизнес-правил против словаря
// lists (задача 5.29 этапа 5, ADR-0030, docs/detectors.md, раздел
// «judge.llm»): полнота, доля ложных и точность по парам «пример — правило»,
// разрезы по правилам, видам, классам и языкам, расход токенов и время
// вызова.
//
// Два режима:
//   - -stand — оценщик-стенд в памяти (judge.Stand): проверяет разметку
//     корпуса и отчёт, цифры качества не показательны. Запускается где
//     угодно, сети не нужно;
//   - -base-url и -model — настоящий оценщик: OpenAI-совместимый сервер
//     заказчика по https. Адрес проверяется так же, как в шлюзе (ADR-0030,
//     раздел 1): соединение — только с адресами частной сети, при каждом
//     соединении. Это замер на машине владельца с локальной моделью. Весь
//     корпус синтетический, но он всё равно уходит только на этот адрес.
//
// Других обращений в сеть команда не делает.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/judge"
	"github.com/azuresong-afk/ai_railway/internal/providers"
	"github.com/azuresong-afk/ai_railway/tools/detector-quality/judgeq"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "judge-quality:", err)
		os.Exit(1)
	}
}

// options — разобранные параметры командной строки.
type options struct {
	corpus, out, profile    string
	stand                   bool
	baseURL, model, keyFile string
	caFile                  string
	threshold               float64
	timeout                 time.Duration
}

func parseFlags(args []string) (*options, error) {
	var o options
	fs := flag.NewFlagSet("judge-quality", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&o.corpus, "corpus", "testdata/corpus/judge", "каталог корпуса (rules.json, samples.jsonl, lists-baseline.json)")
	fs.StringVar(&o.out, "out", "build/judge-quality.md", "куда записать отчёт")
	fs.StringVar(&o.profile, "profile", aisecCrypto.ProfileStandard, "криптопрофиль (standard или gost)")
	fs.BoolVar(&o.stand, "stand", false, "оценщик-стенд в памяти: проверка разметки и отчёта без модели")
	fs.StringVar(&o.baseURL, "base-url", "", "адрес OpenAI-совместимого сервера оценщика в частной сети, https://host:port/v1")
	fs.StringVar(&o.model, "model", "", "имя модели оценщика")
	fs.StringVar(&o.keyFile, "key-file", "", "файл с ключом сервера (права 0600 или уже); пусто — без ключа")
	fs.StringVar(&o.caFile, "ca", "", "файл PEM с корневыми сертификатами сервера, если его выпустил свой УЦ")
	fs.Float64Var(&o.threshold, "threshold", judgeq.DefaultThreshold, "уверенность оценщика, с которой вердикт считается нарушением (0–1)")
	fs.DurationVar(&o.timeout, "timeout", 60*time.Second, "срок одного вызова оценщика")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("лишние аргументы: %s", strings.Join(fs.Args(), " "))
	}
	switch {
	case o.stand == (o.baseURL != ""):
		return nil, errors.New("нужен ровно один режим: -stand или -base-url с -model")
	case !o.stand && o.model == "":
		return nil, errors.New("-base-url требует -model")
	case o.threshold <= 0 || o.threshold > 1:
		return nil, errors.New("-threshold — число больше 0 и не больше 1")
	case o.timeout < time.Second || o.timeout > 10*time.Minute:
		return nil, errors.New("-timeout — от 1 секунды до 10 минут")
	}
	return &o, nil
}

func run(args []string, stdout io.Writer) error {
	o, err := parseFlags(args)
	if err != nil {
		return err
	}
	corpus, err := judgeq.Load(o.corpus)
	if err != nil {
		return err
	}
	baselinePath := filepath.Join(o.corpus, judgeq.BaselineFile)
	baseline, err := judgeq.Baseline(baselinePath, corpus.Rules)
	if err != nil {
		return err
	}
	prof, err := aisecCrypto.New(o.profile)
	if err != nil {
		return err
	}
	hasher, err := prof.Hasher()
	if err != nil {
		return err
	}
	rnd, err := prof.Random()
	if err != nil {
		return err
	}
	var client judge.Client
	mode := "стенд-оценщик в памяти (проверка разметки и отчёта, не качества модели)"
	if o.stand {
		markers, err := judgeq.StandMarkers(baselinePath, corpus.Rules)
		if err != nil {
			return err
		}
		client = judge.Stand{Markers: markers}
	} else {
		if client, err = newClient(o, prof); err != nil {
			return err
		}
		mode = "модель " + o.model + " на сервере заказчика"
	}
	eng, err := judge.NewEngine(judge.Config{Provider: "judge-quality", Model: o.model, Client: client, Hasher: hasher, Random: rnd,
		Shared: judge.NewShared(), BudgetKey: "judge-quality",
		Limits: judge.Limits{CallsPerMinute: 6000, TokensPerHour: 100_000_000}})
	if err != nil {
		return err
	}
	res, err := judgeq.Run(context.Background(), judgeq.Config{Corpus: corpus, Engine: eng, Baseline: baseline,
		Threshold: o.threshold, Timeout: o.timeout, Mode: mode})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(o.out), 0o750); err != nil {
		return err
	}
	if err := os.WriteFile(o.out, []byte(res.Markdown()), 0o600); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "judge-quality: примеров %d, правил %d, не проверено %d; полнота lists %.3f, judge.llm %.3f; доля ложных lists %.3f, judge.llm %.3f (%s)\n",
		res.Samples, res.Rules, res.Unchecked, res.Total.Lists.Recall(), res.Total.Judge.Recall(), res.Total.Lists.FPR(), res.Total.Judge.FPR(), o.out)
	return err
}

// newClient — адаптер оценщика, как в шлюзе (cmd/aisec-gateway, newJudgeClient):
// только https и только адреса частной сети.
func newClient(o *options, prof aisecCrypto.Provider) (judge.Client, error) {
	u, err := config.ParseUpstreamURL(o.baseURL)
	if err != nil {
		return nil, err
	}
	var roots []byte
	if o.caFile != "" {
		if roots, err = aisecCrypto.ReadPEMFile(o.caFile); err != nil {
			return nil, fmt.Errorf("-ca: %w", err)
		}
	}
	key := ""
	if o.keyFile != "" {
		b, err := aisecCrypto.ReadKeyFile(o.keyFile)
		if err != nil {
			return nil, fmt.Errorf("-key-file: %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	tp, err := prof.TLS()
	if err != nil {
		return nil, err
	}
	tr, err := providers.NewPrivateTransport(tp, roots, config.DefaultConnectTimeout, config.DefaultHeaderTimeout)
	if err != nil {
		return nil, err
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return providers.NewOpenAI(providers.OpenAIConfig{BaseConfig: providers.BaseConfig{ID: "judge-quality", Transport: tr, Logger: logger,
		ResponseTimeout: o.timeout}, BaseURL: u, Key: key})
}
