// Команда demo-data наполняет демо-стенд синтетическими событиями: она
// отправляет запросы в Check API шлюза (POST /guard/v1/check) от имени
// приложений стенда. События, оповещения и инциденты рождаются так же, как у
// заказчика, — по правилам сервера; в таблицы ничего не пишется напрямую.
// В поставку не входит. Подробности — README.md рядом.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

const (
	maxDays         = 90
	maxEventsPerDay = 2000
	maxResponse     = 1 << 20
	requestTimeout  = 30 * time.Second
	maxQuotaRetries = 3
)

type options struct {
	gateway     string
	ca          string
	keys        string
	corpus      string
	seed        uint64
	days        int
	perDay      int
	rate        int
	allowRemote bool
	dryRun      bool
}

func main() {
	var o options
	flag.StringVar(&o.gateway, "gateway", "https://127.0.0.1:8443", "адрес шлюза (https); не loopback — только с -allow-remote")
	flag.StringVar(&o.ca, "ca", "", "файл корневого сертификата, которому доверяем при подключении к шлюзу (PEM)")
	flag.StringVar(&o.keys, "keys", "", "файл ключей приложений: строки «приложение=ключ», права 0600")
	flag.StringVar(&o.corpus, "corpus", "testdata/corpus", "каталог корпусов атак")
	flag.Uint64Var(&o.seed, "seed", 1, "зерно: тот же план при том же зерне")
	flag.IntVar(&o.days, "days", 30, "сколько суток охватывает план (1–90)")
	flag.IntVar(&o.perDay, "events-per-day", 40, "средняя норма запросов в сутки на весь стенд (1–2000)")
	flag.IntVar(&o.rate, "rate", 20, "не больше запросов в секунду")
	flag.BoolVar(&o.allowRemote, "allow-remote", false, "разрешить адрес шлюза, который не loopback")
	flag.BoolVar(&o.dryRun, "dry-run", false, "только построить план и показать его состав, ничего не отправляя")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Stdout, o); err != nil {
		fmt.Fprintln(os.Stderr, "demo-data:", err)
		os.Exit(2)
	}
}

// checkGateway отказывает на адрес, который не явно локальный. Имя не
// разрешается в адрес: localhost и IP-литералы loopback считаются локальными.
func checkGateway(raw string, allowRemote bool) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("-gateway: нужен адрес вида https://хост:порт")
	}
	if u.Scheme != "https" {
		return nil, errors.New("-gateway: только https")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	local := host == "localhost" || (ip != nil && ip.IsLoopback())
	if !local && !allowRemote {
		return nil, fmt.Errorf("-gateway: %q не loopback; для чужого стенда нужен флаг -allow-remote", host)
	}
	return u, nil
}

func validate(o options) error {
	switch {
	case o.days < 1 || o.days > maxDays:
		return fmt.Errorf("-days: от 1 до %d", maxDays)
	case o.perDay < 1 || o.perDay > maxEventsPerDay:
		return fmt.Errorf("-events-per-day: от 1 до %d", maxEventsPerDay)
	case o.rate < 1 || o.rate > 1000:
		return errors.New("-rate: от 1 до 1000")
	case o.keys == "":
		return errors.New("-keys обязателен")
	}
	return nil
}

func run(ctx context.Context, w io.Writer, o options) error {
	u, err := checkGateway(o.gateway, o.allowRemote)
	if err != nil {
		return err
	}
	if err := validate(o); err != nil {
		return err
	}
	keys, apps, err := readKeys(o.keys)
	if err != nil {
		return err
	}
	cs, err := loadCorpora(o.corpus)
	if err != nil {
		return err
	}
	sort.Strings(apps) // порядок приложений не зависит от порядка строк файла
	plan := buildPlan(planParams{Seed: o.seed, Days: o.days, EventsPerDay: o.perDay, Apps: apps, Corpora: cs})
	kinds := map[string]int{}
	for _, it := range plan {
		kinds[it.Kind]++
	}
	if _, err := fmt.Fprintf(w, "План: %d запросов за %d суток, приложений %d, зерно %d; %s\n", len(plan), o.days, len(apps), o.seed, summary(kinds)); err != nil {
		return err
	}
	if o.dryRun {
		return nil
	}
	client, err := newClient(o.ca)
	if err != nil {
		return err
	}
	endpoint := u.JoinPath("guard", "v1", "check").String()
	decisions := map[string]int{}
	tick := time.NewTicker(time.Second / time.Duration(o.rate))
	defer tick.Stop()
	for i, it := range plan {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
		d, err := send(ctx, client, endpoint, keys[it.App], it)
		if err != nil {
			return fmt.Errorf("запрос %d из %d: %w", i+1, len(plan), err)
		}
		decisions[d]++
	}
	if _, err := fmt.Fprintf(w, "Отправлено %d запросов; решения шлюза: %s\n", len(plan), summary(decisions)); err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, "Метки времени событий — время приёма шлюзом (сейчас), а не сутки плана.")
	return err
}

func summary(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s %d", k, m[k])
	}
	return strings.Join(parts, ", ")
}

// newClient — клиент TLS, который доверяет только заданному корню; настройки
// TLS даёт internal/crypto (ТЗ, 10.2).
func newClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return nil, errors.New("-ca обязателен: шлюз стенда выпускает сертификат своим УЦ")
	}
	roots, err := aisecCrypto.ReadPEMFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("-ca: %w", err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return nil, err
	}
	tp, err := p.TLS()
	if err != nil {
		return nil, err
	}
	cfg, err := tp.ClientConfig(roots)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   requestTimeout,
		Transport: &http.Transport{TLSClientConfig: cfg, MaxIdleConns: 4},
		// Переходы по адресам не нужны: ключ приложения не должен уйти дальше.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

type checkBody struct {
	Direction string `json:"direction"`
	Source    string `json:"source"`
	Text      string `json:"text"`
	User      string `json:"user"`
}

// send отправляет один запрос и возвращает решение шлюза. При 429 ждёт и
// повторяет не больше maxQuotaRetries раз.
func send(ctx context.Context, c *http.Client, endpoint, key string, it item) (string, error) {
	body, err := json.Marshal(checkBody{it.Direction, it.Source, it.Text, it.User})
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		code, resp, err := post(ctx, c, endpoint, key, body)
		if err != nil {
			return "", err
		}
		switch {
		case code == http.StatusOK:
			var r struct {
				Decision string `json:"decision"`
			}
			if err := json.Unmarshal(resp, &r); err != nil || r.Decision == "" {
				return "", errors.New("ответ шлюза без решения")
			}
			return r.Decision, nil
		case code == http.StatusTooManyRequests && attempt < maxQuotaRetries:
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Second):
			}
		case code == http.StatusUnauthorized || code == http.StatusForbidden:
			return "", fmt.Errorf("шлюз отказал приложению %q (код %d): проверьте ключ и настройку приложения", it.App, code)
		default:
			return "", fmt.Errorf("шлюз ответил кодом %d", code)
		}
	}
}

func post(ctx context.Context, c *http.Client, endpoint, key string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, errors.New("шлюз недоступен: " + redactErr(err)) // текст ошибки может содержать адрес, но не ключ
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: ошибка закрытия тела ответа не влияет на результат
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	return resp.StatusCode, b, err
}

// redactErr оставляет в ошибке сети только внутренний текст без URL.
func redactErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return err.Error()
}
