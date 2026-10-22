package gateway

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Пакет конфигурации с сервера управления (Р7, ОЦЛ.3, DM-42; задача 2.13).
// Шлюз опрашивает внутренний API по mTLS, проверяет подпись и версию до
// разбора содержимого и применяет пакет целиком. Любой отказ — запись в
// технический журнал и отчёт серверу (bundle.rejected в аудите); шлюз
// продолжает работать на последнем исправном пакете.

// Пределы получения пакета.
const (
	// DefaultBundleInterval — период опроса сервера.
	DefaultBundleInterval = 30 * time.Second
	// bundleBackoffMax — предел паузы после ошибок связи.
	bundleBackoffMax = 5 * time.Minute
	// bundleFetchTimeout — таймаут получения пакета: до 8 МиБ, дольше
	// обычного запроса к серверу.
	bundleFetchTimeout = time.Minute
	// BundleKeyHeader — открытый ключ получателя шлюза (base64url без
	// дополнения): им сервер шифрует учётные данные провайдеров.
	BundleKeyHeader = "AISec-Bundle-Key"
	// TrustSeqHeader — номер последнего принятого заявления о доверии
	// (ADR-0018, п. 4): сервер с более новым присылает пакет целиком.
	TrustSeqHeader = "AISec-Trust-Seq"
)

// etagRe — ETag пакета от сервера: версия в кавычках.
var etagRe = regexp.MustCompile(`^"[1-9][0-9]{0,18}"$`)

// BundleConfig — параметры получения пакетов.
type BundleConfig struct {
	// Client — HTTP-клиент с транспортом ControlTransport и сертификатом шлюза.
	Client *http.Client
	// Server — адрес внутреннего API (https://хост:8445).
	Server *url.URL
	Opener *bundle.Opener
	// RecipientKey — открытый ключ получателя шлюза.
	RecipientKey []byte
	// State — каталог состояния: последний применённый пакет.
	State *BundleState
	// Apply применяет проверенный пакет целиком: провайдеры, политики,
	// приложения и ключи. Ошибка — пакет отклоняется (invalid_content), а
	// действует прежний. Секреты пакета затираются после вызова.
	Apply    func(*bundle.Bundle) error
	Logger   *slog.Logger
	Interval time.Duration
	// Sleep ждёт d или отмены ctx (тесты подменяют его).
	Sleep func(ctx context.Context, d time.Duration) bool
}

// statusReport — тело POST /internal/v1/policies/bundle/status.
type statusReport struct {
	Result  string `json:"result"`
	Version int64  `json:"version"`
	Reason  string `json:"reason,omitempty"`
}

// BundleClient получает и применяет пакеты.
type BundleClient struct {
	c BundleConfig
	// mu — один пакет применяется за раз.
	mu      sync.Mutex
	version int64
	// rejected — ETag отклонённого пакета: сервер не присылает его повторно
	// (If-None-Match), пока не соберёт новую версию.
	rejected string
	// pending — отчёт, ещё не доставленный серверу; last — последний
	// доставленный: одинаковый не отправляется повторно.
	pending, last *statusReport
	etag          atomic.Value // string
	key           string
	// keyID — ключ подписи применённого пакета: тот же пакет, подписанный
	// новым ключом после ротации, сохраняется на диск заново.
	keyID string
}

// NewBundleClient проверяет параметры.
func NewBundleClient(c BundleConfig) (*BundleClient, error) {
	if c.Client == nil || c.Server == nil || c.Opener == nil || c.State == nil || c.Apply == nil || len(c.RecipientKey) == 0 {
		return nil, errors.New("пакет конфигурации: не заданы клиент, сервер, проверка, каталог состояния, ключ или применение")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Interval <= 0 {
		c.Interval = DefaultBundleInterval
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	b := &BundleClient{c: c, key: base64.RawURLEncoding.EncodeToString(c.RecipientKey)}
	b.etag.Store("")
	return b, nil
}

// ETag — ETag применённого пакета для heartbeat; пусто — пакета нет.
func (b *BundleClient) ETag() string { return b.etag.Load().(string) }

// TrustRoots — корни УЦ из принятых заявлений о доверии: по ним шлюз
// проверяет перевыпущенный сертификат (ADR-0018, п. 6.3).
func (b *BundleClient) TrustRoots() [][]byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.c.Opener.TrustRoots()
}

// Ready сообщает, применён ли хотя бы один пакет.
func (b *BundleClient) Ready() bool { return b.ETag() != "" }

// LoadSaved применяет пакет, сохранённый при прошлом запуске, — до первого
// ответа сервера шлюз работает на нём. Пакет проверяется так же, как
// полученный по сети: подмена файла на диске — отказ (ОЦЛ.3).
func (b *BundleClient) LoadSaved() bool {
	data, err := b.c.State.Load()
	if err != nil {
		b.c.Logger.Error("сохранённый пакет конфигурации не прочитан; шлюз ждёт пакет от сервера", "error", err)
		b.queue(statusReport{Result: "rejected", Reason: bundle.ReasonFormat})
		return false
	}
	if data == nil {
		return false
	}
	return b.accept(data, "", "file") == nil
}

// Run опрашивает сервер до отмены ctx. Ошибки связи не останавливают шлюз
// (ТЗ, 4.2): пауза растёт до bundleBackoffMax.
func (b *BundleClient) Run(ctx context.Context) {
	backoff := time.Duration(0)
	for {
		wait := b.c.Interval
		if err := b.Poll(ctx); ctx.Err() != nil {
			return
		} else if err != nil {
			backoff = min(max(2*backoff, b.c.Interval), bundleBackoffMax)
			wait = backoff
			var ce *controlError
			switch {
			case errors.As(err, &ce) && ce.Status == http.StatusUnauthorized:
				b.c.Logger.Error("сервер отклонил сертификат шлюза при запросе пакета конфигурации", "status", ce.Status)
				wait = bundleBackoffMax
			case errors.As(err, &ce) && ce.Status == http.StatusServiceUnavailable:
				b.c.Logger.Info("сервер ещё не собрал пакет конфигурации", "status", ce.Status)
				wait = max(b.c.Interval, ce.RetryAfter)
			default:
				b.c.Logger.Warn("пакет конфигурации не получен", "error", err)
			}
		} else {
			backoff = 0
		}
		if !b.c.Sleep(ctx, wait) {
			return
		}
	}
}

// Poll — один опрос: отчёт о прошлом итоге, затем запрос пакета с
// If-None-Match. Ошибка — только связь или ответ сервера; отказ в пакете
// ошибкой опроса не считается.
func (b *BundleClient) Poll(ctx context.Context) error {
	b.flush(ctx)
	data, etag, err := b.fetch(ctx)
	if err != nil {
		return err
	}
	if data != nil {
		_ = b.accept(data, etag, "server") //nolint:gosec // G104: отказ уже записан в журнал и в отчёт
	}
	b.flush(ctx)
	return nil
}

// fetch запрашивает пакет; 304 — data = nil.
func (b *BundleClient) fetch(ctx context.Context) (data []byte, etag string, err error) {
	ctx, cancel := context.WithTimeout(ctx, bundleFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.c.Server.JoinPath("/internal/v1/policies/bundle").String(), nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "aisec-gateway")
	req.Header.Set(BundleKeyHeader, b.key)
	b.mu.Lock()
	req.Header.Set(TrustSeqHeader, strconv.FormatInt(b.c.Opener.TrustSeq(), 10))
	inm := b.ETag()
	if b.rejected != "" {
		if inm != "" {
			inm += ", "
		}
		inm += b.rejected
	}
	b.mu.Unlock()
	if inm != "" {
		req.Header.Set("If-None-Match", inm)
	}
	resp, err := b.c.Client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = resp.Body.Close() }() //nolint:gosec // G104: тело прочитано или отброшено; ошибка закрытия не меняет результат
	switch resp.StatusCode {
	case http.StatusNotModified:
		return nil, "", nil
	case http.StatusOK:
	default:
		ce := &controlError{Status: resp.StatusCode}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 && s <= 3600 {
			ce.RetryAfter = time.Duration(s) * time.Second
		}
		return nil, "", ce
	}
	if etag = resp.Header.Get("ETag"); !etagRe.MatchString(etag) {
		etag = ""
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, bundle.MaxSize+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > bundle.MaxSize {
		// Больше предела — отказ до разбора (DM-42); то же, что от Open.
		b.mu.Lock()
		defer b.mu.Unlock()
		b.rejectLocked(&bundle.RejectError{Reason: bundle.ReasonTooLarge, Err: errors.New("пакет больше предела")}, etag, "server")
		return nil, "", nil
	}
	return data, etag, nil
}

// accept проверяет и применяет пакет. etag — заявленный сервером (для
// отчёта и If-None-Match при отказе), source — server или file.
func (b *BundleClient) accept(data []byte, etag, source string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	seq := b.c.Opener.TrustSeq()
	bd, err := b.c.Opener.Open(data, b.version)
	// Принятые заявления о доверии сохраняются, даже если сам пакет
	// отклонён: каждое проверено по цепочке.
	if b.c.Opener.TrustSeq() != seq {
		if serr := b.c.State.SaveTrust(b.c.Opener.TrustRaw()); serr != nil {
			b.c.Logger.Error("заявления о доверии приняты, но не сохранены на диск", "error", serr)
		} else {
			b.c.Logger.Info("принято заявление о доверии: ключи подписи пакетов и корни УЦ обновлены", "trust_seq", b.c.Opener.TrustSeq())
		}
	}
	if err != nil {
		b.rejectLocked(err, etag, source)
		return err
	}
	defer bd.Secrets.Clear()
	if bd.Header.Version == b.version {
		// Тот же пакет; подписанный новым ключом — на диск, чтобы после
		// перекрытия прежнего ключа шлюз запустился с ним.
		if source != "file" && bd.KeyID != b.keyID {
			if err := b.c.State.Save(bd.Raw); err != nil {
				b.c.Logger.Error("пакет, подписанный новым ключом, не сохранён на диск", "error", err)
			} else {
				b.keyID = bd.KeyID
			}
		}
		return nil
	}
	if err := b.c.Apply(bd); err != nil {
		err = &bundle.RejectError{Reason: bundle.ReasonInvalidContent, Err: err}
		b.rejectLocked(err, bd.ETag(), source)
		return err
	}
	b.version, b.rejected, b.keyID = bd.Header.Version, "", bd.KeyID
	b.etag.Store(bd.ETag())
	if source != "file" {
		if err := b.c.State.Save(bd.Raw); err != nil {
			// Пакет действует; после перезапуска шлюз возьмёт прежний файл
			// и получит этот пакет с сервера заново.
			b.c.Logger.Error("пакет конфигурации применён, но не сохранён на диск", "error", err)
		}
		b.pending = &statusReport{Result: "applied", Version: bd.Header.Version}
	}
	b.c.Logger.Info("пакет конфигурации применён", "version", bd.Header.Version, "key_id", bd.KeyID, "source", source,
		"applications", len(bd.Content.Applications), "providers", len(bd.Content.Providers), "policies", len(bd.Content.Policies))
	return nil
}

// rejectLocked записывает отказ в журнал и ставит отчёт серверу. Текст
// ошибки разбора содержимого в журнал не попадает: в нём могут быть
// фрагменты политик и словарей.
func (b *BundleClient) rejectLocked(err error, etag, source string) {
	reason := bundle.Reason(err)
	var version int64
	if etag != "" {
		version, _ = strconv.ParseInt(etag[1:len(etag)-1], 10, 64) //nolint:gosec // G104: etagRe пропускает только число до 19 цифр; переполнение даёт 0
	}
	attrs := []any{"reason", reason, "version", version, "source", source, "threat", "DM-42"}
	if reason != bundle.ReasonInvalidContent {
		attrs = append(attrs, "error", err)
	}
	b.c.Logger.Warn("пакет конфигурации отклонён; действует прежний", attrs...)
	if source == "server" && etag != "" {
		b.rejected = etag
	}
	b.pending = &statusReport{Result: "rejected", Version: version, Reason: reason}
}

func (b *BundleClient) queue(r statusReport) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.pending = &r
}

// flush доставляет отчёт серверу; при ошибке отчёт остаётся до следующего
// опроса. Повтор того же отчёта не отправляется.
func (b *BundleClient) flush(ctx context.Context) {
	b.mu.Lock()
	r := b.pending
	if r != nil && b.last != nil && *r == *b.last {
		b.pending, r = nil, nil
	}
	b.mu.Unlock()
	if r == nil {
		return
	}
	err := postControl(ctx, b.c.Client, b.c.Server.JoinPath("/internal/v1/policies/bundle/status").String(), r, nil, http.StatusNoContent)
	if err != nil {
		b.c.Logger.Warn("отчёт о пакете конфигурации не доставлен серверу", "result", r.Result, "error", err)
		return
	}
	b.mu.Lock()
	if b.pending == r {
		b.pending = nil
	}
	b.last = r
	b.mu.Unlock()
}
