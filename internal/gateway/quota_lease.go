package gateway

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/ids"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle"
)

// Аренда квот и жёстких бюджетов у сервера управления (ADR-0021, задача
// 4.29 этапа 4). В режиме leased (quota_mode в пакете конфигурации) шлюз
// берёт у сервера долю квоты приложения — аренду — на короткий срок и
// внутри неё считает сам: сервер учитывает выданное сразу, поэтому сумма
// выданного всем шлюзам в окне не больше лимита. Распределяются
// requests_per_minute, tokens_per_minute, tokens_per_day и жёсткий бюджет;
// квоты на пользователя и ключ и ограничения одного запроса остаются
// локальными.
//
// Сроки аренды шлюз отсчитывает по своим монотонным часам от отправки
// запроса: перевод системных часов шлюза или сервера их не продлевает.
// Сервер недоступен, а аренда истекла: приложение с fail_open переходит на
// автономную долю (лимит, делённый на число шлюзов из последнего ответа;
// для суток и бюджета — остаток из последнего ответа на то же число),
// приложение с fail_closed — на ту же долю в льготный срок (срок аренды
// после истечения последней), затем ответ 503 quota_unavailable.

const (
	// quotaBudget — квота жёсткого бюджета в протоколе аренды.
	quotaBudget = "budget"
	leasePath   = "/internal/v1/quota-leases"
	// leaseWait — сколько обработчик запроса ждёт аренду у сервера.
	leaseWait = 2 * time.Second
	// leaseMinInterval — не больше пяти запросов аренды в секунду (сервер
	// принимает десять).
	leaseMinInterval = 200 * time.Millisecond
	// leaseTick — период фоновой проверки отчётов и упреждающих запросов.
	leaseTick = time.Second
	// leaseTimeout — срок одного запроса аренды.
	leaseTimeout = 5 * time.Second
	// Сроки аренды (как на сервере, quotalease): от них — льготный срок.
	leaseMinuteTTL = 10 * time.Second
	leaseLongTTL   = 5 * time.Minute
	// leaseReportAfter — истёкшая аренда с незакрытыми резервами
	// (длинный поток ответа) отчитывается не позже этого срока, считая
	// резервы израсходованными.
	leaseReportAfter = time.Minute
	// leasePrefetch — новая аренда просится заранее, когда свободно меньше
	// 1/leasePrefetch выданного (израсходовано 80 %).
	leasePrefetch = 5
	// leaseMaxQuotas — квот в одном запросе: тело с отчётами укладывается
	// в 64 КиБ; остальные — следующим запросом.
	leaseMaxQuotas = 300
	// leaseMaxBody — оценка тела запроса: не больше предела сервера 64 КиБ.
	leaseMaxBody    = 60 << 10
	leaseMaxReports = 8
	// leaseBackoffMax — предел паузы между попытками при недоступном сервере.
	leaseBackoffMax = 10 * time.Second
	// leaseIdle — состояние квоты без аренд и запросов дольше этого
	// забывается.
	leaseIdle = 10 * time.Minute
	// leaseAutonomousFresh — признак «на автономной доле» для heartbeat
	// держится столько после последнего такого запроса.
	leaseAutonomousFresh = 2 * time.Minute
	// leaseMaxResponse — ответ на запрос предельного размера.
	leaseMaxResponse = 512 << 10
	leaseMaxUnits    = 1 << 62
	// leaseUnknownRetry — повтор для приложения, которого сервер не знает.
	leaseUnknownRetry = 10 * time.Second
)

// ErrQuotaUnavailable — режим leased, сервер управления не выдаёт аренду, а
// льготный срок приложения с fail_closed истёк: ответ 503 quota_unavailable.
var ErrQuotaUnavailable = errors.New("квоты: аренда у сервера управления недоступна")

// LeaseConfig — клиент аренды.
type LeaseConfig struct {
	// Client — HTTP-клиент с транспортом ControlTransport и сертификатом шлюза.
	Client *http.Client
	// Server — адрес внутреннего API (https://хост:8445).
	Server *url.URL
	IDs    *ids.Generator
	Logger *slog.Logger
	// Now — часы с монотонной составляющей; nil — time.Now.
	Now func() time.Time
}

// LeaseClient — аренда квот у сервера. Безопасен для одновременного
// использования; запросы к серверу отправляет Run.
type LeaseClient struct {
	cfg     LeaseConfig
	url     string
	now     func() time.Time
	started time.Time
	kick    chan struct{}

	mu sync.Mutex
	// enabled — пакет конфигурации в режиме leased.
	enabled bool
	// failOpen — режим отказа приложений пакета.
	failOpen map[string]bool
	// loc — пояс установки (раздел budgets пакета): границы суток и месяца
	// автономной доли.
	loc    *time.Location
	states map[leaseKey]*leaseState
	// gateways — шлюзов на связи по последнему ответу; 0 — ответа не было.
	gateways int
	// failing — последний запрос к серверу не удался; epoch растёт при
	// каждом переходе в это состояние (автономная доля считается заново).
	failing  bool
	epoch    int
	failures int
	nextTry  time.Time
	lastSend time.Time
	// round закрывается, когда отправлен и разобран очередной запрос.
	round          chan struct{}
	lastAutonomous time.Time
}

type leaseKey struct{ app, quota string }

// leaseState — аренды и состояние одной квоты приложения.
type leaseState struct {
	key    leaseKey
	leases []*leaseRec
	// limit — лимит из пакета (для автономной доли минутных квот).
	limit int64
	// remaining и remainingKey — свободный остаток окна по последнему
	// ответу сервера и ключ окна (сутки или месяц), к которому он относится.
	remaining    int64
	remainingKey string
	// unlimited — у приложения на сервере нет такой квоты; признак действует
	// до unlimitedUntil (один срок аренды) и до смены пакета: лимит могут
	// вернуть, и шлюз снова спросит сервер.
	unlimited      bool
	unlimitedUntil time.Time
	unknown        bool
	// denyUntil — сервер ответил, что свободного остатка нет: запросы,
	// которые не помещаются в действующие аренды, отклоняются до этого срока.
	denyUntil time.Time
	// want — сколько единиц нужно (ждущий обработчик или упреждающий
	// запрос); waiting — ждущих обработчиков.
	want    int64
	waiting int
	// pending — отправленный, но не подтверждённый запрос: повторяется без
	// изменений (тот же request_id), чтобы сервер не учёл его дважды.
	pending *leasePending
	// offline — расход на автономной доле, ещё не сообщённый серверу
	// (суточная квота и бюджет).
	offline int64
	// lastExpiry — срок последней аренды (льготный срок отсчитывается от него).
	lastExpiry time.Time
	lastUsed   time.Time
	// Автономная доля: минутные квоты — скользящее окно, сутки и месяц —
	// израсходованное в окне autoKey от начала автономной работы autoEpoch.
	auto      *window
	autoKey   string
	autoEpoch int
	autoAllow int64
	autoUsed  int64
	// recent — расход минутной квоты по арендам за последнюю минуту: он
	// входит в автономную долю шлюза. autoDebt — автономный расход минутной
	// квоты, ещё не засчитанный в аренды: после восстановления связи он
	// списывается из первых выдач (сервер его не принимает).
	recent   *window
	autoDebt int64
}

// leaseRec — аренда: выдано, израсходовано по закрытым резервам и занято
// незакрытыми; срок — по монотонным часам шлюза.
type leaseRec struct {
	id                  string
	granted, used, held int64
	expires             time.Time
	reporting, reported bool
}

type leasePending struct {
	req     leaseQuotaRequest
	reports []*leaseRec
	sentAt  time.Time
}

// Тело запроса и ответа POST /internal/v1/quota-leases (api/internal-openapi.yaml).
type leaseRequest struct {
	Apps []leaseAppRequest `json:"apps"`
}

type leaseAppRequest struct {
	App    string              `json:"app"`
	Quotas []leaseQuotaRequest `json:"quotas"`
}

type leaseQuotaRequest struct {
	Quota     string        `json:"quota"`
	RequestID string        `json:"request_id"`
	Want      int64         `json:"want"`
	Reports   []leaseReport `json:"reports,omitempty"`
	Offline   int64         `json:"offline,omitempty"`
}

type leaseReport struct {
	Lease string `json:"lease"`
	Used  int64  `json:"used"`
}

type leaseResponse struct {
	Gateways int `json:"gateways"`
	Apps     []struct {
		App    string       `json:"app"`
		Quotas []leaseGrant `json:"quotas"`
	} `json:"apps"`
}

type leaseGrant struct {
	Quota        string `json:"quota"`
	RequestID    string `json:"request_id"`
	Lease        string `json:"lease"`
	Granted      int64  `json:"granted"`
	TTLMS        int64  `json:"ttl_ms"`
	Remaining    int64  `json:"remaining"`
	Limit        int64  `json:"limit"`
	RetryAfterMS int64  `json:"retry_after_ms"`
	Unlimited    bool   `json:"unlimited"`
	Unknown      bool   `json:"unknown"`
}

// NewLeaseClient — клиент аренды в режиме local (выключен до SetEnabled).
func NewLeaseClient(cfg LeaseConfig) (*LeaseClient, error) {
	if cfg.Client == nil || cfg.Server == nil || cfg.IDs == nil {
		return nil, errors.New("аренда квот: нет клиента, адреса сервера или генератора ID")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	c := &LeaseClient{cfg: cfg, url: cfg.Server.JoinPath(leasePath).String(), now: cfg.Now, kick: make(chan struct{}, 1),
		failOpen: map[string]bool{}, loc: time.UTC, states: map[leaseKey]*leaseState{}, round: make(chan struct{})}
	c.started = c.now()
	return c, nil
}

// SetEnabled включает аренду (пакет в режиме leased) или выключает её:
// аренды забываются, счётчики снова локальные.
func (c *LeaseClient) SetEnabled(on bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.enabled == on {
		return
	}
	c.enabled = on
	if !on {
		c.states = map[leaseKey]*leaseState{}
	}
	c.cfg.Logger.Info("режим квот изменён", "class", "quota", "leased", on)
}

// Enabled — включена ли аренда.
func (c *LeaseClient) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled
}

// setApps — режим отказа приложений пакета (Limiter.Reconfigure).
func (c *LeaseClient) setApps(failOpen map[string]bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.failOpen = failOpen
	c.resetUnlimited()
	c.mu.Unlock()
}

// resetUnlimited — новый пакет: признаки «у приложения нет квоты»
// проверяются у сервера заново. Под c.mu.
func (c *LeaseClient) resetUnlimited() {
	for _, st := range c.states {
		st.unlimited = false
	}
}

// setLocation — пояс установки (Budget.Reconfigure).
func (c *LeaseClient) setLocation(loc *time.Location) {
	if c == nil || loc == nil {
		return
	}
	c.mu.Lock()
	c.loc = loc
	c.resetUnlimited()
	c.mu.Unlock()
}

// Autonomous — шлюз недавно пропускал запросы на автономной доле: признак
// quota_autonomous в heartbeat.
func (c *LeaseClient) Autonomous() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enabled && !c.lastAutonomous.IsZero() && c.now().Sub(c.lastAutonomous) < leaseAutonomousFresh
}

func (c *LeaseClient) signal() {
	select {
	case c.kick <- struct{}{}:
	default:
	}
}

func longQuota(quota string) bool { return quota == QuotaTPD || quota == quotaBudget }

func leaseTTL(quota string) time.Duration {
	if longQuota(quota) {
		return leaseLongTTL
	}
	return leaseMinuteTTL
}

// state — состояние квоты; создаётся при первом обращении. Под c.mu.
func (c *LeaseClient) state(app, quota string, limit int64, now time.Time) *leaseState {
	k := leaseKey{app, quota}
	st, ok := c.states[k]
	if !ok {
		st = &leaseState{key: k, auto: newWindow(c.started, time.Second, 60), recent: newWindow(c.started, time.Second, 60)}
		c.states[k] = st
	}
	st.limit, st.lastUsed = limit, now
	return st
}

// leaseHold — резерв единиц квоты под запрос: в действующих арендах или на
// автономной доле.
type leaseHold struct {
	c     *LeaseClient
	st    *leaseState
	parts []leasePart
	n     int64
	// auto — резерв на автономной доле (событие получает quota_degraded).
	auto   bool
	bucket int64
	done   bool
}

type leasePart struct {
	rec *leaseRec
	n   int64
}

// reserve — n единиц из действующих аренд, начиная с ближайшей к сроку;
// nil — не хватает. Под c.mu.
func (st *leaseState) reserve(now time.Time, n int64) []leasePart {
	var free int64
	active := make([]*leaseRec, 0, len(st.leases))
	for _, r := range st.leases {
		if !r.reporting && now.Before(r.expires) && r.granted > r.used+r.held {
			active = append(active, r)
			free += r.granted - r.used - r.held
		}
	}
	if free < n || (n == 0 && len(active) == 0) {
		return nil
	}
	slices.SortFunc(active, func(a, b *leaseRec) int { return a.expires.Compare(b.expires) })
	parts := []leasePart{}
	for _, r := range active {
		if n == 0 {
			break
		}
		take := min(n, r.granted-r.used-r.held)
		r.held += take
		n -= take
		parts = append(parts, leasePart{r, take})
	}
	return parts
}

// low — свободно меньше 1/leasePrefetch выданного по действующим арендам.
func (st *leaseState) low(now time.Time) bool {
	var free, granted int64
	for _, r := range st.leases {
		if !r.reporting && now.Before(r.expires) {
			free += r.granted - r.used - r.held
			granted += r.granted
		}
	}
	return free*leasePrefetch < granted
}

// take резервирует n единиц квоты quota приложения app с лимитом limit.
// nil, nil — аренда выключена или у приложения на сервере нет лимита:
// действует локальный счётчик. *Exceeded — свободного остатка нет;
// ErrQuotaUnavailable — сервер недоступен, а льготный срок fail_closed истёк.
func (c *LeaseClient) take(ctx context.Context, app, quota string, n, limit int64) (*leaseHold, error) {
	if c == nil {
		return nil, nil
	}
	// n = 0 (пустой вход без предела ответа) — нулевой резерв: Settle
	// всё равно спишет фактический расход из аренды.
	n = max(n, 0)
	deadline := c.now().Add(leaseWait)
	// timedOut — ожидание истекло по таймеру (часы c.now могут стоять).
	timedOut := false
	for {
		c.mu.Lock()
		if !c.enabled {
			c.mu.Unlock()
			return nil, nil
		}
		now := c.now()
		st := c.state(app, quota, limit, now)
		if st.unlimited && now.Before(st.unlimitedUntil) {
			c.mu.Unlock()
			return nil, nil
		}
		st.unlimited = false
		if parts := st.reserve(now, n); parts != nil {
			if st.low(now) && st.pending == nil {
				st.want = max(st.want, n, 1)
				c.signal()
			}
			h := &leaseHold{c: c, st: st, parts: parts, n: n}
			if !longQuota(st.key.quota) {
				st.recent.add(now, n)
				h.bucket = st.recent.bucket(now)
			}
			c.mu.Unlock()
			return h, nil
		}
		switch {
		case now.Before(st.denyUntil):
			wait := st.denyUntil.Sub(now)
			c.mu.Unlock()
			return nil, &Exceeded{Rule: ruleOfLease(quota), Threat: threatOfLease(quota), RetryAfter: wait}
		case c.failing || timedOut || !now.Before(deadline):
			// Запрос остаётся в очереди: фоновый цикл повторит его, когда
			// подойдёт срок следующей попытки.
			st.want = max(st.want, n)
			h, err := c.autonomous(st, n, now)
			c.mu.Unlock()
			c.signal()
			return h, err
		}
		st.want = max(st.want, n, 1)
		st.waiting++
		ch := c.round
		c.mu.Unlock()
		c.signal()
		t := time.NewTimer(max(deadline.Sub(now), time.Millisecond))
		select {
		case <-ch:
		case <-ctx.Done():
		case <-t.C:
			timedOut = true
		}
		t.Stop()
		c.mu.Lock()
		st.waiting--
		c.mu.Unlock()
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
}

func ruleOfLease(quota string) string {
	if quota == quotaBudget {
		return ruleBudget
	}
	return quota
}

func threatOfLease(quota string) string {
	if quota == quotaBudget {
		return "DM-15"
	}
	return "DM-36"
}

// autonomous — резерв на автономной доле (ADR-0021, п. 5). Под c.mu.
func (c *LeaseClient) autonomous(st *leaseState, n int64, now time.Time) (*leaseHold, error) {
	ttl := leaseTTL(st.key.quota)
	grace := c.started.Add(ttl)
	if !st.lastExpiry.IsZero() {
		grace = st.lastExpiry.Add(ttl)
	}
	if !c.failOpen[st.key.app] && !now.Before(grace) {
		// Отказ 503 тоже виден в heartbeat как работа без аренды.
		c.lastAutonomous = now
		return nil, ErrQuotaUnavailable
	}
	gws := int64(max(c.gateways, 1))
	h := &leaseHold{c: c, st: st, n: n, auto: true}
	if !longQuota(st.key.quota) {
		// Доля шлюза включает его расход по арендам за ту же минуту.
		allow := (st.limit + gws - 1) / gws
		used, retry := st.auto.sum(now)
		leased, _ := st.recent.sum(now)
		if used+leased+n > allow {
			return nil, &Exceeded{Rule: st.key.quota, Threat: "DM-36", RetryAfter: max(retry, time.Second)}
		}
		st.auto.add(now, n)
		st.autoDebt = min(st.autoDebt+n, leaseMaxUnits)
		h.bucket = st.auto.bucket(now)
	} else {
		key, end := leaseWindow(st.key.quota, now, c.loc)
		if st.autoKey != key || st.autoEpoch != c.epoch {
			base := st.limit
			if st.remainingKey == key {
				base = st.remaining
			}
			st.autoKey, st.autoEpoch, st.autoAllow, st.autoUsed = key, c.epoch, base/gws, 0
		}
		if st.autoUsed+n > st.autoAllow {
			return nil, &Exceeded{Rule: ruleOfLease(st.key.quota), Threat: threatOfLease(st.key.quota),
				RetryAfter: max(end.Sub(now), time.Second)}
		}
		st.autoUsed += n
	}
	c.lastAutonomous = now
	return h, nil
}

// leaseWindow — ключ окна суток или месяца в поясе loc и его граница.
func leaseWindow(quota string, now time.Time, loc *time.Location) (string, time.Time) {
	t := now.In(loc)
	if quota == QuotaTPD {
		start := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, loc)
		return t.Format("2006-01-02"), start.AddDate(0, 0, 1)
	}
	return bundle.Month(now, loc), bundle.NextMonth(now, loc)
}

// Settle заменяет резерв фактическим расходом (0 — запрос не дошёл до
// модели). Расход сверх резерва берётся из действующих аренд квоты; сверх
// них — не учитывается: превышение ограничено разницей оценки и факта
// (ADR-0021, п. 4). Повторный вызов ничего не меняет.
func (h *leaseHold) Settle(actual int64) {
	if h == nil {
		return
	}
	c := h.c
	c.mu.Lock()
	defer c.mu.Unlock()
	if h.done {
		return
	}
	h.done = true
	actual = max(actual, 0)
	st := h.st
	if h.auto {
		if !longQuota(st.key.quota) {
			st.auto.addAt(c.now(), h.bucket, actual-h.n)
			st.autoDebt = min(max(st.autoDebt+actual-h.n, 0), leaseMaxUnits)
			return
		}
		st.autoUsed = max(st.autoUsed+actual-h.n, 0)
		st.offline = min(st.offline+actual, leaseMaxUnits)
		return
	}
	if !longQuota(st.key.quota) {
		st.recent.addAt(c.now(), h.bucket, actual-h.n)
	}
	rest := actual
	for _, p := range h.parts {
		p.rec.held -= p.n
	}
	charge := func(r *leaseRec) {
		if r.reported || rest == 0 {
			return
		}
		take := min(rest, max(r.granted-r.used-r.held, 0))
		r.used += take
		rest -= take
	}
	for _, p := range h.parts {
		charge(p.rec)
	}
	now := c.now()
	for _, r := range st.leases {
		if !r.reporting && now.Before(r.expires) {
			charge(r)
		}
	}
}

// Degraded — резерв на автономной доле.
func (h *leaseHold) Degraded() bool { return h != nil && h.auto }

// Run отправляет запросы аренды и отчёты до отмены ctx: по сигналу
// обработчика или раз в секунду, не чаще пяти раз в секунду.
func (c *LeaseClient) Run(ctx context.Context) {
	t := time.NewTicker(leaseTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.kick:
		case <-t.C:
		}
		c.mu.Lock()
		now := c.now()
		wait := max(c.lastSend.Add(leaseMinInterval).Sub(now), c.nextTry.Sub(now))
		c.mu.Unlock()
		if wait > 0 && !sleepCtx(ctx, wait) {
			return
		}
		c.roundOnce(ctx)
	}
}

// pendingRef — квота в отправленном запросе.
type pendingRef struct {
	st *leaseState
	p  *leasePending
}

// roundOnce — один запрос аренды со всем, что накопилось.
func (c *LeaseClient) roundOnce(ctx context.Context) {
	c.mu.Lock()
	done := c.round
	c.round = make(chan struct{})
	defer close(done)
	if !c.enabled {
		c.mu.Unlock()
		return
	}
	now := c.now()
	req, refs := c.build(now)
	if len(refs) == 0 {
		c.mu.Unlock()
		return
	}
	c.lastSend = now
	c.mu.Unlock()
	rctx, cancel := context.WithTimeout(ctx, leaseTimeout)
	var resp leaseResponse
	err := postControlLimit(rctx, c.cfg.Client, c.url, req, &resp, http.StatusOK, leaseMaxResponse)
	cancel()
	if ctx.Err() != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return
	}
	if err != nil {
		c.fail(err, refs)
		return
	}
	c.apply(refs, &resp)
}

// build собирает запрос: сначала квоты, которых ждут обработчики. Под c.mu.
func (c *LeaseClient) build(now time.Time) (leaseRequest, []pendingRef) {
	states := make([]*leaseState, 0, len(c.states))
	for k, st := range c.states {
		if st.pending == nil && st.want == 0 && st.offline == 0 && !st.hasReports(now) {
			// Забыть квоту без аренд и запросов.
			if len(st.leases) == 0 && st.waiting == 0 && now.Sub(st.lastUsed) > leaseIdle {
				delete(c.states, k)
			}
			continue
		}
		states = append(states, st)
	}
	slices.SortFunc(states, func(a, b *leaseState) int {
		if a.waiting != b.waiting {
			return b.waiting - a.waiting
		}
		if a.key.app != b.key.app {
			return cmp.Compare(a.key.app, b.key.app)
		}
		return cmp.Compare(a.key.quota, b.key.quota)
	})
	var refs []pendingRef
	byApp := map[string]int{}
	var req leaseRequest
	// size — оценка тела запроса: квоты с отчётами добавляются, пока тело
	// укладывается в leaseMaxBody.
	size := len(`{"apps":[]}`)
	for _, st := range states {
		if len(refs) == leaseMaxQuotas {
			break
		}
		p := st.pending
		var reports []*leaseRec
		if p == nil {
			id, err := c.cfg.IDs.New()
			if err != nil {
				c.cfg.Logger.Error("аренда квот: ID запроса не создан", "class", "quota", "error", err)
				break
			}
			p = &leasePending{req: leaseQuotaRequest{Quota: st.key.quota, RequestID: id.String(), Want: st.want}}
			for _, r := range st.leases {
				if len(reports) == leaseMaxReports {
					break
				}
				if r.ready(now) {
					reports = append(reports, r)
					p.req.Reports = append(p.req.Reports, leaseReport{Lease: r.id, Used: min(r.used+r.held, r.granted)})
				}
			}
			if longQuota(st.key.quota) {
				p.req.Offline = st.offline
			}
		}
		raw, err := json.Marshal(p.req)
		if err != nil {
			break
		}
		add := len(raw) + 1
		if _, ok := byApp[st.key.app]; !ok {
			add += len(`{"app":"","quotas":[]},`) + len(st.key.app)
		}
		if size+add > leaseMaxBody {
			break
		}
		size += add
		if st.pending == nil {
			for _, r := range reports {
				r.reporting = true
			}
			p.reports = reports
			if longQuota(st.key.quota) {
				st.offline = 0
			}
			st.pending = p
		}
		p.sentAt = now
		i, ok := byApp[st.key.app]
		if !ok {
			i = len(req.Apps)
			byApp[st.key.app] = i
			req.Apps = append(req.Apps, leaseAppRequest{App: st.key.app})
		}
		req.Apps[i].Quotas = append(req.Apps[i].Quotas, p.req)
		refs = append(refs, pendingRef{st, p})
	}
	return req, refs
}

// ready — истёкшая аренда, по которой пора отчитаться: резервов нет или
// прошло leaseReportAfter.
func (r *leaseRec) ready(now time.Time) bool {
	return !r.reporting && !now.Before(r.expires) && (r.held == 0 || now.Sub(r.expires) >= leaseReportAfter)
}

func (st *leaseState) hasReports(now time.Time) bool {
	return slices.ContainsFunc(st.leases, func(r *leaseRec) bool { return r.ready(now) })
}

// fail — запрос не удался. Сервер недоступен, в режиме local (409) или
// отвечает ошибкой — автономная доля с паузой до следующей попытки;
// запросы остаются и повторяются без изменений. Отказ в разборе (400) —
// ошибка протокола: отчёты отбрасываются (сервер учитывает такие аренды
// целиком), чтобы шлюз не повторял их бесконечно. Под c.mu.
func (c *LeaseClient) fail(err error, refs []pendingRef) {
	var ce *controlError
	now := c.now()
	if errors.As(err, &ce) && ce.Status == http.StatusTooManyRequests {
		c.nextTry = now.Add(max(ce.RetryAfter, time.Second))
		return
	}
	if errors.As(err, &ce) && ce.Status == http.StatusBadRequest {
		c.cfg.Logger.Error("сервер отклонил запрос аренды квот; отчёты об арендах отброшены", "class", "quota", "status", ce.Status)
		for _, ref := range refs {
			ref.st.drop(ref.p)
			ref.st.pending = nil
		}
	}
	if !c.failing {
		c.failing = true
		c.epoch++
		c.cfg.Logger.Warn("аренда квот у сервера управления недоступна: приложения с fail_open — на автономной доле, "+
			"с fail_closed — после льготного срока отказ 503", "class", "quota", "error", err)
	}
	c.failures++
	c.nextTry = now.Add(min(time.Second<<min(c.failures-1, 4), leaseBackoffMax))
}

// drop убирает аренды, отчёт о которых ушёл в запросе p.
func (st *leaseState) drop(p *leasePending) {
	for _, r := range p.reports {
		r.reported = true
	}
	st.leases = slices.DeleteFunc(st.leases, func(r *leaseRec) bool { return r.reported })
}

// apply разбирает ответ сервера. Срок аренды — от отправки запроса по
// монотонным часам шлюза. Под c.mu.
func (c *LeaseClient) apply(refs []pendingRef, resp *leaseResponse) {
	now := c.now()
	if c.failing {
		c.cfg.Logger.Info("аренда квот у сервера управления восстановлена", "class", "quota")
	}
	c.failing, c.failures, c.nextTry = false, 0, time.Time{}
	c.gateways = min(max(resp.Gateways, 1), bundle.MaxApplications)
	grants := map[string]leaseGrant{}
	for _, a := range resp.Apps {
		for _, g := range a.Quotas {
			grants[g.RequestID] = g
		}
	}
	for _, ref := range refs {
		st, p := ref.st, ref.p
		st.drop(p)
		if st.pending == p {
			st.pending = nil
		}
		// Пока запрос был в пути, ждущий обработчик мог попросить больше:
		// такой спрос уходит следующим запросом.
		if st.want <= p.req.Want {
			st.want = 0
		}
		g, ok := grants[p.req.RequestID]
		if !ok || p.req.Want == 0 || g.Quota != st.key.quota {
			continue
		}
		st.unlimited, st.unknown = g.Unlimited, g.Unknown
		if g.Unlimited {
			st.unlimitedUntil = now.Add(leaseTTL(st.key.quota))
		}
		if g.Unknown {
			st.denyUntil = now.Add(leaseUnknownRetry)
			continue
		}
		st.remaining = min(max(g.Remaining, 0), leaseMaxUnits)
		st.remainingKey, _ = leaseWindow(st.key.quota, p.sentAt, c.loc)
		granted := min(max(g.Granted, 0), leaseMaxUnits)
		ttl := min(time.Duration(max(g.TTLMS, 0))*time.Millisecond, leaseTTL(st.key.quota))
		if granted > 0 && g.Lease != "" && len(g.Lease) <= 64 && ttl > 0 {
			r := &leaseRec{id: g.Lease, granted: granted, expires: p.sentAt.Add(ttl)}
			if !longQuota(st.key.quota) && st.autoDebt > 0 {
				// Автономный расход последней минуты занимает первую выдачу
				// после восстановления: вместе с арендами соседей он не
				// превышает лимит минуты.
				auto, _ := st.auto.sum(now)
				debt := min(st.autoDebt, auto)
				r.used = min(debt, granted)
				st.autoDebt = debt - r.used
			}
			st.leases = append(st.leases, r)
			if r.expires.After(st.lastExpiry) {
				st.lastExpiry = r.expires
			}
		}
		st.denyUntil = time.Time{}
		if granted < p.req.Want {
			retry := min(time.Duration(max(g.RetryAfterMS, 0))*time.Millisecond, 31*24*time.Hour)
			st.denyUntil = now.Add(max(retry, time.Second))
		}
	}
}
