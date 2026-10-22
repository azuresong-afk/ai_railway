package gateway

import (
	"errors"
	"hash/maphash"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
)

// Квоты приложения (ТЗ, 5.2, `quota`; DM-15, DM-36). Счётчики живут в
// памяти экземпляра шлюза (ТЗ, 4.2, решение 16): после перезапуска они
// обнуляются, при нескольких экземплярах квоты соблюдаются приблизительно.
// Синхронизация с сервером управления — этап 2 (heartbeat).
//
// Окна скользящие: минута — 60 корзин по секунде, сутки — 24 корзины по
// часу; значение окна — сумма живых корзин, поэтому границы минуты не дают
// двойной пропуск. Предельные размеры запроса (max_messages, max_tokens)
// проверяет разбор запроса (internal/chat), здесь — частота, токены и
// суммарный размер входного текста.

// Правила квот — имена полей quotas в конфигурации (TPM, TPD — токены в
// минуту и в сутки).
const (
	QuotaRequestsPerMinute        = "requests_per_minute"
	QuotaRequestsPerMinutePerUser = "requests_per_minute_per_user"
	QuotaRequestsPerMinutePerKey  = "requests_per_minute_per_key"
	QuotaTPM                      = "tokens_per_minute"
	QuotaTPD                      = "tokens_per_day"
	QuotaMaxInputBytes            = "max_input_bytes"
)

// MaxTrackedPerApp — предел различных пользователей (и ключей) одного
// приложения в памяти. Идентификатор пользователя приходит от приложения
// (заголовок или поле запроса), поэтому его разнообразие не должно
// исчерпать память: сверх предела пользователи делятся на OverflowBuckets
// корзин по хешу идентификатора.
const MaxTrackedPerApp = 10000

// OverflowBuckets — корзин для пользователей сверх MaxTrackedPerApp. Одна
// общая корзина отказывала бы всем новым пользователям крупного приложения
// сразу (ревью 1.17–1.21, п. 8); с хешем пользователь делит лимит в среднем
// с немногими. Хеш — maphash со случайным зерном экземпляра: подобрать
// идентификатор в корзину жертвы заранее нельзя (идентификатор — к тому же
// псевдоним HMAC).
const OverflowBuckets = 4096

// ErrUnknownApp — приложения нет в конфигурации квот.
var ErrUnknownApp = errors.New("квоты: неизвестное приложение")

// Exceeded — превышена квота: запрос отклоняется с кодом quota_exceeded.
type Exceeded struct {
	// Rule — какая квота (константы Quota…).
	Rule string
	// Threat — строка матрицы обнаружения: DM-15 (размер), DM-36 (частота,
	// токены).
	Threat string
	// RetryAfter — через сколько повторить; 0 — запрос не пройдёт никогда
	// (сам по себе больше предела).
	RetryAfter time.Duration
}

func (e *Exceeded) Error() string { return "превышена квота " + e.Rule }

// QuotaRequest — запрос, проходящий проверку квот.
type QuotaRequest struct {
	App string
	// Key — префикс ключа приложения; User — псевдоним пользователя (HMAC);
	// пустые значения не учитываются.
	Key, User string
	// InputBytes — размер текста сообщений; Tokens — оценка расхода токенов
	// (вход и max_tokens): после ответа уточняется Reservation.Settle.
	InputBytes, Tokens int
}

// Limiter — счётчики квот всех приложений. Безопасен для одновременного
// вызова.
type Limiter struct {
	now  func() time.Time
	mu   sync.Mutex
	apps map[string]*appQuota
}

// Номера корзин считаются от запуска по монотонным часам (now.Sub(start)):
// перевод системных часов назад не обнуляет окна и не продлевает их
// (ревью 1.17–1.21, п. 13).

type appQuota struct {
	q          config.Quotas
	rpm        *window
	tpm, tpd   *window
	users, key *tracked
}

// NewLimiter создаёт счётчики по приложениям конфигурации.
func NewLimiter(apps []config.Application) *Limiter { return newLimiter(apps, time.Now) }

func newLimiter(apps []config.Application, now func() time.Time) *Limiter {
	l := &Limiter{now: now, apps: map[string]*appQuota{}}
	l.Reconfigure(apps)
	return l
}

// Reconfigure применяет новый набор приложений (пакет конфигурации с
// сервера, задача 2.13): у оставшихся приложений счётчики сохраняются и
// действуют новые пределы, новые начинают с нуля, удалённые забываются.
// Иначе каждая смена конфигурации обнуляла бы квоты (DM-36).
func (l *Limiter) Reconfigure(apps []config.Application) {
	l.mu.Lock()
	defer l.mu.Unlock()
	start := l.now()
	next := make(map[string]*appQuota, len(apps))
	for _, a := range apps {
		if cur, ok := l.apps[a.ID]; ok {
			cur.q = a.Quotas
			next[a.ID] = cur
			continue
		}
		next[a.ID] = &appQuota{
			q:   a.Quotas,
			rpm: newWindow(start, time.Second, 60), tpm: newWindow(start, time.Second, 60), tpd: newWindow(start, time.Hour, 24),
			users: newTracked(start), key: newTracked(start),
		}
	}
	l.apps = next
}

// Reservation — зарезервированные токены допущенного запроса.
type Reservation struct {
	l        *Limiter
	a        *appQuota
	reserved int64
	// минутная и суточная корзины, в которые записан резерв: возврат
	// излишка идёт из них, а не из текущих.
	tpmB, tpdB int64
	settled    bool
}

// Admit проверяет все квоты и, если ни одна не превышена, учитывает запрос
// и резерв токенов. Проверка и учёт — одна операция под замком: параллельные
// запросы не проскочат лимит вместе.
func (l *Limiter) Admit(r QuotaRequest) (*Reservation, error) {
	tokens := max(int64(r.Tokens), 0)
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.apps[r.App]
	if !ok {
		return nil, ErrUnknownApp
	}
	now := l.now()
	q := a.q
	if q.MaxInputBytes > 0 && int64(max(r.InputBytes, 0)) > int64(q.MaxInputBytes) {
		return nil, &Exceeded{Rule: QuotaMaxInputBytes, Threat: "DM-15"}
	}
	var uw, kw *window
	if r.User != "" && q.RequestsPerMinutePerUser > 0 {
		uw = a.users.get(now, r.User, 60)
	}
	if r.Key != "" && q.RequestsPerMinutePerKey > 0 {
		kw = a.key.get(now, r.Key, 60)
	}
	for _, c := range []struct {
		rule  string
		w     *window
		limit int
		cost  int64
	}{
		{QuotaRequestsPerMinute, a.rpm, q.RequestsPerMinute, 1},
		{QuotaRequestsPerMinutePerUser, uw, q.RequestsPerMinutePerUser, 1},
		{QuotaRequestsPerMinutePerKey, kw, q.RequestsPerMinutePerKey, 1},
		{QuotaTPM, a.tpm, q.TokensPerMinute, tokens},
		{QuotaTPD, a.tpd, q.TokensPerDay, tokens},
	} {
		if c.limit <= 0 || c.w == nil {
			continue
		}
		used, retry := c.w.sum(now)
		switch {
		case c.cost > int64(c.limit):
			return nil, &Exceeded{Rule: c.rule, Threat: "DM-36"} // не пройдёт никогда
		case used+c.cost > int64(c.limit):
			return nil, &Exceeded{Rule: c.rule, Threat: "DM-36", RetryAfter: retry}
		}
	}
	a.rpm.add(now, 1)
	if uw != nil {
		uw.add(now, 1)
	}
	if kw != nil {
		kw.add(now, 1)
	}
	a.tpm.add(now, tokens)
	a.tpd.add(now, tokens)
	return &Reservation{l: l, a: a, reserved: tokens, tpmB: a.tpm.bucket(now), tpdB: a.tpd.bucket(now)}, nil
}

// SettleAtLeast — Settle с оценкой расхода вместо фактического: резерв
// только увеличивается, но не возвращается — оценка может быть занижена.
func (rs *Reservation) SettleAtLeast(estimate int) {
	if rs == nil {
		return
	}
	rs.Settle(max(estimate, int(rs.reserved)))
}

// Settle заменяет резерв фактическим расходом токенов (после ответа
// провайдера; 0 — запрос не дошёл до модели). Повторный вызов ничего не
// меняет.
func (rs *Reservation) Settle(actual int) {
	if rs == nil {
		return
	}
	rs.l.mu.Lock()
	defer rs.l.mu.Unlock()
	if rs.settled {
		return
	}
	rs.settled = true
	delta := max(int64(actual), 0) - rs.reserved
	if delta == 0 {
		return
	}
	now := rs.l.now()
	rs.a.tpm.addAt(now, rs.tpmB, delta)
	rs.a.tpd.addAt(now, rs.tpdB, delta)
}

// window — скользящее окно из n корзин по step, отсчёт от start.
type window struct {
	start time.Time
	step  time.Duration
	idx   []int64 // номер корзины, записанной в слот
	cnt   []int64
}

func newWindow(start time.Time, step time.Duration, n int) *window {
	return &window{start: start, step: step, idx: make([]int64, n), cnt: make([]int64, n)}
}

// elapsed — время от start по монотонным часам; не меньше нуля.
func (w *window) elapsed(now time.Time) time.Duration { return max(now.Sub(w.start), 0) }

// bucket — номер корзины от 1 (0 в idx — пустой слот).
func (w *window) bucket(now time.Time) int64 { return int64(w.elapsed(now)/w.step) + 1 }

// add прибавляет v к текущей корзине; отрицательная поправка не опускает
// корзину ниже нуля.
func (w *window) add(now time.Time, v int64) {
	b := w.bucket(now)
	s := int(b % int64(len(w.idx)))
	if w.idx[s] != b {
		w.idx[s], w.cnt[s] = b, 0
	}
	w.cnt[s] = max(w.cnt[s]+v, 0)
}

// addAt: доплата идёт в текущую корзину, возврат — в корзину b, если она ещё
// в окне.
func (w *window) addAt(now time.Time, b, v int64) {
	if v >= 0 {
		w.add(now, v)
		return
	}
	if s := int(b % int64(len(w.idx))); w.idx[s] == b {
		w.cnt[s] = max(w.cnt[s]+v, 0)
	}
}

// sum — сумма живых корзин и время до освобождения самой старой непустой.
func (w *window) sum(now time.Time) (total int64, retry time.Duration) {
	b := w.bucket(now)
	n := int64(len(w.idx))
	oldest := b
	for s := range w.idx {
		if w.idx[s] > b-n && w.idx[s] <= b && w.cnt[s] > 0 {
			total += w.cnt[s]
			oldest = min(oldest, w.idx[s])
		}
	}
	if total == 0 {
		return 0, 0
	}
	// корзина oldest выходит из окна, когда номер текущей станет oldest+n
	retry = time.Duration((oldest+n-1)*int64(w.step)) - w.elapsed(now)
	return total, max(retry, time.Millisecond)
}

// tracked — окна по ключу (пользователь, ключ приложения) с пределом числа
// записей; сверх предела — окна корзин по хешу ключа.
type tracked struct {
	start time.Time
	m     map[string]*window
	over  map[uint64]*window
	seed  maphash.Seed
	swept time.Time
}

func newTracked(start time.Time) *tracked {
	return &tracked{start: start, m: map[string]*window{}, over: map[uint64]*window{}, seed: maphash.MakeSeed()}
}

func (t *tracked) get(now time.Time, key string, n int) *window {
	if w, ok := t.m[key]; ok {
		return w
	}
	if len(t.m) >= MaxTrackedPerApp {
		t.sweep(now)
	}
	if len(t.m) >= MaxTrackedPerApp {
		b := maphash.String(t.seed, key) % OverflowBuckets
		w, ok := t.over[b]
		if !ok {
			w = newWindow(t.start, time.Second, n)
			t.over[b] = w
		}
		return w
	}
	w := newWindow(t.start, time.Second, n)
	t.m[key] = w
	return w
}

// sweep удаляет записи без живых запросов; не чаще раза в секунду.
func (t *tracked) sweep(now time.Time) {
	if !t.swept.IsZero() && now.Sub(t.swept) < time.Second && now.Sub(t.swept) >= 0 {
		return
	}
	t.swept = now
	for k, w := range t.m {
		if total, _ := w.sum(now); total == 0 {
			delete(t.m, k)
		}
	}
	for k, w := range t.over {
		if total, _ := w.sum(now); total == 0 {
			delete(t.over, k)
		}
	}
}
