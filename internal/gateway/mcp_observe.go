package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"
)

// Сообщение серверу управления об увиденных инструментах (tools:observe,
// ADR-0023, раздел 1; задача 4.11). Шлюз отправляет новые и изменённые
// описания из tools/list в фоне: ответ клиенту не ждёт сервера, а решение
// по вызову принимается по реестру из пакета. Сервер принимает сообщение по
// серверу не чаще ObserveInterval (иначе 429), поэтому описания копятся и
// уходят одним сообщением.

// Пределы tools:observe.
const (
	// ObserveInterval — не чаще раза в этот срок на MCP-сервер.
	ObserveInterval = 10 * time.Second
	// MaxObserveBatch — описаний в одном сообщении.
	MaxObserveBatch = 256
	// maxObserveSent — запомненных отправленных хешей на сервер: дальше
	// память очищается, и повтор уйдёт ещё раз (сервер его примет как
	// unchanged).
	maxObserveSent = 4096
	// maxObserveBody — описаний в байтах на сообщение: сервер принимает
	// тело до 8 МиБ, остальное уходит следующим сообщением.
	maxObserveBody = 7 << 20
)

// ObservedTool — увиденное описание: имя инструмента, описание как прислал
// сервер, хеш шлюза и признак находок встроенной проверки описаний (DM-24).
type ObservedTool struct {
	Name       string
	Descriptor []byte
	Hash       string
	Suspicious bool
}

// mergeObserved кладёт описание t в очередь p: описание того же имени
// заменяется (Suspicious — у любого из двух, подозрительное описание
// приоритетнее), иначе добавляется, если в очереди меньше limit. Сервер
// отвергает сообщение с повтором имени целиком, и сервер MCP, меняющий
// описание при каждом tools/list, ослеплял бы реестр (ревью 4.r1, 4В5).
// Второе значение — очередь изменилась.
func mergeObserved(p []ObservedTool, t ObservedTool, limit int) ([]ObservedTool, bool) {
	if slices.ContainsFunc(p, func(x ObservedTool) bool { return x.Hash == t.Hash }) {
		return p, false
	}
	if i := slices.IndexFunc(p, func(x ObservedTool) bool { return t.Name != "" && x.Name == t.Name }); i >= 0 {
		old := p[i]
		if !old.Suspicious || t.Suspicious {
			p[i] = t
		}
		p[i].Suspicious = old.Suspicious || t.Suspicious
		return p, true
	}
	if len(p) >= limit {
		return p, false
	}
	return append(p, t), true
}

// ToolObserver копит и отправляет описания. nil — шлюз без сервера
// управления: описания никуда не уходят.
type ToolObserver struct {
	client *http.Client
	url    string
	logger *slog.Logger
	now    func() time.Time

	mu      sync.Mutex
	pending map[string][]ObservedTool
	sent    map[string]map[string]bool
	next    map[string]time.Time // раньше этого срока по серверу не отправлять
	wake    chan struct{}
}

// NewToolObserver — отправитель на сервер server по клиенту mTLS.
func NewToolObserver(client *http.Client, server *url.URL, logger *slog.Logger) *ToolObserver {
	if logger == nil {
		logger = slog.Default()
	}
	return &ToolObserver{client: client, url: server.JoinPath("/internal/v1/agents/tools:observe").String(), logger: logger,
		now: time.Now, pending: map[string][]ObservedTool{}, sent: map[string]map[string]bool{},
		next: map[string]time.Time{}, wake: make(chan struct{}, 1)}
}

// Observe ставит описания сервера в очередь; не блокирует. Уже отправленные
// и уже ждущие хеши пропускаются, сверх MaxObserveBatch ждущих — тоже
// (уйдут после следующего tools/list); ждущее описание того же имени
// заменяется (mergeObserved).
func (o *ToolObserver) Observe(server string, tools []ObservedTool) {
	if o == nil || len(tools) == 0 {
		return
	}
	o.mu.Lock()
	added := false
	for _, t := range tools {
		if o.sent[server][t.Hash] {
			continue
		}
		var ok bool
		if o.pending[server], ok = mergeObserved(o.pending[server], t, MaxObserveBatch); ok {
			added = true
		}
	}
	o.mu.Unlock()
	if added {
		select {
		case o.wake <- struct{}{}:
		default:
		}
	}
}

// Run отправляет накопленное до отмены ctx.
func (o *ToolObserver) Run(ctx context.Context) {
	if o == nil {
		return
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.wake:
		case <-t.C:
		}
		o.flush(ctx)
	}
}

// flush отправляет по одному сообщению на каждый сервер, срок которого
// наступил.
func (o *ToolObserver) flush(ctx context.Context) {
	now := o.now()
	o.mu.Lock()
	batches := map[string][]ObservedTool{}
	for s, p := range o.pending {
		if len(p) > 0 && !now.Before(o.next[s]) {
			batches[s] = p
			delete(o.pending, s)
			o.next[s] = now.Add(ObserveInterval)
		}
	}
	o.mu.Unlock()
	for _, s := range slices.Sorted(maps.Keys(batches)) {
		o.send(ctx, s, batches[s])
	}
}

// observeBody — тело tools:observe (api/internal-openapi.yaml, ObserveTools).
type observeBody struct {
	Server string        `json:"server"`
	Tools  []observeItem `json:"tools"`
}

type observeItem struct {
	Descriptor json.RawMessage `json:"descriptor"`
	Suspicious bool            `json:"suspicious,omitempty"`
}

// send — одно сообщение. Отказ 429 и сетевые ошибки возвращают описания в
// очередь (повтор после срока), прочие отказы — описания отбрасываются с
// записью в технический журнал (без описаний).
func (o *ToolObserver) send(ctx context.Context, server string, tools []ObservedTool) {
	// Повторы имени (возврат после 429, остаток прошлого сообщения)
	// сливаются: сервер отверг бы сообщение целиком (4В5).
	var uniq []ObservedTool
	for _, t := range tools {
		uniq, _ = mergeObserved(uniq, t, len(tools))
	}
	tools = uniq
	size := 0
	for i, t := range tools {
		if size += len(t.Descriptor); size > maxObserveBody && i > 0 {
			// Остаток — следующим сообщением после ObserveInterval.
			o.mu.Lock()
			o.pending[server] = append(slices.Clone(tools[i:]), o.pending[server]...)
			o.mu.Unlock()
			tools = tools[:i]
			break
		}
	}
	body := observeBody{Server: server, Tools: make([]observeItem, len(tools))}
	for i, t := range tools {
		body.Tools[i] = observeItem{Descriptor: t.Descriptor, Suspicious: t.Suspicious}
	}
	err := postControlLimit(ctx, o.client, o.url, body, nil, http.StatusOK, maxControlResponse)
	var ce *controlError
	switch {
	case err == nil:
		o.mu.Lock()
		if o.sent[server] == nil || len(o.sent[server]) >= maxObserveSent {
			o.sent[server] = map[string]bool{}
		}
		for _, t := range tools {
			o.sent[server][t.Hash] = true
		}
		o.mu.Unlock()
		return
	case errors.As(err, &ce) && ce.Status != http.StatusTooManyRequests:
		o.logger.Warn("сервер управления не принял описания инструментов", "mcp_server", server, "tools", len(tools),
			"status", ce.Status)
		return
	}
	o.mu.Lock()
	if errors.As(err, &ce) && ce.RetryAfter > 0 {
		o.next[server] = o.now().Add(ce.RetryAfter)
	}
	for _, t := range tools {
		if len(o.pending[server]) < MaxObserveBatch {
			o.pending[server] = append(o.pending[server], t)
		}
	}
	o.mu.Unlock()
	if ctx.Err() == nil {
		o.logger.Warn("описания инструментов не отправлены, повтор позже", "mcp_server", server, "error", err)
	}
}
