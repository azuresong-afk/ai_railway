package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"sync"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Параметры Idempotency-Key.
const (
	IdempotencyHeader = "Idempotency-Key"
	maxIdempotencyKey = 64
	// maxStoredResponse — больше этого ответ не запоминается.
	maxStoredResponse = 1 << 20
)

// ParseIdempotencyKey проверяет значение заголовка: 1–64 символа
// [A-Za-z0-9._-]. Пустое значение (заголовка нет) возвращает ok=false без ошибки.
func ParseIdempotencyKey(values []string) (key string, present bool, p *Problem) {
	if len(values) == 0 {
		return "", false, nil
	}
	bad := Invalid("Заголовок Idempotency-Key должен быть один и содержать 1–64 символа: латинские буквы, цифры, «.», «_», «-».")
	if len(values) != 1 || !validIdempotencyKey(values[0]) {
		return "", true, bad
	}
	return values[0], true, nil
}

func validIdempotencyKey(s string) bool {
	if s == "" || len(s) > maxIdempotencyKey {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// StoredResponse — запомненный ответ на создающий запрос.
type StoredResponse struct {
	Status      int
	ContentType string
	Location    string
	Body        []byte
}

// IdemState — результат Begin.
type IdemState int

// Состояния ключа.
const (
	IdemNew      IdemState = iota // ключ занят этим запросом, выполнять
	IdemReplay                    // запрос уже выполнен, вернуть сохранённый ответ
	IdemMismatch                  // ключ уже использован с другим запросом
	IdemBusy                      // тот же запрос ещё выполняется
	IdemFull                      // хранилище переполнено
)

// IdempotencyStore хранит ключи. Реализация в памяти — для каркаса и
// одного экземпляра сервера; хранение в PostgreSQL добавляется вместе с
// ресурсами, которым нужна повторяемость после перезапуска.
type IdempotencyStore interface {
	Begin(ctx context.Context, scope, key, fingerprint string) (IdemState, *StoredResponse, error)
	Complete(ctx context.Context, scope, key string, resp StoredResponse) error
	// Release снимает занятость ключа, если ответ запоминать нельзя.
	Release(ctx context.Context, scope, key string) error
}

type idemEntry struct {
	fingerprint string
	resp        *StoredResponse
	expires     time.Time
}

// MemoryIdempotency — хранилище ключей в памяти с ограничением числа и срока.
type MemoryIdempotency struct {
	mu      sync.Mutex
	ttl     time.Duration
	max     int
	now     func() time.Time
	entries map[string]*idemEntry
}

// NewMemoryIdempotency: нулевые значения — срок 24 часа, 10 000 ключей.
func NewMemoryIdempotency(ttl time.Duration, max int, now func() time.Time) *MemoryIdempotency {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if max <= 0 {
		max = 10000
	}
	if now == nil {
		now = time.Now
	}
	return &MemoryIdempotency{ttl: ttl, max: max, now: now, entries: map[string]*idemEntry{}}
}

func idemID(scope, key string) string { return scope + "\x00" + key }

// Begin занимает ключ или сообщает, чем он занят.
func (m *MemoryIdempotency) Begin(_ context.Context, scope, key, fp string) (IdemState, *StoredResponse, error) {
	now := m.now()
	m.mu.Lock()
	defer m.mu.Unlock()
	id := idemID(scope, key)
	if e := m.entries[id]; e != nil {
		if now.Before(e.expires) {
			switch {
			case e.fingerprint != fp:
				return IdemMismatch, nil, nil
			case e.resp == nil:
				return IdemBusy, nil, nil
			}
			return IdemReplay, e.resp, nil
		}
		delete(m.entries, id)
	}
	if len(m.entries) >= m.max {
		for k, e := range m.entries {
			if !now.Before(e.expires) {
				delete(m.entries, k)
			}
		}
		if len(m.entries) >= m.max {
			return IdemFull, nil, nil
		}
	}
	m.entries[id] = &idemEntry{fingerprint: fp, expires: now.Add(m.ttl)}
	return IdemNew, nil, nil
}

// Complete сохраняет ответ.
func (m *MemoryIdempotency) Complete(_ context.Context, scope, key string, resp StoredResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.entries[idemID(scope, key)]; e != nil {
		e.resp = &resp
	}
	return nil
}

// Release удаляет занятый ключ.
func (m *MemoryIdempotency) Release(_ context.Context, scope, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, idemID(scope, key))
	return nil
}

// captureWriter запоминает ответ, пока передаёт его клиенту.
type captureWriter struct {
	http.ResponseWriter
	status   int
	buf      bytes.Buffer
	overflow bool
}

func (c *captureWriter) WriteHeader(code int) {
	if c.status == 0 {
		c.status = code
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *captureWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.buf.Len()+len(p) > maxStoredResponse {
		c.overflow = true
	} else {
		c.buf.Write(p)
	}
	return c.ResponseWriter.Write(p)
}

// idempotent оборачивает обработчик маршрута. Без заголовка запрос
// выполняется как обычно. Отпечаток запроса — хеш метода, адреса и тела:
// тот же ключ с другим запросом — 422, а не тихая подмена.
func idempotent(store IdempotencyStore, hasher aisecCrypto.Hasher, maxBody int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key, present, prob := ParseIdempotencyKey(r.Header.Values(IdempotencyHeader))
		if prob != nil {
			WriteProblem(w, prob)
			return
		}
		if !present {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			WriteProblem(w, bodyProblem(err))
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h := hasher.New()
		for _, part := range []string{r.Method, "\n", r.URL.EscapedPath(), "?", r.URL.RawQuery, "\n"} {
			_, _ = h.Write([]byte(part)) //nolint:gosec // G104: hash.Hash.Write не возвращает ошибок
		}
		_, _ = h.Write(body) //nolint:gosec // G104: hash.Hash.Write не возвращает ошибок
		fp := hex.EncodeToString(h.Sum(nil))
		scope := ""
		if p, ok := PrincipalFrom(r.Context()); ok {
			scope = p.ID
		}
		ctx := r.Context()
		state, saved, err := store.Begin(ctx, scope, key, fp)
		if err != nil {
			WriteProblem(w, errInternal())
			return
		}
		switch state {
		case IdemReplay:
			h := w.Header()
			h.Set("Content-Type", saved.ContentType)
			if saved.Location != "" {
				h.Set("Location", saved.Location)
			}
			h.Set("Idempotent-Replayed", "true")
			w.WriteHeader(saved.Status)
			_, _ = w.Write(saved.Body) //nolint:gosec // G104: разрыв соединения не требует реакции
			return
		case IdemMismatch:
			WriteProblem(w, NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable,
				"Этот Idempotency-Key уже использован с другим запросом. Выберите новый ключ."))
			return
		case IdemBusy:
			w.Header().Set("Retry-After", "1")
			WriteProblem(w, NewProblem(http.StatusConflict, CodeConflict,
				"Запрос с этим Idempotency-Key ещё выполняется. Повторите чуть позже."))
			return
		case IdemFull:
			w.Header().Set("Retry-After", "60")
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Хранилище ключей повторяемости переполнено. Повторите позже."))
			return
		case IdemNew:
		}
		cw := &captureWriter{ResponseWriter: w}
		defer func() {
			// Ответ 5xx, слишком большой или не записанный не запоминается:
			// клиент вправе повторить запрос с тем же ключом.
			if cw.status == 0 || cw.status >= 500 || cw.overflow {
				_ = store.Release(context.WithoutCancel(ctx), scope, key) //nolint:gosec // G104: освобождение ключа — по возможности
				return
			}
			_ = store.Complete(context.WithoutCancel(ctx), scope, key, StoredResponse{ //nolint:gosec // G104: см. выше
				Status: cw.status, ContentType: cw.Header().Get("Content-Type"),
				Location: cw.Header().Get("Location"), Body: cw.buf.Bytes(),
			})
		}()
		next.ServeHTTP(cw, r)
	})
}
