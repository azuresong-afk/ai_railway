package gateway

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Клиент изолированного процесса ML-детекторов aisec-ml (ADR-0024, раздел
// 4). Любой сбой — ErrMLUnavailable: ML-детектор не даёт результата, но и
// не включает fail_closed; событие получает признак ml_unavailable, решение
// принимается по остальным детекторам (fail-open для ML, Р3).

// ErrMLUnavailable — aisec-ml недоступен, перегружен, не уложился в срок или
// нарушил протокол; запрос проходит без проверки ML.
var ErrMLUnavailable = errors.New("aisec-ml недоступен")

// Умолчания клиента.
const (
	DefaultMLTimeout     = 300 * time.Millisecond
	DefaultMLMaxInflight = 16
	DefaultMLMinBackoff  = time.Second
	DefaultMLMaxBackoff  = 30 * time.Second
	// MLMaxChunks — сколько частей по ml.MaxText проверяет ML в одном тексте;
	// остаток не проверяется (ADR-0024, раздел 3).
	MLMaxChunks = 8
	// mlIdleMax — свободное соединение старше этого не берётся: aisec-ml
	// закрывает простаивающие соединения через ml.DefaultIdleTimeout.
	mlIdleMax = ml.DefaultIdleTimeout / 2
	// mlTimeoutsToFail — сколько вызовов подряд должны не уложиться в срок,
	// чтобы включилась отсрочка: одиночный долгий вывод — не сбой процесса.
	mlTimeoutsToFail = 3
)

// MLClientConfig — параметры клиента aisec-ml.
type MLClientConfig struct {
	// Socket — путь к Unix-сокету aisec-ml.
	Socket string
	// Timeout — предел одного вызова (меньше срока детектора).
	Timeout time.Duration
	// MaxInflight — предел одновременных вызовов; сверх — сразу ErrMLUnavailable.
	MaxInflight int
	// MinBackoff, MaxBackoff — отсрочка после сбоя: всё это время вызовы
	// сразу получают ErrMLUnavailable и не добавляют задержки запросу.
	MinBackoff, MaxBackoff time.Duration
	Logger                 *slog.Logger
	// now — часы (тесты).
	now func() time.Time
}

// MLClient — пул соединений с aisec-ml. Безопасен для одновременного вызова.
type MLClient struct {
	cfg    MLClientConfig
	sem    chan struct{}
	nextID atomic.Uint32

	mu        sync.Mutex
	idle      []*mlConn
	downUntil time.Time
	backoff   time.Duration
	down      bool
	timeouts  int
	closed    bool
}

// mlConn — соединение и модели, о которых aisec-ml сообщил в hello.
type mlConn struct {
	c      net.Conn
	models map[string]ml.ModelInfo
	// used — когда соединение вернулось в пул.
	used time.Time
}

// NewMLClient проверяет параметры; соединения открываются при вызовах.
func NewMLClient(cfg MLClientConfig) (*MLClient, error) {
	if !filepath.IsAbs(cfg.Socket) {
		return nil, errors.New("aisec-ml: путь к сокету должен быть абсолютным")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultMLTimeout
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMLMaxInflight
	}
	if cfg.MinBackoff <= 0 {
		cfg.MinBackoff = DefaultMLMinBackoff
	}
	if cfg.MaxBackoff < cfg.MinBackoff {
		cfg.MaxBackoff = max(DefaultMLMaxBackoff, cfg.MinBackoff)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	return &MLClient{cfg: cfg, sem: make(chan struct{}, cfg.MaxInflight)}, nil
}

// Close закрывает свободные соединения; соединения, занятые вызовами,
// закрываются по их завершении.
func (c *MLClient) Close() {
	c.mu.Lock()
	idle := c.idle
	c.idle, c.closed = nil, true
	c.mu.Unlock()
	for _, mc := range idle {
		_ = mc.c.Close() //nolint:gosec // G104: соединение больше не нужно
	}
}

// mlResult — находки модели по всему тексту.
type mlResult struct {
	Info     ml.ModelInfo
	Findings []ml.Score
	// Partial — модель проверила не весь текст.
	Partial bool
}

// Detect проверяет текст моделью. Длинный текст режется на части по
// границам символов, не больше MLMaxChunks; позиции находок — в исходном
// тексте.
func (c *MLClient) Detect(ctx context.Context, model, text string) (*mlResult, error) {
	if !utf8.ValidString(text) {
		return nil, fmt.Errorf("%w: текст не UTF-8", ErrMLUnavailable)
	}
	if c.isDown() {
		return nil, fmt.Errorf("%w: отсрочка после сбоя", ErrMLUnavailable)
	}
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	default:
		return nil, fmt.Errorf("%w: предел одновременных вызовов", ErrMLUnavailable)
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()
	for attempt := 0; ; attempt++ {
		mc, reused, err := c.conn(ctx)
		if err != nil {
			c.failed(parent, ctx, err)
			return nil, fmt.Errorf("%w: %w", ErrMLUnavailable, err)
		}
		res, keep, err := c.detectOn(ctx, mc, model, text)
		if keep {
			c.put(mc)
		} else {
			_ = mc.c.Close() //nolint:gosec // G104: соединение после сбоя не используется
		}
		switch {
		case err == nil:
			c.ok()
			return res, nil
		case keep:
			return nil, fmt.Errorf("%w: %w", ErrMLUnavailable, err)
		case reused && attempt == 0 && ctx.Err() == nil && !errors.Is(err, ml.ErrProtocol) && !errors.Is(err, os.ErrDeadlineExceeded):
			// Свободное соединение мог закрыть aisec-ml (простой, перезапуск):
			// одна попытка на новом соединении.
			continue
		}
		c.failed(parent, ctx, err)
		return nil, fmt.Errorf("%w: %w", ErrMLUnavailable, err)
	}
}

// detectOn — проверка текста по частям на одном соединении. keep —
// соединение можно вернуть в пул.
func (c *MLClient) detectOn(ctx context.Context, mc *mlConn, model, text string) (*mlResult, bool, error) {
	info, ok := mc.models[model]
	if !ok {
		return nil, true, fmt.Errorf("модель %s не загружена", model)
	}
	res := &mlResult{Info: info, Findings: []ml.Score{}}
	chunks, rest := splitText(text, ml.MaxText, MLMaxChunks)
	res.Partial = rest
	for _, ch := range chunks {
		r, keep, err := c.roundTrip(ctx, mc, info, text[ch[0]:ch[1]])
		if err != nil {
			return nil, keep, err
		}
		res.Partial = res.Partial || r.Truncated
		for _, s := range r.Findings {
			s.Start += ch[0]
			s.End += ch[0]
			res.Findings = append(res.Findings, s)
		}
	}
	return res, true, nil
}

// splitText делит текст на части не длиннее size по границам символов;
// rest — частей больше limit, остаток не вошёл.
func splitText(text string, size, limit int) (chunks [][2]int, rest bool) {
	for start := 0; start < len(text); {
		if len(chunks) == limit {
			return chunks, true
		}
		end := min(start+size, len(text))
		for end < len(text) && end > start && !utf8.RuneStart(text[end]) {
			end--
		}
		chunks = append(chunks, [2]int{start, end})
		start = end
	}
	if len(chunks) == 0 {
		chunks = append(chunks, [2]int{0, 0})
	}
	return chunks, false
}

// roundTrip — один запрос detect. keep — соединение исправно (ответ — кадр
// error с кодом, после которого aisec-ml соединение не закрывает).
func (c *MLClient) roundTrip(ctx context.Context, mc *mlConn, info ml.ModelInfo, text string) (_ *ml.Result, keep bool, _ error) {
	body, err := ml.EncodeDetect(info.ID, text)
	if err != nil {
		return nil, true, err
	}
	id := c.nextID.Add(1)
	stop := bindDeadline(ctx, mc.c)
	defer func() {
		// Прерывание по отмене уже сработало или выполняется: срок
		// соединения сдвинут, в пул его возвращать нельзя.
		if !stop() {
			keep = false
		}
	}()
	if err := ml.WriteFrame(mc.c, ml.Header{Type: ml.TypeDetect, ID: id}, body); err != nil {
		return nil, false, err
	}
	h, b, err := ml.ReadFrame(mc.c, ml.ClientSide)
	if err != nil {
		return nil, false, err
	}
	if h.ID != id {
		return nil, false, fmt.Errorf("%w: номер ответа", ml.ErrProtocol)
	}
	switch h.Type {
	case ml.TypeResult:
		r, err := ml.ParseResult(b, info, text)
		if err != nil {
			return nil, false, err
		}
		return r, true, nil
	case ml.TypeError:
		code, err := ml.ParseError(b)
		if err != nil {
			return nil, false, err
		}
		// Перегрузка и неизвестная модель — не сбой соединения.
		keep := code == ml.ErrOverloaded || code == ml.ErrUnknownModel || code == ml.ErrInternal
		return nil, keep, fmt.Errorf("aisec-ml ответил %s", code)
	}
	return nil, false, fmt.Errorf("%w: тип ответа %d", ml.ErrProtocol, h.Type)
}

// bindDeadline переносит срок контекста на соединение и прерывает чтение
// при отмене контекста.
func bindDeadline(ctx context.Context, conn net.Conn) func() bool {
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d) //nolint:gosec // G104: ошибка проявится при чтении
	}
	return context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) }) //nolint:gosec // G104: прерывание чтения
}

// conn — свободное соединение (reused) или новое: проверка прав сокета,
// подключение и hello. Свободные соединения старше mlIdleMax закрываются.
func (c *MLClient) conn(ctx context.Context) (_ *mlConn, reused bool, _ error) {
	var stale []*mlConn
	defer func() {
		for _, mc := range stale {
			_ = mc.c.Close() //nolint:gosec // G104: устаревшее соединение
		}
	}()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, false, errors.New("клиент закрыт")
	}
	now := c.cfg.now()
	for n := len(c.idle); n > 0; n-- {
		mc := c.idle[n-1]
		c.idle = c.idle[:n-1]
		if now.Sub(mc.used) < mlIdleMax {
			c.mu.Unlock()
			return mc, true, nil
		}
		stale = append(stale, mc)
	}
	c.mu.Unlock()
	if err := checkMLSocket(c.cfg.Socket); err != nil {
		return nil, false, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.cfg.Socket)
	if err != nil {
		return nil, false, err
	}
	mc, err := c.hello(ctx, conn)
	if err != nil {
		_ = conn.Close() //nolint:gosec // G104: соединение после сбоя не используется
		return nil, false, err
	}
	return mc, false, nil
}

func (c *MLClient) hello(ctx context.Context, conn net.Conn) (_ *mlConn, err error) {
	stop := bindDeadline(ctx, conn)
	defer func() {
		if !stop() && err == nil {
			err = context.Cause(ctx)
		}
	}()
	id := c.nextID.Add(1)
	if err := ml.WriteFrame(conn, ml.Header{Type: ml.TypeHello, ID: id}, nil); err != nil {
		return nil, err
	}
	h, b, err := ml.ReadFrame(conn, ml.ClientSide)
	if err != nil {
		return nil, err
	}
	if h.Type != ml.TypeHelloOK || h.ID != id {
		return nil, fmt.Errorf("%w: ответ на hello", ml.ErrProtocol)
	}
	hello, err := ml.ParseHelloOK(b)
	if err != nil {
		return nil, err
	}
	mc := &mlConn{c: conn, models: make(map[string]ml.ModelInfo, len(hello.Models))}
	for _, m := range hello.Models {
		mc.models[m.ID] = m
	}
	return mc, nil
}

// checkMLSocket — путь ведёт к сокету (не к ссылке), у остальных нет прав на
// сокет, каталог сокета — каталог, недоступный остальным на запись
// (ADR-0024, раздел 2). Иначе к сокету мог бы подменить процесс другого
// пользователя, и шлюз отправлял бы ему тексты запросов.
func checkMLSocket(path string) error {
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 {
		return errors.New("каталог сокета aisec-ml — не каталог или доступен на запись группе или остальным")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode().Type() != fs.ModeSocket {
		return errors.New("на месте сокета aisec-ml не сокет")
	}
	if info.Mode().Perm()&0o007 != 0 {
		return fmt.Errorf("права сокета aisec-ml %#o: у остальных не должно быть доступа", info.Mode().Perm())
	}
	return nil
}

func (c *MLClient) put(mc *mlConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && len(c.idle) < c.cfg.MaxInflight {
		mc.used = c.cfg.now()
		c.idle = append(c.idle, mc)
		return
	}
	_ = mc.c.Close() //nolint:gosec // G104: лишнее свободное соединение
}

func (c *MLClient) isDown() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cfg.now().Before(c.downUntil)
}

// failed разбирает сбой вызова. Отмена запроса (клиент ушёл, истёк общий
// срок проверки) — не сбой aisec-ml. Срок вызова истёк — отсрочка только
// после mlTimeoutsToFail таких вызовов подряд. Остальное (нет сокета, hello,
// нарушение протокола, обрыв) — сразу.
func (c *MLClient) failed(parent, ctx context.Context, err error) {
	if parent.Err() != nil {
		return
	}
	// Срок соединения равен сроку ctx, и чтение может прерваться раньше,
	// чем сработает таймер контекста: это тоже истечение срока.
	if ctx.Err() != nil || errors.Is(err, os.ErrDeadlineExceeded) {
		c.mu.Lock()
		c.timeouts++
		n := c.timeouts
		c.mu.Unlock()
		if n < mlTimeoutsToFail {
			return
		}
	}
	c.fail(err)
}

// fail — сбой aisec-ml: отсрочка удваивается до MaxBackoff, свободные
// соединения закрываются (процесс мог перезапуститься). Во время отсрочки
// отсрочка не растёт (сбои вызовов, начатых до неё). Переход в
// «недоступен» пишется в журнал один раз, без текста запроса.
func (c *MLClient) fail(err error) {
	c.mu.Lock()
	if c.cfg.now().Before(c.downUntil) {
		c.mu.Unlock()
		return
	}
	c.timeouts = 0
	if c.backoff == 0 {
		c.backoff = c.cfg.MinBackoff
	} else {
		c.backoff = min(c.backoff*2, c.cfg.MaxBackoff)
	}
	c.downUntil = c.cfg.now().Add(c.backoff)
	wasDown := c.down
	c.down = true
	idle := c.idle
	c.idle = nil
	backoff := c.backoff
	c.mu.Unlock()
	for _, mc := range idle {
		_ = mc.c.Close() //nolint:gosec // G104: соединения после сбоя не используются
	}
	if !wasDown {
		c.cfg.Logger.Warn("aisec-ml недоступен: ML-детекторы пропускаются (ml_unavailable)", "error", err, "retry_in", backoff.String())
	}
}

func (c *MLClient) ok() {
	c.mu.Lock()
	wasDown := c.down
	c.down, c.backoff, c.timeouts = false, 0, 0
	c.mu.Unlock()
	if wasDown {
		c.cfg.Logger.Info("aisec-ml снова доступен")
	}
}

// MLDetectorSpec — ML-детектор в реестре: описание из
// internal/detect/builtin (MLSpecs).
type MLDetectorSpec = builtin.MLSpec

// MLDetector — ML-детектор: обычный detect.Detector с клиентом aisec-ml.
type MLDetector struct {
	spec   MLDetectorSpec
	cats   []string
	client *MLClient
}

// NewMLDetector проверяет описание детектора.
func NewMLDetector(spec MLDetectorSpec, client *MLClient) (*MLDetector, error) {
	if client == nil || !ml.ValidModelID(spec.Model) || len(spec.Directions) == 0 || len(spec.Categories) == 0 ||
		spec.Threshold <= 0 || spec.Threshold > 1 {
		return nil, fmt.Errorf("ML-детектор %s: неполное описание", spec.ID)
	}
	d := &MLDetector{spec: spec, client: client}
	for _, c := range spec.Categories {
		if !slices.Contains(d.cats, c) {
			d.cats = append(d.cats, c)
		}
	}
	slices.Sort(d.cats)
	// Проверка ID, версии, категорий и строки матрицы — тем же правилом, что
	// у находок.
	if _, err := detect.NewRegistry(d); err != nil {
		return nil, fmt.Errorf("ML-детектор %s: %w", spec.ID, err)
	}
	for _, dir := range spec.Directions {
		probe := detect.Finding{Detector: spec.ID, Version: spec.Version, Category: d.cats[0], Threat: spec.ThreatFor(dir)}
		if err := detect.ValidateFinding(probe, d, ""); err != nil {
			return nil, fmt.Errorf("ML-детектор %s: %w", spec.ID, err)
		}
	}
	return d, nil
}

// ID детектора.
func (d *MLDetector) ID() string { return d.spec.ID }

// Version кода детектора.
func (d *MLDetector) Version() string { return d.spec.Version }

// Directions детектора.
func (d *MLDetector) Directions() []detect.Direction { return slices.Clone(d.spec.Directions) }

// Categories — все категории находок.
func (d *MLDetector) Categories() []string { return slices.Clone(d.cats) }

// MLBacked — детектор работает через aisec-ml: его сбой не включает
// fail_closed, а ставит признак ml_unavailable (ADR-0024, раздел 4).
func (d *MLDetector) MLBacked() bool { return true }

// errMLPartial — модель проверила не весь текст: событие получает
// ml_unavailable, находки проверенной части возвращаются вместе с ошибкой
// (detect.ErrPartial). У классификаторов находка в проверенной части для
// решения политики достаточна — ошибка ставится, только если находок нет.
// У разметки (Spans) — всегда: непроверенный остаток не замаскирован.
var errMLPartial = fmt.Errorf("%w: %w", ErrMLUnavailable, detect.ErrPartial)

// Detect — находки модели не ниже порога.
func (d *MLDetector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	res, err := d.client.Detect(ctx, d.spec.Model, t.Text)
	if err != nil {
		return nil, err
	}
	// Модель из пакета должна подходить детектору: иначе детектор молча
	// ничего бы не находил.
	if !slices.Contains(res.Info.Directions, string(t.Direction)) {
		return nil, fmt.Errorf("%w: модель %s не проверяет направление %s", ErrMLUnavailable, res.Info.ID, t.Direction)
	}
	for label := range d.spec.Categories {
		if !res.Info.HasLabel(label) {
			return nil, fmt.Errorf("%w: у модели %s нет метки %s", ErrMLUnavailable, res.Info.ID, label)
		}
	}
	rule := mlRule(res.Info)
	threat := d.spec.ThreatFor(t.Direction)
	var out []detect.Finding
	for _, s := range res.Findings {
		cat, ok := d.spec.Categories[s.Label]
		if !ok || s.Score < d.spec.Threshold {
			continue
		}
		start, end := s.Start, s.End
		if d.spec.Spans {
			start, end = expandWords(t.Text, start, end)
		}
		out = append(out, detect.Finding{Detector: d.spec.ID, Version: d.spec.Version, Category: cat, Threat: threat,
			Score: s.Score, Start: start, End: end, Rule: rule})
	}
	if res.Partial && (d.spec.Spans || len(out) == 0) {
		return out, errMLPartial
	}
	return out, nil
}

// mlRule — модель и её версия в поле Rule находки (трассировка решения).
func mlRule(info ml.ModelInfo) string {
	r := info.ID + "-" + info.Version
	if len(r) > 64 {
		return info.ID
	}
	for _, ch := range r {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
			return info.ID
		}
	}
	return r
}

// mlBacked — детектор id в реестре работает через aisec-ml.
func mlBacked(reg *detect.Registry, id string) bool {
	if reg == nil {
		return false
	}
	d, ok := reg.Get(id)
	if !ok {
		return false
	}
	m, ok := d.(interface{ MLBacked() bool })
	return ok && m.MLBacked()
}

// withoutML — детекторы ids без ML-детекторов; если ML-детекторы были,
// событие получает ml_unavailable (общий срок проверки истёк, а сбой ML
// fail_closed не включает).
func (in *inspection) withoutML(reg *detect.Registry, ids []string) []string {
	out := slices.DeleteFunc(slices.Clone(ids), func(id string) bool { return mlBacked(reg, id) })
	if len(out) != len(ids) {
		in.MLUnavailable = true
	}
	return out
}
