package integrity

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Action — реакция на нарушение (ОЦЛ.5, DM-42).
type Action string

// Реакции.
const (
	// ActionAlert — оповещение: запись в журналы, компонент продолжает работу.
	ActionAlert Action = "alert"
	// ActionStop — оповещение и остановка компонента.
	ActionStop Action = "stop"
)

// ParseAction разбирает значение параметра -integrity-action.
func ParseAction(s string) (Action, error) {
	switch Action(s) {
	case ActionAlert, ActionStop:
		return Action(s), nil
	}
	return "", fmt.Errorf("ожидается %s или %s", ActionAlert, ActionStop)
}

// Период периодической проверки (ОЦЛ.2).
const (
	DefaultInterval = time.Hour
	MinInterval     = time.Minute
)

// ErrViolation — компонент остановлен из-за нарушения целостности.
var ErrViolation = errors.New("нарушена целостность компонента")

// RecordFunc сохраняет итог проверки (integrity_checks и журнал аудита);
// by — кто запустил проверку, ip — откуда (для ручной проверки из консоли).
type RecordFunc func(ctx context.Context, res Result, by audit.Actor, ip netip.Addr) error

// MonitorConfig — параметры Monitor.
type MonitorConfig struct {
	Checker  *Checker
	Action   Action
	Interval time.Duration
	Logger   *slog.Logger
	// Record — сохранение итога; nil — только технический журнал (шлюз без БД).
	Record RecordFunc
	// OnStop вызывается при нарушении с реакцией stop после запуска
	// (периодическая или ручная проверка): компонент завершает работу.
	OnStop func(error)
}

// Monitor проверяет целостность при запуске, периодически и по команде и
// применяет реакцию. Проверки идут строго по одной.
type Monitor struct {
	cfg MonitorConfig
	mu  sync.Mutex
}

// systemActor — «кто» для проверок при запуске и по расписанию.
func systemActor(component string) audit.Actor {
	return audit.Actor{Type: audit.ActorSystem, ID: "integrity-" + component, Name: "Контроль целостности"}
}

// NewMonitor проверяет параметры.
func NewMonitor(cfg MonitorConfig) (*Monitor, error) {
	if cfg.Checker == nil {
		return nil, errors.New("контроль целостности: нет Checker")
	}
	if _, err := ParseAction(string(cfg.Action)); err != nil {
		return nil, fmt.Errorf("контроль целостности: реакция: %w", err)
	}
	if cfg.Interval < MinInterval {
		return nil, fmt.Errorf("контроль целостности: период не меньше %s", MinInterval)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.OnStop == nil {
		cfg.OnStop = func(error) {}
	}
	return &Monitor{cfg: cfg}, nil
}

// Startup — проверка при запуске. При нарушении с реакцией stop возвращает
// ErrViolation: компонент не начинает работу.
func (m *Monitor) Startup(ctx context.Context) (Result, error) {
	res, err := m.check(ctx, TriggerStartup, systemActor(m.cfg.Checker.Component()), netip.Addr{})
	if err != nil {
		return res, err
	}
	if res.TestSigned {
		m.cfg.Logger.Warn("манифест проверен тестовым ключом: сборка не для поставки", "class", "integrity")
	}
	if !res.OK() && m.cfg.Action == ActionStop {
		return res, fmt.Errorf("%w: %s", ErrViolation, res.Reason)
	}
	return res, nil
}

// CheckBy — проверка по команде администратора (ОЦЛ.2). Реакция та же, что
// у периодической проверки.
func (m *Monitor) CheckBy(ctx context.Context, by audit.Actor, ip netip.Addr) (Result, error) {
	res, err := m.check(ctx, TriggerManual, by, ip)
	if err == nil {
		m.react(res)
	}
	return res, err
}

// Run проверяет целостность каждые Interval, пока не отменён ctx. Первая
// проверка — через Interval: при запуске проверяет Startup.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(m.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		res, err := m.check(ctx, TriggerPeriodic, systemActor(m.cfg.Checker.Component()), netip.Addr{})
		if err != nil {
			return
		}
		m.react(res)
	}
}

func (m *Monitor) react(res Result) {
	if !res.OK() && m.cfg.Action == ActionStop {
		m.cfg.OnStop(fmt.Errorf("%w: %s", ErrViolation, res.Reason))
	}
}

func (m *Monitor) check(ctx context.Context, trig Trigger, by audit.Actor, ip netip.Addr) (Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	res, err := m.cfg.Checker.Check(ctx, trig)
	if err != nil {
		return res, err
	}
	m.log(res)
	if m.cfg.Record != nil {
		if err := m.cfg.Record(ctx, res, by, ip); err != nil {
			// Итог уже в техническом журнале; без записи в БД проверка всё
			// равно выполнена и реакция применяется.
			m.cfg.Logger.Error("итог проверки целостности не сохранён", "class", "db", "error", err)
		}
	}
	return res, nil
}

// log пишет итог в технический журнал: пути и виды нарушений, без содержимого.
func (m *Monitor) log(res Result) {
	attrs := []any{"class", "integrity", "trigger", string(res.Trigger), "reason", string(res.Reason),
		"manifest_version", res.ManifestVersion, "checked", res.Checked, "test_signed", res.TestSigned}
	if res.OK() {
		m.cfg.Logger.Info("целостность не нарушена", attrs...)
		return
	}
	attrs = append(attrs, "failures", res.Failures, "omitted", res.Omitted, "action", string(m.cfg.Action))
	m.cfg.Logger.Error("нарушена целостность компонента", attrs...)
}
