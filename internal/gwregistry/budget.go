package gwregistry

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// Счётчики расхода в heartbeat (ТЗ 4.2, решение Р7 этапа 3, задача 3.18).
// Каждый процесс шлюза (started_at) присылает нарастающие счётчики расхода
// по приложениям за текущий и, после смены месяца, прошлый месяц; сервер
// хранит наибольшее значение по процессу и отвечает расходом остальных
// процессов и шлюзов по приложениям с жёстким бюджетом. После перезапуска
// шлюз получает расход прежнего процесса в этом ответе.

// Пределы раздела budget в heartbeat.
const (
	// MaxBudgetMonths — месяцев в одном heartbeat: текущий и прошлый.
	MaxBudgetMonths = 2
	// MaxBudgetApps — приложений в месяце (bundle.MaxApplications).
	MaxBudgetApps = 2000
	// maxBudgetValue — предел счётчика (защита от переполнения сумм в БД).
	maxBudgetValue = 1 << 62
)

var (
	budgetAppRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	budgetMonthRe = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])$`)
)

// BudgetUsage — счётчики процесса шлюза за месяц по приложению: расход в
// единицах 1e-7 ₽ (bundle.Cost), токены и запросы с известной и
// неизвестной ценой модели.
type BudgetUsage struct {
	App              string
	Cost             int64
	PricedTokens     int64
	UnpricedTokens   int64
	Requests         int64
	UnpricedRequests int64
}

// BudgetMonth — счётчики за месяц «ГГГГ-ММ» в часовом поясе установки.
type BudgetMonth struct {
	Month string
	Apps  []BudgetUsage
}

// BudgetReport — счётчики процесса шлюза; месяцы по возрастанию, последний
// — текущий месяц шлюза (может быть без приложений).
type BudgetReport struct {
	Months []BudgetMonth
}

// BudgetState — ответ сервера: расход остальных процессов и шлюзов за
// месяц Month по приложениям с жёстким бюджетом.
type BudgetState struct {
	Month  string
	Others map[string]int64
}

// BudgetSync — хранилище расхода (internal/apps).
type BudgetSync interface {
	SyncBudget(ctx context.Context, gatewayID string, startedAt time.Time, rep BudgetReport) (BudgetState, error)
}

// SetBudgetSync подключает счётчики расхода. Вызывается до начала
// обслуживания запросов; nil — раздел budget heartbeat не сохраняется.
func (s *Service) SetBudgetSync(b BudgetSync) { s.budgets = b }

// validate проверяет раздел budget heartbeat.
func (r *BudgetReport) validate() error {
	if r == nil {
		return nil
	}
	if len(r.Months) == 0 || len(r.Months) > MaxBudgetMonths {
		return fmt.Errorf("%w: budget.months — от 1 до %d", ErrInvalidRequest, MaxBudgetMonths)
	}
	for i, m := range r.Months {
		if !budgetMonthRe.MatchString(m.Month) || i > 0 && m.Month <= r.Months[i-1].Month {
			return fmt.Errorf("%w: budget.months — месяцы ГГГГ-ММ по возрастанию без повторов", ErrInvalidRequest)
		}
		if len(m.Apps) > MaxBudgetApps {
			return fmt.Errorf("%w: budget: больше %d приложений в месяце", ErrInvalidRequest, MaxBudgetApps)
		}
		seen := make(map[string]bool, len(m.Apps))
		for _, a := range m.Apps {
			if !budgetAppRe.MatchString(a.App) || seen[a.App] {
				return fmt.Errorf("%w: budget: неверный или повторный ID приложения", ErrInvalidRequest)
			}
			seen[a.App] = true
			for _, v := range []int64{a.Cost, a.PricedTokens, a.UnpricedTokens, a.Requests, a.UnpricedRequests} {
				if v < 0 || v > maxBudgetValue {
					return fmt.Errorf("%w: budget: счётчик — от 0 до 2^62", ErrInvalidRequest)
				}
			}
		}
	}
	return nil
}

// syncBudget сохраняет счётчики heartbeat; сбой — только в технический
// журнал: heartbeat уже записан, счётчики придут со следующим.
func (s *Service) syncBudget(ctx context.Context, gatewayID string, in HeartbeatInput) *BudgetState {
	if in.Budget == nil || s.budgets == nil {
		return nil
	}
	st, err := s.budgets.SyncBudget(ctx, gatewayID, in.StartedAt, *in.Budget)
	if err != nil {
		s.logger.Error("счётчики расхода шлюза не сохранены", "gateway_id", gatewayID, "error", err)
		return nil
	}
	return &st
}
