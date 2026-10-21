package events

import (
	"context"
	"log/slog"
	"time"
)

// MaintainEvery — период фонового задания секций и сроков хранения.
const MaintainEvery = time.Hour

// Maintainer — секции и сроки хранения (PGStore).
type Maintainer interface {
	EnsurePartitions(ctx context.Context) (int, error)
	DropExpired(ctx context.Context) ([]string, error)
}

// Maintain выполняет задание один раз: создаёт секции на неделю вперёд и
// назад и удаляет секции старше сроков хранения (Р9, ТЗ 5.5).
func Maintain(ctx context.Context, m Maintainer, logger *slog.Logger) error {
	n, err := m.EnsurePartitions(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		logger.Info("созданы секции событий", "count", n)
	}
	dropped, err := m.DropExpired(ctx)
	if err != nil {
		return err
	}
	if len(dropped) > 0 {
		logger.Info("удалены секции событий по сроку хранения", "partitions", dropped)
	}
	return nil
}

// RunMaintenance повторяет Maintain каждые every до отмены ctx. Сбой
// пишется в журнал; следующий запуск — по расписанию.
func RunMaintenance(ctx context.Context, m Maintainer, every time.Duration, logger *slog.Logger) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := Maintain(ctx, m, logger); err != nil && ctx.Err() == nil {
				logger.Error("обслуживание секций событий не выполнено", "error", err)
			}
		}
	}
}
