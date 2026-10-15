package main

import (
	"context"
	"os"
	"os/signal"
	"syscall" //nolint:depguard // ADR-0004: только syscall.SIGTERM для корректного завершения; прочее syscall.* запрещает forbidigo
)

// shutdownContext отменяется по SIGINT или SIGTERM (остановка оркестратором)
// — шлюз дорабатывает активные запросы и завершается (ТЗ, 4.4).
func shutdownContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
