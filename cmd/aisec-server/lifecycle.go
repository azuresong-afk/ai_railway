package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// lifecycleTimeout — запись об остановке идёт после отмены контекста
// сервера: у неё свой короткий срок.
const lifecycleTimeout = 5 * time.Second

// lifecycleLog — журналы аудита и технического состояния (audit.Log).
type lifecycleLog interface {
	Record(ctx context.Context, e audit.Entry) error
	Tech(ctx context.Context, e audit.TechEntry) error
}

var serverActor = audit.Actor{Type: audit.ActorSystem, ID: "server", Name: "Сервер управления"}

// recordStart пишет запуск сервера: component.start в журнал аудита и
// запись start в журнал технического состояния (РСБ.2, РСБ.7; В27 ревью
// 2.r5). Ошибка записи не останавливает запуск: она уходит в технический
// журнал процесса, а сбой БД виден на «Состоянии системы».
func recordStart(ctx context.Context, l lifecycleLog, logger *slog.Logger) {
	details := map[string]any{"component": "server", "version": version}
	if err := l.Record(ctx, audit.Entry{Actor: serverActor, Action: "component.start",
		Object: audit.Object{Type: "component", ID: "server"}, Result: audit.ResultSuccess, Details: details}); err != nil {
		logger.Error("запуск не записан в журнал аудита", "class", "db", "error", err)
	}
	if err := l.Tech(ctx, audit.TechEntry{Component: "server", Kind: audit.TechStart, Level: audit.LevelInfo,
		Message: "сервер управления запущен", Details: details}); err != nil {
		logger.Error("запуск не записан в журнал технического состояния", "class", "db", "error", err)
	}
}

// recordStop пишет остановку сервера; runErr — причина, если остановка
// аварийная (результат failure, класс ошибки в журнале технического
// состояния).
func recordStop(ctx context.Context, l lifecycleLog, runErr error, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), lifecycleTimeout)
	defer cancel()
	details := map[string]any{"component": "server", "version": version}
	result, level, msg := audit.ResultSuccess, audit.LevelInfo, "сервер управления остановлен"
	if runErr != nil {
		result, level, msg = audit.ResultFailure, audit.LevelError, "сервер управления остановлен с ошибкой"
		// Текст ошибки не пишется: в нём могут быть адреса и пути; он — в
		// техническом журнале процесса, здесь — класс.
		details["class"] = string(stopClass(runErr))
	}
	if err := l.Record(ctx, audit.Entry{Actor: serverActor, Action: "component.stop",
		Object: audit.Object{Type: "component", ID: "server"}, Result: result, Details: details}); err != nil {
		logger.Error("остановка не записана в журнал аудита", "class", "db", "error", err)
	}
	if err := l.Tech(ctx, audit.TechEntry{Component: "server", Kind: audit.TechStop, Level: level,
		Message: msg, Details: details}); err != nil {
		logger.Error("остановка не записана в журнал технического состояния", "class", "db", "error", err)
	}
}

// stopClass — класс аварийной остановки (РСБ.2: ошибки с классификацией).
func stopClass(err error) audit.ErrorClass {
	if errors.Is(err, integrity.ErrViolation) {
		return audit.ClassIntegrity
	}
	return audit.ClassInternal
}
