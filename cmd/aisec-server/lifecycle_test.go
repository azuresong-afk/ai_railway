package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

type fakeLifecycleLog struct {
	entries []audit.Entry
	tech    []audit.TechEntry
	fail    bool
}

func (f *fakeLifecycleLog) Record(ctx context.Context, e audit.Entry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.fail {
		return errors.New("БД недоступна")
	}
	f.entries = append(f.entries, e)
	return nil
}

func (f *fakeLifecycleLog) Tech(ctx context.Context, e audit.TechEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.fail {
		return errors.New("БД недоступна")
	}
	f.tech = append(f.tech, e)
	return nil
}

// Запуск и остановка сервера пишутся в оба журнала (РСБ.2, РСБ.7; В27
// ревью 2.r5); остановка — и после отмены контекста сервера.
func TestRecordLifecycle(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	l := &fakeLifecycleLog{}
	ctx, cancel := context.WithCancel(context.Background())
	recordStart(ctx, l, logger)
	cancel()
	recordStop(ctx, l, nil, logger)
	if len(l.entries) != 2 || l.entries[0].Action != "component.start" || l.entries[1].Action != "component.stop" {
		t.Fatalf("записи аудита: %+v", l.entries)
	}
	if l.entries[1].Result != audit.ResultSuccess || l.entries[0].Actor.Type != audit.ActorSystem {
		t.Fatalf("остановка: %+v", l.entries[1])
	}
	if len(l.tech) != 2 || l.tech[0].Kind != audit.TechStart || l.tech[1].Kind != audit.TechStop {
		t.Fatalf("технический журнал: %+v", l.tech)
	}
}

// Аварийная остановка: результат failure и класс ошибки без её текста.
func TestRecordStopFailure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tc := range []struct {
		err   error
		class audit.ErrorClass
	}{
		{errors.New("listen tcp 10.0.0.1:8443: bind"), audit.ClassInternal},
		{errors.Join(errors.New("x"), fmt.Errorf("шлюз: %w", integrity.ErrViolation)), audit.ClassIntegrity},
	} {
		l := &fakeLifecycleLog{}
		recordStop(context.Background(), l, tc.err, logger)
		if len(l.entries) != 1 || l.entries[0].Result != audit.ResultFailure {
			t.Fatalf("запись аудита: %+v", l.entries)
		}
		d := l.entries[0].Details.(map[string]any)
		if d["class"] != string(tc.class) || len(d) != 3 {
			t.Fatalf("подробности: %v", d)
		}
		if len(l.tech) != 1 || l.tech[0].Level != audit.LevelError || l.tech[0].Kind != audit.TechStop {
			t.Fatalf("технический журнал: %+v", l.tech)
		}
	}
}

// Сбой записи не останавливает сервер и не роняет его.
func TestRecordLifecycleStoreDown(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	l := &fakeLifecycleLog{fail: true}
	recordStart(context.Background(), l, logger)
	recordStop(context.Background(), l, nil, logger)
	if len(l.entries) != 0 || len(l.tech) != 0 {
		t.Fatal("записи при недоступной БД")
	}
}
