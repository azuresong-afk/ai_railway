package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
)

type fakeCheckpoints struct {
	any bool
	err error
}

func (f fakeCheckpoints) Any(context.Context) (bool, error) { return f.any, f.err }

// В5 ревью 2.r1 (решение владельца): есть контрольные точки, а ключа их
// проверки нет — сервер не запускается; новая установка без точек стартует.
func TestRequireAuditKey(t *testing.T) {
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := requireAuditKey(ctx, fakeCheckpoints{any: true}, false, log)
	if err == nil || !strings.Contains(err.Error(), "-audit-signing-pub") {
		t.Fatalf("точки без ключа: %v", err)
	}
	if err := requireAuditKey(ctx, fakeCheckpoints{}, false, log); err != nil {
		t.Fatalf("новая установка без ключа: %v", err)
	}
	if err := requireAuditKey(ctx, fakeCheckpoints{any: true}, true, log); err != nil {
		t.Fatalf("точки с ключом: %v", err)
	}
	// Сбой БД — отказ запуска, а не молчаливый пропуск проверки.
	if err := requireAuditKey(ctx, fakeCheckpoints{err: errors.New("db down")}, false, log); err == nil {
		t.Fatal("сбой БД пропущен")
	}
}
