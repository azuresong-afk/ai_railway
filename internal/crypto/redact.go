package crypto

import (
	"fmt"
	"io"
	"log/slog"
)

// redacted встраивается в типы с ключами и секретами: при любом глаголе fmt
// и в slog они выводятся только именем алгоритма, а не содержимым полей.
type redacted struct{ name string }

// Format выводит только имя алгоритма при любом глаголе fmt (%v, %+v, %#v, %x, %s…).
func (r redacted) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, r.name) //nolint:gosec // G104: у fmt.Formatter нет способа вернуть ошибку записи
}

// LogValue выводит в slog только имя алгоритма.
func (r redacted) LogValue() slog.Value { return slog.StringValue(r.name) }

// Name — имя алгоритма для отчётов и SBOM.
func (r redacted) Name() string { return r.name }
