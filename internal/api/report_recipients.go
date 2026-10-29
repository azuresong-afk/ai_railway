package api

import (
	"context"
	"errors"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/reports"
)

// ReportDirectory — справочник получателей отчётов по расписанию на учётных
// записях консоли (задача 4.6): адрес берётся из записи, права — из роли.
type ReportDirectory struct{ Auth *auth.Service }

// Recipient — см. reports.Directory. Запись без адреса не ошибка: получатель
// пропускается при отправке.
func (d ReportDirectory) Recipient(ctx context.Context, userID string) (reports.Recipient, error) {
	u, err := d.Auth.User(ctx, userID)
	if errors.Is(err, auth.ErrNotFound) {
		return reports.Recipient{}, reports.ErrRecipientNotFound
	}
	if err != nil {
		return reports.Recipient{}, err
	}
	return d.of(ctx, u, nil)
}

// of строит получателя по записи; grants — необязательный кеш прав по ролям
// для обхода списка пользователей.
func (d ReportDirectory) of(ctx context.Context, u auth.User, grants map[auth.Role]auth.Grants) (reports.Recipient, error) {
	g, ok := grants[u.Role]
	if !ok {
		var err error
		if g, err = d.Auth.Grants(ctx, u.Role); err != nil {
			return reports.Recipient{}, err
		}
		if grants != nil {
			grants[u.Role] = g
		}
	}
	full := g.Full(auth.PermReportsRead)
	return reports.Recipient{Email: u.Email, Active: u.Status == auth.StatusActive, CanRead: full,
		Scope: reports.Scope{Budgets: full && g.Full(auth.PermBudgetsRead), Incidents: full && g.Full(auth.PermIncidentsRead),
			Alerts: full && g.Full(auth.PermAlertsRead), Compliance: full && g.Full(auth.PermComplianceRead)}}, nil
}
