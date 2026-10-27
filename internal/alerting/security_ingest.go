package alerting

import (
	"context"
	"slices"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// gatewayAuthAlert — причина неудачной аутентификации на шлюзе, по которой
// поднимается DM-38: адрес заблокирован ограничителем шлюза после серии
// неудач (правило частоты по адресу, ИАФ.8), запрос с отозванным ключом
// (ТЗ 5.16: «отозванный ключ — всегда оповещение») или действующий ключ вне
// разрешённых адресов (ключ, вероятно, утёк). Неверный, просроченный или
// неполный ключ по одному — шум: серию таких ловит ограничитель шлюза.
func gatewayAuthAlert(reason string) bool {
	return reason == auth.ReasonRateLimited || reason == auth.ReasonRevoked || reason == auth.ReasonAddress
}

// processAuthFailures — DM-38 по принятым событиям auth_failure в
// транзакции приёма: одно оповещение на адрес (перебор) или префикс ключа
// (отозванный или чужой адрес), ссылки на события — в оповещении.
func processAuthFailures(ctx context.Context, ops txOps, evs []*events.Event) error {
	// DM-24 (agents.tool_poisoning) — в той же транзакции приёма.
	if err := processToolPoisoning(ctx, ops, evs); err != nil {
		return err
	}
	g := group{by: map[string]*Trigger{}}
	for _, e := range evs {
		if e.Type != events.TypeAuthFailure || e.AuthFailure == nil || !gatewayAuthAlert(e.AuthFailure.Reason) {
			continue
		}
		f := e.AuthFailure
		field, value := "key_prefix", f.KeyPrefix
		if f.Reason == auth.ReasonRateLimited || value == "" {
			field, value = "remote_addr", f.RemoteAddr
		}
		if value == "" {
			continue
		}
		ts, err := events.PartitionTime(e.ID)
		if err != nil {
			continue
		}
		t := g.get(GroupKey([]string{field}, map[string]string{field: value}), map[string]string{field: value})
		t.add(EventRef{ID: e.ID, TS: ts}, e.Time)
		reasons, _ := t.Details["reasons"].([]any)
		if !slices.Contains(reasons, any(f.Reason)) {
			if t.Details == nil {
				t.Details = map[string]any{}
			}
			t.Details["reasons"] = append(reasons, f.Reason)
		}
	}
	if len(g.order) == 0 {
		return nil
	}
	keys := slices.Clone(g.order)
	// Порядок ключей фиксирован: блокировки строк — в одном порядке.
	slices.Sort(keys)
	raises := make([]Raise, 0, len(keys))
	for _, k := range keys {
		raises = append(raises, Raise{Key: BuiltinGatewayAuth, Trigger: *g.by[k]})
	}
	return raiseBuiltin(ctx, ops, raises)
}
