package api

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/policy"
	"github.com/azuresong-afk/ai_railway/internal/policy/argschema"
)

// Раздел tools политики в API (ADR-0023, раздел 2; задача 4.9): поля как в
// YAML. Ограничения аргументов — объект JSON (подмножество JSON Schema),
// разбирается строго, как в YAML; длительности — строки вида 10m.

// PolicyToolsJSON — политика вызовов инструментов агентами.
type PolicyToolsJSON struct {
	Unapproved      string               `json:"unapproved"`
	Default         string               `json:"default"`
	ApprovalTimeout string               `json:"approval_timeout,omitempty"`
	Limits          PolicyToolLimitsJSON `json:"limits"`
	Rules           []PolicyToolRuleJSON `json:"rules"`
}

// PolicyToolLimitsJSON — лимиты вызовов (DM-23); 0 — без предела.
type PolicyToolLimitsJSON struct {
	AgentPerMinute int    `json:"agent_per_minute"`
	SessionCalls   int    `json:"session_calls"`
	Repeat         int    `json:"repeat"`
	RepeatWindow   string `json:"repeat_window,omitempty"`
}

// PolicyToolRateJSON — лимиты частоты правила; 0 — без предела.
type PolicyToolRateJSON struct {
	PerMinute int `json:"per_minute"`
	PerHour   int `json:"per_hour"`
}

// PolicyToolRuleJSON — правило политики вызовов.
type PolicyToolRuleJSON struct {
	ID       string              `json:"id"`
	Agents   []string            `json:"agents,omitempty"`
	Tool     string              `json:"tool,omitempty"`
	Risk     []string            `json:"risk,omitempty"`
	Action   string              `json:"action"`
	Args     json.RawMessage     `json:"args,omitempty"`
	Rate     *PolicyToolRateJSON `json:"rate,omitempty"`
	Severity string              `json:"severity"`
	Message  string              `json:"message,omitempty"`
}

// argsLimits — разбор схемы аргументов из запроса: пределы схемы проверяет
// policy.Spec.Validate, здесь — только размер и вложенность документа.
var argsLimits = argschema.Limits{MaxSize: argschema.MaxSchemaSize, MaxDepth: 2*argschema.MaxSchemaDepth + 4,
	MaxValues: 4096, MaxString: argschema.MaxKeyLen}

func parseDuration(field, s string) (policy.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("%s — длительность вида 10m", field)
	}
	return policy.Duration(d), nil
}

// toolsSpec переводит раздел из API в спецификацию; проверка — Validate.
func (t *PolicyToolsJSON) toolsSpec() (*policy.ToolsSpec, error) {
	if t == nil {
		return nil, nil
	}
	timeout, err := parseDuration("tools.approval_timeout", t.ApprovalTimeout)
	if err != nil {
		return nil, err
	}
	window, err := parseDuration("tools.limits.repeat_window", t.Limits.RepeatWindow)
	if err != nil {
		return nil, err
	}
	out := &policy.ToolsSpec{Unapproved: policy.Action(t.Unapproved), Default: policy.Action(t.Default), ApprovalTimeout: timeout,
		Limits: policy.ToolLimits{AgentPerMinute: t.Limits.AgentPerMinute, SessionCalls: t.Limits.SessionCalls,
			Repeat: t.Limits.Repeat, RepeatWindow: window}}
	for i, r := range t.Rules {
		rs := policy.ToolRuleSpec{ID: r.ID, Agents: r.Agents, Tool: r.Tool, Risk: convert[string, policy.ToolRisk](r.Risk),
			Action: policy.Action(r.Action), Severity: policy.Severity(r.Severity), Message: r.Message}
		if len(r.Args) > 0 && string(r.Args) != "null" {
			v, err := argschema.ParseJSON(r.Args, argsLimits)
			if err != nil {
				return nil, fmt.Errorf("tools.rules[%d].args — %w", i, err)
			}
			// Версия хранится в YAML: число, которое не переживает перевод
			// в float64, сохранилось бы другим — отказ, а не округление.
			if !argschema.Exact(v, argsLimits) {
				return nil, fmt.Errorf("tools.rules[%d].args — число нельзя сохранить точно: не больше 15–17 значащих цифр", i)
			}
			m, ok := argschema.ToAny(v).(map[string]any)
			if !ok {
				return nil, fmt.Errorf("tools.rules[%d].args — ожидается объект", i)
			}
			rs.Args = m
		}
		if r.Rate != nil {
			rs.Rate = &policy.ToolRate{PerMinute: r.Rate.PerMinute, PerHour: r.Rate.PerHour}
		}
		out.Rules = append(out.Rules, rs)
	}
	return out, nil
}

// toolsJSON — раздел для ответа; nil — раздела нет (умолчания совместимости).
func toolsJSON(t *policy.ToolsSpec) *PolicyToolsJSON {
	if t == nil {
		return nil
	}
	out := &PolicyToolsJSON{Unapproved: string(t.Unapproved), Default: string(t.Default),
		Limits: PolicyToolLimitsJSON{AgentPerMinute: t.Limits.AgentPerMinute, SessionCalls: t.Limits.SessionCalls,
			Repeat: t.Limits.Repeat}, Rules: make([]PolicyToolRuleJSON, 0, len(t.Rules))}
	if t.ApprovalTimeout != 0 {
		out.ApprovalTimeout = t.ApprovalTimeout.String()
	}
	if t.Limits.RepeatWindow != 0 {
		out.Limits.RepeatWindow = t.Limits.RepeatWindow.String()
	}
	for _, r := range t.Rules {
		rj := PolicyToolRuleJSON{ID: r.ID, Agents: r.Agents, Tool: r.Tool, Risk: convert[policy.ToolRisk, string](r.Risk),
			Action: string(r.Action), Severity: string(r.Severity), Message: r.Message}
		if r.Args != nil {
			if b, err := json.Marshal(r.Args); err == nil {
				rj.Args = b
			}
		}
		if r.Rate != nil {
			rj.Rate = &PolicyToolRateJSON{PerMinute: r.Rate.PerMinute, PerHour: r.Rate.PerHour}
		}
		out.Rules = append(out.Rules, rj)
	}
	return out
}

// ToolRuleChangeView — изменённое правило tools: имена полей, до и после.
type ToolRuleChangeView struct {
	ID     string             `json:"id"`
	Fields []string           `json:"fields"`
	Before PolicyToolRuleJSON `json:"before"`
	After  PolicyToolRuleJSON `json:"after"`
}

func toolRuleJSON(r policy.ToolRuleSpec) PolicyToolRuleJSON {
	t := toolsJSON(&policy.ToolsSpec{Rules: []policy.ToolRuleSpec{r}})
	return t.Rules[0]
}
