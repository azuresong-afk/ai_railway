package compliance

import (
	"strings"
	"testing"
	"time"
)

func run(t *testing.T, s *Snapshot, name string, params map[string]string) CheckResult {
	t.Helper()
	if err := validateCheckRef(CheckRef{Name: name, Params: params}); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return RunCheck(s, CheckRef{Name: name, Params: params})
}

// Каждая проверка: выполнено, не выполнено и граничный случай.
func TestChecks(t *testing.T) {
	good := goodSnapshot
	type tc struct {
		name   string
		params map[string]string
		mod    func(*Snapshot)
		want   Status
		detail string
	}
	cases := []tc{
		{"filter_enforced", map[string]string{"direction": "input"}, nil, StatusMet, "включена для 1 из 1 приложений промышленной среды"},
		{"filter_enforced", map[string]string{"direction": "output"}, func(s *Snapshot) { s.Apps[0].OutputRules = 0 }, StatusNotMet, "для 0 из 1"},
		{"filter_enforced", nil, func(s *Snapshot) { s.Apps[0].PolicyMode = "monitor" }, StatusNotMet, "для 0 из 1"},
		// Граничный случай: приложений нет.
		{"filter_enforced", nil, func(s *Snapshot) { s.Apps = nil }, StatusNotApplicable, "Нет приложений промышленной среды"},
		// Все приложения в тесте: промышленных нет — не применимо; для env=test считается.
		{"filter_enforced", nil, func(s *Snapshot) { s.Apps[0].Env = "test" }, StatusNotApplicable, "Нет приложений"},
		{"filter_enforced", map[string]string{"env": "test"}, func(s *Snapshot) { s.Apps[0].Env = "test" }, StatusMet, "тестовой среды"},
		{"filter_enforced", map[string]string{"env": "any"}, func(s *Snapshot) {
			s.Apps = append(s.Apps, AppFact{Slug: "t", Env: "test", PolicyMode: "monitor"})
		}, StatusPartial, "для 1 из 2 приложений всех сред"},
		{"pii_protection_external", nil, nil, StatusMet, "1 из 1"},
		{"pii_protection_external", nil, func(s *Snapshot) { s.Apps[0].PIIRules = 0 }, StatusNotMet, "0 из 1"},
		{"pii_protection_external", nil, func(s *Snapshot) { s.Apps[0].ExternalProvider = false }, StatusNotApplicable, "Нет приложений с внешним провайдером"},
		{"content_storage", nil, nil, StatusMet, "1 из 1"},
		{"content_storage", nil, func(s *Snapshot) { s.Apps[0].Storage = "none" }, StatusNotMet, "0 из 1"},
		{"quota_configured", nil, nil, StatusMet, "Квоты заданы"},
		{"quota_configured", map[string]string{"field": "tokens_per_day"}, nil, StatusNotMet, "0 из 1"},
		{"quota_configured", map[string]string{"field": "max_input_bytes"}, nil, StatusMet, "Предел объёма входных данных"},
		{"quota_configured", nil, func(s *Snapshot) { s.Apps[0].Quotas = map[string]int{} }, StatusNotMet, "0 из 1"},
		{"model_list_restricted", nil, nil, StatusMet, "1 из 1"},
		{"model_list_restricted", nil, func(s *Snapshot) { s.Apps[0].Models = 0 }, StatusNotMet, "0 из 1"},
		{"tool_policy_strict", nil, nil, StatusMet, "1 из 1"},
		{"tool_policy_strict", nil, func(s *Snapshot) { s.Apps[0].ToolsBlockUnapproved = false }, StatusNotMet, "0 из 1"},
		{"mfa_privileged_roles", nil, nil, StatusMet, "2 из 2"},
		{"mfa_privileged_roles", nil, func(s *Snapshot) { s.PrivilegedRoles[1].MFA = false }, StatusPartial, "1 из 2"},
		{"mfa_privileged_roles", nil, func(s *Snapshot) { s.PrivilegedRoles[1].MFA = false; s.MFARequiredAll = true }, StatusMet, "2 из 2"},
		// Роли без пользователей не считаются; если их нет вовсе — не применимо.
		{"mfa_privileged_roles", nil, func(s *Snapshot) { s.PrivilegedRoles = []RoleFact{{ID: "x", Users: 0}} }, StatusNotApplicable, "Нет ролей"},
		{"audit_chain_verified", nil, nil, StatusMet, "цела"},
		{"audit_chain_verified", nil, func(s *Snapshot) { s.AuditChain = nil }, StatusNotMet, "ещё не было"},
		{"audit_chain_verified", nil, func(s *Snapshot) { s.AuditChain.OK = false }, StatusNotMet, "нарушение"},
		{"audit_chain_verified", nil, func(s *Snapshot) { s.AuditChain.CheckedAt = testNow.Add(-49 * time.Hour) }, StatusPartial, "старше 48 ч"},
		// Граница срока: ровно 48 часов ещё допустимо.
		{"audit_chain_verified", nil, func(s *Snapshot) { s.AuditChain.CheckedAt = testNow.Add(-48 * time.Hour) }, StatusMet, "цела"},
		{"integrity_verified", nil, nil, StatusMet, "(1)"},
		{"integrity_verified", nil, func(s *Snapshot) { s.Integrity.ServerOK = false }, StatusNotMet, "сервера не пройдены"},
		{"integrity_verified", nil, func(s *Snapshot) { s.Integrity.GatewaysOK = 0 }, StatusPartial, "0 из 1"},
		{"integrity_verified", nil, func(s *Snapshot) { s.Integrity = nil }, StatusNotMet, "ещё нет"},
		{"alert_rules_enabled", map[string]string{"min": "3"}, nil, StatusMet, "10"},
		{"alert_rules_enabled", map[string]string{"min": "3"}, func(s *Snapshot) { s.AlertRulesEnabled = 2 }, StatusPartial, "2"},
		{"alert_rules_enabled", nil, func(s *Snapshot) { s.AlertRulesEnabled = 0 }, StatusNotMet, "0"},
		{"notification_channel", nil, nil, StatusMet, "1"},
		{"notification_channel", nil, func(s *Snapshot) { s.ChannelsEnabled = 0 }, StatusNotMet, "Ни один канал"},
	}
	covered := map[string]bool{}
	for i, c := range cases {
		s := good()
		if c.mod != nil {
			c.mod(s)
		}
		r := run(t, s, c.name, c.params)
		covered[c.name] = true
		if r.Status != c.want || !strings.Contains(r.Detail, c.detail) {
			t.Errorf("#%d %s %v: %s %q; ожидалось %s с %q", i, c.name, c.params, r.Status, r.Detail, c.want, c.detail)
		}
		if r.Title == "" {
			t.Errorf("%s: нет названия", c.name)
		}
	}
	for _, n := range CheckNames() {
		if !covered[n] {
			t.Errorf("проверка %s без теста", n)
		}
	}
}

// Нет данных от источника — проверка не засчитывается.
func TestCheckUnavailableGroup(t *testing.T) {
	groups := map[string]string{"filter_enforced": GroupApps, "mfa_privileged_roles": GroupRoles, "audit_chain_verified": GroupAuditChain,
		"integrity_verified": GroupIntegrity, "alert_rules_enabled": GroupAlerts, "notification_channel": GroupChannels}
	for name, g := range groups {
		s := goodSnapshot()
		s.Unavailable[g] = true
		r := run(t, s, name, nil)
		if r.Status != StatusNotMet || !strings.HasPrefix(r.Detail, "Нет данных") {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestRunCheckUnknown(t *testing.T) {
	r := RunCheck(goodSnapshot(), CheckRef{Name: "nope"})
	if r.Status != StatusNotMet {
		t.Fatalf("неизвестная проверка: %+v", r)
	}
}
