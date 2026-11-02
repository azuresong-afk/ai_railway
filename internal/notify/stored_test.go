package notify

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Канал, сохранённый сервисом, проходит проверку сохранённого канала;
// неверное значение в каждом месте — отказ с именем поля (остаток 5.8,
// остатки волны A этапа 5).
func TestCheckStoredChannel(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	hookURL, signing := "https://hooks.example.ru/synthetic-path", strings.Repeat("k", MinSigningKey)
	stored := map[string]StoredChannel{}
	for name, in := range map[string]ChannelInput{
		"email": {Name: "Почта", Type: TypeEmail, Settings: Settings{Host: "smtp.example.ru", CAPEM: e.caPEM, Username: "aisec",
			From: "aisec@example.ru", To: []string{"soc@example.ru"}}, Secrets: SecretsInput{Password: ptr("synthetic-smtp")}},
		"webhook": {Name: "Hook", Type: TypeWebhook, Settings: Settings{CAPEM: e.caPEM},
			Secrets: SecretsInput{URL: &hookURL, SigningKey: &signing}},
		"syslog": {Name: "SIEM", Type: TypeSyslog, Settings: Settings{Host: "siem.example.ru", CAPEM: e.caPEM}},
	} {
		c, err := e.svc.CreateChannel(ctx, e.by, in)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sec, err := e.svc.secrets(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if sec != (Secrets{}) {
			if raw, err = json.Marshal(sec); err != nil { //nolint:gosec // G117: синтетические секреты теста
				t.Fatal(err)
			}
		}
		settings, err := json.Marshal(c.Settings)
		if err != nil {
			t.Fatal(err)
		}
		sc := StoredChannel{Name: c.Name, Type: c.Type, Enabled: c.Enabled, MinSeverity: c.MinSeverity, Settings: settings,
			SecretFields: c.SecretFields, Secrets: raw, AuditStream: c.AuditStream}
		if err := CheckStoredChannel(e.tp, sc); err != nil {
			t.Fatalf("%s: сохранённый сервисом канал отклонён: %v", name, err)
		}
		stored[name] = sc
	}
	bad := []struct {
		name, base, field string
		change            func(c *StoredChannel)
	}{
		{"url_origin не по адресу", "webhook", "settings", func(c *StoredChannel) {
			c.Settings = []byte(strings.Replace(string(c.Settings), "hooks.example.ru", "other.example.ru", 1))
		}},
		{"неизвестное поле settings", "email", "settings", func(c *StoredChannel) {
			c.Settings = []byte(strings.Replace(string(c.Settings), "{", `{"address":"x",`, 1))
		}},
		{"без значения по умолчанию", "syslog", "settings", func(c *StoredChannel) {
			c.Settings = []byte(strings.Replace(string(c.Settings), `"port":6514,`, "", 1))
		}},
		{"secret_fields не по секретам", "email", "secret_fields", func(c *StoredChannel) { c.SecretFields = []string{} }},
		{"секреты не JSON", "webhook", "secrets", func(c *StoredChannel) { c.Secrets = []byte("not json") }},
		{"неверный корень", "syslog", "ca_pem", func(c *StoredChannel) {
			c.Settings = []byte(strings.ReplaceAll(string(c.Settings), "BEGIN CERTIFICATE", "BEGIN X"))
		}},
		{"пароль SMTP без имени", "email", "settings.username", func(c *StoredChannel) {
			c.Settings = []byte(strings.Replace(string(c.Settings), `"username":"aisec",`, "", 1))
		}},
		{"имя с пробелами", "syslog", "name", func(c *StoredChannel) { c.Name = " SIEM" }},
		{"журнал аудита в почту", "email", "audit_stream", func(c *StoredChannel) { c.AuditStream = true }},
	}
	for _, tc := range bad {
		c := stored[tc.base]
		c.Settings, c.SecretFields, c.Secrets = append([]byte(nil), c.Settings...), append([]string(nil), c.SecretFields...),
			append([]byte(nil), c.Secrets...)
		tc.change(&c)
		err := CheckStoredChannel(e.tp, c)
		var ie *InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), tc.field) {
			t.Errorf("%s: %v", tc.name, err)
		}
		if err != nil && strings.Contains(err.Error(), "synthetic") {
			t.Errorf("%s: значение секрета в ошибке: %v", tc.name, err)
		}
	}
}
