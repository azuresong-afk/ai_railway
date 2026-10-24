package bundle

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

const tlsKeyPEM = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElD\n-----END PRIVATE KEY-----\n"

// Ключ сертификата заказчика среди секретов (задача 3.27): ровно тогда,
// когда в содержимом есть раздел gateway_tls, один раз и отдельным
// элементом; иначе пакет отклоняется.
func TestParseSecretsGatewayTLS(t *testing.T) {
	sec := &GatewayTLS{Host: "aisec-gw.example.ru", ChainPEM: "x", Fingerprint: strings.Repeat("a", 64), NotAfter: time.Now()}
	with := &Content{Providers: []Provider{{ID: "llm"}}, GatewayTLS: sec}
	without := &Content{Providers: []Provider{{ID: "llm"}}}
	cases := []struct {
		name  string
		plain string
		c     *Content
		want  string
	}{
		{"ключ без раздела", `[{"provider":"llm","credential":"k"},{"tls_key":"` + strings.ReplaceAll(tlsKeyPEM, "\n", `\n`) + `"}]`, without, "без раздела gateway_tls"},
		{"ключ дважды", `[{"tls_key":"a"},{"tls_key":"b"}]`, with, "дважды"},
		{"ключ вместе с провайдером", `[{"provider":"llm","credential":"k","tls_key":"a"}]`, with, "вместе с учётными данными"},
		{"раздел без ключа", `[{"provider":"llm","credential":"k"}]`, with, "без ключа сертификата"},
		{"ключ не PEM", `[{"tls_key":"\u0001"}]`, with, "только PEM"},
		{"ключ слишком большой", fmt.Sprintf(`[{"tls_key":"%s"}]`, strings.Repeat("A", 16<<10+1)), with, "до 16384 байт"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, _, err := parseSecrets([]byte(c.plain), c.c)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("ожидалась ошибка %q: %v", c.want, err)
			}
		})
	}
	sec2, key, err := parseSecrets([]byte(`[{"provider":"llm","credential":"k"},{"tls_key":"`+strings.ReplaceAll(tlsKeyPEM, "\n", `\n`)+`"}]`), with)
	if err != nil || string(key) != tlsKeyPEM || sec2["llm"] != "k" {
		t.Fatalf("верные секреты: %v %v", sec2, err)
	}
	// Ключ при выводе в журнал скрыт.
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("пакет", "key", key)
	if s := b.String() + fmt.Sprintf("%v %s %q", key, key, key); strings.Contains(s, "PRIVATE") {
		t.Fatalf("ключ в выводе: %s", s)
	}
}
