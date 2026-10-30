package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

// aisec-cli servicedb inspect (ADR-0028, п. 8): проверка файла встроенным
// ключом производителя без сети и БД; при отказе — код 1 и причина.
func TestServicedbInspect(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	good, err := os.ReadFile("../../testdata/shadowai/catalog-test.aisecdb")
	if err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	_, testKey, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	var out, errOut bytes.Buffer
	code := run([]string{"servicedb", "inspect", write("good.aisecdb", good)}, &out, &errOut, now)
	// Тестовый каталог подписан ключами репозитория: его принимает только
	// сборка без aisec_release.
	if testKey && (code != 0 || !strings.Contains(out.String(), "Вид: shadow_ai_catalog (Каталог ИИ-сервисов)") ||
		!strings.Contains(out.String(), "Версия: 1 от 2026-10-28, записей: 28") || !strings.Contains(out.String(), "номер 1")) {
		t.Fatalf("верный файл: %d %s %s", code, out.String(), errOut.String())
	}
	if !testKey && (code != 1 || !strings.Contains(out.String(), "НЕ ПРИНЯТ")) {
		t.Fatalf("поставочная сборка приняла тестовый файл: %d %s", code, out.String())
	}
	for name, tc := range map[string]struct {
		args []string
		want string
	}{
		"подпись испорчена": {[]string{"servicedb", "inspect", write("bad.aisecdb",
			bytes.Replace(good, []byte(`"signature":"`), []byte(`"signature":"AAAA`), 1))}, "НЕ ПРИНЯТ — подпись"},
		"не служебная база": {[]string{"servicedb", "inspect", write("x.aisecdb", []byte("{}"))}, "не служебная база"},
		"нет файла":         {[]string{"servicedb", "inspect", filepath.Join(dir, "none")}, "no such file"},
		"каталог":           {[]string{"servicedb", "inspect", dir}, "не обычный файл"},
		"сверх размера":     {[]string{"servicedb", "inspect", write("big", bytes.Repeat([]byte(" "), aisecCrypto.MaxServiceDBSize+1))}, "больше"},
		"без файла":         {[]string{"servicedb", "inspect"}, "укажите один файл"},
		"подписи нет":       {[]string{"servicedb", "sign"}, "подкоманда: inspect"},
	} {
		out.Reset()
		errOut.Reset()
		if code := run(tc.args, &out, &errOut, now); code != 1 || !strings.Contains(out.String()+errOut.String(), tc.want) {
			t.Errorf("%s: код %d, вывод %q %q", name, code, out.String(), errOut.String())
		}
	}
}
