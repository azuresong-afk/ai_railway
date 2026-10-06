// Команда devcerts выпускает материалы для стенда разработки: УЦ и серверный
// сертификат для шлюза и mock-llm, ключ приложения и файл конфигурации шлюза
// с его хешем. Только для разработки; в поставку не входит. Закрытый ключ УЦ
// не сохраняется: после выпуска он не нужен, а значит, не может утечь со стенда.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

func main() {
	out := flag.String("out", ".dev-keys", "каталог для сертификатов (создаётся с правами 0700)")
	hosts := flag.String("hosts", "localhost,127.0.0.1,::1,aisec-gateway,mock-llm", "имена и адреса через запятую")
	days := flag.Int("days", 30, "срок действия, дней")
	force := flag.Bool("force", false, "перезаписать существующие файлы")
	flag.Parse()

	if err := run(*out, splitHosts(*hosts), time.Duration(*days)*24*time.Hour, *force, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "devcerts:", err)
		os.Exit(1)
	}
}

func splitHosts(s string) []string {
	var out []string
	for _, h := range strings.Split(s, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// Имена файлов в каталоге.
const (
	CAFile     = "ca.pem"
	CertFile   = "server.pem"
	KeyFile    = "server-key.pem"
	AppKeyFile = "app-key"      // ключ приложения стенда (Authorization: Bearer)
	ConfigFile = "gateway.yaml" // конфигурация шлюза стенда
	dirPerm    = 0o700
	publicPerm = 0o644
	secretPerm = 0o600
)

func run(dir string, hosts []string, validity time.Duration, force bool, now time.Time) error {
	if len(hosts) == 0 {
		return errors.New("не указано ни одного имени")
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return err
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return err
	}
	if !force {
		for _, f := range []string{CAFile, CertFile, KeyFile, AppKeyFile, ConfigFile} {
			if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
				return fmt.Errorf("%s уже существует; укажите -force, чтобы перезаписать", filepath.Join(dir, f))
			}
		}
	}
	ca, err := aisecCrypto.NewCA("AISec dev CA (только для разработки)", validity, now)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.IssueServer(hosts, validity, now)
	if err != nil {
		return err
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	rnd, err := p.Random()
	if err != nil {
		return err
	}
	h, err := p.Hasher()
	if err != nil {
		return err
	}
	appKey, prefix, hash, err := auth.NewAppKey(rnd, h)
	if err != nil {
		return err
	}
	expires := now.Add(validity).UTC().Format(time.DateOnly)
	// Ключ пишется первым и с правами 0600: даже при сбое посередине он не
	// окажется доступен другим пользователям.
	for _, f := range []struct {
		name string
		data []byte
		perm os.FileMode
	}{
		{KeyFile, keyPEM, secretPerm},
		{AppKeyFile, []byte(appKey + "\n"), secretPerm},
		{CertFile, certPEM, publicPerm},
		{CAFile, ca.CertPEM(), publicPerm},
		{ConfigFile, []byte(devConfig + auth.FormatKeyEntry(prefix, hash, expires)), publicPerm},
	} {
		if err := writeFile(filepath.Join(dir, f.name), f.data, f.perm); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(os.Stdout, "devcerts: %s, %s, %s, %s, %s в %s (до %s)\n",
		CAFile, CertFile, KeyFile, AppKeyFile, ConfigFile, dir, now.Add(validity).Format("02.01.2006"))
	return err
}

// devConfig — конфигурация шлюза стенда (docker compose, deploy/compose/dev):
// пути — внутри контейнера; ключ приложения дописывается при выпуске.
const devConfig = `# Конфигурация шлюза стенда разработки. Создана tools/devcerts; не для поставки.
schema_version: 1
gateway:
  events_file: /data/events.jsonl
providers:
  - id: mock
    type: openai
    base_url: https://mock-llm:9443
    ca_file: /keys/ca.pem
applications:
  - id: dev-app
    name: Приложение стенда разработки
    env: test
    provider: mock
    models: [mock-echo, mock-stream-slow]
    policy: base
    policy_mode: monitor
    fail_mode: fail_closed
    storage: none
    user_from: none
    keys:
`

// writeFile записывает файл через временный и переименование, выставляя права
// до записи содержимого.
func writeFile(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".devcerts-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) //nolint:errcheck // после переименования файла уже нет; ошибка не важна
	if err := tmp.Chmod(perm); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if _, err := tmp.Write(data); err != nil {
		return errors.Join(err, tmp.Close())
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
