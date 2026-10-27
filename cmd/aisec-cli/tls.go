package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Сертификаты TLS консоли и шлюза для установки без корпоративного УЦ
// (задача 4.32 этапа 4): aisec-cli выпускает их от собственного УЦ
// установки. Закрытый ключ УЦ живёт только в памяти команды и не
// сохраняется: выпустить им другие сертификаты нельзя, поэтому корень,
// который администратор добавляет в доверенные, не опаснее самих
// сертификатов. Перевыпуск — новый УЦ и замена ca.crt у клиентов.
const (
	tlsCAFile          = "ca.crt"
	tlsConsoleCertFile = "console.crt"
	tlsConsoleKeyFile  = "console.key"
	tlsGatewayCertFile = "gateway.crt"
	tlsGatewayKeyFile  = "gateway.key"
	// tlsDefaultDays — срок по умолчанию; предел — MaxCertValidity (825 суток).
	tlsDefaultDays = 365
	// tlsMaxHostsArg ограничивает длину аргумента -hosts до разбора.
	tlsMaxHostsArg = 8 << 10
)

var tlsFileNames = []string{tlsConsoleKeyFile, tlsGatewayKeyFile, tlsConsoleCertFile, tlsGatewayCertFile, tlsCAFile}

func tlsCmd(args []string, stdout, stderr io.Writer, now time.Time) error {
	if len(args) == 0 || args[0] != "init" {
		return errors.New("подкоманда: init")
	}
	fs := flag.NewFlagSet("tls init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "пустой каталог с правами 0700 для сертификатов и ключей (обязательный)")
	hostsArg := fs.String("hosts", "", "имена и IP-адреса консоли и шлюза через запятую (обязательный)")
	days := fs.Int("days", tlsDefaultDays, "срок действия в сутках, от 1 до 825")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *out == "" {
		return errors.New("укажите -out")
	}
	hosts, err := parseTLSHosts(*hostsArg)
	if err != nil {
		return err
	}
	validity := time.Duration(*days) * 24 * time.Hour
	if *days < 1 || validity > aisecCrypto.MaxCertValidity {
		return fmt.Errorf("days: от 1 до %d", int(aisecCrypto.MaxCertValidity/(24*time.Hour)))
	}
	return runTLSInit(*out, hosts, validity, now, stdout)
}

// parseTLSHosts разбирает список имён и адресов: пробелы вокруг элементов
// и пустые элементы отбрасываются, имена проверяются и приводятся к нижнему
// регистру (NormalizeHost), повторы убираются с сохранением порядка.
// Первое имя станет CommonName сертификатов.
func parseTLSHosts(s string) ([]string, error) {
	if len(s) > tlsMaxHostsArg {
		return nil, fmt.Errorf("hosts: длиннее %d байт", tlsMaxHostsArg)
	}
	var hosts []string
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		h, err := aisecCrypto.NormalizeHost(part)
		if err != nil {
			return nil, fmt.Errorf("hosts: %q: %w", part, err)
		}
		if !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	if len(hosts) == 0 {
		return nil, errors.New("укажите -hosts: имена и адреса, по которым открывают консоль и обращаются к шлюзу")
	}
	return hosts, nil
}

// runTLSInit выпускает УЦ и два серверных сертификата на одни и те же
// имена (у консоли и шлюза разные ключи и владельцы) и пишет файлы с
// O_EXCL: существующие не перезаписываются. При ошибке созданные файлы
// удаляются.
func runTLSInit(dir string, hosts []string, validity time.Duration, now time.Time, stdout io.Writer) error {
	root, err := openKeyDir(dir)
	if err != nil {
		return err
	}
	defer closeQuietly(root)
	for _, name := range tlsFileNames {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: файл уже существует или недоступен — tls init не перезаписывает файлы; укажите пустой каталог", name)
		}
	}
	ca, err := aisecCrypto.NewCA("AISec local CA "+now.UTC().Format("2006-01-02 15:04"), validity, now)
	if err != nil {
		return err
	}
	consoleCert, consoleKey, err := ca.IssueServer(hosts, validity, now)
	if err != nil {
		return err
	}
	gatewayCert, gatewayKey, err := ca.IssueServer(hosts, validity, now)
	if err != nil {
		clear(consoleKey)
		return err
	}
	// Закрытые ключи пишутся первыми: при сбое посередине на диске не
	// останется сертификата без ключа, который выглядел бы готовым.
	files := []keyFile{
		{tlsConsoleKeyFile, consoleKey, permSecret},
		{tlsGatewayKeyFile, gatewayKey, permSecret},
		{tlsConsoleCertFile, consoleCert, permPublic},
		{tlsGatewayCertFile, gatewayCert, permPublic},
		{tlsCAFile, ca.CertPEM(), permPublic},
	}
	created, err := writeKeyFiles(root, files)
	if err != nil {
		removeFiles(root, created)
		return err
	}
	say(stdout, "Сертификаты TLS созданы в %s, действуют до %s (UTC):\n", dir, ca.NotAfter().UTC().Format("02.01.2006"))
	for _, f := range files {
		say(stdout, "  %-12s %04o\n", f.name, f.perm)
	}
	say(stdout, "Имена и адреса: %s\n", strings.Join(hosts, ", "))
	say(stdout, "Корень собственного УЦ установки — %s, отпечаток SHA-256:\n  %s\n", tlsCAFile, ca.Fingerprint())
	say(stdout, "Добавьте %s в доверенные корневые сертификаты у администраторов (браузер) и у приложений.\n"+
		"Закрытый ключ УЦ не сохранён: выпустить им другие сертификаты нельзя. Перевыпуск — снова tls init в пустой каталог и замена %s у клиентов.\n",
		tlsCAFile, tlsCAFile)
	return nil
}
