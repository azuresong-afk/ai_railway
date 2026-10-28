package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Проверка готовых сертификатов TLS до установки (задача 4.33 этапа 4):
// сертификаты УЦ заказчика или выпущенные tls init. Каталог — те же пять
// файлов, что пишет tls init; цепочки и ключи проверяет
// internal/crypto.ParseServerCert — та же функция, что принимает
// сертификат заказчика для адреса шлюза в консоли (задача 3.27).

// tlsExpiryWarn — меньше этого срока до конца действия — предупреждение.
const tlsExpiryWarn = 30 * 24 * time.Hour

// tlsCheckPair — сертификат и ключ одного сервиса и имена, которые должны
// быть в SAN сертификата.
type tlsCheckPair struct {
	cert, key string
	names     []string
}

// tlsCheckReport — итог по пунктам: строки для вывода и счётчики.
type tlsCheckReport struct {
	lines         []string
	errors, warns int
}

func (r *tlsCheckReport) ok(format string, a ...any) {
	r.lines = append(r.lines, "  [в порядке] "+fmt.Sprintf(format, a...))
}

func (r *tlsCheckReport) fail(format string, a ...any) {
	r.errors++
	r.lines = append(r.lines, "  [ошибка] "+fmt.Sprintf(format, a...))
}

func (r *tlsCheckReport) warn(format string, a ...any) {
	r.warns++
	r.lines = append(r.lines, "  [внимание] "+fmt.Sprintf(format, a...))
}

func tlsCheckCmd(args []string, stdout, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("tls check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "каталог с console.crt, console.key, gateway.crt, gateway.key и ca.crt (обязательный)")
	hostsArg := fs.String("hosts", "", "имена и IP-адреса, по которым открывают консоль и обращаются к шлюзу, через запятую (обязательный)")
	consoleName := fs.String("console-name", "", "имя консоли внутри установки (AISEC_CONSOLE_HOST): должно быть в сертификате консоли")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *dir == "" {
		return errors.New("укажите -dir")
	}
	hosts, err := parseTLSHosts(*hostsArg)
	if err != nil {
		return err
	}
	consoleNames := hosts
	if *consoleName != "" {
		name, err := aisecCrypto.NormalizeHost(*consoleName)
		if err != nil {
			return fmt.Errorf("console-name: %q — нужно DNS-имя или IP-адрес без зоны", *consoleName)
		}
		consoleNames = appendUnique([]string{name}, hosts)
	}
	root, err := os.OpenRoot(*dir)
	if err != nil {
		return fmt.Errorf("каталог сертификатов: %w", err)
	}
	defer closeQuietly(root)
	rep := runTLSCheck(root, []tlsCheckPair{
		{tlsConsoleCertFile, tlsConsoleKeyFile, consoleNames},
		{tlsGatewayCertFile, tlsGatewayKeyFile, hosts},
	}, now)
	say(stdout, "Проверка сертификатов TLS в %s на %s (UTC):\n", *dir, now.UTC().Format("02.01.2006 15:04"))
	for _, l := range rep.lines {
		say(stdout, "%s\n", l)
	}
	if rep.errors > 0 {
		say(stdout, "Итог: ошибок — %d, предупреждений — %d. С такими сертификатами установку не продолжайте.\n", rep.errors, rep.warns)
		return fmt.Errorf("сертификаты не прошли проверку: ошибок — %d", rep.errors)
	}
	say(stdout, "Итог: ошибок нет, предупреждений — %d. Сертификаты годятся для установки.\n", rep.warns)
	return nil
}

// appendUnique добавляет к list имена из more, которых в нём ещё нет.
func appendUnique(list, more []string) []string {
	for _, m := range more {
		dup := false
		for _, l := range list {
			if l == m {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, m)
		}
	}
	return list
}

// runTLSCheck проверяет ca.crt (ровно один самоподписанный сертификат УЦ)
// и каждую пару: цепочка «сертификат, промежуточные» плюс корень из ca.crt
// и ключ разбираются ParseServerCert для каждого имени — пара ключа,
// стойкость ключей, keyUsage и serverAuth, срок каждого сертификата,
// путь до корня без лишних сертификатов, имя в SAN (IP — в IP SAN).
func runTLSCheck(root *os.Root, pairs []tlsCheckPair, now time.Time) *tlsCheckReport {
	rep := &tlsCheckReport{}
	caPEM, caDER, err := readTLSCA(root, now, rep)
	if err != nil {
		rep.fail("%s: %v", tlsCAFile, err)
		for _, p := range pairs {
			rep.fail("%s и %s: не проверены — сначала исправьте %s", p.cert, p.key, tlsCAFile)
		}
		return rep
	}
	for _, p := range pairs {
		checkTLSPair(root, p, caPEM, caDER, now, rep)
	}
	return rep
}

// readTLSCA читает ca.crt: один блок CERTIFICATE, корень УЦ (CheckRootDER).
func readTLSCA(root *os.Root, now time.Time, rep *tlsCheckReport) (caPEM, der []byte, err error) {
	data, err := readTLSFile(root, tlsCAFile, aisecCrypto.MaxServerChainPEM)
	if err != nil {
		return nil, nil, err
	}
	der, err = aisecCrypto.CertDER(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w — в файле должен быть ровно один корневой сертификат УЦ; промежуточные — в %s и %s после сертификата", err, tlsConsoleCertFile, tlsGatewayCertFile)
	}
	notAfter, err := aisecCrypto.CheckRootDER(der)
	if err != nil {
		return nil, nil, fmt.Errorf("%w — нужен самоподписанный корневой сертификат УЦ, выпустившего сертификаты консоли и шлюза", err)
	}
	if !now.Before(notAfter) {
		return nil, nil, fmt.Errorf("корневой сертификат истёк %s", notAfter.UTC().Format("02.01.2006"))
	}
	rep.ok("%s: корневой сертификат УЦ, действует до %s", tlsCAFile, notAfter.UTC().Format("02.01.2006"))
	return aisecCrypto.CertPEMFromDER(der), der, nil
}

func checkTLSPair(root *os.Root, p tlsCheckPair, caPEM, caDER []byte, now time.Time, rep *tlsCheckReport) {
	what := p.cert + " и " + p.key
	certPEM, err := readTLSFile(root, p.cert, aisecCrypto.MaxServerChainPEM)
	if err != nil {
		rep.fail("%s: %v", p.cert, err)
		return
	}
	keyPEM, err := readTLSFile(root, p.key, aisecCrypto.MaxServerKeyPEM)
	if err != nil {
		rep.fail("%s: %v", p.key, err)
		return
	}
	defer clear(keyPEM)
	// Корень в файле сертификата допустим (так выгружают «полную цепочку»),
	// второй раз он не добавляется: иначе ParseServerCert увидит лишний
	// сертификат.
	chain := certPEM
	if !pemHasCert(certPEM, caDER) {
		chain = append(append([]byte{}, certPEM...), caPEM...)
	}
	var (
		sc       aisecCrypto.ServerCert
		okNames  int
		problems []string
	)
	for _, name := range p.names {
		got, key, err := aisecCrypto.ParseServerCert(chain, keyPEM, name, now)
		clear(key)
		if err != nil {
			msg := err.Error()
			dup := false
			for _, pr := range problems {
				if pr == msg {
					dup = true
					break
				}
			}
			if !dup {
				problems = append(problems, msg)
			}
			continue
		}
		sc = got
		okNames++
	}
	if len(problems) > 0 {
		for _, pr := range problems {
			rep.fail("%s: %s", what, pr)
		}
		return
	}
	if okNames == 0 {
		rep.fail("%s: нет имён для проверки", what)
		return
	}
	// ParseServerCert находит лист по ключу в любом месте цепочки, а сервер и
	// шлюз загружают файл как есть (tls.X509KeyPair): ключу должен
	// соответствовать первый сертификат файла.
	if leaf, _ := pem.Decode(sc.ChainPEM); leaf == nil || !bytes.Equal(firstCertDER(certPEM), leaf.Bytes) {
		rep.fail("%s: первым в %s должен быть сам сертификат сервиса, за ним — промежуточные сертификаты УЦ", what, p.cert)
		return
	}
	rep.ok("%s: %s, цепочка из %d сертификатов до корня из %s, назначение serverAuth, действует до %s; имена: %s",
		what, sc.KeyAlg, sc.ChainLen, tlsCAFile, sc.NotAfter.Format("02.01.2006"), tlsNamesLine(sc))
	if left := sc.NotAfter.Sub(now); left < tlsExpiryWarn {
		rep.warn("%s: до конца срока цепочки меньше 30 суток (до %s) — закажите новые сертификаты заранее", p.cert, sc.NotAfter.Format("02.01.2006 15:04"))
	}
}

// tlsNamesLine — имена и адреса из SAN, не больше десяти.
func tlsNamesLine(sc aisecCrypto.ServerCert) string {
	names := append(append([]string{}, sc.DNSNames...), sc.IPAddresses...)
	if len(names) > 10 {
		names = append(names[:10], fmt.Sprintf("и ещё %d", len(names)-10))
	}
	return strings.Join(names, ", ")
}

// firstCertDER — содержимое первого блока PEM, если это CERTIFICATE.
func firstCertDER(data []byte) []byte {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	return block.Bytes
}

// pemHasCert сообщает, есть ли в data блок CERTIFICATE с содержимым der.
// Повреждённые данные — «нет»: их разберёт и отклонит ParseServerCert.
// Покрыт fuzz-тестом FuzzPEMHasCert.
func pemHasCert(data, der []byte) bool {
	rest := data
	for range aisecCrypto.MaxServerChainCerts + 1 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, der) {
			return true
		}
	}
	return false
}

// readTLSFile читает обычный файл каталога не больше limit байт: ссылки,
// каталоги и устройства не принимаются, os.Root не выпускает за каталог.
func readTLSFile(root *os.Root, name string, limit int64) (data []byte, err error) {
	info, err := root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("нет файла")
	}
	if err != nil {
		return nil, fmt.Errorf("не читается: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("не обычный файл (символьные ссылки, каталоги и устройства не принимаются)")
	}
	if info.Size() == 0 {
		return nil, errors.New("пустой файл")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("больше %d КиБ", limit>>10)
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, fmt.Errorf("не читается: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	// Повторно — на открытом дескрипторе: файл могли подменить после Lstat
	// (например, каналом FIFO, чтение из которого зависло бы).
	if info, err = f.Stat(); err != nil {
		return nil, fmt.Errorf("не читается: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("файл подменён во время проверки")
	}
	data, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("не читается: %w", err)
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, fmt.Errorf("больше %d КиБ", limit>>10)
	}
	return data, nil
}
