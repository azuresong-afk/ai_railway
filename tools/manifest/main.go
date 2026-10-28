// Команда manifest формирует и подписывает манифест целостности (ТЗ 7.5,
// ОЦЛ.1; решение Р10; ADR-0012, ADR-0022) — цели make manifest, release-dir
// и release-sign.
//
//	manifest build -out build/aisec-manifest.json (-test-key ФАЙЛ | -unsigned) \
//	    -version V -created ВРЕМЯ -bin build/bin -cmds 'aisec-gateway …' \
//	    -static web/dist -migrations migrations [-detect КАТАЛОГ]
//	manifest sign -key ФАЙЛ -manifest build/release/aisec-manifest.json [-expect-sha256 HEX]
//	manifest fingerprint -pub ФАЙЛ
//	manifest gen-key -key ФАЙЛ -pub ФАЙЛ
//	manifest gen-subkey -key ФАЙЛ -pub ФАЙЛ [-test]
//	manifest endorse -key КЛЮЧ_ПРОИЗВОДИТЕЛЯ -subkey-pub ФАЙЛ -purpose service_db -serial N \
//	    -not-after ДАТА [-not-before ДАТА] [-comment ТЕКСТ] -out ФАЙЛ [-test]
//	manifest sign-db -key РАБОЧИЙ_КЛЮЧ -endorsement ФАЙЛ -vendor-pub ФАЙЛ -kind shadow_ai_catalog \
//	    -in catalog.yaml -out ФАЙЛ [-test]
//	manifest inspect-db -in ФАЙЛ
//
// Ключ производителя (-key) хранится вне репозитория на отдельном носителе,
// файл с правами 0400; sign и gen-key работают только на машине без сети
// (ADR-0022), поэтому сборка поставки (build -unsigned) и подпись — разные
// шаги. Тестовый ключ (-test-key) лежит в репозитории и годится только для
// CI и разработки: им подписанный манифест принимают лишь сборки без тега
// aisec_release.
//
// Рабочие ключи служебных баз и лицензий (ADR-0022, п. 2; ADR-0027, п. 3)
// создаются и заверяются ключом производителя тоже только без сети:
// gen-subkey, endorse, sign-db (subkey.go).
package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
}

const commands = "build, sign, fingerprint, gen-key, gen-subkey, endorse, sign-db или inspect-db"

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается команда: " + commands)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	switch args[0] {
	case "build":
		return build(p, args[1:], stdout, stderr)
	case "sign":
		return sign(p, args[1:], stdout, stderr)
	case "fingerprint":
		return fingerprint(p, args[1:], stdout, stderr)
	case "gen-key":
		return genKey(p, args[1:], stdout, stderr)
	case "gen-subkey":
		return genSubkey(p, args[1:], stdout, stderr)
	case "endorse":
		return endorse(p, args[1:], stdout, stderr)
	case "sign-db":
		return signDB(p, args[1:], stdout, stderr)
	case "inspect-db":
		return inspectDB(p, args[1:], stdout, stderr)
	}
	return fmt.Errorf("неизвестная команда %q: ожидается %s", args[0], commands)
}

func build(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "файл манифеста; подпись — рядом, с суффиксом .sig")
	testKey := fs.String("test-key", "", "тестовый ключ из репозитория — НЕ ДЛЯ ПОСТАВКИ")
	unsigned := fs.Bool("unsigned", false, "без подписи: манифест поставки подписывает manifest sign на машине без сети (ADR-0022)")
	version := fs.String("version", "", "версия продукта")
	created := fs.String("created", "", "время сборки, RFC 3339 (время последнего коммита)")
	bin := fs.String("bin", "", "каталог исполняемых файлов")
	cmds := fs.String("cmds", "", "исполняемые файлы поставки через пробел")
	static := fs.String("static", "", "каталог статики веб-консоли (web/dist)")
	migrations := fs.String("migrations", "", "каталог миграций (*.sql)")
	detect := fs.String("detect", "", "каталог служебных баз детекторов (необязательно)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("лишние аргументы: %d", fs.NArg())
	}
	if *out == "" || *bin == "" || *cmds == "" || *static == "" || *migrations == "" || *version == "" {
		return errors.New("обязательны -out, -bin, -cmds, -static, -migrations, -version")
	}
	if (*testKey == "") != *unsigned {
		return errors.New("нужен ровно один из -test-key и -unsigned; ключ производителя — только manifest sign на машине без сети")
	}
	ts, err := time.Parse(time.RFC3339, *created)
	if err != nil {
		return errors.New("-created: ожидается время RFC 3339")
	}
	var signer aisecCrypto.Signer
	if !*unsigned {
		if signer, err = loadTestSigner(p, *testKey); err != nil {
			return err
		}
	}
	sources := []integrity.Source{
		{Kind: integrity.KindBinary, Dir: *bin, Files: strings.Fields(*cmds)},
		{Kind: integrity.KindStatic, Dir: *static, Recursive: true},
		{Kind: integrity.KindMigration, Dir: *migrations, Glob: "*.sql"},
	}
	if *detect != "" {
		sources = append(sources, integrity.Source{Kind: integrity.KindDetectorDB, Dir: *detect, Recursive: true})
	}
	m, err := integrity.Build(p, integrity.BuildInput{Version: *version, Created: ts, Sources: sources})
	if err != nil {
		return err
	}
	data, err := integrity.Marshal(m)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		return err
	}
	// Подпись от прежней сборки рядом с новым манифестом не остаётся: её
	// создаёт только подпись этого манифеста.
	if err := os.Remove(*out + ".sig"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// Манифест и подпись публичны: читаются пользователем службы и администратором.
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // G306: манифест — открытые сведения, не секрет
		return err
	}
	if *unsigned {
		sum, err := manifestSum(p, data)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "Манифест без подписи: %s, версия %s, файлов: %d\nSHA-256 манифеста: %s\n"+
			"Подпишите его на машине без сети: manifest sign -key КЛЮЧ -manifest %s -expect-sha256 %s\n",
			*out, m.Version, len(m.Files), sum, filepath.Base(*out), sum)
		return err
	}
	sig, err := integrity.Sign(signer, data)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out+".sig", sig, 0o644); err != nil { //nolint:gosec // G306: подпись — открытые сведения, не секрет
		return err
	}
	if _, err := fmt.Fprintln(stderr, "manifest: ВНИМАНИЕ: манифест подписан тестовым ключом — НЕ ДЛЯ ПОСТАВКИ"); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Манифест: %s, файлов: %d, подпись: %s.sig\n", *out, len(m.Files), *out)
	return err
}

// loadTestSigner читает тестовый ключ репозитория. Он обязан совпадать со
// встроенным в сборку без aisec_release — иначе манифест не примет ни один
// компонент.
func loadTestSigner(p aisecCrypto.Provider, path string) (aisecCrypto.Signer, error) {
	data, err := aisecCrypto.ReadPEMFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ подписи манифеста: %w", err)
	}
	s, err := decodeSigner(p, path, data)
	if err != nil {
		return nil, err
	}
	v, isTest, err := integrity.EmbeddedVerifier(p)
	if err != nil {
		return nil, err
	}
	if !isTest || !bytes.Equal(v.PublicKey(), s.PublicKey()) {
		return nil, errors.New("тестовый ключ не совпадает с ключом, встроенным в сборку")
	}
	return s, nil
}

// loadVendorSigner читает ключ производителя: файл 0400 или 0600, не ключ из
// репозитория (Н35 ревью 2.r4).
func loadVendorSigner(p aisecCrypto.Provider, path string) (aisecCrypto.Signer, error) {
	data, err := aisecCrypto.ReadKeyFile(path)
	if err != nil {
		return nil, fmt.Errorf("ключ производителя: %w", err)
	}
	s, err := decodeSigner(p, path, data)
	if err != nil {
		return nil, err
	}
	if integrity.IsTestPublicKey(s.PublicKey()) {
		return nil, fmt.Errorf("%s: это ключ из репозитория — для поставки нужен ключ производителя", path)
	}
	return s, nil
}

func decodeSigner(p aisecCrypto.Provider, path string, data []byte) (aisecCrypto.Signer, error) {
	defer clear(data)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, сборка — %s", path, profile, p.Name())
	}
	return p.NewSigner(seed)
}

// manifestSum — хеш байтов манифеста (SHA-256 в профиле standard), hex: по
// нему тот, кто подписывает, сверяет манифест со сборочной машиной.
func manifestSum(p aisecCrypto.Provider, data []byte) (string, error) {
	h, err := p.Hasher()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(data)), nil
}

// netInterfaces подменяют тесты: в контейнере CI сеть есть всегда.
var netInterfaces = net.Interfaces

// checkOffline — ключ производителя используется только на машине без сети
// (решение Р1, ADR-0022): отказ, если работает хотя бы один сетевой
// интерфейс, кроме петлевого. Интерфейс без несущей (кабель отключён,
// Wi-Fi выключен) не считается.
func checkOffline() error {
	ifs, err := netInterfaces()
	if err != nil {
		return fmt.Errorf("проверка сети: %w", err)
	}
	var up []string
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 || i.Flags&net.FlagRunning == 0 {
			continue
		}
		up = append(up, i.Name)
	}
	if len(up) > 0 {
		return fmt.Errorf("ключ производителя используется только на машине без сети (ADR-0022), а работают интерфейсы: %s — отключите их", strings.Join(up, ", "))
	}
	return nil
}

// sign подписывает готовый манифест поставки ключом производителя на машине
// без сети (ADR-0022): манифест разбирается тем же строгим правилом, что и
// при проверке, его хеш сверяется с напечатанным на сборочной машине,
// существующая подпись не перезаписывается, готовая подпись проверяется
// открытым ключом.
func sign(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "закрытый ключ производителя (AISEC MANIFEST SIGNING KEY, права 0400) на отдельном носителе")
	manifest := fs.String("manifest", "", "манифест без подписи (manifest build -unsigned); подпись — рядом, с суффиксом .sig")
	expect := fs.String("expect-sha256", "", "хеш манифеста, напечатанный на сборочной машине (рекомендуется)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *manifest == "" {
		return errors.New("обязательны -key и -manifest")
	}
	if err := checkOffline(); err != nil {
		return err
	}
	info, err := os.Lstat(*manifest)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > integrity.MaxManifestSize {
		return fmt.Errorf("%s: не обычный файл или больше %d байт", *manifest, integrity.MaxManifestSize)
	}
	data, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	m, err := integrity.Parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", *manifest, err)
	}
	if m.Profile != p.Name() {
		return fmt.Errorf("%s: манифест профиля %s, подпись — %s", *manifest, m.Profile, p.Name())
	}
	sum, err := manifestSum(p, data)
	if err != nil {
		return err
	}
	if *expect != "" && !strings.EqualFold(strings.TrimSpace(*expect), sum) {
		return fmt.Errorf("хеш манифеста %s не совпадает с -expect-sha256: манифест изменён после сборки", sum)
	}
	s, err := loadVendorSigner(p, *keyFile)
	if err != nil {
		return err
	}
	fp, err := integrity.Fingerprint(p, s.PublicKey())
	if err != nil {
		return err
	}
	sig, err := integrity.Sign(s, data)
	if err != nil {
		return err
	}
	v, err := p.NewVerifier(s.PublicKey())
	if err != nil {
		return err
	}
	if err := integrity.VerifySignature(v, data, sig); err != nil {
		return err
	}
	// Подпись публична; существующий файл не перезаписывается — подпись
	// другого манифеста или прежняя попытка видны оператору.
	if err := writeNew(*manifest+".sig", sig, 0o644); err != nil {
		return err
	}
	if *expect == "" {
		if _, err := fmt.Fprintln(stderr, "manifest: хеш не сверен (-expect-sha256): сравните SHA-256 ниже с напечатанным на сборочной машине"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "Подписан манифест %s: версия %s, сборка %s, файлов: %d\nSHA-256 манифеста: %s\nОтпечаток ключа производителя: %s\nПодпись: %s.sig\n",
		*manifest, m.Version, m.Created.UTC().Format(time.RFC3339), len(m.Files), sum, fp, *manifest)
	return err
}

// fingerprint печатает отпечаток открытого ключа проверки манифеста — для
// руководства установки и README поставки (ADR-0022).
func fingerprint(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("fingerprint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pubFile := fs.String("pub", "", "открытый ключ (AISEC MANIFEST SIGNING PUBLIC KEY)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *pubFile == "" {
		return errors.New("обязателен -pub")
	}
	data, err := aisecCrypto.ReadPEMFile(*pubFile)
	if err != nil {
		return err
	}
	profile, pub, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		return fmt.Errorf("%s: %w", *pubFile, err)
	}
	if profile != p.Name() {
		return fmt.Errorf("%s: ключ профиля %s, ожидается %s", *pubFile, profile, p.Name())
	}
	fp, err := integrity.Fingerprint(p, pub)
	if err != nil {
		return err
	}
	if integrity.IsTestPublicKey(pub) {
		if _, err := fmt.Fprintln(stderr, "manifest: ВНИМАНИЕ: это ключ из репозитория — НЕ ДЛЯ ПОСТАВКИ"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(stdout, fp)
	return err
}

// genKey создаёт пару ключей манифеста на машине без сети: закрытый — 0400
// без перезаписи, открытый — для internal/integrity/keys/manifest.pub.
// Тестовые пары репозитория создаются так же, с флагом -test (сеть не
// проверяется).
func genKey(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "куда записать закрытый ключ (файл не должен существовать)")
	pubFile := fs.String("pub", "", "куда записать открытый ключ (файл не должен существовать)")
	testPair := fs.Bool("test", false, "тестовая пара для репозитория (testdata/integrity/) — НЕ ДЛЯ ПОСТАВКИ, сеть не проверяется")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *pubFile == "" {
		return errors.New("обязательны -key и -pub")
	}
	if !*testPair {
		if err := checkOffline(); err != nil {
			return err
		}
	}
	s, err := p.GenerateSigner()
	if err != nil {
		return err
	}
	seed := s.Seed()
	defer clear(seed)
	priv, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindManifestSigning, p.Name(), seed)
	if err != nil {
		return err
	}
	defer clear(priv)
	pub, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindManifestSigningPublic, p.Name(), s.PublicKey())
	if err != nil {
		return err
	}
	if err := writeNew(*keyFile, priv, 0o400); err != nil {
		return err
	}
	if err := writeNew(*pubFile, pub, 0o444); err != nil {
		return err
	}
	fp, err := integrity.Fingerprint(p, s.PublicKey())
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Ключ: %s\nОткрытый ключ: %s\nОтпечаток: %s\n", *keyFile, *pubFile, fp)
	return err
}

func writeNew(path string, data []byte, perm os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm) //nolint:gosec // G304: путь задаёт производитель в командной строке
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	_, err = f.Write(data)
	return err
}
