// Команда manifest формирует и подписывает манифест целостности (ТЗ 7.5,
// ОЦЛ.1; решение Р10; ADR-0012) — цель make manifest.
//
//	manifest build -out build/aisec-manifest.json (-key ФАЙЛ | -test-key ФАЙЛ) \
//	    -version V -created ВРЕМЯ -bin build/bin -cmds 'aisec-gateway …' \
//	    -static web/dist -migrations migrations [-detect КАТАЛОГ]
//	manifest gen-key -key ФАЙЛ -pub ФАЙЛ
//
// Ключ производителя (-key) хранится вне репозитория, файл с правами 0400.
// Тестовый ключ (-test-key) лежит в репозитории и годится только для CI и
// разработки: им подписанный манифест принимают лишь сборки без тега
// aisec_release.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
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

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("ожидается команда: build или gen-key")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		return err
	}
	switch args[0] {
	case "build":
		return build(p, args[1:], stdout, stderr)
	case "gen-key":
		return genKey(p, args[1:], stderr)
	}
	return fmt.Errorf("неизвестная команда %q: ожидается build или gen-key", args[0])
}

func build(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "файл манифеста; подпись — рядом, с суффиксом .sig")
	keyFile := fs.String("key", "", "закрытый ключ производителя (AISEC MANIFEST SIGNING KEY, права 0400)")
	testKey := fs.String("test-key", "", "тестовый ключ из репозитория — НЕ ДЛЯ ПОСТАВКИ")
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
	if (*keyFile == "") == (*testKey == "") {
		return errors.New("нужен ровно один из -key и -test-key")
	}
	ts, err := time.Parse(time.RFC3339, *created)
	if err != nil {
		return errors.New("-created: ожидается время RFC 3339")
	}
	signer, err := loadSigner(p, *keyFile, *testKey)
	if err != nil {
		return err
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
	sig, err := integrity.Sign(signer, data)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o750); err != nil {
		return err
	}
	// Манифест и подпись публичны: читаются пользователем службы и администратором.
	if err := os.WriteFile(*out, data, 0o644); err != nil { //nolint:gosec // G306: манифест — открытые сведения, не секрет
		return err
	}
	if err := os.WriteFile(*out+".sig", sig, 0o644); err != nil { //nolint:gosec // G306: подпись — открытые сведения, не секрет
		return err
	}
	if *testKey != "" {
		if _, err := fmt.Fprintln(stderr, "manifest: ВНИМАНИЕ: манифест подписан тестовым ключом — НЕ ДЛЯ ПОСТАВКИ"); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(stdout, "Манифест: %s, файлов: %d, подпись: %s.sig\n", *out, len(m.Files), *out)
	return err
}

// loadSigner читает ключ производителя (строгие права файла) или тестовый
// ключ репозитория. Тестовый ключ обязан совпадать со встроенным в сборку
// без aisec_release — иначе манифест не примет ни один компонент.
func loadSigner(p aisecCrypto.Provider, keyFile, testKey string) (aisecCrypto.Signer, error) {
	var (
		data []byte
		err  error
		path = keyFile
	)
	if keyFile != "" {
		data, err = aisecCrypto.ReadKeyFile(keyFile)
	} else {
		path = testKey
		data, err = aisecCrypto.ReadPEMFile(testKey)
	}
	if err != nil {
		return nil, fmt.Errorf("ключ подписи манифеста: %w", err)
	}
	defer clear(data)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindManifestSigning)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if profile != p.Name() {
		return nil, fmt.Errorf("%s: ключ профиля %s, сборка — %s", path, profile, p.Name())
	}
	s, err := p.NewSigner(seed)
	if err != nil {
		return nil, err
	}
	// Тестовый ключ через -key — путь в поставку для ключа из репозитория (Н35).
	if keyFile != "" && integrity.IsTestPublicKey(s.PublicKey()) {
		return nil, fmt.Errorf("%s: это тестовый ключ репозитория — для поставки нужен ключ производителя", path)
	}
	if testKey != "" {
		v, isTest, err := integrity.EmbeddedVerifier(p)
		if err != nil {
			return nil, err
		}
		if !isTest || !bytes.Equal(v.PublicKey(), s.PublicKey()) {
			return nil, errors.New("тестовый ключ не совпадает с ключом, встроенным в сборку")
		}
	}
	return s, nil
}

// genKey создаёт пару ключей манифеста: закрытый — 0400 без перезаписи,
// открытый — для internal/integrity/keys/.
func genKey(p aisecCrypto.Provider, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("gen-key", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "куда записать закрытый ключ (файл не должен существовать)")
	pubFile := fs.String("pub", "", "куда записать открытый ключ (файл не должен существовать)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *pubFile == "" {
		return errors.New("обязательны -key и -pub")
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
	return writeNew(*pubFile, pub, 0o444)
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
