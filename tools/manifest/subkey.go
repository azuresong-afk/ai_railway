package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
	"github.com/azuresong-afk/ai_railway/internal/servicedb/kinds"
	"github.com/azuresong-afk/ai_railway/internal/shadowai"
)

// Рабочие ключи производителя и служебные базы (ADR-0022, п. 2; ADR-0027,
// п. 2–3). Все команды с закрытыми ключами работают только на машине без
// сети; -test — тестовые пары репозитория (testdata/shadowai/), сеть не
// проверяется, а заверение подписывает тестовый ключ производителя.

// dbSummary — краткое описание проверенного содержимого базы.
func dbSummary(k servicedb.Kind, c servicedb.Content) string {
	return fmt.Sprintf("%s: версия %d от %s, записей: %d", k.Title, c.Version, c.Date.Format(time.DateOnly), c.Records)
}

// genSubkey создаёт пару рабочего ключа: закрытый — 0400 без перезаписи,
// открытый переносится на заверение (endorse).
func genSubkey(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gen-subkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "куда записать закрытый рабочий ключ (файл не должен существовать)")
	pubFile := fs.String("pub", "", "куда записать открытый рабочий ключ (файл не должен существовать)")
	testPair := fs.Bool("test", false, "тестовая пара для репозитория — НЕ ДЛЯ ПОСТАВКИ, сеть не проверяется")
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
	priv, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindVendorSubkey, p.Name(), seed)
	if err != nil {
		return err
	}
	defer clear(priv)
	pub, err := aisecCrypto.EncodeKeyPEM(aisecCrypto.KeyKindVendorSubkeyPublic, p.Name(), s.PublicKey())
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
	_, err = fmt.Fprintf(stdout, "Рабочий ключ: %s\nОткрытый ключ: %s\nОтпечаток: %s\n", *keyFile, *pubFile, fp)
	return err
}

// parseDay — ГГГГ-ММ-ДД (полночь UTC) или RFC 3339.
func parseDay(s string) (time.Time, error) {
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%q: ожидается ГГГГ-ММ-ДД или RFC 3339", s)
	}
	return t.UTC(), nil
}

// endorse подписывает заявление о рабочем ключе ключом производителя
// (контекст aisec-vendor-subkey-v1) на машине без сети.
func endorse(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("endorse", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "закрытый ключ производителя (AISEC MANIFEST SIGNING KEY, права 0400) на отдельном носителе")
	subPub := fs.String("subkey-pub", "", "открытый рабочий ключ (gen-subkey)")
	purpose := fs.String("purpose", "", "назначение: service_db или license")
	serial := fs.String("serial", "", "номер заверения — сквозной, по журналу выпусков производителя")
	notBefore := fs.String("not-before", "", "начало срока: ГГГГ-ММ-ДД или RFC 3339; по умолчанию — сегодня")
	notAfter := fs.String("not-after", "", "конец срока: ГГГГ-ММ-ДД или RFC 3339, не дальше 5 лет")
	comment := fs.String("comment", "", "комментарий для журнала выпусков (до 200 символов)")
	out := fs.String("out", "", "файл заверения (не должен существовать)")
	testPair := fs.Bool("test", false, "заверить тестовым ключом производителя из репозитория — НЕ ДЛЯ ПОСТАВКИ")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *subPub == "" || *purpose == "" || *serial == "" || *notAfter == "" || *out == "" {
		return errors.New("обязательны -key, -subkey-pub, -purpose, -serial, -not-after и -out")
	}
	n, err := strconv.ParseUint(*serial, 10, 64)
	if err != nil {
		return errors.New("-serial: целое число от 1")
	}
	e := aisecCrypto.Endorsement{Purpose: *purpose, Profile: p.Name(), Serial: n, Comment: *comment}
	if *notBefore == "" {
		e.NotBefore = time.Now().UTC().Truncate(24 * time.Hour)
	} else if e.NotBefore, err = parseDay(*notBefore); err != nil {
		return fmt.Errorf("-not-before: %w", err)
	}
	if e.NotAfter, err = parseDay(*notAfter); err != nil {
		return fmt.Errorf("-not-after: %w", err)
	}
	data, err := aisecCrypto.ReadPEMFile(*subPub)
	if err != nil {
		return err
	}
	profile, pub, err := aisecCrypto.DecodeKeyPEM(data, aisecCrypto.KeyKindVendorSubkeyPublic)
	if err != nil {
		return fmt.Errorf("%s: %w", *subPub, err)
	}
	if profile != p.Name() {
		return fmt.Errorf("%s: ключ профиля %s, ожидается %s", *subPub, profile, p.Name())
	}
	e.PublicKey = pub
	var vendor aisecCrypto.Signer
	if *testPair {
		vendor, err = loadTestSigner(p, *keyFile)
	} else {
		if err = checkOffline(); err != nil {
			return err
		}
		vendor, err = loadVendorSigner(p, *keyFile)
	}
	if err != nil {
		return err
	}
	file, err := aisecCrypto.SignEndorsement(vendor, e)
	if err != nil {
		return err
	}
	v, err := p.NewVerifier(vendor.PublicKey())
	if err != nil {
		return err
	}
	if _, _, err := aisecCrypto.VerifyEndorsement(p, v, file, aisecCrypto.EndorsementCheck{Purpose: e.Purpose}); err != nil {
		return err
	}
	if err := writeNew(*out, file, 0o644); err != nil {
		return err
	}
	vfp, err := integrity.Fingerprint(p, vendor.PublicKey())
	if err != nil {
		return err
	}
	sfp, err := integrity.Fingerprint(p, pub)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Заверение: %s\nНазначение: %s, номер %d, срок %s — %s\nОтпечаток рабочего ключа: %s\nОтпечаток ключа производителя: %s\n",
		*out, e.Purpose, e.Serial, e.NotBefore.UTC().Format(time.RFC3339), e.NotAfter.UTC().Format(time.RFC3339), sfp, vfp)
	return err
}

// loadVendorPub — открытый ключ производителя для проверки заверения перед
// подписью базы; ключ из репозитория — только с -test.
func loadVendorPub(p aisecCrypto.Provider, path string, test bool) (aisecCrypto.Verifier, error) {
	if test {
		v, isTest, err := integrity.EmbeddedVerifier(p)
		if err != nil {
			return nil, err
		}
		if !isTest {
			return nil, errors.New("-test: инструмент собран с ключом производителя")
		}
		return v, nil
	}
	if path == "" {
		return nil, errors.New("обязателен -vendor-pub — открытый ключ производителя (internal/integrity/keys/manifest.pub)")
	}
	v, err := aisecCrypto.LoadVerifierFile(p, path, aisecCrypto.KeyKindManifestSigningPublic)
	if err != nil {
		return nil, err
	}
	if integrity.IsTestPublicKey(v.PublicKey()) {
		return nil, fmt.Errorf("%s: это ключ из репозитория — для поставки нужен ключ производителя", path)
	}
	return v, nil
}

// signDB подписывает служебную базу рабочим ключом: содержимое разбирается
// правилами модуля, заверение проверяется ключом производителя, готовый
// файл — так же, как его проверит сервер.
func signDB(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign-db", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "закрытый рабочий ключ (AISEC VENDOR SUBKEY, права 0400)")
	endorsement := fs.String("endorsement", "", "файл заверения рабочего ключа (endorse)")
	vendorPub := fs.String("vendor-pub", "", "открытый ключ производителя (manifest.pub) для проверки заверения")
	kind := fs.String("kind", shadowai.CatalogKind, "вид базы из реестра выпуска (internal/servicedb/kinds)")
	in := fs.String("in", "", "содержимое базы (например, internal/shadowai/catalog/catalog.yaml)")
	out := fs.String("out", "", "подписанный файл базы (не должен существовать)")
	testPair := fs.Bool("test", false, "тестовые ключи репозитория — НЕ ДЛЯ ПОСТАВКИ, сеть не проверяется")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *endorsement == "" || *in == "" || *out == "" {
		return errors.New("обязательны -key, -endorsement, -in и -out")
	}
	k, err := servicedb.KindByName(kinds.All(), *kind)
	if err != nil {
		return fmt.Errorf("-kind: %w", err)
	}
	if !*testPair {
		if err := checkOffline(); err != nil {
			return err
		}
	}
	vendor, err := loadVendorPub(p, *vendorPub, *testPair)
	if err != nil {
		return err
	}
	endorseData, err := readLimited(*endorsement, aisecCrypto.MaxEndorsementSize)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	e, _, err := aisecCrypto.VerifyEndorsement(p, vendor, endorseData, aisecCrypto.EndorsementCheck{Purpose: aisecCrypto.PurposeServiceDB, At: now})
	if err != nil {
		return err
	}
	payload, err := readLimited(*in, aisecCrypto.MaxServiceDBPayload)
	if err != nil {
		return err
	}
	// Содержимое разбирается разборщиком вида до подписи: неверную базу не
	// подписать.
	content, err := k.Parse(payload)
	if err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	summary := dbSummary(k, content)
	// Тестовый рабочий ключ лежит в репозитории, права файла git не хранит.
	readKey := aisecCrypto.ReadKeyFile
	if *testPair {
		readKey = aisecCrypto.ReadPEMFile
	}
	keyData, err := readKey(*keyFile)
	if err != nil {
		return fmt.Errorf("рабочий ключ: %w", err)
	}
	defer clear(keyData)
	profile, seed, err := aisecCrypto.DecodeKeyPEM(keyData, aisecCrypto.KeyKindVendorSubkey)
	if err != nil {
		return fmt.Errorf("%s: %w", *keyFile, err)
	}
	if profile != p.Name() {
		return fmt.Errorf("%s: ключ профиля %s, ожидается %s", *keyFile, profile, p.Name())
	}
	sub, err := p.NewSigner(seed)
	if err != nil {
		return err
	}
	file, err := aisecCrypto.SignServiceDB(sub, endorseData, *kind, payload)
	if err != nil {
		return err
	}
	// Готовый файл проверяется так же, как его проверит сервер при загрузке.
	if _, err := servicedb.Verify(p, vendor, k, file, now); err != nil {
		return fmt.Errorf("проверка готового файла: %w", err)
	}
	if err := writeNew(*out, file, 0o644); err != nil {
		return err
	}
	sum, err := manifestSum(p, file)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Подписана база %s: %s\nЗаверение: номер %d, действует до %s\nSHA-256 файла: %s\n",
		*out, summary, e.Serial, e.NotAfter.UTC().Format(time.RFC3339), sum)
	return err
}

// inspectDB показывает вид, версию и заверение файла базы. С -vendor-pub
// подпись проверяется (без срока), без него — только разбирается.
func inspectDB(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect-db", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "файл служебной базы")
	vendorPub := fs.String("vendor-pub", "", "открытый ключ производителя для проверки подписи (необязательно)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *in == "" {
		return errors.New("обязателен -in")
	}
	data, err := readLimited(*in, aisecCrypto.MaxServiceDBSize)
	if err != nil {
		return err
	}
	db, err := aisecCrypto.InspectServiceDB(data)
	if err != nil {
		return err
	}
	verified := "Подпись не проверялась (укажите -vendor-pub)"
	if *vendorPub != "" {
		v, err := aisecCrypto.LoadVerifierFile(p, *vendorPub, aisecCrypto.KeyKindManifestSigningPublic)
		if err != nil {
			return err
		}
		if db, err = aisecCrypto.VerifyServiceDB(p, v, data, db.Kind, aisecCrypto.EndorsementCheck{}); err != nil {
			return err
		}
		verified = "Подпись и заверение проверены"
	}
	summary := "вид неизвестен этому инструменту"
	if k, err := servicedb.KindByName(kinds.All(), db.Kind); err == nil {
		c, err := k.Parse(db.Payload)
		if err != nil {
			return err
		}
		summary = dbSummary(k, c)
	}
	fp, err := integrity.Fingerprint(p, db.Endorsement.PublicKey)
	if err != nil {
		return err
	}
	e := db.Endorsement
	_, err = fmt.Fprintf(stdout, "Вид: %s\n%s\nЗаверение: %s, номер %d, срок %s — %s\nОтпечаток рабочего ключа: %s\n%s\n",
		db.Kind, summary, e.Purpose, e.Serial, e.NotBefore.Format(time.RFC3339), e.NotAfter.Format(time.RFC3339), fp, verified)
	return err
}

// readLimited читает обычный файл не больше max байт.
func readLimited(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > max {
		return nil, fmt.Errorf("%s: не обычный файл или больше %d байт", path, max)
	}
	return os.ReadFile(path) //nolint:gosec // G304: путь задаёт производитель в командной строке
}
