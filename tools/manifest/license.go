package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/license"
)

// Лицензии (ADR-0026, п. 9): подпись рабочим ключом с назначением license
// на машине без сети, как sign-db; -test — тестовые ключи репозитория
// (testdata/license/), сеть не проверяется.

// licenseSummary — сведения лицензии одной строкой на поле.
func licenseSummary(l *license.License) string {
	modules := "нет"
	if len(l.Modules) > 0 {
		modules = strings.Join(l.Modules, ", ")
	}
	limit := func(n int) string {
		if n == 0 {
			return "без ограничения"
		}
		return fmt.Sprint(n)
	}
	return fmt.Sprintf("Лицензия № %d (%s)\nВладелец: %s, ИНН %s\nВыдана: %s\nДействует: %s — %s\nШлюзов: %s, приложений: %s\nМодули: %s",
		l.Number, l.Type, l.Licensee.Organization, l.Licensee.INN, l.IssuedAt.Format(time.RFC3339),
		l.ValidFrom.Format(time.RFC3339), l.ValidUntil.Format(time.RFC3339), limit(l.Limits.Gateways), limit(l.Limits.Applications), modules)
}

// signLicense подписывает содержимое лицензии рабочим ключом: содержимое
// разбирается правилами internal/license, заверение проверяется ключом
// производителя на текущее время, готовый файл — так же, как его проверит
// сервер.
func signLicense(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("sign-license", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "закрытый рабочий ключ лицензий (AISEC VENDOR SUBKEY, права 0400)")
	endorsement := fs.String("endorsement", "", "файл заверения рабочего ключа с назначением license (endorse)")
	vendorPub := fs.String("vendor-pub", "", "открытый ключ производителя (manifest.pub) для проверки заверения")
	in := fs.String("in", "", "содержимое лицензии в JSON (формат aisec-license-data-v1, ADR-0026, п. 3)")
	out := fs.String("out", "", "подписанный файл лицензии *.aiseclic (не должен существовать)")
	testPair := fs.Bool("test", false, "тестовые ключи репозитория — НЕ ДЛЯ ПОСТАВКИ, сеть не проверяется")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *keyFile == "" || *endorsement == "" || *in == "" || *out == "" {
		return errors.New("обязательны -key, -endorsement, -in и -out")
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
	e, _, err := aisecCrypto.VerifyEndorsement(p, vendor, endorseData, aisecCrypto.EndorsementCheck{Purpose: aisecCrypto.PurposeLicense, At: now})
	if err != nil {
		return err
	}
	payload, err := readLimited(*in, aisecCrypto.MaxLicensePayload)
	if err != nil {
		return err
	}
	l, err := license.Parse(payload)
	if err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	if !e.ValidAt(l.IssuedAt) {
		return fmt.Errorf("%s: %w", *in, license.ErrIssuedDate)
	}
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
	file, err := aisecCrypto.SignLicense(sub, endorseData, payload)
	if err != nil {
		return err
	}
	sg, err := license.Verify(p, vendor, file, now)
	if err != nil {
		return fmt.Errorf("проверка готового файла: %w", err)
	}
	if err := writeNew(*out, file, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "Подписана лицензия %s\n%s\nЗаверение: номер %d, действует до %s\nОтпечаток рабочего ключа: %s\nХеш файла: %s\n",
		*out, licenseSummary(sg.License), e.Serial, e.NotAfter.UTC().Format(time.RFC3339), sg.Fingerprint, sg.FileHash)
	return err
}

// inspectLicense показывает сведения файла лицензии. С -vendor-pub подпись
// проверяется (без срока заверения), без него — только разбирается.
func inspectLicense(p aisecCrypto.Provider, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect-license", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "", "файл лицензии *.aiseclic")
	vendorPub := fs.String("vendor-pub", "", "открытый ключ производителя для проверки подписи (необязательно)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 || *in == "" {
		return errors.New("обязателен -in")
	}
	data, err := readLimited(*in, aisecCrypto.MaxLicenseSize)
	if err != nil {
		return err
	}
	sl, err := aisecCrypto.InspectLicense(data)
	if err != nil {
		return err
	}
	l, err := license.Parse(sl.Payload)
	if err != nil {
		return err
	}
	verified := "Подпись не проверялась (укажите -vendor-pub)"
	if *vendorPub != "" {
		v, err := aisecCrypto.LoadVerifierFile(p, *vendorPub, aisecCrypto.KeyKindManifestSigningPublic)
		if err != nil {
			return err
		}
		if _, err := license.Verify(p, v, data, time.Time{}); err != nil {
			return err
		}
		verified = "Подпись и заверение проверены"
	}
	e := sl.Endorsement
	_, err = fmt.Fprintf(stdout, "%s\nЗаверение: %s, номер %d, срок %s — %s\n%s\n", licenseSummary(l), e.Purpose, e.Serial,
		e.NotBefore.Format(time.RFC3339), e.NotAfter.Format(time.RFC3339), verified)
	return err
}
