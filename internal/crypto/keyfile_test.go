package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestKeyPEMRoundTrip(t *testing.T) {
	for kind, size := range keyFileSize {
		key := bytes.Repeat([]byte{7}, size)
		data, err := EncodeKeyPEM(kind, ProfileStandard, key)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if !strings.Contains(string(data), "Profile: standard") {
			t.Fatalf("%s: нет заголовка профиля:\n%s", kind, data)
		}
		profile, got, err := DecodeKeyPEM(data, kind)
		if err != nil || profile != ProfileStandard || !bytes.Equal(got, key) {
			t.Fatalf("%s: %q %x %v", kind, profile, got, err)
		}
	}
	// Ключ профиля gost читается и сообщает свой профиль: вызывающий
	// откажет, если профиль установки другой.
	data, err := EncodeKeyPEM(KeyKindMaster, ProfileGOST, make([]byte, AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	if p, _, err := DecodeKeyPEM(data, KeyKindMaster); err != nil || p != ProfileGOST {
		t.Fatalf("gost: %q %v", p, err)
	}
}

func TestEncodeKeyPEMRejects(t *testing.T) {
	cases := map[string]func() ([]byte, error){
		"неизвестный вид":     func() ([]byte, error) { return EncodeKeyPEM("RSA PRIVATE KEY", ProfileStandard, make([]byte, 32)) },
		"неизвестный профиль": func() ([]byte, error) { return EncodeKeyPEM(KeyKindMaster, "fips", make([]byte, 32)) },
		"короткий ключ":       func() ([]byte, error) { return EncodeKeyPEM(KeyKindMaster, ProfileStandard, make([]byte, 31)) },
		"длинный ключ":        func() ([]byte, error) { return EncodeKeyPEM(KeyKindSigning, ProfileStandard, make([]byte, 33)) },
	}
	for name, f := range cases {
		if _, err := f(); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestDecodeKeyPEMRejects(t *testing.T) {
	good, err := EncodeKeyPEM(KeyKindMaster, ProfileStandard, make([]byte, AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	block := func(typ string, headers map[string]string, n int) []byte {
		return pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: make([]byte, n)})
	}
	std := map[string]string{"Profile": ProfileStandard}
	cases := map[string][]byte{
		"пусто":                 nil,
		"не PEM":                []byte("0123456789abcdef0123456789abcdef"),
		"другой вид ключа":      block(KeyKindSigning, std, 32),
		"чужой тип":             block("PRIVATE KEY", std, 32),
		"без заголовка":         block(KeyKindMaster, nil, 32),
		"лишний заголовок":      block(KeyKindMaster, map[string]string{"Profile": ProfileStandard, "Comment": "x"}, 32),
		"неизвестный профиль":   block(KeyKindMaster, map[string]string{"Profile": "fips"}, 32),
		"короткий ключ":         block(KeyKindMaster, std, 16),
		"длинный ключ":          block(KeyKindMaster, std, 64),
		"два блока":             append(append([]byte(nil), good...), good...),
		"мусор после блока":     append(append([]byte(nil), good...), "x"...),
		"больше предела":        append(append([]byte(nil), good...), bytes.Repeat([]byte(" "), maxKeyFile)...),
		"мусор перед блоком":    append([]byte("x\n"), good...),
		"заголовок с регистром": block(KeyKindMaster, map[string]string{"profile": ProfileStandard}, 32),
	}
	for name, data := range cases {
		if _, key, err := DecodeKeyPEM(data, KeyKindMaster); err == nil {
			t.Errorf("%s: ожидалась ошибка, ключ %x", name, key)
		}
	}
	if _, _, err := DecodeKeyPEM(good, "SOMETHING"); err == nil {
		t.Error("неизвестный ожидаемый вид: ожидалась ошибка")
	}
	// Пробелы и перевод строки после блока допустимы: так файл сохраняют редакторы.
	if _, _, err := DecodeKeyPEM(append(append([]byte(nil), good...), "\n\n"...), KeyKindMaster); err != nil {
		t.Errorf("перевод строки после блока: %v", err)
	}
}

func FuzzDecodeKeyPEM(f *testing.F) {
	for kind, size := range keyFileSize {
		data, err := EncodeKeyPEM(kind, ProfileStandard, make([]byte, size))
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data, kind)
	}
	f.Add([]byte("-----BEGIN AISEC MASTER KEY-----\nProfile: gost\n\n-----END AISEC MASTER KEY-----\n"), KeyKindMaster)
	f.Fuzz(func(t *testing.T, data []byte, kind string) {
		profile, key, err := DecodeKeyPEM(data, kind)
		if err != nil {
			return
		}
		// Принятое должно быть корректным и кодироваться обратно в тот же ключ.
		if len(key) != keyFileSize[kind] || (profile != ProfileStandard && profile != ProfileGOST) {
			t.Fatalf("принят некорректный ключ: %q %q %d", kind, profile, len(key))
		}
		again, err := EncodeKeyPEM(kind, profile, key)
		if err != nil {
			t.Fatal(err)
		}
		p2, k2, err := DecodeKeyPEM(again, kind)
		if err != nil || p2 != profile || !bytes.Equal(k2, key) {
			t.Fatalf("повторный разбор: %q %x %v", p2, k2, err)
		}
	})
}

func TestStorageAAD(t *testing.T) {
	a, err := StorageAAD("data_keys", "wrapped", "0192")
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != "aisec-aad-v1|data_keys|wrapped|0192" {
		t.Fatalf("формат AAD: %q", a)
	}
	b, err := StorageAAD("data_keys", "wrapped", "0193")
	if err != nil || bytes.Equal(a, b) {
		t.Fatalf("разные строки — одинаковые AAD: %v", err)
	}
	long := strings.Repeat("x", maxAADPart+1)
	for _, parts := range [][3]string{
		{"", "c", "1"}, {"t", "", "1"}, {"t", "c", ""},
		{"t|x", "c", "1"}, {"t", "c|x", "1"}, {"t", "c", "1|x"},
		{long, "c", "1"},
	} {
		if _, err := StorageAAD(parts[0], parts[1], parts[2]); err == nil {
			t.Errorf("%q: ожидалась ошибка", parts)
		}
	}
	// AAD из StorageAAD привязывает шифротекст к строке (Р4).
	p := mustStandard(t)
	g, err := p.NewAEAD(make([]byte, AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := g.Seal([]byte("секрет"), a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.Open(sealed, b); err == nil {
		t.Fatal("шифротекст открылся с AAD другой строки")
	}
}

func TestLoadCA(t *testing.T) {
	now := time.Now()
	ca, err := NewCA("AISec internal CA", 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadCA(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.NotAfter().Equal(ca.NotAfter()) || !bytes.Equal(loaded.CertPEM(), ca.CertPEM()) {
		t.Fatal("загруженный УЦ отличается от исходного")
	}
	// Сертификат, выпущенный загруженным УЦ, проверяется исходным корнем.
	certPEM, _, err := loaded.IssueServer([]string{"aisec-server"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "aisec-server", CurrentTime: now}); err != nil {
		t.Fatalf("цепочка: %v", err)
	}

	other, err := NewCA("other", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := other.KeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	_, leafKey, err := ca.IssueServer([]string{"x"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][2][]byte{
		"чужой ключ":              {ca.CertPEM(), otherKey},
		"листовой сертификат":     {certPEM, leafKey},
		"ключ вместо сертификата": {keyPEM, keyPEM},
		"сертификат вместо ключа": {ca.CertPEM(), ca.CertPEM()},
		"пусто":                      {nil, nil},
		"два сертификата":            {append(ca.CertPEM(), other.CertPEM()...), keyPEM},
		"мусор после ключа":          {ca.CertPEM(), append(append([]byte(nil), keyPEM...), "x"...)},
		"мусор перед сертификатом":   {append([]byte("x\n"), ca.CertPEM()...), keyPEM},
		"мусор перед ключом":         {ca.CertPEM(), append([]byte("x\n"), keyPEM...)},
		"слишком большой сертификат": {bytes.Repeat([]byte(" "), maxPEMFile+1), keyPEM},
	}
	// Сертификат УЦ с ключом ca, но подписанный чужим УЦ.
	foreignDER, err := x509.CreateCertificate(rand.Reader, ca.cert, other.cert, &ca.key.PublicKey, other.key)
	if err != nil {
		t.Fatal(err)
	}
	cases["не самоподписанный"] = [2][]byte{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreignDER}), keyPEM}
	for name, c := range cases {
		if _, err := LoadCA(c[0], c[1]); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestCAExpiredRefusesIssue(t *testing.T) {
	past := time.Now().Add(-48 * time.Hour)
	ca, err := NewCA("old", time.Hour, past)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.IssueServer([]string{"x"}, time.Hour, time.Now()); err == nil {
		t.Fatal("истёкший УЦ выпустил сертификат")
	}
}

func TestCADoesNotLeakKey(t *testing.T) {
	ca, err := NewCA("leak", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ca.key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	d := hex.EncodeToString(raw)
	var buf bytes.Buffer
	l := slog.New(slog.NewTextHandler(&buf, nil))
	l.Info("ca", "ca", ca)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		fmt.Fprintf(&buf, verb, ca)
	}
	if strings.Contains(buf.String(), d) {
		t.Fatal("закрытый ключ УЦ попал в вывод")
	}
}

func FuzzLoadCA(f *testing.F) {
	ca, err := NewCA("fuzz", time.Hour, time.Now())
	if err != nil {
		f.Fatal(err)
	}
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ca.CertPEM(), keyPEM)
	f.Add([]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"), keyPEM)
	f.Fuzz(func(t *testing.T, certPEM, keyPEM []byte) {
		loaded, err := LoadCA(certPEM, keyPEM)
		if err != nil {
			return
		}
		// Принятый УЦ должен быть УЦ на P-256 с парным ключом.
		if !loaded.cert.IsCA || !loaded.key.PublicKey.Equal(loaded.cert.PublicKey) {
			t.Fatal("принят некорректный УЦ")
		}
	})
}
