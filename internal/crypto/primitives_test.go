package crypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestAEAD(t *testing.T) {
	p := mustStandard(t)
	key := bytes.Repeat([]byte{1}, AEADKeySize)
	a, err := p.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	if a.Name() != "AES-256-GCM" {
		t.Fatalf("имя: %s", a.Name())
	}
	msg, aad := []byte("ключ данных"), []byte("data_keys/key/42")
	s1, err := a.Seal(msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := a.Seal(msg, aad)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("одинаковый шифротекст для двух вызовов: nonce повторяется")
	}
	if len(s1) != len(msg)+12+16 {
		t.Fatalf("длина шифротекста %d", len(s1))
	}
	key[0] = 2 // ключ не зависит от буфера после создания
	out, err := a.Open(s1, aad)
	if err != nil || !bytes.Equal(out, msg) {
		t.Fatalf("Open: %q %v", out, err)
	}
	// Пустой открытый текст допустим.
	empty, err := a.Seal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := a.Open(empty, nil); err != nil || len(out) != 0 {
		t.Fatalf("пустой текст: %q %v", out, err)
	}

	other, err := p.NewAEAD(bytes.Repeat([]byte{3}, AEADKeySize))
	if err != nil {
		t.Fatal(err)
	}
	bad := map[string]func() ([]byte, error){
		"другие AAD (перестановка строк)": func() ([]byte, error) { return a.Open(s1, []byte("data_keys/key/43")) },
		"без AAD":             func() ([]byte, error) { return a.Open(s1, nil) },
		"другой ключ":         func() ([]byte, error) { return other.Open(s1, aad) },
		"обрезан":             func() ([]byte, error) { return a.Open(s1[:len(s1)-1], aad) },
		"короче nonce и тега": func() ([]byte, error) { return a.Open(s1[:27], aad) },
		"пусто":               func() ([]byte, error) { return a.Open(nil, aad) },
		"изменён nonce": func() ([]byte, error) {
			c := bytes.Clone(s1)
			c[0] ^= 1
			return a.Open(c, aad)
		},
		"изменён шифротекст": func() ([]byte, error) {
			c := bytes.Clone(s1)
			c[13] ^= 0x80
			return a.Open(c, aad)
		},
	}
	for name, f := range bad {
		if out, err := f(); !errors.Is(err, ErrDecrypt) || out != nil {
			t.Errorf("%s: %q %v", name, out, err)
		}
	}
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := p.NewAEAD(make([]byte, n)); err == nil {
			t.Errorf("принят ключ %d байт", n)
		}
	}
	if _, err := a.Seal(make([]byte, MaxAEADPlaintext+1), nil); err == nil {
		t.Fatal("принят слишком длинный открытый текст")
	}
}

// RFC 8032, раздел 7.1, тесты 1–3 и SHA(abc).
var rfc8032 = []struct{ seed, pub, msg, sig string }{
	{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
	{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
		"3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	{"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
		"fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	{"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
		"ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"},
}

func TestSignRFC8032(t *testing.T) {
	p := mustStandard(t)
	for i, v := range rfc8032 {
		s, err := p.NewSigner(mustHex(v.seed))
		if err != nil {
			t.Fatal(err)
		}
		msg := mustHex(v.msg)
		sig, err := s.Sign(msg)
		if err != nil {
			t.Fatal(err)
		}
		if hex.EncodeToString(sig) != v.sig || hex.EncodeToString(s.PublicKey()) != v.pub {
			t.Fatalf("тест %d: подпись или открытый ключ не совпали", i+1)
		}
		if hex.EncodeToString(s.Seed()) != v.seed {
			t.Fatalf("тест %d: Seed не совпал", i+1)
		}
		vr, err := p.NewVerifier(mustHex(v.pub))
		if err != nil {
			t.Fatal(err)
		}
		if !vr.Verify(msg, sig) {
			t.Fatalf("тест %d: подпись не прошла проверку", i+1)
		}
		bad := bytes.Clone(sig)
		bad[0] ^= 1
		if vr.Verify(msg, bad) || vr.Verify(append(bytes.Clone(msg), 0), sig) || vr.Verify(msg, sig[:63]) || vr.Verify(msg, nil) {
			t.Fatalf("тест %d: принята чужая подпись или сообщение", i+1)
		}
	}
}

func TestSignGenerateAndKeys(t *testing.T) {
	p := mustStandard(t)
	s1, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := p.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1.PublicKey(), s2.PublicKey()) {
		t.Fatal("две сгенерированные пары совпали")
	}
	// Ключ восстанавливается из Seed, копии не связаны с внутренним состоянием.
	seed := s1.Seed()
	r, err := p.NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	clear(seed)
	pub := s1.PublicKey()
	pub[0] ^= 1
	if !bytes.Equal(r.PublicKey(), s1.PublicKey()) {
		t.Fatal("ключ, восстановленный из Seed, отличается")
	}
	v, err := p.NewVerifier(s1.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := r.Sign([]byte("пакет"))
	if err != nil {
		t.Fatal(err)
	}
	if !v.Verify([]byte("пакет"), sig) {
		t.Fatal("подпись восстановленным ключом не прошла проверку")
	}
	other, err := p.NewVerifier(s2.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if other.Verify([]byte("пакет"), sig) {
		t.Fatal("подпись принята чужим открытым ключом")
	}
	for _, n := range []int{0, 31, 33, 64} {
		if _, err := p.NewSigner(make([]byte, n)); err == nil {
			t.Errorf("принят закрытый ключ %d байт", n)
		}
		if _, err := p.NewVerifier(make([]byte, n)); err == nil {
			t.Errorf("принят открытый ключ %d байт", n)
		}
	}
}

// RFC 6238, приложение B, SHA-1: секрет ASCII «12345678901234567890».
var rfc6238 = []struct {
	unix int64
	code string
}{
	{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"},
	{1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
}

func TestTOTPRFC6238(t *testing.T) {
	secret := []byte("12345678901234567890")
	for _, v := range rfc6238 {
		step := uint64(v.unix / 30) //nolint:gosec // G115: время в векторах положительное
		if got := hotp(secret, step, 8); got != v.code {
			t.Errorf("T=%d: %s, ожидалось %s", v.unix, got, v.code)
		}
	}
	tp, err := mustStandard(t).NewTOTP(secret)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range rfc6238 {
		// Продукт использует 6 цифр: это последние 6 цифр 8-значного кода.
		step, ok := tp.Verify(v.code[2:], time.Unix(v.unix, 0), 0)
		if !ok || step != v.unix/30 {
			t.Errorf("T=%d: Verify = %d, %v", v.unix, step, ok)
		}
	}
}

func TestTOTPWindowAndReplay(t *testing.T) {
	secret := bytes.Repeat([]byte{0x5a}, TOTPSecretSize)
	tp, err := mustStandard(t).NewTOTP(secret)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	cur := now.Unix() / 30
	code := func(s int64) string { return hotp(secret, uint64(s), TOTPDigits) } //nolint:gosec // G115: шаг положительный

	for _, d := range []int64{-1, 0, 1} {
		if step, ok := tp.Verify(code(cur+d), now, 0); !ok || step != cur+d {
			t.Errorf("сдвиг %d: %d, %v", d, step, ok)
		}
	}
	for _, d := range []int64{-2, 2, 100} {
		if _, ok := tp.Verify(code(cur+d), now, 0); ok {
			t.Errorf("принят код вне окна, сдвиг %d", d)
		}
	}
	// Повтор: код текущего шага после его принятия и код раньше принятого.
	if _, ok := tp.Verify(code(cur), now, cur); ok {
		t.Fatal("принят повтор кода того же шага")
	}
	if _, ok := tp.Verify(code(cur-1), now, cur); ok {
		t.Fatal("принят код шага раньше уже принятого")
	}
	if step, ok := tp.Verify(code(cur+1), now, cur); !ok || step != cur+1 {
		t.Fatal("не принят код следующего шага")
	}
	for _, bad := range []string{"", "12345", "1234567", "12345a", " 12345", "１２３４５６", "-12345"} {
		if _, ok := tp.Verify(bad, now, 0); ok {
			t.Errorf("принят код %q", bad)
		}
	}
	if _, ok := tp.Verify(code(0), time.Unix(-30, 0), -10); ok {
		t.Fatal("принят код до начала эпохи")
	}
	secret[0] ^= 1                                                                                                  // секрет скопирован
	if _, ok := tp.Verify(hotp(bytes.Repeat([]byte{0x5a}, TOTPSecretSize), uint64(cur), TOTPDigits), now, 0); !ok { //nolint:gosec // G115: шаг положительный
		t.Fatal("TOTP зависит от буфера секрета после создания")
	}
	for _, n := range []int{0, 10, 19, 21, 32} {
		if _, err := mustStandard(t).NewTOTP(make([]byte, n)); err == nil {
			t.Errorf("принят секрет %d байт", n)
		}
	}
}

// Ключи и секреты новых типов не выводятся ни через fmt, ни через slog.
func TestPrimitivesDoNotLeakKeys(t *testing.T) {
	p := mustStandard(t)
	key := bytes.Repeat([]byte("K"), AEADKeySize)
	a, err := p.NewAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	s, err := p.NewSigner(bytes.Repeat([]byte("K"), SigningSeedSize))
	if err != nil {
		t.Fatal(err)
	}
	tp, err := p.NewTOTP(bytes.Repeat([]byte("K"), TOTPSecretSize))
	if err != nil {
		t.Fatal(err)
	}
	seedHex := hex.EncodeToString(s.Seed())
	for _, v := range []any{a, s, tp} {
		var logBuf bytes.Buffer
		slog.New(slog.NewTextHandler(&logBuf, nil)).Info("проверка", "v", v)
		slog.New(slog.NewJSONHandler(&logBuf, nil)).Info("проверка", "v", v)
		out := fmt.Sprintf("%v %+v %#v %s %x %X %q %d", v, v, v, v, v, v, v, v) + fmt.Sprint([]any{v}) + logBuf.String()
		lower := strings.ToLower(out)
		if strings.Contains(out, "KKKK") || strings.Contains(lower, "4b4b4b4b") || strings.Contains(lower, seedHex[:16]) || strings.Contains(out, "75 75") {
			t.Fatalf("секрет попал в вывод: %s", out)
		}
		if !strings.Contains(out, v.(interface{ Name() string }).Name()) {
			t.Fatalf("в выводе нет имени алгоритма: %s", out)
		}
	}
}

// FuzzAEADOpen: шифротекст из БД — недоверенный вход. Open не паникует, на
// произвольных данных отвечает только ErrDecrypt и не выдаёт открытый текст.
func FuzzAEADOpen(f *testing.F) {
	a, err := standard{}.NewAEAD(bytes.Repeat([]byte{9}, AEADKeySize))
	if err != nil {
		f.Fatal(err)
	}
	valid, err := a.Seal([]byte("данные"), []byte("aad"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid, []byte("aad"))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 28), []byte("aad"))
	f.Fuzz(func(t *testing.T, sealed, aad []byte) {
		out, err := a.Open(sealed, aad)
		if err == nil {
			// Подлинный шифротекст фаззер получает только из затравки. Сравнивать
			// с valid нельзя: каждый процесс фаззинга шифрует затравку со своим nonce.
			if string(aad) != "aad" || string(out) != "данные" {
				t.Fatalf("принят чужой шифротекст: %x", sealed)
			}
			return
		}
		if !errors.Is(err, ErrDecrypt) || out != nil {
			t.Fatalf("ошибка другого вида: %v %q", err, out)
		}
	})
}

// FuzzTOTPVerify: код приходит от пользователя. Verify не паникует, принимает
// только 6 цифр, а принятый шаг лежит в окне и позже lastStep.
func FuzzTOTPVerify(f *testing.F) {
	secret := bytes.Repeat([]byte{0x33}, TOTPSecretSize)
	tp, err := standard{}.NewTOTP(secret)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("123456", int64(1_800_000_000), int64(0))
	f.Add(hotp(secret, 60_000_000, TOTPDigits), int64(1_800_000_000), int64(59_999_999))
	f.Add("", int64(-1), int64(-1))
	f.Fuzz(func(t *testing.T, code string, unix, lastStep int64) {
		step, ok := tp.Verify(code, time.Unix(unix, 0), lastStep)
		if !ok {
			if step != 0 {
				t.Fatalf("отказ с шагом %d", step)
			}
			return
		}
		cur := unix / 30
		if len(code) != TOTPDigits || step <= lastStep || step < cur-TOTPSkew || step > cur+TOTPSkew ||
			hotp(secret, uint64(step), TOTPDigits) != code { //nolint:gosec // G115: принятый шаг положительный
			t.Fatalf("принят код %q на шаге %d (текущий %d, lastStep %d)", code, step, cur, lastStep)
		}
	})
}
