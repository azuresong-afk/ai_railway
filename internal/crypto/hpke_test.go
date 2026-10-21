package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func TestSealToRoundTrip(t *testing.T) {
	p := mustStandard(t)
	r, err := p.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	if len(r.PublicKey()) != RecipientPublicKeySize {
		t.Fatalf("длина открытого ключа %d", len(r.PublicKey()))
	}
	info := []byte("aisec-config-bundle/1|gw|42")
	msg := []byte(`{"openai":"sk-синтетический"}`)
	sealed, err := p.SealTo(r.PublicKey(), info, msg)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("sk-")) {
		t.Fatal("открытый текст в шифротексте")
	}
	got, err := r.Open(sealed, info)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open: %q, %v", got, err)
	}
	// Шифротекст случайный: два вызова дают разные байты.
	again, err := p.SealTo(r.PublicKey(), info, msg)
	if err != nil || bytes.Equal(again, sealed) {
		t.Fatal("повторное шифрование дало тот же шифротекст")
	}

	// Ключ восстанавливается из сохранённого закрытого ключа.
	priv, err := r.PrivateKey()
	if err != nil || len(priv) != RecipientKeySize {
		t.Fatalf("PrivateKey: %d, %v", len(priv), err)
	}
	r2, err := p.NewRecipient(priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r2.PublicKey(), r.PublicKey()) {
		t.Fatal("восстановленный ключ — другой открытый ключ")
	}
	if got, err := r2.Open(sealed, info); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("Open восстановленным ключом: %v", err)
	}
}

func TestSealToRejects(t *testing.T) {
	p := mustStandard(t)
	r, err := p.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	other, err := p.GenerateRecipient()
	if err != nil {
		t.Fatal(err)
	}
	info := []byte("info")
	sealed, err := p.SealTo(r.PublicKey(), info, []byte("секрет"))
	if err != nil {
		t.Fatal(err)
	}
	flipped := bytes.Clone(sealed)
	flipped[len(flipped)-1] ^= 1
	encFlipped := bytes.Clone(sealed)
	encFlipped[0] ^= 1
	for name, c := range map[string]struct {
		r      Recipient
		sealed []byte
		info   []byte
	}{
		"чужой ключ":                {other, sealed, info},
		"другой info":               {r, sealed, []byte("info2")},
		"изменён тег":               {r, flipped, info},
		"изменён ключ инкапсуляции": {r, encFlipped, info},
		"обрезан":                   {r, sealed[:20], info},
		"пусто":                     {r, nil, info},
		"слишком длинный info":      {r, sealed, make([]byte, MaxSealToInfo+1)},
	} {
		if _, err := c.r.Open(c.sealed, c.info); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := p.SealTo(make([]byte, RecipientPublicKeySize-1), info, []byte("x")); err == nil {
		t.Error("принят короткий открытый ключ")
	}
	if _, err := p.SealTo(r.PublicKey(), make([]byte, MaxSealToInfo+1), []byte("x")); err == nil {
		t.Error("принят длинный info")
	}
	if _, err := p.SealTo(r.PublicKey(), info, make([]byte, MaxSealToPlaintext+1)); err == nil {
		t.Error("принят слишком длинный открытый текст")
	}
	// Нулевой открытый ключ X25519 даёт нулевой общий секрет — отказ.
	if _, err := p.SealTo(make([]byte, RecipientPublicKeySize), info, []byte("x")); err == nil {
		t.Error("принят нулевой открытый ключ")
	}
	if _, err := p.NewRecipient(make([]byte, RecipientKeySize+1)); err == nil {
		t.Error("принят закрытый ключ неверной длины")
	}
}

func TestRecipientDoesNotLeakKey(t *testing.T) {
	p := mustStandard(t)
	r, err := p.NewRecipient(bytes.Repeat([]byte("K"), RecipientKeySize))
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%v %+v %#v %s %x", r, r, r, r, r)
	if bytes.Contains([]byte(out), []byte("KKKK")) || bytes.Contains([]byte(out), []byte("4b4b4b4b")) {
		t.Fatalf("закрытый ключ попал в вывод: %s", out)
	}
	if !bytes.Contains([]byte(out), []byte("HPKE")) {
		t.Fatalf("в выводе нет имени алгоритма: %s", out)
	}
}

// FuzzRecipientOpen: шифротекст из пакета — недоверенный вход. Open не
// паникует и на произвольных данных отвечает только ErrDecrypt.
func FuzzRecipientOpen(f *testing.F) {
	p := standard{}
	r, err := p.NewRecipient(bytes.Repeat([]byte{7}, RecipientKeySize))
	if err != nil {
		f.Fatal(err)
	}
	valid, err := p.SealTo(r.PublicKey(), []byte("info"), []byte("данные"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid, []byte("info"))
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 48), []byte("info"))
	f.Fuzz(func(t *testing.T, sealed, info []byte) {
		out, err := r.Open(sealed, info)
		if err == nil {
			// Шифрование вероятностное: в каждом процессе fuzz свой valid,
			// поэтому сверяется результат, а не байты шифротекста.
			if !bytes.Equal(out, []byte("данные")) || !bytes.Equal(info, []byte("info")) {
				t.Fatalf("расшифрован произвольный шифротекст: %q", out)
			}
			return
		}
		if !errors.Is(err, ErrDecrypt) {
			t.Fatalf("ошибка не ErrDecrypt: %v", err)
		}
	})
}
