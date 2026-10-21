package crypto

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"
)

func mustPasswordHasher(t *testing.T) PasswordHasher {
	t.Helper()
	h, err := mustStandard(t).PasswordHasher()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestPasswordHashVerify(t *testing.T) {
	h := mustPasswordHasher(t)
	ctx := context.Background()
	pw := []byte("Синтетический-пароль-1")
	enc, err := h.Hash(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("формат: %s", enc)
	}
	if strings.Contains(enc, string(pw)) {
		t.Fatal("пароль в открытом виде в хеше")
	}
	p, salt, key, err := parseArgon2id(enc)
	if err != nil || p != argon2Default || len(salt) != 16 || len(key) != 32 {
		t.Fatalf("разбор своего хеша: %+v %d %d %v", p, len(salt), len(key), err)
	}
	enc2, err := h.Hash(ctx, pw)
	if err != nil {
		t.Fatal(err)
	}
	if enc == enc2 {
		t.Fatal("два хеша одного пароля совпали: соль не случайна")
	}
	if ok, rehash, err := h.Verify(ctx, pw, enc); !ok || rehash || err != nil {
		t.Fatalf("верный пароль: %v %v %v", ok, rehash, err)
	}
	for _, wrong := range []string{"Синтетический-пароль-2", "синтетический-пароль-1", "Синтетический-пароль-1 ", "x"} {
		if ok, _, err := h.Verify(ctx, []byte(wrong), enc); ok || err != nil {
			t.Errorf("неверный пароль %q: %v %v", wrong, ok, err)
		}
	}
}

func TestPasswordLimits(t *testing.T) {
	h := mustPasswordHasher(t)
	ctx := context.Background()
	enc, err := h.Hash(ctx, []byte(strings.Repeat("я", MaxPasswordLen/2))) // ровно MaxPasswordLen байт
	if err != nil {
		t.Fatal(err)
	}
	if ok, _, err := h.Verify(ctx, []byte(strings.Repeat("я", MaxPasswordLen/2)), enc); !ok || err != nil {
		t.Fatalf("пароль на границе длины: %v %v", ok, err)
	}
	for _, n := range []int{0, MaxPasswordLen + 1} {
		if _, err := h.Hash(ctx, make([]byte, n)); err == nil {
			t.Errorf("Hash принял пароль %d байт", n)
		}
		if _, _, err := h.Verify(ctx, make([]byte, n), enc); err == nil {
			t.Errorf("Verify принял пароль %d байт", n)
		}
	}
}

// Хеш с другими параметрами (например, после их повышения) проверяется и
// помечается для пересчёта.
func TestPasswordNeedsRehash(t *testing.T) {
	h := mustPasswordHasher(t)
	pw := []byte("Синтетический-пароль-1")
	old := argon2Params{memory: argon2MinMemory, time: 2, threads: 1, saltLen: 16, keyLen: 32}
	salt := []byte("0123456789abcdef")
	key, err := argon2Compute(context.Background(), pw, salt, old)
	if err != nil {
		t.Fatal(err)
	}
	enc := encodeArgon2id(old, salt, key)
	if ok, rehash, err := h.Verify(context.Background(), pw, enc); !ok || !rehash || err != nil {
		t.Fatalf("старые параметры: %v %v %v", ok, rehash, err)
	}
}

// Ожидание слота ограничено контекстом: при занятых слотах вход не висит.
func TestPasswordConcurrencyLimit(t *testing.T) {
	h := mustPasswordHasher(t)
	enc, err := h.Hash(context.Background(), []byte("пароль"))
	if err != nil {
		t.Fatal(err)
	}
	slots := argon2Slots()
	n := cap(slots)
	for range n {
		slots <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	_, err1 := h.Hash(ctx, []byte("пароль"))
	_, _, err2 := h.Verify(ctx, []byte("пароль"), enc)
	cancel()
	for range n {
		<-slots
	}
	if !errors.Is(err1, context.DeadlineExceeded) || !errors.Is(err2, context.DeadlineExceeded) {
		t.Fatalf("ожидался отказ по контексту: %v, %v", err1, err2)
	}
	if ok, _, err := h.Verify(context.Background(), []byte("пароль"), enc); !ok || err != nil {
		t.Fatalf("после освобождения слотов: %v %v", ok, err)
	}
}

const validPHC = "$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFiY2RlZg$" +
	"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

func TestParseArgon2id(t *testing.T) {
	p, salt, key, err := parseArgon2id(validPHC)
	if err != nil || p != argon2Default || string(salt) != "0123456789abcdef" || len(key) != 32 {
		t.Fatalf("корректная строка: %+v %q %d %v", p, salt, len(key), err)
	}
	if got := encodeArgon2id(p, salt, key); got != validPHC {
		t.Fatalf("обратное кодирование: %s", got)
	}
	s := "MDEyMzQ1Njc4OWFiY2RlZg"
	k := "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
	bad := []string{
		"",
		"argon2id$v=19$m=65536,t=3,p=2$" + s + "$" + k,
		"$argon2i$v=19$m=65536,t=3,p=2$" + s + "$" + k,
		"$argon2d$v=19$m=65536,t=3,p=2$" + s + "$" + k,
		"$argon2id$v=16$m=65536,t=3,p=2$" + s + "$" + k,
		"$argon2id$m=65536,t=3,p=2$" + s + "$" + k,
		"$argon2id$v=19$t=3,m=65536,p=2$" + s + "$" + k,
		"$argon2id$v=19$m=65536,t=3$" + s + "$" + k,
		"$argon2id$v=19$m=65536,t=3,p=2,x=1$" + s + "$" + k,
		"$argon2id$v=19$m=065536,t=3,p=2$" + s + "$" + k,
		"$argon2id$v=19$m=+65536,t=3,p=2$" + s + "$" + k,
		"$argon2id$v=19$m=1024,t=3,p=2$" + s + "$" + k,     // память ниже минимума
		"$argon2id$v=19$m=4194304,t=3,p=2$" + s + "$" + k,  // 4 ГиБ
		"$argon2id$v=19$m=65537,t=3,p=2$" + s + "$" + k,    // выше параметра по умолчанию
		"$argon2id$v=19$m=19456,t=1,p=2$" + s + "$" + k,    // t = 1 требует m ≥ 46 МиБ
		"$argon2id$v=19$m=65536,t=0,p=2$" + s + "$" + k,    // t = 0
		"$argon2id$v=19$m=65536,t=1000,p=2$" + s + "$" + k, // слишком долго
		"$argon2id$v=19$m=65536,t=3,p=0$" + s + "$" + k,
		"$argon2id$v=19$m=65536,t=3,p=255$" + s + "$" + k,
		"$argon2id$v=19$m=99999999999,t=3,p=2$" + s + "$" + k,
		"$argon2id$v=19$m=65536,t=3,p=2$" + s + "==$" + k, // дополнение
		"$argon2id$v=19$m=65536,t=3,p=2$" + s + "$" + k + "=",
		"$argon2id$v=19$m=65536,t=3,p=2$" + s[:21] + "\n" + s[21:] + "$" + k, // перевод строки
		"$argon2id$v=19$m=65536,t=3,p=2$" + s[:21] + "h$" + k,                // лишние биты
		"$argon2id$v=19$m=65536,t=3,p=2$MDEyMzQ1Njc4OWFi$" + k,               // соль 12 байт
		"$argon2id$v=19$m=65536,t=3,p=2$" + s + "$AAECAwQFBgcICQo",           // хеш 11 байт
		"$argon2id$v=19$m=65536,t=3,p=2$" + s + "$" + k + "$",
		"$argon2id$v=19$m=65536,t=3,p=2$" + s + "$" + strings.Repeat("A", 300),
	}
	for _, b := range bad {
		if _, _, _, err := parseArgon2id(b); !errors.Is(err, ErrInvalidPasswordHash) {
			t.Errorf("принята строка %q: %v", b, err)
		}
	}
	// Verify с повреждённым хешем — ошибка, а не «неверный пароль».
	if ok, _, err := mustPasswordHasher(t).Verify(context.Background(), []byte("пароль"), bad[1]); ok || !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("повреждённый хеш: %v %v", ok, err)
	}
}

// Векторы эталонной реализации phc-winner-argon2 (src/test.c, Argon2id версии 19):
// пароль «password», соль «somesalt», p = 1. Проверяют x/crypto на рабочих
// параметрах памяти, а не только на малых, как самотест.
func TestArgon2idReferenceVectors(t *testing.T) {
	for _, v := range []struct {
		time, memory uint32
		want         string
	}{
		{2, 256, "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe"},
		{2, 65536, "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"},
	} {
		key, err := argon2Compute(context.Background(), []byte("password"), []byte("somesalt"),
			argon2Params{memory: v.memory, time: v.time, threads: 1, keyLen: 32})
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(key); got != v.want {
			t.Errorf("t=%d m=%d: %s", v.time, v.memory, got)
		}
	}
}

// FuzzParseArgon2id: разбор не паникует, принятые строки укладываются в
// границы и однозначны — обратное кодирование даёт ту же строку.
func FuzzParseArgon2id(f *testing.F) {
	f.Add(validPHC)
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAECAwQFBgcICQoLDA0ODw")
	f.Add("$argon2id$v=19$m=65536,t=3,p=2$$")
	f.Add("$argon2id$v=19$m=,t=,p=$x$y")
	f.Add("$$$$$")
	f.Fuzz(func(t *testing.T, s string) {
		p, salt, key, err := parseArgon2id(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("ошибка другого вида: %v", err)
			}
			return
		}
		if p.memory < argon2MinMemory || p.memory > argon2MaxMemory || p.time < 1 || p.time > argon2MaxTime ||
			(p.time == 1 && p.memory < argon2MinMemoryT1) ||
			p.threads < 1 || p.threads > argon2MaxThreads || p.saltLen != len(salt) || p.keyLen != len(key) ||
			len(salt) < argon2MinSaltLen || len(salt) > argon2MaxSaltLen || len(key) < argon2MinKeyLen || len(key) > argon2MaxKeyLen {
			t.Fatalf("параметры вне границ: %+v", p)
		}
		if got := encodeArgon2id(p, salt, key); got != s {
			t.Fatalf("разбор неоднозначен: %q → %q", s, got)
		}
	})
}
