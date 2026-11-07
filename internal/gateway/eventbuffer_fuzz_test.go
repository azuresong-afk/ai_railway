package gateway

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// fuzzBodies — открытые тексты записей fuzzSegment.
var fuzzBodies = []string{`{"id":"a"}`, `{"id":"b","content":{"request":"Привет"}}`}

// fuzzSegment — правильный сегмент из двух записей на ключе key.
func fuzzSegment(tb testing.TB, a aisecCrypto.AEAD, key evbKeyID) []byte {
	tb.Helper()
	at := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	seg := evbSegHeader{key: key, seq: 7, created: at}.encode()
	for i, body := range fuzzBodies {
		off := int64(len(seg))
		ts := at.Add(time.Duration(i) * time.Second)
		sealed, err := a.Seal([]byte(body), recordAAD(key, 7, off, ts))
		if err != nil {
			tb.Fatal(err)
		}
		seg = append(seg, encodeRecord(ts, sealed)...)
	}
	return seg
}

// FuzzEventBuffer — файлы буфера событий на диске (задача 6.31, ADR-0037):
// каталог состояния мог быть изменён, поэтому курсор, заголовок сегмента и
// записи — недоверенный ввод. Без паники; длины проверяются до чтения
// тела; курсор записывается и читается обратно тем же; разобранные
// записи укладываются в файл, расшифровываются только неизменённые.
func FuzzEventBuffer(f *testing.F) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		f.Fatal(err)
	}
	a, err := p.NewAEAD(bytes.Repeat([]byte{3}, aisecCrypto.AEADKeySize))
	if err != nil {
		f.Fatal(err)
	}
	key := evbKeyID{1, 2, 3, 4, 5, 6, 7, 8}
	good := fuzzSegment(f, a, key)
	f.Add(good)
	f.Add(good[:len(good)-3])
	f.Add(good[:evbSegHeaderSize])
	f.Add(evbCursor{seq: 7, off: 100, idx: 2}.encode())
	f.Add([]byte("AISECEVB"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		if c, err := parseCursor(data); err == nil {
			if back, err := parseCursor(c.encode()); err != nil || back != c {
				t.Fatalf("курсор не читается обратно: %+v → %+v, %v", c, back, err)
			}
		}
		if len(data) >= evbRecHeaderSize {
			if h, err := parseRecHeader(data[:evbRecHeaderSize]); err == nil && (h.n < 1 || h.n > evbMaxSealed || h.at.IsZero()) {
				t.Fatalf("заголовок записи вне пределов принят: %+v", h)
			}
		}
		r := bytes.NewReader(data)
		sc, err := scanSegment(r, int64(len(data)))
		if err != nil {
			return
		}
		if sc.end < evbSegHeaderSize || sc.end > int64(len(data)) || sc.records < 0 || (sc.broken != (sc.end < int64(len(data)))) {
			t.Fatalf("обход: %+v при длине %d", sc, len(data))
		}
		off, n := int64(evbSegHeaderSize), int64(0)
		for off < sc.end {
			h, sealed, err := readRecord(r, off, sc.end)
			if err != nil {
				// CRC или подмена: обход по заголовкам прошёл, чтение — нет.
				break
			}
			plain, err := a.Open(sealed, recordAAD(sc.header.key, sc.header.seq, off, h.at))
			if err == nil {
				var e events.Event
				_ = json.Unmarshal(plain, &e) //nolint:gosec // G104: проверяется только отсутствие паники
				// Подделать запись без ключа нельзя: расшифровывается только
				// то, что зашифровано (nonce случайный — сравнение по тексту).
				if string(plain) != fuzzBodies[0] && string(plain) != fuzzBodies[1] {
					t.Fatalf("расшифрована запись, которой не было: %q", plain)
				}
			}
			off += evbRecHeaderSize + int64(h.n)
			n++
		}
		if n > sc.records {
			t.Fatalf("прочитано %d записей, обход нашёл %d", n, sc.records)
		}
	})
}

// Разбор имён и пределов формата — без fuzz.
func TestEventBufferFormatLimits(t *testing.T) {
	for _, tc := range []struct {
		name string
		ok   bool
	}{
		{segName(1), true}, {"seg-0000000000000001.evb", true}, {"seg-000000000000000A.evb", false},
		{"seg-1.evb", false}, {"seg-0000000000000001.evb.bak", false}, {"key-00000000000000ff.pem", false},
	} {
		if _, ok := parseHexName(tc.name, evbSegPrefix, evbSegSuffix); ok != tc.ok {
			t.Errorf("%s: %v", tc.name, ok)
		}
	}
	at := time.Unix(1, 0)
	big := make([]byte, evbRecHeaderSize)
	copy(big, encodeRecord(at, []byte{1})[:evbRecHeaderSize])
	big[0], big[1], big[2], big[3] = 0xff, 0xff, 0xff, 0xff
	if _, err := parseRecHeader(big); err == nil {
		t.Fatal("запись длиннее предела принята")
	}
	zero := encodeRecord(at, nil)[:evbRecHeaderSize]
	if _, err := parseRecHeader(zero); err == nil {
		t.Fatal("пустая запись принята")
	}
	if _, err := scanSegment(bytes.NewReader(nil), evbMaxSegment+1); err == nil {
		t.Fatal("сегмент больше предела принят")
	}
	c := evbCursor{seq: 1, off: evbSegHeaderSize, idx: 1}.encode()
	if _, err := parseCursor(c); err == nil {
		t.Fatal("курсор с записями без места под них принят")
	}
}

// Значения флагов буфера в internal/config совпадают с пределами буфера.
func TestEventBufferDefaultsMatchConfig(t *testing.T) {
	if config.DefaultEventBufferMiB<<20 != DefaultEventBufferMaxBytes || config.MinEventBufferMiB<<20 != MinEventBufferMaxBytes ||
		config.MaxEventBufferMiB<<20 > MaxEventBufferMaxBytes || config.DefaultEventBufferMaxAge != DefaultEventBufferMaxAge ||
		config.MinEventBufferMaxAge != MinEventBufferMaxAge || config.MaxEventBufferMaxAge != MaxEventBufferMaxAge {
		t.Fatal("значения буфера событий в internal/config и internal/gateway расходятся")
	}
}
