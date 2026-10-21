package events

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/ids"
)

// testNow — «сейчас» сервера в тестах пакета.
var testNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

// idAt — UUIDv7 со временем at (RFC 9562: 48 бит миллисекунд, версия 7,
// вариант 10); остальные биты — из наносекунд, чтобы ID различались.
func idAt(t testing.TB, at time.Time) string {
	t.Helper()
	var u [16]byte
	ms := uint64(at.UnixMilli())
	for i := range 6 {
		u[i] = byte(ms >> (40 - 8*i)) //nolint:gosec // G115: нужен именно младший байт сдвига
	}
	n := uint64(at.Nanosecond()) ^ uint64(at.Unix()) //nolint:gosec // G115: время теста положительное, нужны только биты
	for i := 6; i < 16; i++ {
		u[i] = byte(n >> (8 * (i % 8))) //nolint:gosec // G115: нужен именно младший байт сдвига
	}
	u[6] = u[6]&0x0f | 0x70
	u[8] = u[8]&0x3f | 0x80
	s := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	if _, err := ids.Parse(s); err != nil {
		t.Fatal(err)
	}
	return s
}

// incoming — корректное событие пакета со временем at.
func incoming(t testing.TB, at time.Time) Event {
	t.Helper()
	e := *request()
	e.ID = idAt(t, at)
	e.Time = at.Add(-time.Millisecond)
	return e
}

func encodeBatch(t testing.TB, b Batch) []byte {
	t.Helper()
	data, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeBatchOK(t *testing.T) {
	data := encodeBatch(t, Batch{Events: []Event{incoming(t, testNow)},
		Stats: &SenderStats{StartedAt: testNow.Add(-time.Hour), Dropped: 3, Rejected: 1}})
	b, err := DecodeBatch(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Events) != 1 || b.Stats == nil || b.Stats.Dropped != 3 || b.Stats.Rejected != 1 {
		t.Fatalf("пакет: %+v", b)
	}
	if code := Check(&b.Events[0], testNow); code != "" {
		t.Fatalf("Check: %s", code)
	}
}

func TestDecodeBatchErrors(t *testing.T) {
	ev := string(encodeBatch(t, Batch{Events: []Event{incoming(t, testNow)}}))
	inner := strings.TrimSuffix(strings.TrimPrefix(ev, `{"events":[`), `]}`)
	cases := map[string]string{
		"не JSON":           `{"events":[`,
		"пусто":             ``,
		"нет событий":       `{"events":[]}`,
		"null":              `{"events":null}`,
		"неизвестное поле":  `{"events":[` + inner + `],"gateway_id":"x"}`,
		"поле события":      `{"events":[` + strings.Replace(inner, `"id"`, `"gateway_id":"x","id"`, 1) + `]}`,
		"второе значение":   ev + ` {}`,
		"мусор после":       ev + `x`,
		"stats без времени": `{"events":[` + inner + `],"stats":{"dropped":1,"rejected":0}}`,
		"тип поля":          `{"events":[` + inner + `],"stats":{"started_at":"2026-10-21T00:00:00Z","dropped":-1,"rejected":0}}`,
		"массив":            `[` + inner + `]`,
		"больше 500":        `{"events":[` + strings.Repeat(inner+",", MaxBatchEvents) + inner + `]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeBatch(strings.NewReader(body)); !errors.Is(err, ErrBatch) {
				t.Fatalf("ожидалась ErrBatch: %v", err)
			}
		})
	}
	t.Run("ровно 500", func(t *testing.T) {
		body := `{"events":[` + strings.Repeat(inner+",", MaxBatchEvents-1) + inner + `]}`
		if _, err := DecodeBatch(strings.NewReader(body)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("больше MaxBatchBytes", func(t *testing.T) {
		big := `{"events":[` + inner + `],"x":"` + strings.Repeat("a", MaxBatchBytes) + `"}`
		if _, err := DecodeBatch(strings.NewReader(big)); !errors.Is(err, ErrBatch) {
			t.Fatalf("%v", err)
		}
	})
}

// Ошибка чтения тела (например, превышен MaxBytesReader) возвращается как
// есть: обработчик отвечает на неё 413, а не 400.
func TestDecodeBatchReadError(t *testing.T) {
	boom := errors.New("чтение прервано")
	r := io.MultiReader(strings.NewReader(`{"events":[`), errReaderOf(boom))
	if _, err := DecodeBatch(r); !errors.Is(err, boom) {
		t.Fatalf("ожидалась ошибка чтения: %v", err)
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

func errReaderOf(err error) io.Reader { return failingReader{err: err} }

func TestCheckRejects(t *testing.T) {
	long := strings.Repeat("я", maxShort)
	cases := map[string]struct {
		edit func(*Event)
		code string
	}{
		"схема":                   {func(e *Event) { e.PolicyMode = "audit" }, RejectInvalid},
		"none с содержимым":       {func(e *Event) { e.Storage = StorageNone }, RejectInvalid},
		"ID не UUID":              {func(e *Event) { e.ID = "not-a-uuid" }, RejectID},
		"ID прописными":           {func(e *Event) { e.ID = strings.ToUpper(e.ID) }, RejectID},
		"ID версии 4":             {func(e *Event) { e.ID = "0192f1a0-7b3c-4d4e-8f00-000000000000" }, RejectID},
		"старше 7 суток":          {func(e *Event) { at := testNow.Add(-MaxEventAge - time.Minute); e.ID, e.Time = idAt(t, at), at }, RejectTime},
		"в будущем":               {func(e *Event) { at := testNow.Add(MaxClockSkew + time.Minute); e.ID, e.Time = idAt(t, at), at }, RejectTime},
		"время не совпадает с ID": {func(e *Event) { e.Time = e.Time.Add(-MaxClockSkew - time.Second) }, RejectTime},
		"длинное приложение":      {func(e *Event) { e.App = long }, RejectLimits},
		"длинная модель":          {func(e *Event) { e.Model = strings.Repeat("m", maxShort+1) }, RejectLimits},
		"содержимое больше":       {func(e *Event) { e.Content.Request = strings.Repeat("a", MaxContentBytes+1) }, RejectLimits},
		"пустое содержимое":       {func(e *Event) { e.Content = &Content{} }, RejectLimits},
		"много находок":           {func(e *Event) { e.Findings = make([]Finding, maxFindings+1) }, RejectLimits},
		"много угроз":             {func(e *Event) { e.Threats = slicesRepeat("DM-01", maxThreats+1) }, RejectLimits},
		"отрицательная задержка":  {func(e *Event) { e.LatencyMS = map[string]int64{"total": -1} }, RejectLimits},
		"находка наоборот":        {func(e *Event) { e.Findings[0].Start, e.Findings[0].End = 5, 1 }, RejectLimits},
		"длинная заметка":         {func(e *Event) { e.Decision.Trace = []TraceStep{{Note: strings.Repeat("n", maxNote+1)}} }, RejectLimits},
		"NUL в содержимом":        {func(e *Event) { e.Content.Request = "a\x00b" }, RejectNUL},
		"NUL в приложении":        {func(e *Event) { e.App = "a\x00" }, RejectNUL},
		"NUL в находке":           {func(e *Event) { e.Findings[0].Location = "x\x00" }, RejectNUL},
		"NUL в правиле":           {func(e *Event) { e.Decision.Rule = "r\x00" }, RejectNUL},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := incoming(t, testNow)
			c.edit(&e)
			if got := Check(&e, testNow); got != c.code {
				t.Fatalf("код %q, ожидался %q", got, c.code)
			}
		})
	}
}

func TestCheckBoundaries(t *testing.T) {
	cases := map[string]func(*Event){
		"ровно 7 суток":         func(e *Event) { at := testNow.Add(-MaxEventAge); e.ID, e.Time = idAt(t, at), at },
		"ровно +5 минут":        func(e *Event) { at := testNow.Add(MaxClockSkew); e.ID, e.Time = idAt(t, at), at },
		"содержимое на пределе": func(e *Event) { e.Content.Request = strings.Repeat("a", MaxContentBytes) },
		"256 байт":              func(e *Event) { e.App = strings.Repeat("a", maxShort) },
		"full":                  func(e *Event) { e.Storage = StorageFull },
		"без содержимого":       func(e *Event) { e.Content = nil },
		"обратная косая черта":  func(e *Event) { e.Content.Request = `\u0000 — текст, а не символ` },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			e := incoming(t, testNow)
			edit(&e)
			if got := Check(&e, testNow); got != "" {
				t.Fatalf("отказ %q", got)
			}
		})
	}
}

func TestHasNUL(t *testing.T) {
	for in, want := range map[string]bool{
		`"a\u0000"`:      true,
		`"a\\u0000"`:     false,
		`"a\\\u0000"`:    true,
		`"\u00001"`:      true,
		`"u0000"`:        false,
		`"\\\\u0000"`:    false,
		`{"a":"\u0000"}`: true,
	} {
		if got := hasNUL([]byte(in)); got != want {
			t.Errorf("%s: %v", in, got)
		}
	}
}

func slicesRepeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// FuzzDecodeBatch — разбор пакета событий от шлюза (недоверенный ввод
// внутреннего API): не паникует, принятый пакет укладывается в пределы,
// а принятое Check событие можно записать (без U+0000, в окне времени).
func FuzzDecodeBatch(f *testing.F) {
	f.Add(encodeBatch(f, Batch{Events: []Event{incoming(f, testNow)}, Stats: &SenderStats{StartedAt: testNow}}))
	f.Add([]byte(`{"events":[{"id":"0192f1a0-7b3c-7d4e-8f00-000000000000","time":"2026-10-21T12:00:00Z","type":"auth_failure","auth_failure":{"reason":"r\u0000"}}]}`))
	f.Add([]byte(`{"events":[{}]}`))
	f.Add([]byte(`{"events":null,"stats":{"started_at":"0001-01-01T00:00:00Z"}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := DecodeBatch(bytes.NewReader(data))
		if err != nil {
			if !errors.Is(err, ErrBatch) {
				t.Fatalf("неожиданная ошибка: %v", err)
			}
			return
		}
		if len(b.Events) == 0 || len(b.Events) > MaxBatchEvents {
			t.Fatalf("событий %d", len(b.Events))
		}
		for i := range b.Events {
			e := &b.Events[i]
			if Check(e, testNow) != "" {
				continue
			}
			if _, err := PartitionTime(e.ID); err != nil {
				t.Fatalf("принят ID %q", e.ID)
			}
			if e.Time.Before(testNow.Add(-MaxEventAge)) || e.Time.After(testNow.Add(MaxClockSkew)) {
				t.Fatalf("принято время %v", e.Time)
			}
			d, err := json.Marshal(e.Details())
			if err != nil || hasNUL(d) || len(d) > maxDetailsBytes {
				t.Fatalf("принятые метаданные нельзя записать: %v", err)
			}
			if c := e.Content; c != nil && (strings.ContainsRune(c.Request, 0) || len(c.Request) > MaxContentBytes) {
				t.Fatal("принято содержимое с U+0000 или сверх предела")
			}
		}
	})
}
