package rag

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestParseManifest(t *testing.T) {
	h := strings.Repeat("ab", 32)
	ok := fmt.Sprintf(`{"documents":[{"id":"a/b.md","sha256":"%s","size":0},{"id":"Отчёт 2026.docx#3","sha256":"%s","size":12,"excluded":true}]}`, h, h)
	ds, err := ParseManifest([]byte(ok))
	if err != nil || len(ds) != 2 || !ds[1].Excluded || len(ds[0].SHA256) != 32 {
		t.Fatalf("%+v %v", ds, err)
	}
	if ds, err := ParseManifest([]byte(`{"documents":[]}`)); err != nil || len(ds) != 0 {
		t.Fatalf("пустой манифест: %v", err)
	}
	bad := map[string]string{
		"нет списка":           `{}`,
		"неизвестное поле":     `{"documents":[],"x":1}`,
		"мусор после":          `{"documents":[]} {}`,
		"пустой ID":            fmt.Sprintf(`{"documents":[{"id":"","sha256":"%s","size":1}]}`, h),
		"длинный ID":           fmt.Sprintf(`{"documents":[{"id":"%s","sha256":"%s","size":1}]}`, strings.Repeat("a", MaxDocumentID+1), h),
		"управляющий символ":   fmt.Sprintf(`{"documents":[{"id":"a\u0007","sha256":"%s","size":1}]}`, h),
		"смена направления":    fmt.Sprintf(`{"documents":[{"id":"a\u202eb","sha256":"%s","size":1}]}`, h),
		"пробел в конце":       fmt.Sprintf(`{"documents":[{"id":"a ","sha256":"%s","size":1}]}`, h),
		"повтор ID":            fmt.Sprintf(`{"documents":[{"id":"a","sha256":"%s","size":1},{"id":"a","sha256":"%s","size":1}]}`, h, h),
		"хеш в верхнем":        fmt.Sprintf(`{"documents":[{"id":"a","sha256":"%s","size":1}]}`, strings.ToUpper(h)),
		"короткий хеш":         `{"documents":[{"id":"a","sha256":"abcd","size":1}]}`,
		"отрицательный размер": fmt.Sprintf(`{"documents":[{"id":"a","sha256":"%s","size":-1}]}`, h),
		"большой размер":       fmt.Sprintf(`{"documents":[{"id":"a","sha256":"%s","size":%d}]}`, h, MaxDocumentSize+1),
	}
	for name, body := range bad {
		var ie *InputError
		if _, err := ParseManifest([]byte(body)); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		} else if strings.Contains(err.Error(), "a\u202eb") {
			t.Errorf("%s: значение в тексте ошибки: %v", name, err)
		}
	}
}

// Предел числа документов и число ошибок в ответе.
func TestParseManifestLimits(t *testing.T) {
	h := strings.Repeat("0", 64)
	var b strings.Builder
	b.WriteString(`{"documents":[`)
	for i := range MaxDocuments + 1 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"id":"d%d","sha256":"%s","size":1}`, i, h)
	}
	b.WriteString(`]}`)
	if b.Len() > MaxBody {
		t.Fatalf("тело теста больше предела: %d", b.Len())
	}
	var ie *InputError
	if _, err := ParseManifest([]byte(b.String())); !errors.As(err, &ie) || !strings.Contains(err.Error(), "100000") {
		t.Fatalf("сверх предела документов: %v", err)
	}
	if _, err := ParseManifest(make([]byte, MaxBody+1)); !errors.As(err, &ie) {
		t.Fatalf("сверх предела тела: %v", err)
	}
	b.Reset()
	b.WriteString(`{"documents":[`)
	for i := range 100 {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"id":"","sha256":"x","size":-1}`)
	}
	b.WriteString(`]}`)
	_, err := ParseManifest([]byte(b.String()))
	if !errors.As(err, &ie) || len(ie.Errs) != maxReportedErrors+1 || !strings.Contains(ie.Errs[maxReportedErrors].Error(), "ещё ошибок: 280") {
		t.Fatalf("ошибок в ответе: %v", err)
	}
}

func TestParseExclusion(t *testing.T) {
	in, err := ParseExclusion([]byte(`{"document_id":"kb/a.md","reason":"инъекция\nв разделе 3"}`))
	if err != nil || in.DocumentID != "kb/a.md" {
		t.Fatalf("%+v %v", in, err)
	}
	for _, body := range []string{`{"document_id":""}`, `{"document_id":"a","reason":"\u0000"}`, `{"document_id":"a","x":1}`,
		`{"document_id":"a","reason":"` + strings.Repeat("я", MaxReason+1) + `"}`, `{"document_id":"a"} 1`} {
		var ie *InputError
		if _, err := ParseExclusion([]byte(body)); !errors.As(err, &ie) {
			t.Errorf("%s: %v", body, err)
		}
	}
}

// FuzzParseManifest — разбор манифеста: только InputError при отказе;
// принятый — ID по правилам и без повторов, хеш из 32 байт, размер в
// пределах; повторная запись разбирается так же.
func FuzzParseManifest(f *testing.F) {
	h := strings.Repeat("ab", 32)
	f.Add([]byte(`{"documents":[{"id":"a","sha256":"` + h + `","size":1}]}`))
	f.Add([]byte(`{"documents":[{"id":"a","sha256":"` + h + `","size":1,"excluded":true},{"id":"b","sha256":"` + h + `","size":0}]}`))
	f.Add([]byte(`{"documents":[]}`))
	f.Add([]byte(`{"documents":[{"id":"\u202e","sha256":"","size":-1}]}`))
	f.Add([]byte(`{"documents":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		ds, err := ParseManifest(data)
		if err != nil {
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ошибка не InputError: %v", err)
			}
			return
		}
		if len(ds) > MaxDocuments {
			t.Fatalf("документов %d", len(ds))
		}
		seen := map[string]bool{}
		in := ManifestInput{Documents: []DocumentInput{}}
		for _, d := range ds {
			if d.ID == "" || len(d.ID) > MaxDocumentID || !utf8.ValidString(d.ID) || seen[d.ID] ||
				strings.ContainsFunc(d.ID, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
				t.Fatalf("недопустимый ID принят: %q", d.ID)
			}
			if len(d.SHA256) != 32 || d.Size < 0 || d.Size > MaxDocumentSize {
				t.Fatalf("недопустимый документ принят: %+v", d)
			}
			seen[d.ID] = true
			in.Documents = append(in.Documents, DocumentInput{ID: d.ID, SHA256: hex.EncodeToString(d.SHA256), Size: d.Size, Excluded: d.Excluded})
		}
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseManifest(b)
		if err != nil || len(again) != len(ds) {
			t.Fatalf("повторный разбор: %v", err)
		}
	})
}

func FuzzParseExclusion(f *testing.F) {
	f.Add([]byte(`{"document_id":"a","reason":"r"}`))
	f.Add([]byte(`{"document_id":"\u202e"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := ParseExclusion(data)
		if err != nil {
			return
		}
		if CheckDocumentID(in.DocumentID) != nil || utf8.RuneCountInString(in.Reason) > MaxReason {
			t.Fatalf("недопустимое исключение принято: %+v", in)
		}
	})
}
