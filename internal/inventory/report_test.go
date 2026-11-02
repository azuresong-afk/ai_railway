package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Разбор отчёта сканера (задачи 5.21 и 5.22): строгий JSON, пределы
// ADR-0029 (4 МиБ, 10 000 файлов, 100 находок на файл), правила путей как у
// ручной записи; в отчёте verify только пути, размеры и хеши.

const repHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func reportJSON(t testing.TB, in ReportInput) []byte {
	t.Helper()
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func validScan() ReportInput {
	return ReportInput{Kind: ReportScan, Host: "gpu-01.example.ru", ScannerVersion: "1.5.0", Files: []ReportFile{
		{Path: "model.safetensors", Size: 4096, Format: "safetensors", Tensors: 12, SHA256: repHash},
		{Path: "tokenizer_config.json", Size: 512, Format: "tokenizer_config", SHA256: repHash,
			ChatTemplates: []ReportTemplate{{Source: "tokenizer_config", Text: "{{ messages }}"}}},
		{Path: "weights/old.bin", Size: 10, Format: "pickle", SHA256: repHash,
			Findings: []ReportFinding{{Code: "pickle", Severity: SeverityBlock, Detail: "опкод REDUCE"}}},
	}}
}

func TestParseReportAccepts(t *testing.T) {
	in, err := ParseReport(reportJSON(t, validScan()))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Files) != 3 || in.Files[2].Findings[0].Code != "pickle" || in.Files[1].ChatTemplates[0].Text != "{{ messages }}" {
		t.Fatalf("разбор: %+v", in)
	}
	// Пустой каталог и отчёт verify только с хешами.
	empty := ReportInput{Kind: ReportVerify, Host: "h", ScannerVersion: "dev", Files: []ReportFile{}}
	if _, err := ParseReport(reportJSON(t, empty)); err != nil {
		t.Fatal(err)
	}
	v := ReportInput{Kind: ReportVerify, Host: "h", ScannerVersion: "dev", Files: []ReportFile{{Path: "a/b.gguf", Size: 1, SHA256: repHash}}}
	if _, err := ParseReport(reportJSON(t, v)); err != nil {
		t.Fatal(err)
	}
}

func TestParseReportRejects(t *testing.T) {
	for name, c := range map[string]struct {
		mut  func(*ReportInput)
		want string
	}{
		"вид":               {func(r *ReportInput) { r.Kind = "upload" }, "kind"},
		"узел":              {func(r *ReportInput) { r.Host = "узел 1" }, "host"},
		"версия":            {func(r *ReportInput) { r.ScannerVersion = "" }, "scanner_version"},
		"нет files":         {func(r *ReportInput) { r.Files = nil }, "files"},
		"путь ..":           {func(r *ReportInput) { r.Files[0].Path = "../etc/passwd" }, "files[0].path"},
		"путь повтор":       {func(r *ReportInput) { r.Files[1].Path = r.Files[0].Path }, "повторяется"},
		"путь U+202E":       {func(r *ReportInput) { r.Files[0].Path = "a‮bin.safetensors" }, "files[0].path"},
		"размер":            {func(r *ReportInput) { r.Files[0].Size = -1 }, "files[0].size"},
		"хеш":               {func(r *ReportInput) { r.Files[0].SHA256 = strings.ToUpper(repHash) }, "files[0].sha256"},
		"формат":            {func(r *ReportInput) { r.Files[0].Format = "Safe Tensors" }, "files[0].format"},
		"вес находки":       {func(r *ReportInput) { r.Files[2].Findings[0].Severity = "info" }, "severity"},
		"код находки":       {func(r *ReportInput) { r.Files[2].Findings[0].Code = "PICKLE" }, "code"},
		"пояснение":         {func(r *ReportInput) { r.Files[2].Findings[0].Detail = "a\x1b[31m" }, "detail"},
		"шаблон пустой":     {func(r *ReportInput) { r.Files[1].ChatTemplates[0].Text = "" }, "text"},
		"шаблон длинный":    {func(r *ReportInput) { r.Files[1].ChatTemplates[0].Text = strings.Repeat("x", MaxTemplateBytes+1) }, "text"},
		"шаблон NUL":        {func(r *ReportInput) { r.Files[1].ChatTemplates[0].Text = "a\x00b" }, "text"},
		"источник":          {func(r *ReportInput) { r.Files[1].ChatTemplates[0].Source = "" }, "source"},
		"тензоры":           {func(r *ReportInput) { r.Files[0].Tensors = MaxTensors + 1 }, "tensors"},
		"verify с форматом": {func(r *ReportInput) { r.Kind = ReportVerify }, "verify"},
		"находок много": {func(r *ReportInput) {
			r.Files[2].Findings = make([]ReportFinding, MaxReportFindings+1)
			for i := range r.Files[2].Findings {
				r.Files[2].Findings[i] = ReportFinding{Code: "pickle", Severity: SeverityBlock}
			}
		}, "не больше 100"},
		"шаблонов в файле": {func(r *ReportInput) {
			r.Files[1].ChatTemplates = make([]ReportTemplate, MaxFileTemplates+1)
		}, "chat_templates"},
	} {
		in := validScan()
		c.mut(&in)
		_, err := ParseReport(reportJSON(t, in))
		var ie *InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, raw := range map[string]string{
		"не JSON":          `{`,
		"неизвестное поле": `{"kind":"scan","host":"h","scanner_version":"1","files":[],"weights":"AAAA"}`,
		"второе значение":  `{"kind":"scan","host":"h","scanner_version":"1","files":[]} {}`,
		"тело слишком большое": `{"kind":"scan","host":"h","scanner_version":"1","files":[],"findings":[{"code":"x","severity":"warn","detail":"` +
			strings.Repeat("a", MaxReportBody) + `"}]}`,
	} {
		if _, err := ParseReport([]byte(raw)); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

// Граница: ровно 10 000 файлов принимаются, 10 001 — нет; ошибок в ответе
// не больше maxReportErrors+1 строк.
func TestParseReportLimits(t *testing.T) {
	in := ReportInput{Kind: ReportVerify, Host: "h", ScannerVersion: "1", Files: make([]ReportFile, MaxReportFiles)}
	for i := range in.Files {
		in.Files[i] = ReportFile{Path: fmt.Sprintf("f%05d.bin", i), Size: 1, SHA256: repHash}
	}
	if _, err := ParseReport(reportJSON(t, in)); err != nil {
		t.Fatal(err)
	}
	in.Files = append(in.Files, ReportFile{Path: "extra.bin", SHA256: repHash})
	if _, err := ParseReport(reportJSON(t, in)); err == nil || !strings.Contains(err.Error(), "10000") {
		t.Fatalf("10 001 файл: %v", err)
	}
	bad := ReportInput{Kind: ReportVerify, Host: "h", ScannerVersion: "1", Files: make([]ReportFile, 500)}
	for i := range bad.Files {
		bad.Files[i] = ReportFile{Path: "../x" + fmt.Sprint(i)}
	}
	_, err := ParseReport(reportJSON(t, bad))
	var ie *InputError
	if !errors.As(err, &ie) || len(ie.Errs) != maxReportErrors+1 || !strings.Contains(err.Error(), "и ещё ошибок") {
		t.Fatalf("предел ошибок: %v", err)
	}
}

// FuzzParseReport: недоверенный отчёт с узла заказчика не роняет разбор;
// принятый отчёт соблюдает пределы и правила путей.
func FuzzParseReport(f *testing.F) {
	f.Add(reportJSON(f, validScan()))
	f.Add([]byte(`{"kind":"verify","host":"h","scanner_version":"1","files":[{"path":"a","size":1,"sha256":"` + repHash + `"}]}`))
	f.Add([]byte(`{"kind":"scan","host":"h","scanner_version":"1","files":[{"path":"a/../b","size":0,"format":"x"}]}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := ParseReport(data)
		if err != nil {
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ошибка не InputError: %v", err)
			}
			return
		}
		if len(in.Files) > MaxReportFiles || len(in.Findings) > MaxReportFindings || (in.Kind != ReportScan && in.Kind != ReportVerify) {
			t.Fatalf("принят отчёт вне пределов: %d файлов", len(in.Files))
		}
		seen := map[string]bool{}
		for _, f := range in.Files {
			if checkPath(f.Path) != nil || seen[f.Path] || len(f.Findings) > MaxReportFindings || len(f.ChatTemplates) > MaxFileTemplates {
				t.Fatalf("принят неверный файл %q", f.Path)
			}
			seen[f.Path] = true
			for _, tm := range f.ChatTemplates {
				if tm.Text == "" || len(tm.Text) > MaxTemplateBytes {
					t.Fatal("принят шаблон вне пределов")
				}
			}
		}
	})
}
