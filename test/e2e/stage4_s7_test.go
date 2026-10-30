//go:build e2e

package e2e

// Сценарий S7 этапа 4 (задача 4.30): подготовка к аттестации. Аудитор
// смотрит состояние соответствия требованиям, администратор безопасности
// ставит ручную отметку по организационной мере, и отчёт «Соответствие
// требованиям» уходит в HTML, CSV и XLSX с итогом, пунктами, доказательствами
// и этой отметкой — без содержимого запросов и ответов. На настоящем
// сервере и живой PostgreSQL.

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

// s7Item — пункт соответствия из API консоли.
type s7Item struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Draft  bool   `json:"draft"`
	Manual bool   `json:"manual"`
	Status string `json:"status"`
	Mark   *struct {
		Status  string
		Comment string
		SetBy   string `json:"set_by"`
	}
}

// s7Overview — обзор соответствия.
type s7Overview struct {
	Summary struct {
		Percent *int
		Counted int
		Drafts  int
	}
	Items []s7Item
}

func s7Get(t *testing.T, c *s2Client) s7Overview {
	t.Helper()
	r := c.do("GET", "/api/v1/compliance", nil)
	if r.code != http.StatusOK {
		t.Fatalf("соответствие: %s", r)
	}
	var ov s7Overview
	r.json(t, &ov)
	return ov
}

func TestE2EStage4_S7_ComplianceReport(t *testing.T) {
	st := s3NewStack(t, s3Opts{})
	st.policy("support")
	app := st.app("support-bot", "support")
	st.startGateway()

	// Немного трафика, чтобы автоматические проверки и доказательства не были пустыми.
	phone := pii.SynthPhone(7)
	if code, body := st.chat(app.key, "Перезвоните клиенту по телефону "+phone+"."); code != http.StatusOK {
		t.Fatalf("запрос с ПДн: %d %s", code, body)
	}
	if code, _ := st.chat(app.key, s3InjectionText); code != http.StatusBadRequest {
		t.Fatalf("инъекция не заблокирована: %d", code)
	}

	// Аудитор и администратор системы читают состояние, но не ставят отметки.
	auditor := st.admin.createUser("auditor-s7", auth.RoleAuditor)
	ac := st.s.client("198.51.100.51")
	ac.signIn(auditor)
	sysadmin := st.admin.createUser("sysadmin-s7", auth.RoleSystemAdmin)
	sc := st.s.client("198.51.100.52")
	sc.signIn(sysadmin)
	before := s7Get(t, ac)
	if before.Summary.Percent == nil || before.Summary.Counted == 0 || len(before.Items) == 0 {
		t.Fatalf("обзор соответствия пуст: %+v", before.Summary)
	}
	if s7Get(t, sc).Summary.Counted != before.Summary.Counted {
		t.Fatal("у администратора системы другой обзор соответствия")
	}
	// Пункт, которому нужна ручная отметка (организационная мера), не из проекта документа.
	var manual s7Item
	for _, it := range before.Items {
		if it.Manual && !it.Draft && it.Status == "manual" {
			manual = it
			break
		}
	}
	if manual.ID == "" {
		t.Fatalf("в базе нет пункта с ручной отметкой: %+v", before.Items)
	}
	const comment = "Приказ об ответственном за обеспечение безопасности ПДн издан"
	mark := map[string]any{"status": "met", "comment": comment, "document": "Приказ № 12 от 01.09.2026",
		"review_by": time.Now().AddDate(1, 0, 0).Format("2006-01-02")}
	for who, c := range map[string]*s2Client{"аудитор": ac, "администратор системы": sc} {
		if r := c.do("PUT", "/api/v1/compliance/requirements/"+manual.ID+"/mark", mark); r.code != http.StatusForbidden {
			t.Fatalf("отметка от роли «%s»: %s", who, r)
		}
	}
	if st.s.auditCount("compliance.mark_set") != 0 {
		t.Fatal("отказ в доступе оставил отметку в аудите")
	}
	if r := st.admin.do("PUT", "/api/v1/compliance/requirements/"+manual.ID+"/mark", mark); r.code != http.StatusOK {
		t.Fatalf("отметка: %s", r)
	}
	if n := st.s.auditCount("compliance.mark_set"); n != 1 {
		t.Fatalf("записей compliance.mark_set: %d", n)
	}
	after := s7Get(t, ac)
	var marked s7Item
	for _, it := range after.Items {
		if it.ID == manual.ID {
			marked = it
		}
	}
	if marked.Status != "met" || marked.Mark == nil || marked.Mark.Comment != comment || marked.Mark.SetBy == "" {
		t.Fatalf("пункт после отметки: %+v", marked)
	}
	if after.Summary.Percent == nil || *after.Summary.Percent <= *before.Summary.Percent || after.Summary.Counted != before.Summary.Counted {
		t.Fatalf("итог после отметки: %+v (был %+v)", after.Summary, before.Summary)
	}

	// Отчёт: период не нужен, нужны reports.read и compliance.read — аналитик без второго получает 403.
	analystUser := st.admin.createUser("analyst-s7", auth.RoleAnalyst)
	an := st.s.client("198.51.100.53")
	an.signIn(analystUser)
	if r := an.do("GET", "/api/v1/reports/compliance?format=html", nil); r.code != http.StatusForbidden {
		t.Fatalf("отчёт соответствия аналитику: %s", r)
	}
	exports := st.s.auditCount("data.export")
	r := ac.do("GET", "/api/v1/reports/compliance?format=html", nil)
	if r.code != http.StatusOK || !strings.HasPrefix(r.hdr.Get("Content-Type"), "text/html") {
		t.Fatalf("отчёт HTML: %d %v", r.code, r.hdr)
	}
	html := string(r.body)
	for _, want := range []string{"Соответствие требованиям", "База требований", "Итог соответствия", "Сводка", "Требования из проектов документов",
		manual.ID, comment, "Приказ № 12 от 01.09.2026", "фильтр событий"} {
		if !strings.Contains(html, want) {
			t.Fatalf("в отчёте нет %q:\n%.2000s", want, html)
		}
	}
	for _, bad := range []string{phone, "previous instructions", "<script", app.key} {
		if strings.Contains(html, bad) {
			t.Fatalf("в отчёте недопустимое %q", bad)
		}
	}
	if csp := r.hdr.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") && !strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("у отчёта HTML нет собственной политики CSP: %q", csp)
	}

	csv := ac.do("GET", "/api/v1/reports/compliance?format=csv", nil)
	if csv.code != http.StatusOK || !strings.HasPrefix(csv.hdr.Get("Content-Type"), "text/csv") ||
		!strings.HasPrefix(string(csv.body), "\ufeff") || !strings.Contains(string(csv.body), manual.ID) ||
		!strings.Contains(string(csv.body), comment) || strings.Contains(string(csv.body), phone) {
		t.Fatalf("отчёт CSV: %d %v\n%.600s", csv.code, csv.hdr, csv.body)
	}
	x := ac.do("GET", "/api/v1/reports/compliance?format=xlsx", nil)
	if x.code != http.StatusOK || !strings.Contains(x.hdr.Get("Content-Type"), "spreadsheetml") {
		t.Fatalf("отчёт XLSX: %d %v", x.code, x.hdr)
	}
	zr, err := zip.NewReader(bytes.NewReader(x.body), int64(len(x.body)))
	if err != nil {
		t.Fatalf("XLSX не архив: %v", err)
	}
	var sheet string
	for _, f := range zr.File {
		if strings.Contains(strings.ToLower(f.Name), "vba") || strings.HasSuffix(f.Name, ".bin") {
			t.Fatalf("в XLSX макросы или бинарные части: %s", f.Name)
		}
		if strings.HasPrefix(f.Name, "xl/worksheets/") || f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, 8<<20))
			_ = rc.Close() //nolint:gosec // G104: часть архива прочитана
			if err != nil {
				t.Fatal(err)
			}
			sheet += string(b)
		}
	}
	if !strings.Contains(sheet, manual.ID) || !strings.Contains(sheet, comment) || strings.Contains(sheet, "<f>") || strings.Contains(sheet, phone) {
		t.Fatalf("содержимое XLSX: нет пункта или отметки, есть формулы или ПДн:\n%.600s", sheet)
	}

	// Каждая выгрузка пишет data.export до выдачи данных, по записи на формат.
	if n := st.s.auditCount("data.export") - exports; n != 3 {
		t.Fatalf("записей data.export за выгрузки отчёта: %d", n)
	}
	formats := map[string]bool{}
	rows, err := st.s.pg().Query(context.Background(),
		`SELECT details->>'format' FROM audit_log WHERE action = 'data.export' AND details->>'report' = 'compliance'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var f *string
		if err := rows.Scan(&f); err != nil {
			t.Fatal(err)
		}
		if f != nil {
			formats[*f] = true
		}
	}
	if rows.Close(); rows.Err() != nil || !formats["html"] || !formats["csv"] || !formats["xlsx"] {
		t.Fatalf("форматы в data.export отчёта соответствия: %v %v", formats, rows.Err())
	}
}
