package api

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/inventory"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Сканер моделей и запрет модели (ТЗ 5.12, DM-27–DM-29; задачи 5.21 и 5.22
// этапа 5, ADR-0029, п. 4 и дополнение 1). Отчёт и эталонные хеши — токен
// узла с моделями (models.report); список отчётов — inventory.read; снятие
// запрета — администратор безопасности в консоли с повторной проверкой;
// база эталонов шаблонов чата — служебная база по ADR-0028 со своим правом.

// templatesMaxBody — подписанный файл базы эталонов (как у каталога).
const templatesMaxBody = 4 << 20

func inventoryScanRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/inventory/models/{id}/reference", Permission: auth.PermModelsReport,
			Handler: needInventory(d, d.inventoryReference)},
		{Method: http.MethodPost, Path: "/api/v1/inventory/models/{id}/scan-reports", Permission: auth.PermModelsReport,
			MaxBody: inventory.MaxReportBody, Handler: needInventory(d, d.postScanReport)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/models/{id}/scan-reports", Permission: auth.PermInventoryRead,
			Handler: needInventory(d, d.listScanReports)},
		{Method: http.MethodPost, Path: "/api/v1/inventory/models/{id}/unblock", Permission: auth.PermInventoryUnblock, SessionOnly: true,
			MaxBody: smallMaxBody, Handler: needInventory(d, d.unblockModel)},
		{Method: http.MethodGet, Path: "/api/v1/inventory/chat-templates", Permission: auth.PermInventoryRead,
			Handler: needTemplates(d, d.getChatTemplates)},
		{Method: http.MethodPut, Path: "/api/v1/inventory/chat-templates", Permission: auth.PermModelsTemplatesLoad,
			MaxBody: templatesMaxBody, Handler: needTemplates(d, d.putChatTemplates)},
		// Возврат предыдущей версии — только из консоли (5Н3 ревью 5.r1).
		{Method: http.MethodPost, Path: "/api/v1/inventory/chat-templates/rollback", Permission: auth.PermModelsTemplatesLoad, SessionOnly: true,
			MaxBody: smallMaxBody, Handler: needTemplates(d, d.rollbackChatTemplates)},
	}
}

func needTemplates(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return needInventory(d, func(w http.ResponseWriter, r *http.Request) {
		if d.Inventory.TemplatesDB() == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "База эталонов шаблонов чата не подключена на сервере."))
			return
		}
		h(w, r)
	})
}

// scanProblem — ошибки отчётов и запрета поверх inventoryProblem.
func scanProblem(logger *slog.Logger, err error) *Problem {
	var re *reauthError
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, inventory.ErrNotBlocked):
		return NewProblem(http.StatusConflict, CodeConflict, "Модель не запрещена: снимать нечего.")
	case errors.Is(err, inventory.ErrConfirmNeeded):
		return NewProblem(http.StatusForbidden, CodeForbidden, "Запрет модели снимают в консоли с вводом текущего пароля или кода.")
	}
	return inventoryProblem(logger, err)
}

func (d Deps) inventoryReference(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	ref, err := d.Inventory.Reference(r.Context(), id)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, ref)
}

// ScanFileView — файл отчёта с находками (в списке отчётов — только файлы
// с находками, без хешей прочих файлов).
type ScanFileView struct {
	Path     string                    `json:"path"`
	Size     int64                     `json:"size"`
	Format   string                    `json:"format,omitempty"`
	SHA256   string                    `json:"sha256,omitempty"`
	Findings []inventory.ReportFinding `json:"findings"`
}

// maxFindingFiles — файлов с находками в ответе об отчёте.
const maxFindingFiles = 100

// ScanReportView — отчёт сканера.
type ScanReportView struct {
	ID             string                     `json:"id"`
	ModelID        string                     `json:"model_id"`
	Kind           string                     `json:"kind"`
	Host           string                     `json:"host"`
	ScannerVersion string                     `json:"scanner_version"`
	ReceivedAt     time.Time                  `json:"received_at"`
	ReceivedBy     string                     `json:"received_by"`
	Verdict        string                     `json:"verdict"`
	Hashes         string                     `json:"hashes"`
	Templates      string                     `json:"templates"`
	Files          int                        `json:"files"`
	Findings       int                        `json:"findings"`
	Truncated      bool                       `json:"truncated"`
	Blocked        bool                       `json:"blocked"`
	BlockReasons   []string                   `json:"block_reasons"`
	ReportFindings []inventory.ReportFinding  `json:"report_findings"`
	FindingFiles   []ScanFileView             `json:"finding_files"`
	Mismatches     []inventory.HashMismatch   `json:"mismatches"`
	MismatchTotal  int                        `json:"mismatch_total"`
	ChatTemplates  []inventory.StoredTemplate `json:"chat_templates"`
}

func scanReportView(rep inventory.ScanReport) ScanReportView {
	v := ScanReportView{ID: rep.ID, ModelID: rep.ModelID, Kind: rep.Kind, Host: rep.Host, ScannerVersion: rep.ScannerVersion,
		ReceivedAt: rep.ReceivedAt.UTC(), ReceivedBy: rep.ReceivedBy, Verdict: rep.Verdict, Hashes: rep.Hashes, Templates: rep.Templates,
		Files: rep.Files, Findings: rep.Findings, Truncated: rep.Detail.Truncated, Blocked: rep.Blocked,
		BlockReasons: orEmpty(rep.Detail.BlockReasons), ReportFindings: orEmpty(rep.Detail.Findings), FindingFiles: []ScanFileView{},
		Mismatches: orEmpty(rep.Detail.Mismatches), MismatchTotal: rep.Detail.MismatchTotal, ChatTemplates: orEmpty(rep.Detail.Templates)}
	for _, f := range rep.Detail.Files {
		if len(f.Findings) == 0 {
			continue
		}
		if len(v.FindingFiles) == maxFindingFiles {
			break
		}
		v.FindingFiles = append(v.FindingFiles, ScanFileView{Path: f.Path, Size: f.Size, Format: f.Format, SHA256: f.SHA256, Findings: f.Findings})
	}
	return v
}

func orEmpty[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// ScanReportResult — ответ на отчёт: итог и состояние модели после него.
type ScanReportResult struct {
	ScanReportView
	ModelStatus string `json:"model_status"`
}

// postScanReport принимает отчёт aisec-cli models scan или verify.
func (d Deps) postScanReport(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	if !fileContentType(r, "application/json") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — отчёт сканера в формате JSON (Content-Type: application/json)."))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Отчёт сканера больше 4 МиБ."))
			return
		}
		WriteProblem(w, NewProblem(http.StatusBadRequest, CodeInvalidRequest, "Тело запроса не прочитано."))
		return
	}
	in, err := inventory.ParseReport(data)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	rep, m, err := d.Inventory.SubmitReport(r.Context(), by, id, in)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusCreated, ScanReportResult{ScanReportView: scanReportView(rep), ModelStatus: m.Status})
}

// ScanReportList — последние отчёты модели (новые первыми).
type ScanReportList struct {
	Items []ScanReportView `json:"items"`
}

func (d Deps) listScanReports(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	reps, err := d.Inventory.Reports(r.Context(), id)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	out := ScanReportList{Items: make([]ScanReportView, 0, len(reps))}
	for _, rep := range reps {
		out.Items = append(out.Items, scanReportView(rep))
	}
	WriteJSON(w, http.StatusOK, out)
}

// unblockModel снимает запрет модели: текущий пароль или код TOTP в теле.
func (d Deps) unblockModel(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathID(w, r, inventoryModelNotFound)
	if !ok {
		return
	}
	var req reauthFields
	if p := DecodeJSON(w, r, &req, smallMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	by.Confirm = d.confirmFunc(r, req, inventory.ActionUnblocked, inventory.ErrConfirmNeeded)
	if _, err := d.Inventory.Unblock(r.Context(), by, id); err != nil {
		WriteProblem(w, scanProblem(d.Logger, err))
		return
	}
	m, us, err := d.Inventory.Model(r.Context(), id)
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	d.writeInventoryCard(w, http.StatusOK, m, us)
}

// ChatTemplateFamilyView — семейство в базе эталонов.
type ChatTemplateFamilyView struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Match    []string `json:"match"`
	Variants []string `json:"variants"`
}

// ChatTemplatesView — база эталонов шаблонов чата: состояние версий и
// семейства действующей версии (без текстов шаблонов).
type ChatTemplatesView struct {
	Active   string                   `json:"active"`
	Current  *servicedb.VersionState  `json:"current,omitempty"`
	Previous *servicedb.VersionState  `json:"previous,omitempty"`
	Families []ChatTemplateFamilyView `json:"families"`
}

func (d Deps) chatTemplatesView(w http.ResponseWriter, r *http.Request) {
	st, active, err := d.Inventory.TemplatesDB().Snapshot(r.Context())
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	v := ChatTemplatesView{Active: st.Active, Current: st.Current, Previous: st.Previous, Families: []ChatTemplateFamilyView{}}
	if active != nil {
		if b, ok := active.Content.Value.(*inventory.TemplateBase); ok {
			for _, f := range b.Families {
				fv := ChatTemplateFamilyView{ID: f.ID, Title: f.Title, Match: f.Match, Variants: []string{}}
				for _, t := range f.Templates {
					name := t.Variant
					if t.Name != "" {
						name += " (" + t.Name + ")"
					}
					fv.Variants = append(fv.Variants, name)
				}
				v.Families = append(v.Families, fv)
			}
		}
	}
	WriteJSON(w, http.StatusOK, v)
}

func (d Deps) getChatTemplates(w http.ResponseWriter, r *http.Request) { d.chatTemplatesView(w, r) }

// putChatTemplates принимает подписанный файл базы эталонов
// (application/octet-stream) целиком.
func (d Deps) putChatTemplates(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	if !fileContentType(r, "application/octet-stream") {
		WriteProblem(w, NewProblem(http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"Тело запроса — подписанный файл базы эталонов (Content-Type: application/octet-stream)."))
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			WriteProblem(w, NewProblem(http.StatusRequestEntityTooLarge, CodePayloadTooLarge, "Файл базы эталонов больше 4 МиБ."))
			return
		}
		WriteProblem(w, NewProblem(http.StatusBadRequest, CodeInvalidRequest, "Тело запроса не прочитано."))
		return
	}
	_, err = d.Inventory.TemplatesDB().Upload(r.Context(), servicedb.By{Actor: by.Actor, IP: by.IP}, data)
	if p := serviceDBProblem(err, "базу эталонов", false); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	d.chatTemplatesView(w, r)
}

// rollbackChatTemplates возвращает предыдущую версию базы эталонов после
// её повторной проверки.
func (d Deps) rollbackChatTemplates(w http.ResponseWriter, r *http.Request) {
	by, ok := d.inventoryBy(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	_, err := d.Inventory.TemplatesDB().Rollback(r.Context(), servicedb.By{Actor: by.Actor, IP: by.IP})
	if p := serviceDBProblem(err, "базу эталонов", true); p != nil {
		WriteProblem(w, p)
		return
	}
	if err != nil {
		WriteProblem(w, inventoryProblem(d.Logger, err))
		return
	}
	d.chatTemplatesView(w, r)
}
