package inventory

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Отчёты сканера и запрет использования модели (ТЗ 5.12, DM-27–DM-29;
// задачи 5.21 и 5.22 этапа 5, ADR-0029, п. 4 и дополнение 1).
//
// Сервер решает о запрете сам, по содержанию отчёта: находка сканера с
// весом block (pickle, нарушенная структура, предел), внедрённые инструкции
// в шаблоне чата (DM-28) или расхождение файлов весов и адаптеров с
// эталонными хешами реестра (DM-29). Модель переводится в состояние blocked
// той же транзакцией, что сохраняет отчёт и пишет аудит; запрещённая модель
// исключается из пакета конфигурации шлюзов. Снимает запрет администратор
// безопасности (inventory.unblock) с повторной проверкой паролем или кодом.

// StatusBlocked — запрет использования модели (5.22).
const StatusBlocked = "blocked"

// MaxReportsPerModel — отчётов сканера на модель: старые удаляются.
const MaxReportsPerModel = 20

// Итоги отчёта.
const (
	VerdictOK    = "ok"
	VerdictWarn  = "warn"
	VerdictBlock = "block"
)

// Итоги сверки хешей.
const (
	HashesMatch       = "match"
	HashesMismatch    = "mismatch"
	HashesNoReference = "no_reference"
)

// Расхождения файла с реестром.
const (
	MismatchChanged   = "changed"    // хеш или размер не совпадают
	MismatchMissing   = "missing"    // файла из реестра нет на узле
	MismatchExtra     = "extra"      // лишний файл весов или адаптера
	MismatchNotHashed = "not_hashed" // файл есть, но не прочитан сканером
)

// Причины запрета.
const (
	BlockScan         = "scan"          // находка сканера с весом block (DM-27)
	BlockChatTemplate = "chat_template" // инъекция в шаблоне чата (DM-28)
	BlockHashMismatch = "hash_mismatch" // расхождение с эталонными хешами (DM-29)
)

// Коды аудита отчётов и запрета (ADR-0029, п. 7).
const (
	ActionScanReported = "models.scan_reported"
	ActionHashMismatch = "models.hash_mismatch"
	ActionBlocked      = "models.blocked"
	ActionUnblocked    = "models.unblocked"
)

// maxMismatches — расхождений в отчёте поимённо; дальше — только число.
const maxMismatches = 100

// maxAuditPaths — путей в записи аудита models.hash_mismatch.
const maxAuditPaths = 20

// maxStoredTemplateText — текст шаблонов вне эталона, сохраняемый в
// отчёте для разбора (шаблон — метаданные модели, не данные
// пользователей): не больше стольких байт на отчёт.
const maxStoredTemplateText = 128 << 10

// Ошибки отчётов и запрета.
var (
	// ErrNotBlocked — модель не запрещена: снимать нечего.
	ErrNotBlocked = errors.New("модель не запрещена")
	// ErrBlocked — действие недопустимо для запрещённой модели (удаление
	// обошло бы снятие запрета).
	ErrBlocked = errors.New("модель запрещена")
	// ErrConfirmNeeded — снятие запрета без повторной проверки (не из
	// сессии консоли).
	ErrConfirmNeeded = errors.New("нужна повторная проверка паролем или кодом")
)

// HashMismatch — расхождение файла с эталоном реестра.
type HashMismatch struct {
	Path     string `json:"path"`
	Role     string `json:"role,omitempty"`
	Problem  string `json:"problem"`
	Expected string `json:"expected_sha256,omitempty"`
	Actual   string `json:"actual_sha256,omitempty"`
	// ExpectedSize и ActualSize — размеры; -1 — неизвестен.
	ExpectedSize int64 `json:"expected_size"`
	ActualSize   int64 `json:"actual_size"`
}

// StoredTemplate — шаблон чата в сохранённом отчёте: итог проверки и, для
// шаблонов вне эталона, текст (в пределах maxStoredTemplateText).
type StoredTemplate struct {
	TemplateCheck
	Text string `json:"text,omitempty"`
}

// ReportDetail — проверенный отчёт и итоги сервера (столбец report).
type ReportDetail struct {
	Files      []ReportFile    `json:"files"`
	Findings   []ReportFinding `json:"findings,omitempty"`
	Truncated  bool            `json:"truncated,omitempty"`
	Mismatches []HashMismatch  `json:"mismatches,omitempty"`
	// MismatchTotal — расхождений всего (поимённо — до maxMismatches).
	MismatchTotal int              `json:"mismatch_total"`
	Templates     []StoredTemplate `json:"templates,omitempty"`
	BlockReasons  []string         `json:"block_reasons,omitempty"`
}

// ScanReport — отчёт сканера в реестре.
type ScanReport struct {
	ID             string
	ModelID        string
	Kind           string
	Host           string
	ScannerVersion string
	ReceivedAt     time.Time
	ReceivedBy     string
	Verdict        string
	Hashes         string
	Templates      string
	Files          int
	Findings       int
	// Blocked — отчёт перевёл модель в состояние blocked.
	Blocked bool
	Detail  ReportDetail
}

// ReferenceFile — эталонный файл модели для models verify.
type ReferenceFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
}

// Reference — эталонные хеши файлов модели (models.report).
type Reference struct {
	ModelID string          `json:"model_id"`
	Status  string          `json:"status"`
	HashAlg string          `json:"hash_alg"`
	Files   []ReferenceFile `json:"files"`
}

// BlockedModel — запрещённая модель для пакета шлюза.
type BlockedModel struct {
	Provider string
	Name     string
}

// Reference — эталонные хеши модели: все файлы реестра.
func (s *Service) Reference(ctx context.Context, id string) (Reference, error) {
	m, err := s.store.Model(ctx, s.orgID, id)
	if err != nil {
		return Reference{}, err
	}
	ref := Reference{ModelID: m.ID, Status: m.Status, HashAlg: HashAlg, Files: make([]ReferenceFile, 0, len(m.Files))}
	for _, f := range m.Files {
		ref.Files = append(ref.Files, ReferenceFile{Path: f.Path, Size: f.Size, Role: f.Role, SHA256: hex.EncodeToString(f.Hash)})
	}
	return ref, nil
}

// TemplatesDB — база эталонов шаблонов чата (nil — не подключена).
func (s *Service) TemplatesDB() *servicedb.Manager { return s.templates }

// activeTemplates — действующая база эталонов и её версия; nil — базы нет.
func (s *Service) activeTemplates(ctx context.Context) (*TemplateBase, uint64, error) {
	if s.templates == nil {
		return nil, 0, nil
	}
	v, err := s.templates.Active(ctx)
	if err != nil || v == nil {
		return nil, 0, err
	}
	b, ok := v.Content.Value.(*TemplateBase)
	if !ok {
		return nil, 0, errors.New("реестр ИИ: база эталонов другого вида")
	}
	return b, v.Content.Version, nil
}

// SubmitReport принимает отчёт сканера по модели id: сверка хешей с
// реестром, проверка шаблонов чата, итог и, если нужно, запрет модели — одной
// транзакцией с записями аудита.
func (s *Service) SubmitReport(ctx context.Context, by By, id string, in ReportInput) (ScanReport, Model, error) {
	reportID, err := s.newID()
	if err != nil {
		return ScanReport{}, Model{}, err
	}
	base, baseVersion, err := s.activeTemplates(ctx)
	if err != nil {
		return ScanReport{}, Model{}, err
	}
	// Шаблоны проверяются до транзакции: детекторы не держат блокировку
	// строки модели. Имя модели для семейства — из реестра, поэтому сначала
	// читается модель.
	m0, err := s.store.Model(ctx, s.orgID, id)
	if err != nil {
		return ScanReport{}, Model{}, err
	}
	checks, tmplResult, err := s.checkTemplates(ctx, base, baseVersion, m0.Name, in)
	if err != nil {
		return ScanReport{}, Model{}, err
	}
	now := s.now()
	var out Model
	rep, err := s.store.AddReport(ctx, s.orgID, id, func(m *Model) (ScanReport, []audit.Entry, error) {
		r := evaluate(m, in, checks, tmplResult)
		r.ID, r.ModelID, r.ReceivedAt, r.ReceivedBy = reportID, m.ID, now, by.ref()
		entries := []audit.Entry{by.entry(ActionScanReported, m.ID, map[string]any{"provider": m.Provider, "name": m.Name,
			"report": r.ID, "kind": r.Kind, "host": r.Host, "scanner_version": r.ScannerVersion, "verdict": r.Verdict, "hashes": r.Hashes,
			"templates": r.Templates, "files": r.Files, "findings": r.Findings, "block_reasons": r.Detail.BlockReasons})}
		if r.Hashes == HashesMismatch {
			entries = append(entries, by.entry(ActionHashMismatch, m.ID, mismatchDetails(m, r)))
		}
		if len(r.Detail.BlockReasons) > 0 && m.Status != StatusBlocked {
			m.Status, m.UpdatedAt, m.UpdatedBy = StatusBlocked, now, by.ref()
			r.Blocked = true
			entries = append(entries, by.entry(ActionBlocked, m.ID, map[string]any{"provider": m.Provider, "name": m.Name,
				"report": r.ID, "reasons": r.Detail.BlockReasons, "host": r.Host}))
		}
		out = *m
		return r, entries, nil
	})
	if err != nil {
		return ScanReport{}, Model{}, err
	}
	return rep, out, nil
}

func mismatchDetails(m *Model, r ScanReport) map[string]any {
	counts := map[string]int{}
	paths := []string{}
	for _, x := range r.Detail.Mismatches {
		counts[x.Problem]++
		if len(paths) < maxAuditPaths {
			paths = append(paths, x.Path)
		}
	}
	return map[string]any{"provider": m.Provider, "name": m.Name, "report": r.ID, "host": r.Host, "kind": r.Kind,
		"changed": counts[MismatchChanged], "missing": counts[MismatchMissing], "extra": counts[MismatchExtra],
		"not_hashed": counts[MismatchNotHashed], "total": r.Detail.MismatchTotal, "paths": paths}
}

// checkTemplates проверяет все шаблоны отчёта. Одинаковый шаблон в
// нескольких файлах (GGUF и tokenizer_config.json) проверяется один раз.
func (s *Service) checkTemplates(ctx context.Context, base *TemplateBase, version uint64, model string, in ReportInput) ([]StoredTemplate, string, error) {
	result := TemplatesNone
	var out []StoredTemplate
	cache := map[string]TemplateCheck{}
	budget := maxStoredTemplateText
	for _, f := range in.Files {
		for _, t := range f.ChatTemplates {
			norm := NormalizeTemplate(t.Text)
			c, ok := cache[norm]
			if !ok {
				var err error
				if c, err = checkTemplate(ctx, base, version, model, f.Path, t); err != nil {
					return nil, "", err
				}
				cache[norm] = c
			}
			c.File, c.Source, c.Name = f.Path, t.Source, t.Name
			st := StoredTemplate{TemplateCheck: c}
			if c.Result != TemplateBaselineOK && len(t.Text) <= budget {
				st.Text, budget = t.Text, budget-len(t.Text)
			}
			out = append(out, st)
			if templateRank[c.Result] > templateRank[result] {
				result = c.Result
			}
		}
	}
	return out, result, nil
}

// evaluate — итоги отчёта по модели m (с файлами реестра).
func evaluate(m *Model, in ReportInput, templates []StoredTemplate, tmplResult string) ScanReport {
	r := ScanReport{Kind: in.Kind, Host: in.Host, ScannerVersion: in.ScannerVersion, Files: len(in.Files), Templates: tmplResult,
		Detail: ReportDetail{Files: in.Files, Findings: in.Findings, Truncated: in.Truncated, Templates: templates}}
	block, warn := false, false
	tally := func(fs []ReportFinding) {
		for _, f := range fs {
			r.Findings++
			switch f.Severity {
			case SeverityBlock:
				block = true
			case SeverityWarn:
				warn = true
			}
		}
	}
	tally(in.Findings)
	for _, f := range in.Files {
		tally(f.Findings)
	}
	if block {
		r.Detail.BlockReasons = append(r.Detail.BlockReasons, BlockScan)
	}
	switch tmplResult {
	case TemplateInjection:
		r.Detail.BlockReasons = append(r.Detail.BlockReasons, BlockChatTemplate)
	case TemplateChanged:
		warn = true
	}
	r.Hashes, r.Detail.Mismatches, r.Detail.MismatchTotal = compareHashes(m.Files, in)
	if r.Hashes == HashesMismatch {
		r.Detail.BlockReasons = append(r.Detail.BlockReasons, BlockHashMismatch)
	}
	switch {
	case len(r.Detail.BlockReasons) > 0:
		r.Verdict = VerdictBlock
	case warn:
		r.Verdict = VerdictWarn
	default:
		r.Verdict = VerdictOK
	}
	return r
}

// guarded — роли файлов, которые сверяются с реестром (DM-29: веса, LoRA и
// другие расширения). Токенизатор и конфигурация сверяются, только если их
// нет — не расхождение: их меняют без смены весов.
func guarded(role string) bool { return role == RoleWeights || role == RoleAdapter }

// compareHashes сверяет файлы отчёта с эталоном реестра: изменённый или
// пропавший файл весов или адаптера, а также лишний файл в формате весов,
// которого нет в реестре. Эталона нет (в реестре нет файлов весов и
// адаптеров) — no_reference.
func compareHashes(ref []File, in ReportInput) (string, []HashMismatch, int) {
	var guardedRef []File
	known := make(map[string]bool, len(ref))
	for _, f := range ref {
		known[f.Path] = true
		if guarded(f.Role) {
			guardedRef = append(guardedRef, f)
		}
	}
	if len(guardedRef) == 0 {
		return HashesNoReference, nil, 0
	}
	got := make(map[string]ReportFile, len(in.Files))
	for _, f := range in.Files {
		got[f.Path] = f
	}
	var out []HashMismatch
	total := 0
	add := func(x HashMismatch) {
		total++
		if len(out) < maxMismatches {
			out = append(out, x)
		}
	}
	for _, f := range guardedRef {
		exp := hex.EncodeToString(f.Hash)
		g, ok := got[f.Path]
		switch {
		case !ok:
			add(HashMismatch{Path: f.Path, Role: f.Role, Problem: MismatchMissing, Expected: exp, ExpectedSize: f.Size, ActualSize: -1})
		case g.SHA256 == "":
			add(HashMismatch{Path: f.Path, Role: f.Role, Problem: MismatchNotHashed, Expected: exp, ExpectedSize: f.Size, ActualSize: g.Size})
		case !bytes.Equal(g.fileHash(), f.Hash) || g.Size != f.Size:
			add(HashMismatch{Path: f.Path, Role: f.Role, Problem: MismatchChanged, Expected: exp, Actual: g.SHA256,
				ExpectedSize: f.Size, ActualSize: g.Size})
		}
	}
	for _, f := range in.Files {
		if known[f.Path] || !extraWeights(f) {
			continue
		}
		add(HashMismatch{Path: f.Path, Problem: MismatchExtra, Actual: f.SHA256, ExpectedSize: -1, ActualSize: f.Size})
	}
	if total == 0 {
		return HashesMatch, nil, 0
	}
	return HashesMismatch, out, total
}

// extraWeights — файл, которого нет в реестре, похож на веса или адаптер:
// формат весов по сигнатуре (scan) или, в отчёте verify без форматов, —
// расширение файла весов (adapter_model.safetensors — тоже).
func extraWeights(f ReportFile) bool {
	if f.Format != "" {
		return weightFormats[f.Format]
	}
	p := strings.ToLower(f.Path)
	for _, ext := range []string{".safetensors", ".gguf", ".onnx", ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".npy", ".npz", ".h5", ".msgpack"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

// Reports — последние отчёты сканера по модели (новые первыми).
func (s *Service) Reports(ctx context.Context, id string) ([]ScanReport, error) {
	return s.store.Reports(ctx, s.orgID, id, MaxReportsPerModel)
}

// Blocked — запрещённые модели с провайдером: их исключает пакет шлюза.
func (s *Service) Blocked(ctx context.Context) ([]BlockedModel, error) {
	ms, err := s.store.Blocked(ctx, s.orgID)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(ms, func(a, b BlockedModel) int {
		if c := strings.Compare(a.Provider, b.Provider); c != 0 {
			return c
		}
		return strings.Compare(a.Name, b.Name)
	})
	return ms, nil
}

// Unblock снимает запрет модели (models.unblocked): повторная проверка
// паролем или кодом (by.Confirm), запись — ослабление защиты (DM-40).
func (s *Service) Unblock(ctx context.Context, by By, id string) (Model, error) {
	return s.store.UpdateModel(ctx, s.orgID, id, func(m *Model) (audit.Entry, error) {
		if m.Status != StatusBlocked {
			return audit.Entry{}, ErrNotBlocked
		}
		if by.Confirm == nil {
			return audit.Entry{}, ErrConfirmNeeded
		}
		if err := by.Confirm(ctx); err != nil {
			return audit.Entry{}, err
		}
		m.Status, m.UpdatedAt, m.UpdatedBy = StatusActive, s.now(), by.ref()
		return by.entry(ActionUnblocked, m.ID, map[string]any{"provider": m.Provider, "name": m.Name,
			"weakening": true, "weakening_reasons": []string{"model_unblocked"}}), nil
	})
}

// marshalDetail — столбец report: JSON без экранирования HTML.
func marshalDetail(d ReportDetail) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
