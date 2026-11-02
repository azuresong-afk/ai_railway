package inventory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/audit"
)

// Отчёты сканера и запрет модели (задача 5.22 этапа 5, ADR-0029, п. 4 и
// дополнение 1): сверка хешей весов и адаптеров с реестром, запрет при
// расхождении или находке с запретом, снятие запрета с повторной
// проверкой, хранение последних отчётов.

const otherHash = "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752"

// guardedModel — модель провайдера с весами, адаптером и токенизатором.
func guardedModel(mem *Memory, id string) {
	mem.models[id] = Model{ID: id, Kind: KindProvider, Provider: "vllm", Name: "llama-ft", Origin: OriginManual, Status: StatusActive,
		Files: []File{
			{Path: "model.safetensors", Size: 4096, Role: RoleWeights, HashAlg: HashAlg, Hash: hexHash(repHash)},
			{Path: "adapter/adapter_model.safetensors", Size: 512, Role: RoleAdapter, HashAlg: HashAlg, Hash: hexHash(repHash)},
			{Path: "tokenizer.json", Size: 100, Role: RoleTokenizer, HashAlg: HashAlg, Hash: hexHash(repHash)},
		}}
}

func verifyReport(files ...ReportFile) ReportInput {
	return ReportInput{Kind: ReportVerify, Host: "gpu-01", ScannerVersion: "1.5.0", Files: files}
}

func okFiles() []ReportFile {
	return []ReportFile{{Path: "model.safetensors", Size: 4096, SHA256: repHash},
		{Path: "adapter/adapter_model.safetensors", Size: 512, SHA256: repHash},
		{Path: "tokenizer.json", Size: 100, SHA256: repHash}}
}

func TestSubmitReportHashes(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		files   func() []ReportFile
		hashes  string
		problem string
	}{
		"совпадает":          {okFiles, HashesMatch, ""},
		"токенизатор другой": {func() []ReportFile { f := okFiles(); f[2].SHA256 = otherHash; return f }, HashesMatch, ""},
		"токенизатора нет":   {func() []ReportFile { return okFiles()[:2] }, HashesMatch, ""},
		"веса изменены":      {func() []ReportFile { f := okFiles(); f[0].SHA256 = otherHash; return f }, HashesMismatch, MismatchChanged},
		"размер другой":      {func() []ReportFile { f := okFiles(); f[0].Size = 4097; return f }, HashesMismatch, MismatchChanged},
		"адаптер пропал":     {func() []ReportFile { f := okFiles(); return append(f[:1], f[2]) }, HashesMismatch, MismatchMissing},
		"не прочитан":        {func() []ReportFile { f := okFiles(); f[1].SHA256 = ""; return f }, HashesMismatch, MismatchNotHashed},
		"лишний адаптер": {func() []ReportFile {
			return append(okFiles(), ReportFile{Path: "lora/extra.safetensors", Size: 10, SHA256: otherHash})
		}, HashesMismatch, MismatchExtra},
		"лишний pickle": {func() []ReportFile {
			return append(okFiles(), ReportFile{Path: "evil.PT", Size: 10, SHA256: otherHash})
		}, HashesMismatch, MismatchExtra},
		"лишний README": {func() []ReportFile {
			return append(okFiles(), ReportFile{Path: "README.md", Size: 10, SHA256: otherHash})
		}, HashesMatch, ""},
	} {
		t.Run(name, func(t *testing.T) {
			mem := NewMemory()
			guardedModel(mem, "m1")
			s := aibomService(t, mem)
			r, m, err := s.SubmitReport(ctx, testBy, "m1", verifyReport(tc.files()...))
			if err != nil {
				t.Fatal(err)
			}
			if r.Hashes != tc.hashes {
				t.Fatalf("сверка %s: %+v", r.Hashes, r.Detail.Mismatches)
			}
			acts := actions(mem)
			if tc.problem == "" {
				if r.Verdict != VerdictOK || m.Status != StatusActive || r.Blocked || acts[ActionHashMismatch] || acts[ActionBlocked] {
					t.Fatalf("без расхождений: %+v, аудит %v", r, acts)
				}
				return
			}
			if r.Verdict != VerdictBlock || !r.Blocked || m.Status != StatusBlocked || r.Detail.MismatchTotal != 1 ||
				r.Detail.Mismatches[0].Problem != tc.problem || r.Detail.BlockReasons[0] != BlockHashMismatch {
				t.Fatalf("расхождение: %+v", r)
			}
			if !acts[ActionScanReported] || !acts[ActionHashMismatch] || !acts[ActionBlocked] {
				t.Fatalf("аудит: %v", acts)
			}
			if bm, _ := s.Blocked(ctx); len(bm) != 1 || bm[0] != (BlockedModel{Provider: "vllm", Name: "llama-ft"}) {
				t.Fatalf("запрещённые: %+v", bm)
			}
		})
	}
}

func TestSubmitReportScanAndNoReference(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	guardedModel(mem, "m1")
	// Модель без файлов весов в реестре — сверять не с чем.
	mem.models["m2"] = Model{ID: "m2", Kind: KindProvider, Provider: "vllm", Name: "qwen", Origin: OriginTraffic, Status: StatusActive}
	s := aibomService(t, mem)

	r, m, err := s.SubmitReport(ctx, testBy, "m2", verifyReport(okFiles()...))
	if err != nil || r.Hashes != HashesNoReference || r.Verdict != VerdictOK || m.Status != StatusActive {
		t.Fatalf("без эталона: %+v %v", r, err)
	}
	// Находка с весом warn — warn, без запрета; block — запрет.
	in := ReportInput{Kind: ReportScan, Host: "gpu-01", ScannerVersion: "1.5.0", Files: []ReportFile{
		{Path: "model.safetensors", Size: 4096, Format: "safetensors", SHA256: repHash,
			Findings: []ReportFinding{{Code: "header.metadata", Severity: SeverityWarn, Detail: "x"}}},
		{Path: "adapter/adapter_model.safetensors", Size: 512, Format: "safetensors", SHA256: repHash}}}
	r, m, err = s.SubmitReport(ctx, testBy, "m1", in)
	if err != nil || r.Verdict != VerdictWarn || r.Findings != 1 || m.Status != StatusActive || r.Templates != TemplatesNone {
		t.Fatalf("warn: %+v %v", r, err)
	}
	in.Findings = []ReportFinding{{Code: "limit.files", Severity: SeverityBlock, Detail: "предел"}}
	r, m, err = s.SubmitReport(ctx, testBy, "m1", in)
	if err != nil || r.Verdict != VerdictBlock || !r.Blocked || m.Status != StatusBlocked || r.Detail.BlockReasons[0] != BlockScan {
		t.Fatalf("block: %+v %v", r, err)
	}
	// Повторный запрет уже запрещённой модели — без новой записи models.blocked.
	n := count(mem, ActionBlocked)
	r, _, err = s.SubmitReport(ctx, testBy, "m1", in)
	if err != nil || r.Blocked || r.Verdict != VerdictBlock || count(mem, ActionBlocked) != n {
		t.Fatalf("повтор: %+v %v", r, err)
	}
	if _, _, err := s.SubmitReport(ctx, testBy, "nope", in); !errors.Is(err, ErrNotFound) {
		t.Fatalf("нет модели: %v", err)
	}
	// Эталонные хеши — все файлы реестра.
	ref, err := s.Reference(ctx, "m1")
	if err != nil || ref.Status != StatusBlocked || len(ref.Files) != 3 || ref.Files[0].SHA256 != repHash || ref.HashAlg != HashAlg {
		t.Fatalf("эталон: %+v %v", ref, err)
	}
}

func count(mem *Memory, action string) int {
	n := 0
	for _, r := range mem.Records {
		if r.Action == action {
			n++
		}
	}
	return n
}

func TestUnblockAndDelete(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	guardedModel(mem, "m1")
	s := aibomService(t, mem)
	admin := By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "secadm"}}
	if _, err := s.Unblock(ctx, admin, "m1"); !errors.Is(err, ErrNotBlocked) {
		t.Fatalf("не запрещена: %v", err)
	}
	f := okFiles()
	f[0].SHA256 = otherHash
	if _, m, err := s.SubmitReport(ctx, testBy, "m1", verifyReport(f...)); err != nil || m.Status != StatusBlocked {
		t.Fatalf("запрет: %+v %v", m, err)
	}
	if err := s.DeleteModel(ctx, admin, "m1"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("удаление запрещённой: %v", err)
	}
	// Без повторной проверки (токен) — отказ.
	if _, err := s.Unblock(ctx, admin, "m1"); !errors.Is(err, ErrConfirmNeeded) {
		t.Fatalf("без проверки: %v", err)
	}
	// Неверный пароль — отказ, модель запрещена.
	bad := errors.New("неверный пароль")
	admin.Confirm = func(context.Context) error { return bad }
	if _, err := s.Unblock(ctx, admin, "m1"); !errors.Is(err, bad) {
		t.Fatalf("неверная проверка: %v", err)
	}
	if m, _, _ := s.Model(ctx, "m1"); m.Status != StatusBlocked || count(mem, ActionUnblocked) != 0 {
		t.Fatalf("после отказа: %+v", m)
	}
	called := 0
	admin.Confirm = func(context.Context) error { called++; return nil }
	m, err := s.Unblock(ctx, admin, "m1")
	if err != nil || m.Status != StatusActive || called != 1 {
		t.Fatalf("снятие: %+v %v", m, err)
	}
	rec := mem.Records[len(mem.Records)-1]
	d, _ := rec.Details.(map[string]any)
	if rec.Action != ActionUnblocked || d["weakening"] != true || rec.Actor.ID != "u1" {
		t.Fatalf("аудит снятия: %+v", rec)
	}
	if bm, _ := s.Blocked(ctx); len(bm) != 0 {
		t.Fatalf("после снятия: %+v", bm)
	}
	if err := s.DeleteModel(ctx, admin, "m1"); err != nil {
		t.Fatalf("удаление после снятия: %v", err)
	}
}

func TestReportsKeepLatest(t *testing.T) {
	ctx := context.Background()
	mem := NewMemory()
	guardedModel(mem, "m1")
	s := aibomService(t, mem)
	var last string
	for i := range MaxReportsPerModel + 5 {
		in := verifyReport(okFiles()...)
		in.Host = fmt.Sprintf("gpu-%02d", i)
		r, _, err := s.SubmitReport(ctx, testBy, "m1", in)
		if err != nil {
			t.Fatal(err)
		}
		last = r.ID
	}
	list, err := s.Reports(ctx, "m1")
	if err != nil || len(list) != MaxReportsPerModel || list[0].ID != last || list[0].Host != fmt.Sprintf("gpu-%02d", MaxReportsPerModel+4) {
		t.Fatalf("отчёты: %d %v", len(list), err)
	}
}

func TestMismatchLimits(t *testing.T) {
	mem := NewMemory()
	guardedModel(mem, "m1")
	s := aibomService(t, mem)
	files := okFiles()
	for i := range maxMismatches + 10 {
		files = append(files, ReportFile{Path: fmt.Sprintf("extra/%03d.gguf", i), Size: 1, SHA256: otherHash})
	}
	r, _, err := s.SubmitReport(context.Background(), testBy, "m1", verifyReport(files...))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Detail.Mismatches) != maxMismatches || r.Detail.MismatchTotal != maxMismatches+10 {
		t.Fatalf("расхождений %d из %d", len(r.Detail.Mismatches), r.Detail.MismatchTotal)
	}
	for _, rec := range mem.Records {
		if rec.Action != ActionHashMismatch {
			continue
		}
		d := rec.Details.(map[string]any)
		paths := d["paths"].([]string)
		if len(paths) != maxAuditPaths || d["extra"] != maxMismatches || d["total"] != maxMismatches+10 ||
			strings.Contains(fmt.Sprint(d), otherHash) {
			t.Fatalf("аудит расхождений: %v", d)
		}
	}
}
