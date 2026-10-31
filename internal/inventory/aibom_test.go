package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/audit"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/cyclonedx"
)

// AI-BOM реестра ИИ (задача 5.18, ADR-0029, п. 3): обязательные поля и типы
// компонентов CycloneDX 1.6, адрес провайдера без учётных данных, без ключей
// приложений, запись data.export с видом и числом компонентов (DM-41).

func aibomMemory() *Memory {
	mem := NewMemory()
	mem.Providers = []Provider{
		// Синтетический адрес с учётными данными: проверка, что они не попадают в AI-BOM.
		{ID: "p1", Slug: "gigachat", Name: "GigaChat", Type: "gigachat", External: true, //nolint:gosec // G101: синтетический адрес теста, не секрет
			Endpoint: "https://user:secret@gigachat.example.ru/api/v1?token=x"},
		{ID: "p2", Slug: "vllm", Name: "vLLM в контуре", Type: "openai", External: false, Endpoint: "http://10.0.0.5:8000/v1"},
	}
	mem.Apps = []App{
		{ID: "a1", Slug: "billing", Name: "Биллинг", Env: "prod", Department: "Финансы", Provider: "gigachat", Models: []string{"GigaChat-Pro"},
			Keys: []Key{{ID: "k1", Name: "Основной", Prefix: "aisec_keyprefix1", State: KeyActive}}},
		{ID: "a2", Slug: "support", Name: "Поддержка", Env: "prod", Provider: "vllm"},
		{ID: "a3", Slug: "old", Name: "Архив", Provider: "gigachat", Archived: true},
	}
	now := time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC)
	mem.models["m1"] = Model{ID: "m1", Kind: KindProvider, Provider: "gigachat", Name: "GigaChat-Pro", Origin: OriginTraffic, Status: StatusActive, CreatedAt: now}
	mem.models["m2"] = Model{ID: "m2", Kind: KindCustomer, Provider: "vllm", Name: "llama-ft", Version: "3", Title: "Кредитный ассистент",
		Owner: "Отдел ИИ", Origin: OriginManual, Status: StatusActive, CreatedAt: now.Add(time.Second),
		Files: []File{{Path: "model.safetensors", Size: 4096, Role: RoleWeights, HashAlg: HashAlg, Hash: make([]byte, 32)},
			{Path: "adapter/lora.safetensors", Size: 512, Role: "adapter", HashAlg: HashAlg, Hash: []byte(strings.Repeat("\x01", 32))}}}
	mem.usage = []Usage{{ID: 1, App: "support", Provider: "vllm", Model: "llama-ft", FirstSeen: now, LastSeen: now},
		{ID: 2, App: "ghost", Provider: "vllm", Model: "llama-ft", FirstSeen: now, LastSeen: now}}
	return mem
}

func aibomService(t *testing.T, mem *Memory) *Service {
	t.Helper()
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Store: mem, Provider: p, Clock: func() time.Time { return time.Date(2026, 10, 31, 13, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func findComponent(cs []cyclonedx.Component, ref string) *cyclonedx.Component {
	for i := range cs {
		if cs[i].BOMRef == ref {
			return &cs[i]
		}
		if c := findComponent(cs[i].Components, ref); c != nil {
			return c
		}
	}
	return nil
}

func TestAIBOMDocument(t *testing.T) {
	mem := aibomMemory()
	by := By{Actor: audit.Actor{Type: audit.ActorUser, ID: "u1", Name: "sysadm"}}
	bom, err := aibomService(t, mem).ExportAIBOM(context.Background(), by, "1.5.0")
	if err != nil {
		t.Fatal(err)
	}
	if err := cyclonedx.Validate(bom); err != nil {
		t.Fatalf("документ не по схеме: %v", err)
	}
	if bom.Metadata.Component.Type != "application" || bom.Metadata.Component.Version != "1.5.0" {
		t.Errorf("metadata.component: %+v", bom.Metadata.Component)
	}
	m := findComponent(bom.Components, "model:m2")
	if m == nil || m.Type != "machine-learning-model" || m.Publisher != "Отдел ИИ" || m.Version != "3" || len(m.Components) != 2 {
		t.Fatalf("модель заказчика: %+v", m)
	}
	f := m.Components[0]
	if f.Type != "file" || f.Name != "adapter/lora.safetensors" || len(f.Hashes) != 1 || f.Hashes[0].Alg != "SHA-256" ||
		f.Hashes[0].Content != strings.Repeat("01", 32) {
		t.Errorf("файл модели: %+v", f)
	}
	if c := findComponent(bom.Components, "app:old"); c != nil {
		t.Errorf("архивное приложение в AI-BOM: %+v", c)
	}
	if len(bom.Services) != 2 || bom.Services[0].TrustZone != "external" || bom.Services[1].TrustZone != "internal" {
		t.Fatalf("сервисы: %+v", bom.Services)
	}
	if ep := bom.Services[0].Endpoints; len(ep) != 1 || ep[0] != "https://gigachat.example.ru:443" {
		t.Errorf("адрес провайдера: %v", ep)
	}
	if ep := bom.Services[1].Endpoints; len(ep) != 1 || ep[0] != "http://10.0.0.5:8000" {
		t.Errorf("адрес провайдера в контуре: %v", ep)
	}
	data, err := json.Marshal(bom)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"secret", "token=x", "aisec_keyprefix1", "/api/v1"} {
		if strings.Contains(string(data), leak) {
			t.Errorf("в AI-BOM попало %q", leak)
		}
	}
	deps := map[string][]string{}
	for _, d := range bom.Dependencies {
		deps[d.Ref] = d.DependsOn
	}
	if fmt.Sprint(deps["app:billing"]) != "[model:m1 provider:gigachat]" || fmt.Sprint(deps["app:support"]) != "[model:m2 provider:vllm]" {
		t.Errorf("связи приложений: %v", deps)
	}
	if fmt.Sprint(deps["aisec"]) != "[app:billing app:support]" || fmt.Sprint(deps["model:m2"]) != "[provider:vllm]" {
		t.Errorf("связи установки и моделей: %v", deps)
	}
	rec := mem.Records[len(mem.Records)-1]
	det, _ := rec.Details.(map[string]any)
	if rec.Action != "data.export" || det["kind"] != ExportKindAIBOM || det["components"] != 6 ||
		det["services"] != 2 || det["rows"] != 8 || rec.Actor.Name != "sysadm" {
		t.Errorf("запись аудита: %+v", rec)
	}
	// Тот же реестр в то же время — тот же серийный номер.
	again, err := aibomService(t, mem).ExportAIBOM(context.Background(), by, "1.5.0")
	if err != nil || again.SerialNumber != bom.SerialNumber {
		t.Errorf("серийный номер не воспроизводится: %v", err)
	}
}

func TestAIBOMEmptyRegistry(t *testing.T) {
	bom, err := aibomService(t, NewMemory()).ExportAIBOM(context.Background(), By{}, "dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := cyclonedx.Validate(bom); err != nil || len(bom.Components) != 0 {
		t.Fatalf("пустой реестр: %+v, %v", bom, err)
	}
}

func TestAIBOMTooLarge(t *testing.T) {
	mem := NewMemory()
	files := make([]File, MaxFiles)
	for i := range files {
		files[i] = File{Path: fmt.Sprintf("f%d", i), HashAlg: HashAlg, Hash: make([]byte, 32), Role: RoleWeights}
	}
	for i := range MaxAIBOMFiles/MaxFiles + 1 {
		id := fmt.Sprintf("m%d", i)
		mem.models[id] = Model{ID: id, Kind: KindCustomer, Name: id, Files: files}
	}
	n := len(mem.Records)
	_, err := aibomService(t, mem).ExportAIBOM(context.Background(), By{}, "dev")
	if !errors.Is(err, ErrExportTooLarge) || len(mem.Records) != n {
		t.Fatalf("предел файлов: %v, записей %d → %d", err, n, len(mem.Records))
	}
}

func TestEndpointOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://api.example.com/v1":     "https://api.example.com:443",
		"https://u:p@[::1]:8443/x?y=1#z": "https://[::1]:8443",
		"ftp://example.com":              "",
		"not a url":                      "",
		"https://":                       "",
	} {
		if got := endpointOf(in); got != want {
			t.Errorf("endpointOf(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}
