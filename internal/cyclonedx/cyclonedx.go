// Пакет cyclonedx — структуры и сериализация CycloneDX 1.6 JSON (только
// используемые поля). Им пользуются SBOM поставки (tools/sbom, ТЗ 8.6) и
// выгрузка AI-BOM реестра ИИ (ТЗ 5.11; задача 5.18 этапа 5, ADR-0029, п. 3).
// Библиотеки CycloneDX не нужны: документ — обычный JSON по схеме 1.6.
package cyclonedx

import (
	"encoding/json"
	"fmt"
	"strings"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
)

// Формат и версия спецификации.
const (
	BOMFormat   = "CycloneDX"
	SpecVersion = "1.6"
)

// BOM — документ CycloneDX.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Services     []Service    `json:"services,omitempty"`
	Dependencies []Dependency `json:"dependencies"`
}

// Metadata — сведения о документе и продукте.
type Metadata struct {
	Timestamp string    `json:"timestamp"`
	Tools     Tools     `json:"tools"`
	Component Component `json:"component"`
}

// Tools — чем сформирован документ.
type Tools struct {
	Components []Component `json:"components"`
}

// Component — компонент. Поля после Properties появились для AI-BOM и при
// пустом значении не выводятся: SBOM поставки от них не меняется.
type Component struct {
	Type               string        `json:"type"`
	BOMRef             string        `json:"bom-ref,omitempty"`
	Name               string        `json:"name"`
	Version            string        `json:"version,omitempty"`
	Description        string        `json:"description,omitempty"`
	PURL               string        `json:"purl,omitempty"`
	Hashes             []Hash        `json:"hashes,omitempty"`
	Licenses           []License     `json:"licenses,omitempty"`
	ExternalReferences []ExternalRef `json:"externalReferences,omitempty"`
	Properties         []Property    `json:"properties,omitempty"`
	Publisher          string        `json:"publisher,omitempty"`
	Components         []Component   `json:"components,omitempty"`
}

// Service — внешний или внутренний сервис (провайдер LLM в AI-BOM).
type Service struct {
	BOMRef      string     `json:"bom-ref,omitempty"`
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Endpoints   []string   `json:"endpoints,omitempty"`
	TrustZone   string     `json:"trustZone,omitempty"`
	Properties  []Property `json:"properties,omitempty"`
}

// Hash — хеш компонента.
type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// License — лицензия в виде выражения SPDX.
type License struct {
	Expression string `json:"expression"`
}

// ExternalRef — внешняя ссылка.
type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property — свойство «имя — значение».
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Dependency — связь «компонент зависит от».
type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// SerialFor выводит серийный номер из содержимого документа: одинаковый
// состав — одинаковый номер (воспроизводимая сборка SBOM).
func SerialFor(bom *BOM, hasher aisecCrypto.Hasher) string {
	var buf strings.Builder
	buf.WriteString(bom.Metadata.Component.Version + "|" + bom.Metadata.Timestamp + "|")
	for _, c := range bom.Components {
		buf.WriteString(c.BOMRef + "|" + c.Version + "|")
		for _, x := range c.Hashes {
			buf.WriteString(x.Content + "|")
		}
	}
	s := hasher.Sum([]byte(buf.String()))
	s[6] = (s[6] & 0x0f) | 0x80 // версия 8 — UUID, определяемый приложением (RFC 9562)
	s[8] = (s[8] & 0x3f) | 0x80 // вариант RFC 9562
	return fmt.Sprintf("urn:uuid:%x-%x-%x-%x-%x", s[0:4], s[4:6], s[6:8], s[8:10], s[10:16])
}

// Parse разбирает документ CycloneDX JSON не больше max байт; неизвестные
// поля пропускаются.
func Parse(data []byte, max int) (*BOM, error) {
	if len(data) > max {
		return nil, fmt.Errorf("документ CycloneDX больше %d байт", max)
	}
	var bom BOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("разбор документа CycloneDX: %w", err)
	}
	return &bom, nil
}
