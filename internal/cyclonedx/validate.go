package cyclonedx

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Проверка документа по правилам схемы CycloneDX 1.6 для используемых полей:
// формат и версия, серийный номер, время, типы компонентов и алгоритмы хешей
// из перечислений схемы, вид хеша, уникальность bom-ref и ссылки связей.
// Полная схема JSON в репозиторий не входит; SBOM поставки дополнительно
// проверяет sbom-utility по официальной схеме (make sbom).

// componentTypes — перечисление component.type схемы 1.6.
var componentTypes = map[string]bool{
	"application": true, "framework": true, "library": true, "container": true, "platform": true,
	"operating-system": true, "device": true, "device-driver": true, "firmware": true, "file": true,
	"machine-learning-model": true, "data": true, "cryptographic-asset": true,
}

// hashAlgs — перечисление hash-alg схемы 1.6.
var hashAlgs = map[string]bool{
	"MD5": true, "SHA-1": true, "SHA-256": true, "SHA-384": true, "SHA-512": true,
	"SHA3-256": true, "SHA3-384": true, "SHA3-512": true, "BLAKE2b-256": true, "BLAKE2b-384": true,
	"BLAKE2b-512": true, "BLAKE3": true, "Streebog-256": true, "Streebog-512": true,
}

var (
	serialRe   = regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	hashRe     = regexp.MustCompile(`^([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}|[a-fA-F0-9]{96}|[a-fA-F0-9]{128})$`)
	trustZones = map[string]bool{"": true, "external": true, "internal": true}
)

// Validate проверяет документ; ошибки собираются все.
func Validate(bom *BOM) error {
	var errs []error
	if bom.BOMFormat != BOMFormat || bom.SpecVersion != SpecVersion {
		errs = append(errs, fmt.Errorf("ожидается CycloneDX %s, получено %s %s", SpecVersion, bom.BOMFormat, bom.SpecVersion))
	}
	if !serialRe.MatchString(bom.SerialNumber) {
		errs = append(errs, errors.New("serialNumber — не urn:uuid по RFC 9562"))
	}
	if bom.Version < 1 {
		errs = append(errs, errors.New("version — целое не меньше 1"))
	}
	if _, err := time.Parse(time.RFC3339, bom.Metadata.Timestamp); err != nil {
		errs = append(errs, errors.New("metadata.timestamp — не дата и время RFC 3339"))
	}
	refs := map[string]bool{}
	addRef := func(where, ref string) {
		if ref == "" {
			return
		}
		if refs[ref] {
			errs = append(errs, fmt.Errorf("%s: bom-ref %q повторяется", where, ref))
		}
		refs[ref] = true
	}
	var walk func(where string, cs []Component)
	checkComponent := func(where string, c Component) {
		if !componentTypes[c.Type] {
			errs = append(errs, fmt.Errorf("%s: тип компонента %q вне перечисления схемы", where, c.Type))
		}
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("%s: нет name", where))
		}
		addRef(where, c.BOMRef)
		for _, h := range c.Hashes {
			if !hashAlgs[h.Alg] || !hashRe.MatchString(h.Content) {
				errs = append(errs, fmt.Errorf("%s: хеш %s не по схеме", where, h.Alg))
			}
		}
		for _, p := range c.Properties {
			if p.Name == "" {
				errs = append(errs, fmt.Errorf("%s: свойство без имени", where))
			}
		}
		walk(where, c.Components)
	}
	walk = func(where string, cs []Component) {
		for i, c := range cs {
			checkComponent(fmt.Sprintf("%s[%d]", where, i), c)
		}
	}
	checkComponent("metadata.component", bom.Metadata.Component)
	for i, c := range bom.Metadata.Tools.Components {
		if !componentTypes[c.Type] || c.Name == "" {
			errs = append(errs, fmt.Errorf("metadata.tools.components[%d]: нет типа или имени", i))
		}
	}
	walk("components", bom.Components)
	for i, s := range bom.Services {
		where := fmt.Sprintf("services[%d]", i)
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("%s: нет name", where))
		}
		if !trustZones[s.TrustZone] {
			errs = append(errs, fmt.Errorf("%s: зона доверия %q", where, s.TrustZone))
		}
		addRef(where, s.BOMRef)
	}
	seen := map[string]bool{}
	for i, d := range bom.Dependencies {
		where := fmt.Sprintf("dependencies[%d]", i)
		if !refs[d.Ref] {
			errs = append(errs, fmt.Errorf("%s: ref %q не найден", where, d.Ref))
		}
		if seen[d.Ref] {
			errs = append(errs, fmt.Errorf("%s: связи %q указаны дважды", where, d.Ref))
		}
		seen[d.Ref] = true
		uniq := map[string]bool{}
		for _, r := range d.DependsOn {
			if !refs[r] || uniq[r] {
				errs = append(errs, fmt.Errorf("%s: dependsOn %q не найден или повторяется", where, r))
			}
			uniq[r] = true
		}
	}
	return errors.Join(errs...)
}
