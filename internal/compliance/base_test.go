package compliance

import (
	"strings"
	"testing"
)

func TestEmbeddedBase(t *testing.T) {
	b, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if b.Version < 1 || len(b.Requirements) < 20 {
		t.Fatalf("встроенная база: версия %d, пунктов %d", b.Version, len(b.Requirements))
	}
	// Начальное наполнение: таблица ТЗ 2.1 и драйверы 2.4.
	for _, id := range []string{"f117.p60.access", "f117.p61.control-interaction", "fstec-m.3.18.log-all", "f117d.filter-io", "fz152.external-models", "pp1119.access-log"} {
		if _, ok := b.ByID(id); !ok {
			t.Errorf("нет пункта %s", id)
		}
	}
	drafts, sources := 0, map[string]bool{}
	for _, r := range b.Requirements {
		sources[r.Source] = true
		if r.Draft {
			if r.Source != "fstec-117-draft" {
				t.Errorf("%s: признак «проект» у пункта не из проекта изменений", r.ID)
			}
			drafts++
		} else if r.Source == "fstec-117-draft" {
			t.Errorf("%s: пункт проекта без признака draft", r.ID)
		}
	}
	if drafts == 0 || len(sources) != 5 {
		t.Fatalf("проектов %d, источников %d", drafts, len(sources))
	}
}

func TestParseBaseRejects(t *testing.T) {
	good := miniBase(1, "2026-10-28")
	if _, err := ParseBase([]byte(good)); err != nil {
		t.Fatalf("эталон: %v", err)
	}
	cases := map[string]string{
		"неизвестная проверка":     strings.Replace(good, "name: content_storage", "name: no_such_check", 1),
		"неизвестный параметр":     strings.Replace(good, "{name: content_storage}", "{name: content_storage, params: {x: y}}", 1),
		"значение параметра":       strings.Replace(good, "{name: content_storage}", "{name: content_storage, params: {env: moon}}", 1),
		"неизвестное поле":         strings.Replace(good, "title: Ручной", "title: Ручной, extra: 1", 1),
		"повтор id":                strings.Replace(good, "id: manual.one", "id: auto.one", 1),
		"нет источника":            strings.Replace(good, "source: src-a, clause: п. 2", "source: nope, clause: п. 2", 1),
		"версия 0":                 strings.Replace(good, "version: 1", "version: 0", 1),
		"плохая дата":              strings.Replace(good, "2026-10-28", "28.10.2026", 1),
		"другой format":            strings.Replace(good, "aisec-compliance-base-v1", "v2", 1),
		"второй документ":          good + "---\nformat: x\n",
		"пустой пересказ":          strings.Replace(good, "summary: Пересказ, applies: [gis], checks", "summary: '', applies: [gis], checks", 1),
		"неизвестная применимость": strings.Replace(good, "applies: [gis, ispdn]", "applies: [moon]", 1),
		"без проверки и manual":    strings.Replace(good, "applies: [gis, ispdn], manual: true", "applies: [gis]", 1),
		"внешняя ссылка":           strings.Replace(good, "checks: [{name: content_storage}]}", "checks: [{name: content_storage}], evidence: [{kind: screen, title: x, path: 'https://evil.example/'}]}", 1),
		"управляющий символ":       strings.Replace(good, "title: Автоматический", "title: \"A\\u0007B\"", 1),
		"пусто":                    "",
	}
	for name, y := range cases {
		if _, err := ParseBase([]byte(y)); err == nil {
			t.Errorf("%s: база принята", name)
		}
	}
	if _, err := ParseBase(make([]byte, maxBaseSize+1)); err == nil {
		t.Error("слишком большой файл принят")
	}
}

func TestEveryCheckHasTitleAndDefaults(t *testing.T) {
	for _, n := range CheckNames() {
		d := checkRegistry[n]
		if d.title == "" {
			t.Errorf("%s: нет названия", n)
		}
		for pn, p := range d.params {
			if !p.valid(p.def) {
				t.Errorf("%s.%s: значение по умолчанию %q недопустимо", n, pn, p.def)
			}
		}
	}
}

func FuzzParseBase(f *testing.F) {
	f.Add([]byte(miniBase(1, "2026-10-28")))
	f.Add([]byte("format: aisec-compliance-base-v1\nversion: 1\ndate: \"2026-10-28\"\n"))
	f.Add([]byte("{"))
	if b, err := embeddedFS.ReadFile("requirements/fstec.yaml"); err == nil {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := ParseBase(data)
		if err != nil {
			return
		}
		// Принятая база обязана быть самосогласованной.
		for _, r := range b.Requirements {
			if _, ok := b.ByID(r.ID); !ok || b.SourceTitle(r.Source) == "" {
				t.Fatalf("принятая база несогласована: %s", r.ID)
			}
			for _, c := range r.Checks {
				if err := validateCheckRef(c); err != nil {
					t.Fatalf("принята проверка, которую реестр отвергает: %v", err)
				}
			}
		}
	})
}
