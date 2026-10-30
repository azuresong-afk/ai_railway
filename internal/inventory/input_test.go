package inventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// Разбор ручной записи реестра ИИ (ADR-0029, п. 8): позитивные, негативные
// и граничные случаи; fuzz — FuzzParseModelInput, FuzzParseModelPatch.

const testHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func fileJSON(path string) string {
	return fmt.Sprintf(`{"path":%q,"size":1024,"role":"weights","sha256":%q}`, path, testHash)
}

func TestParseModelInputAccepts(t *testing.T) {
	in, err := ParseModelInput([]byte(`{"kind":"customer","name":"llama-ft-кредиты","version":"2026.10","title":"Модель кредитного отдела",
		"description":"Дообучена на синтетике.\nВторая строка.","owner":"Отдел ИИ","files":[` + fileJSON("model.safetensors") + `,` +
		fileJSON("adapters/lora-1/adapter.safetensors") + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	fs := in.files()
	if len(fs) != 2 || fs[0].HashAlg != HashAlg || len(fs[0].Hash) != 32 || fs[1].Path != "adapters/lora-1/adapter.safetensors" {
		t.Fatalf("файлы: %+v", fs)
	}
	if _, err := ParseModelInput([]byte(`{"kind":"provider","provider":"gigachat","name":"GigaChat-Pro"}`)); err != nil {
		t.Fatal(err)
	}
	// Граница: имя 256 символов кириллицей (512 байт), 256 файлов, путь 512 байт.
	files := make([]string, MaxFiles)
	for i := range files {
		files[i] = fileJSON(fmt.Sprintf("part-%03d.bin", i))
	}
	long := strings.Repeat("я", maxName)
	path := strings.Repeat("a", MaxPathBytes)
	body := fmt.Sprintf(`{"kind":"customer","name":%q,"files":[%s,%s]}`, long, strings.Join(files[:MaxFiles-1], ","), fileJSON(path))
	in, err = ParseModelInput([]byte(body))
	if err != nil || len(in.Files) != MaxFiles {
		t.Fatalf("граничный вход: %v", err)
	}
	if _, err := ParseModelInput([]byte(`{"kind":"customer","name":"m","files":[{"path":"w","size":1125899906842624,"role":"other","sha256":"` + testHash + `"}]}`)); err != nil {
		t.Fatalf("размер 2^50: %v", err)
	}
}

func TestParseModelInputRejects(t *testing.T) {
	file := func(path string, size int64, role, hash string) string {
		return fmt.Sprintf(`{"kind":"customer","name":"m","files":[{"path":%q,"size":%d,"role":%q,"sha256":%q}]}`, path, size, role, hash)
	}
	cases := map[string]string{
		"не JSON":                 `{"kind":`,
		"неизвестное поле":        `{"kind":"customer","name":"m","weights":"AAAA"}`,
		"два значения":            `{"kind":"customer","name":"m"} {}`,
		"вид":                     `{"kind":"pickle","name":"m"}`,
		"провайдер без ID":        `{"kind":"provider","name":"m"}`,
		"ID провайдера":           `{"kind":"customer","provider":"Giga Chat","name":"m"}`,
		"пустое имя":              `{"kind":"customer","name":""}`,
		"длинное имя":             fmt.Sprintf(`{"kind":"customer","name":%q}`, strings.Repeat("я", maxName+1)),
		"управляющий символ":      `{"kind":"customer","name":"m\u0007"}`,
		"пробел в имени":          `{"kind":"customer","name":" m"}`,
		"длинная версия":          fmt.Sprintf(`{"kind":"customer","name":"m","version":%q}`, strings.Repeat("1", maxVersion+1)),
		"длинное описание":        fmt.Sprintf(`{"kind":"customer","name":"m","description":%q}`, strings.Repeat("я", maxDescription+1)),
		"табуляция в описании":    `{"kind":"customer","name":"m","description":"a\tb"}`,
		"путь ..":                 file("../etc/passwd", 1, "weights", testHash),
		"путь в середине ..":      file("a/../b", 1, "weights", testHash),
		"абсолютный путь":         file("/opt/model.bin", 1, "weights", testHash),
		"путь с диском":           file("C:/model.bin", 1, "weights", testHash),
		"обратная косая":          file(`a\b`, 1, "weights", testHash),
		"пустая часть":            file("a//b", 1, "weights", testHash),
		"точка":                   file("./a", 1, "weights", testHash),
		"длинный путь":            file(strings.Repeat("a", MaxPathBytes+1), 1, "weights", testHash),
		"отрицательный размер":    file("a", -1, "weights", testHash),
		"размер больше 2^50":      file("a", MaxFileSize+1, "weights", testHash),
		"роль":                    file("a", 1, "code", testHash),
		"хеш в верхнем регистре":  file("a", 1, "weights", strings.ToUpper(testHash)),
		"короткий хеш":            file("a", 1, "weights", testHash[:62]),
		"хеш не hex":              file("a", 1, "weights", strings.Repeat("z", 64)),
		"повтор пути":             `{"kind":"customer","name":"m","files":[` + fileJSON("a") + `,` + fileJSON("a") + `]}`,
		"тело больше предела":     `{"kind":"customer","name":"m","description":"` + strings.Repeat(" ", MaxBody) + `"}`,
		"размер — не целое число": `{"kind":"customer","name":"m","files":[{"path":"a","size":1.5,"role":"weights","sha256":"` + testHash + `"}]}`,
	}
	files := make([]string, MaxFiles+1)
	for i := range files {
		files[i] = fileJSON(fmt.Sprintf("f%d", i))
	}
	cases["257 файлов"] = `{"kind":"customer","name":"m","files":[` + strings.Join(files, ",") + `]}`
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseModelInput([]byte(body))
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ожидалась ошибка входа, получено %v", err)
			}
			// Текст ошибки не содержит значений из входа.
			if strings.Contains(err.Error(), "passwd") || strings.Contains(err.Error(), testHash) {
				t.Errorf("значение входа в тексте ошибки: %v", err)
			}
		})
	}
}

func TestParseModelPatch(t *testing.T) {
	p, err := ParseModelPatch([]byte(`{"title":"Новое","files":[]}`))
	if err != nil || p.Title == nil || *p.Title != "Новое" || p.Files == nil || len(*p.Files) != 0 || p.Version != nil {
		t.Fatalf("%+v, %v", p, err)
	}
	if p, err := ParseModelPatch([]byte(`{}`)); err != nil || p.Files != nil || p.files() != nil {
		t.Fatalf("пустое изменение: %+v, %v", p, err)
	}
	for _, body := range []string{`{"name":"другое"}`, `{"provider":"x"}`, `{"kind":"x"}`, `{"owner":"` + strings.Repeat("я", maxOwner+1) + `"}`,
		`{"files":[` + fileJSON("..") + `]}`, `[]`, `null x`} {
		if _, err := ParseModelPatch([]byte(body)); err == nil {
			t.Errorf("%s: принято", body)
		}
	}
}

// checkAccepted — свойства принятого входа: те же пределы, что проверяет
// разборщик, и согласованные хеши.
func checkAccepted(t *testing.T, name, version, title, owner, desc string, files []FileInput, hashes [][]byte) {
	t.Helper()
	for _, f := range []struct {
		v  string
		hi int
	}{{name, maxName}, {version, maxVersion}, {title, maxTitle}, {owner, maxOwner}, {desc, maxDescription}} {
		if utf8.RuneCountInString(f.v) > f.hi {
			t.Fatalf("поле длиннее %d символов принято", f.hi)
		}
	}
	if len(files) > MaxFiles || len(hashes) != len(files) {
		t.Fatalf("файлов %d, хешей %d", len(files), len(hashes))
	}
	seen := map[string]bool{}
	for i, f := range files {
		if checkPath(f.Path) != nil || seen[f.Path] || f.Size < 0 || f.Size > MaxFileSize || !validRoles[f.Role] || len(hashes[i]) != 32 {
			t.Fatalf("недопустимый файл принят: %+v", f)
		}
		seen[f.Path] = true
		for _, part := range strings.Split(f.Path, "/") {
			if part == ".." {
				t.Fatalf("выход за каталог принят: %q", f.Path)
			}
		}
	}
}

func FuzzParseModelInput(f *testing.F) {
	f.Add([]byte(`{"kind":"customer","name":"m","files":[` + fileJSON("model.safetensors") + `]}`))
	f.Add([]byte(`{"kind":"provider","provider":"gigachat","name":"GigaChat-Pro","version":"1"}`))
	f.Add([]byte(`{"kind":"customer","name":"m","files":[` + fileJSON("../x") + `]}`))
	f.Add([]byte(`{"kind":"customer","name":"\u0000"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		in, err := ParseModelInput(data)
		if err != nil {
			var ie *InputError
			if !errors.As(err, &ie) {
				t.Fatalf("ошибка не InputError: %v", err)
			}
			return
		}
		if in.Kind != KindProvider && in.Kind != KindCustomer || in.Kind == KindProvider && in.Provider == "" ||
			in.Provider != "" && !slugRe.MatchString(in.Provider) || in.Name == "" {
			t.Fatalf("недопустимая модель принята: %+v", in)
		}
		checkAccepted(t, in.Name, in.Version, in.Title, in.Owner, in.Description, in.Files, in.hashes)
		// Принятый вход после повторной записи разбирается в то же.
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		again, err := ParseModelInput(b)
		if err != nil || again.Name != in.Name || len(again.Files) != len(in.Files) {
			t.Fatalf("повторный разбор: %v", err)
		}
	})
}

func FuzzParseModelPatch(f *testing.F) {
	f.Add([]byte(`{"title":"t","files":[` + fileJSON("a/b") + `]}`))
	f.Add([]byte(`{"kind":"customer"}`))
	f.Add([]byte(`{"files":null}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseModelPatch(data)
		if err != nil {
			return
		}
		if p.Kind != nil && *p.Kind != KindProvider && *p.Kind != KindCustomer {
			t.Fatalf("недопустимый вид принят: %q", *p.Kind)
		}
		deref := func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		}
		var files []FileInput
		if p.Files != nil {
			files = *p.Files
		}
		checkAccepted(t, "", deref(p.Version), deref(p.Title), deref(p.Owner), deref(p.Description), files, p.hashes)
	})
}
