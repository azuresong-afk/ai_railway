package inventory

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// Сохранённая модель из копии конфигурации проверяется правилами ручной
// записи (остаток 5.17 этапа 5): допустимые проходят, каждое нарушение —
// *InputError с именем поля.
func TestCheckStoredModel(t *testing.T) {
	good := func() StoredModel {
		return StoredModel{Kind: KindCustomer, Name: "llama-ft", Version: "1", Title: "Модель поддержки", Owner: "ИТ",
			Description: "Строка 1\nСтрока 2", Origin: OriginManual, Status: StatusActive,
			Files: []File{{Path: "weights/model.gguf", Size: 10, Role: RoleWeights, HashAlg: HashAlg, Hash: bytes.Repeat([]byte{1}, 32)}}}
	}
	if err := CheckStoredModel(good()); err != nil {
		t.Fatal(err)
	}
	traffic := StoredModel{Kind: KindProvider, Provider: "openai-main", Name: "gpt-x", Origin: OriginTraffic, Status: StatusActive}
	if err := CheckStoredModel(traffic); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		mut  func(*StoredModel)
		want string
	}{
		"вид":                   {func(m *StoredModel) { m.Kind = "other" }, "kind"},
		"провайдер без ID":      {func(m *StoredModel) { m.Kind = KindProvider }, "provider"},
		"ID провайдера":         {func(m *StoredModel) { m.Provider = "Open AI" }, "provider"},
		"пустое имя":            {func(m *StoredModel) { m.Name = "" }, "name"},
		"пробел в имени":        {func(m *StoredModel) { m.Name = " x" }, "name"},
		"смена направления":     {func(m *StoredModel) { m.Title = "a‮b" }, "title"},
		"длинный владелец":      {func(m *StoredModel) { m.Owner = strings.Repeat("я", maxOwner+1) }, "owner"},
		"управляющий символ":    {func(m *StoredModel) { m.Description = "a\x00b" }, "description"},
		"происхождение":         {func(m *StoredModel) { m.Origin = "import" }, "origin"},
		"состояние":             {func(m *StoredModel) { m.Status = "deleted" }, "status"},
		"путь с ..":             {func(m *StoredModel) { m.Files[0].Path = "../x" }, "files[0].path"},
		"повтор пути":           {func(m *StoredModel) { m.Files = append(m.Files, m.Files[0]) }, "files[1].path"},
		"размер":                {func(m *StoredModel) { m.Files[0].Size = -1 }, "files[0].size"},
		"роль":                  {func(m *StoredModel) { m.Files[0].Role = "binary" }, "files[0].role"},
		"короткий хеш":          {func(m *StoredModel) { m.Files[0].Hash = []byte{1} }, "files[0].hash"},
		"алгоритм хеша":         {func(m *StoredModel) { m.Files[0].HashAlg = "MD5" }, "files[0].hash"},
		"файлов больше предела": {func(m *StoredModel) { m.Files = make([]File, MaxFiles+1) }, "files"},
	} {
		m := good()
		tc.mut(&m)
		err := CheckStoredModel(m)
		var ie *InputError
		if !errors.As(err, &ie) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
