package redteam

import (
	"os"
	"reflect"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

// Библиотека сценариев версии 1 (задача 5.31): исходник
// internal/redteam/scenariosdb/scenarios.json принимает разборщик базы,
// тестовая подпись совпадает с исходником. Содержание (строки матрицы из
// ТЗ, охват, честность критериев) проверяют тесты пакета scenariosdb.

const (
	libSource = "scenariosdb/scenarios.json"
	libSigned = "../../testdata/redteam/scenarios-library-test.aisecdb"
)

func TestLibraryParsedByDatabaseParser(t *testing.T) {
	data, err := os.ReadFile(libSource)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseScenarios(data)
	if err != nil {
		t.Fatalf("разборщик базы не принял библиотеку: %v", err)
	}
	langs := map[string]int{}
	for _, s := range base.Scenarios {
		langs[s.Lang]++
	}
	if langs[LangRU] == 0 || langs[LangEN] == 0 {
		t.Fatalf("в библиотеке должны быть оба языка, есть %v", langs)
	}
}

// Тестовая подпись библиотеки совпадает с исходником и проходит
// проверку вида с тестовым ключом производителя.
func TestLibraryTestSignature(t *testing.T) {
	data, err := os.ReadFile(libSigned)
	if err != nil {
		t.Fatal(err)
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		t.Fatal(err)
	}
	v, err := servicedb.Verify(p, vendor, DBKind(), data, time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(libSource)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseScenarios(src)
	if err != nil {
		t.Fatal(err)
	}
	got := v.Content.Value.(*Base)
	if !reflect.DeepEqual(got.Scenarios, want.Scenarios) || got.Version != want.Version || v.Content.Records != len(want.Scenarios) {
		t.Fatal("подписанная тестовая библиотека расходится с исходником: пересоздайте её (internal/redteam/scenariosdb/README.md)")
	}
}
