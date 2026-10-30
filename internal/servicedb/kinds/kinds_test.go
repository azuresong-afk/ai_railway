package kinds

import (
	"os"
	"testing"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/servicedb"
)

func TestAllKindsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range All() {
		if k.Name == "" || k.Title == "" || k.Parse == nil || seen[k.Name] {
			t.Fatalf("вид %+v", k)
		}
		seen[k.Name] = true
	}
	if !seen["shadow_ai_catalog"] || !seen["compliance_requirements"] {
		t.Fatalf("виды: %v", seen)
	}
}

// FuzzInspect: недоверенный файл, который заказчик проверяет командой
// aisec-cli servicedb inspect (и инструмент подписи — inspect-db), не роняет
// разбор конверта, заверения и содержимого любого зарегистрированного вида;
// принятый файл согласован со своим отчётом.
func FuzzInspect(f *testing.F) {
	good, err := os.ReadFile("../../../testdata/shadowai/catalog-test.aisecdb")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(good)
	f.Add([]byte(`{"format":"aisec-service-db-v1","kind":"compliance_requirements","endorsement":{},"payload":"","signature":""}`))
	f.Add([]byte("{}"))
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		f.Fatal(err)
	}
	vendor, err := servicedb.EmbeddedVendor(p)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := servicedb.Inspect(p, vendor, All(), data, now)
		if err != nil {
			return
		}
		if r.Verified != (r.Reason == "") || (r.Verified && (r.Version == 0 || r.Records < 0)) {
			t.Fatalf("несогласованный отчёт: %+v", r)
		}
	})
}
