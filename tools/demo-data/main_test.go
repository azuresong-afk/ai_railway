package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

// testCorpora — корпус из репозитория (тесты идут из каталога пакета).
func testCorpora(t *testing.T) *corpora {
	t.Helper()
	cs, err := loadCorpora(filepath.Join("..", "..", "testdata", "corpus"))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func testPlan(t *testing.T, seed uint64, days int) []item {
	return buildPlan(planParams{Seed: seed, Days: days, EventsPerDay: 40, Apps: []string{"bot-a", "bot-b"}, Corpora: testCorpora(t)})
}

func TestPlanDeterministicBySeed(t *testing.T) {
	a, b := testPlan(t, 7, 30), testPlan(t, 7, 30)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("один и тот же план при том же зерне ожидался")
	}
	if reflect.DeepEqual(a, testPlan(t, 8, 30)) {
		t.Fatal("другое зерно должно давать другой план")
	}
}

func TestPlanShape(t *testing.T) {
	plan := testPlan(t, 1, 30)
	kinds := map[string]int{}
	days := map[int]bool{}
	for _, it := range plan {
		kinds[it.Kind]++
		days[it.Day] = true
		if it.Text == "" || it.User == "" || (it.Direction != "input" && it.Direction != "output") {
			t.Fatalf("некорректный запрос плана: %+v", it)
		}
	}
	if len(days) != 30 {
		t.Errorf("суток в плане %d, ожидалось 30", len(days))
	}
	for _, k := range []string{"benign", "pii", "attack", "wave", "leak"} {
		if kinds[k] == 0 {
			t.Errorf("в плане нет запросов вида %s: %v", k, kinds)
		}
	}
}

// Значения ПДн плана — только синтетические: контрольные суммы верны, а
// номера несут служебный признак (нули в начале), который не бывает у
// настоящих документов.
func TestPlanPIISynthetic(t *testing.T) {
	re := regexp.MustCompile(`\d{3}-\d{3}-\d{3} \d{2}|\b\d{12}\b|\b\d{10}\b`)
	checked := 0
	for _, it := range testPlan(t, 3, 30) {
		if it.Kind != "pii" {
			continue
		}
		for _, m := range re.FindAllString(it.Text, -1) {
			d := strings.NewReplacer("-", "", " ", "").Replace(m)
			ok := false
			switch len(d) {
			case 11:
				ok = pii.ValidSNILS(d)
			case 12:
				ok = pii.ValidINN12(d)
			case 10:
				ok = pii.ValidINN10(d)
			}
			if !ok {
				t.Fatalf("значение %q не проходит контрольную сумму", m)
			}
			checked++
		}
		if strings.Contains(it.Text, "@") && !strings.Contains(it.Text, ".example") && !strings.Contains(it.Text, ".test") && !strings.Contains(it.Text, ".invalid") {
			t.Fatalf("адрес почты не из зарезервированного домена: %q", it.Text)
		}
		if strings.Contains(it.Text, "+7") && !strings.Contains(it.Text, "+7 300") {
			t.Fatalf("телефон не из зарезервированного диапазона: %q", it.Text)
		}
	}
	if checked == 0 {
		t.Fatal("ни одного номера не проверено")
	}
}

func TestCheckGatewayRefusesRemote(t *testing.T) {
	for _, ok := range []string{"https://127.0.0.1:8443", "https://localhost:8443", "https://[::1]:8443"} {
		if _, err := checkGateway(ok, false); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"https://gw.example.ru:8443", "https://10.0.0.5:8443", "https://8.8.8.8", "http://127.0.0.1:8443", "https://u:p@127.0.0.1", "127.0.0.1:8443", ""} {
		if _, err := checkGateway(bad, false); err == nil {
			t.Errorf("%q: ожидался отказ", bad)
		}
	}
	if _, err := checkGateway("https://gw.example.ru:8443", true); err != nil {
		t.Errorf("с -allow-remote: %v", err)
	}
	if _, err := checkGateway("http://gw.example.ru", true); err == nil {
		t.Error("http не допускается и с -allow-remote")
	}
}

func TestReadKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keys, names, err := readKeys(write("ok", "# комментарий\nbot-a=k1\n\nbot-b = k2\n", 0o600))
	if err != nil || keys["bot-b"] != "k2" || !reflect.DeepEqual(names, []string{"bot-a", "bot-b"}) {
		t.Fatalf("%v %v %v", keys, names, err)
	}
	for name, body := range map[string]string{"nokey": "bot-a\n", "dup": "a=1\na=2\n", "empty": "# ничего\n", "blank": "a=\n"} {
		if _, _, err := readKeys(write(name, body, 0o600)); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
	if _, _, err := readKeys(write("open", "a=1\n", 0o644)); err == nil {
		t.Error("файл с открытыми правами должен отклоняться")
	}
}

func TestRunValidation(t *testing.T) {
	base := options{gateway: "https://127.0.0.1:1", keys: "x", corpus: "x", days: 30, perDay: 40, rate: 20}
	for name, mod := range map[string]func(*options){
		"remote":   func(o *options) { o.gateway = "https://gw.example.ru" },
		"days":     func(o *options) { o.days = 91 },
		"days0":    func(o *options) { o.days = 0 },
		"perDay":   func(o *options) { o.perDay = 5000 },
		"rate":     func(o *options) { o.rate = 0 },
		"nokeys":   func(o *options) { o.keys = "" },
		"nokeyfil": func(o *options) {},
	} {
		o := base
		mod(&o)
		if err := run(context.Background(), &bytes.Buffer{}, o); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestSendAgainstStand(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/guard/v1/check" || r.Header.Get("Authorization") != "Bearer key-a" {
			http.Error(w, "x", http.StatusUnauthorized)
			return
		}
		var b checkBody
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Text == "" {
			http.Error(w, "x", http.StatusBadRequest)
			return
		}
		if got.Add(1) == 1 { // первый запрос упирается в квоту и повторяется
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(`{"decision":"redact"}`)) //nolint:gosec // G104: ошибка записи в тестовый ответ проявится в клиенте
	}))
	defer srv.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := newClient(ca)
	if err != nil {
		t.Fatal(err)
	}
	it := item{App: "bot-a", User: "u", Direction: "input", Source: "user", Text: "текст"}
	d, err := send(context.Background(), c, srv.URL+"/guard/v1/check", "key-a", it)
	if err != nil || d != "redact" {
		t.Fatalf("%q %v", d, err)
	}
	if _, err := send(context.Background(), c, srv.URL+"/guard/v1/check", "чужой", it); err == nil || strings.Contains(err.Error(), "чужой") {
		t.Fatalf("отказ ожидался без ключа в тексте: %v", err)
	}
}
