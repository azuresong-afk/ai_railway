package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
)

const specSample = `# ТЗ
### 5.16 Матрица обнаружения
| ID | Что выявляется | Механизм | Реакция | Этап | OWASP | БДУ |
|---|---|---|---|---|---|---|
| DM-01 | Прямая инъекция: подробности | м | р | 1; оповещение — 3; ML — 4 | LLM01 | Б1 |
| DM-02 | Подделка | м | р | 1 | LLM01 | Б1 |
| DM-38 | Неудачная аутентификация | м | р | 1; оповещение — 3 | — | О |
| DM-48 | Аудио | м | р | по запросу | LLM01 | Б1 |
| DM-40 | Ослабление защиты | м | р | 3 | — | О |
### 5.17 Дальше
| DM-99 | Вне матрицы | м | р | 1 | — | — |
`

func TestParseMatrix(t *testing.T) {
	rows, err := ParseMatrix(specSample)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 5 {
		t.Fatalf("строк %d: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.ID != "DM-01" || r.What != "Прямая инъекция" || r.Stage != 1 || len(r.Parts) != 2 ||
		r.Parts[0] != (Part{"оповещение", 3}) || r.Parts[1] != (Part{"ML", 4}) {
		t.Fatalf("неверный разбор DM-01: %+v", r)
	}
	for _, r := range rows {
		if r.ID == "DM-48" && r.Stage != OnRequest {
			t.Fatalf("DM-48 должна быть «по запросу»: %+v", r)
		}
		if r.ID == "DM-99" {
			t.Fatal("строка вне раздела 5.16 попала в матрицу")
		}
	}
}

func TestParseMatrixErrors(t *testing.T) {
	cases := map[string]string{
		"нет раздела":  "# ТЗ\n",
		"нет строк":    "### 5.16 Матрица\nтекст\n### 5.17 x\n",
		"повтор ID":    "### 5.16 М\n| DM-01 | a | b | c | 1 | d | e |\n| DM-01 | a | b | c | 1 | d | e |\n",
		"колонки":      "### 5.16 М\n| DM-01 | a | b | 1 |\n",
		"неверный ID":  "### 5.16 М\n| DM-1 | a | b | c | 1 | d | e |\n",
		"этап":         "### 5.16 М\n| DM-01 | a | b | c | MVP | d | e |\n",
		"часть":        "### 5.16 М\n| DM-01 | a | b | c | 1; оповещение 3 | d | e |\n",
		"часть раньше": "### 5.16 М\n| DM-01 | a | b | c | 3; оповещение — 2 | d | e |\n",
	}
	for name, spec := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseMatrix(spec); err == nil {
				t.Fatal("ожидалась ошибка")
			}
		})
	}
}

// Матрица в настоящем ТЗ должна разбираться без ошибок.
func TestParseRealSpec(t *testing.T) {
	data, err := os.ReadFile("../../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseMatrix(string(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 50 {
		t.Fatalf("в матрице ТЗ %d строк, ожидалось не меньше 50", len(rows))
	}
}

func TestParseGoTestJSON(t *testing.T) {
	data := []byte(`# сборка
{"Action":"run","Test":"TestDM02_X"}
{"Action":"pass","Test":"TestDM02_X"}
{"Action":"fail","Test":"TestY/DM38"}
{"Action":"skip","Test":"TestZ"}
{"Action":"pass","Package":"p"}
`)
	got, _, err := ParseGoTestJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{{"TestDM02_X", true}, {"TestY/DM38", false}, {"TestZ", false}}
	if len(got) != len(want) {
		t.Fatalf("получено %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%d: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
	if _, _, err := ParseGoTestJSON([]byte("{не json\n")); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

// Упавший тест, пакет или сборка — проблема отчёта, даже если тест не
// покрывает строк матрицы (замечание G2 этапа 5: при упавших e2e отчёт
// говорил «0 проблем»). Пропуск падением не считается.
func TestParseGoTestJSONFailures(t *testing.T) {
	data := []byte(`{"Action":"pass","Package":"a","Test":"TestOK"}
{"Action":"fail","Package":"a","Test":"TestParent/sub"}
{"Action":"fail","Package":"a","Test":"TestParent"}
{"Action":"fail","Package":"a","Test":"TestFlat"}
{"Action":"fail","Package":"a"}
{"Action":"skip","Package":"b","Test":"TestSkipped"}
{"Action":"pass","Package":"b"}
{"Action":"fail","Package":"c"}
{"ImportPath":"d.test","Action":"build-fail"}
{"Action":"fail","Package":"d"}
`)
	_, got, err := ParseGoTestJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"сборка d.test не прошла",
		"тест TestParent/sub (a) не прошёл",
		"тест TestFlat (a) не прошёл",
		"пакет c не прошёл (сборка, паника вне теста, таймаут или TestMain)",
		"пакет d не прошёл (сборка, паника вне теста, таймаут или TestMain)",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("падения:\n%q\nожидалось\n%q", got, want)
	}
	if _, got, err := ParseGoTestJSON([]byte(`{"Action":"pass","Package":"a","Test":"TestOK"}
{"Action":"skip","Package":"a","Test":"TestS"}
{"Action":"pass","Package":"a"}
`)); err != nil || len(got) != 0 {
		t.Fatalf("без падений: %q %v", got, err)
	}
}

// run: упавший e2e-тест без маркера покрытия делает отчёт неуспешным и
// попадает в его проблемы.
func TestRunFailsOnFailedTest(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.md")
	if err := os.WriteFile(spec, []byte(specSample), 0o600); err != nil {
		t.Fatal(err)
	}
	report := filepath.Join(dir, "e2e.json")
	if err := os.WriteFile(report, []byte(`{"Action":"fail","Package":"e2e","Test":"TestE2EStage5_Something"}
{"Action":"fail","Package":"e2e"}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "r")
	err := run(spec, 0, []string{report}, nil, dir, out)
	if err == nil || !strings.Contains(err.Error(), "e2e.json: тест TestE2EStage5_Something (e2e) не прошёл") {
		t.Fatalf("ошибка: %v", err)
	}
	md, rerr := os.ReadFile(out + ".md") //nolint:gosec // G304: путь — от t.TempDir(), внешнего ввода в тесте нет
	if rerr != nil || !strings.Contains(string(md), "TestE2EStage5_Something") {
		t.Fatalf("отчёт без падения: %v\n%s", rerr, md)
	}
}

func TestParseJUnit(t *testing.T) {
	data := []byte(`<testsuites><testsuite><testcase name="DM40 alert"/><testcase name="DM41"><failure/></testcase>
<testsuite><testcase name="nested DM02"/><testcase name="skip"><skipped/></testcase></testsuite></testsuite></testsuites>`)
	got, err := ParseJUnit(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 || !got[0].Passed || got[1].Passed || !got[2].Passed || got[3].Passed {
		t.Fatalf("неверный разбор: %+v", got)
	}
	single, err := ParseJUnit([]byte(`<testsuite><testcase name="DM02"/></testsuite>`))
	if err != nil || len(single) != 1 {
		t.Fatalf("одиночный testsuite: %+v %v", single, err)
	}
	if _, err := ParseJUnit([]byte("<testsuites>")); err == nil {
		t.Fatal("ожидалась ошибка")
	}
}

func TestParseCovers(t *testing.T) {
	covs, bad := ParseCovers("Проверяет что-то.\nПокрывает: DM-38 (оповещение), DM-40.\nПокрывает: DM-1\n")
	if len(covs) != 2 || covs[0] != (Coverage{ID: "DM-38", Part: "оповещение"}) || covs[1] != (Coverage{ID: "DM-40"}) {
		t.Fatalf("покрытие: %+v", covs)
	}
	if len(bad) != 1 || !strings.Contains(bad[0], "DM-1") {
		t.Fatalf("ошибки разметки: %q", bad)
	}
}

func TestCollectMarkers(t *testing.T) {
	fsys := fstest.MapFS{
		"a/a_test.go":        {Data: []byte("package a\n\n// TestAlert проверяет оповещение.\n// Покрывает: DM-38 (оповещение)\nfunc TestAlert(t *testing.T) {}\n\n// Покрывает: DM-2\nfunc TestBad(t *testing.T) {}\n\n// Покрывает: DM-40\nfunc helper() {}\n")},
		"a/a.go":             {Data: []byte("package a\n// Покрывает: DM-01\nfunc TestNotTest() {}\n")},
		"vendor/v/v_test.go": {Data: []byte("package v\n// Покрывает: DM-01\nfunc TestV() {}\n")},
		"b/b_test.go":        {Data: []byte("//go:build aisec_onnx && cgo\n\npackage b\n\n// Покрывает: DM-45\nfunc TestORT(t *testing.T) {}\n")},
		"c/c_test.go":        {Data: []byte("//go:build e2e\n\npackage c\n\n// Покрывает: DM-01\nfunc TestE2E(t *testing.T) {}\n")},
		// Собирается без тега aisec_onnx — маркеры обязательные (5Н23 ревью 5.r3).
		"d/d_test.go": {Data: []byte("//go:build !aisec_onnx\n\npackage d\n\n// Покрывает: DM-46\nfunc TestNoORT(t *testing.T) {}\n")},
		"e/e_test.go": {Data: []byte("//go:build aisec_onnx || " + runtime.GOOS + "\n\npackage e\n\n// Покрывает: DM-46\nfunc TestEither(t *testing.T) {}\n")},
	}
	m, problems, err := CollectMarkers(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if m["TestORT"][0] != (Coverage{ID: "DM-45", Optional: true}) || m["TestE2E"][0] != (Coverage{ID: "DM-01"}) {
		t.Fatalf("необязательные маркеры: %+v", m)
	}
	for _, name := range []string{"TestNoORT", "TestEither"} {
		if m[name][0] != (Coverage{ID: "DM-46"}) {
			t.Fatalf("%s: маркер необязательный: %+v", name, m[name])
		}
		delete(m, name)
	}
	delete(m, "TestORT")
	delete(m, "TestE2E")
	if len(m) != 1 || len(m["TestAlert"]) != 1 || m["TestAlert"][0] != (Coverage{ID: "DM-38", Part: "оповещение"}) {
		t.Fatalf("маркеры: %+v", m)
	}
	if len(problems) != 1 || !strings.Contains(problems[0], "TestBad") {
		t.Fatalf("проблемы: %q", problems)
	}
}

func TestCompute(t *testing.T) {
	rows, err := ParseMatrix(specSample)
	if err != nil {
		t.Fatal(err)
	}
	results := []Result{
		{"TestDM01_Direct", true},
		{"TestDM02_Structure", false},
		{"TestAlert", true},
		{"TestDM77_Unknown", true},
		{"TestDM40_Early", true},
	}
	markers := map[string][]Coverage{
		"TestAlert":  {{"DM-38", "оповещение", false}, {"DM-38", "нет такой", false}},
		"TestNotRun": {{"DM-02", "", false}},
		// Тест под тегом aisec_onnx, который не запускался, — не ошибка.
		"TestORTNotRun": {{"DM-45", "", true}},
	}
	rep := Compute(rows, 1, results, markers)
	status := map[string]string{}
	for _, it := range rep.Items {
		status[it.ID+"/"+it.Part] = it.Status
	}
	want := map[string]string{
		"DM-01/":           StatusCovered,
		"DM-01/оповещение": StatusLater,
		"DM-02/":           StatusFailing,
		"DM-38/":           StatusMissing,
		"DM-38/оповещение": StatusUnexpected,
		"DM-48/":           StatusOnRequest,
		"DM-40/":           StatusUnexpected,
	}
	for k, v := range want {
		if status[k] != v {
			t.Errorf("%s: статус %q, ожидалось %q", k, status[k], v)
		}
	}
	joined := strings.Join(rep.Problems, "\n")
	for _, s := range []string{"DM-02: тест не проходит", "DM-38: этап 1, нет прошедшего теста", "DM-77", "нет части «нет такой»", "TestNotRun"} {
		if !strings.Contains(joined, s) {
			t.Errorf("нет проблемы %q в %q", s, rep.Problems)
		}
	}
	if strings.Contains(joined, "TestORTNotRun") {
		t.Errorf("необязательный тест, который не запускался, — проблема: %q", rep.Problems)
	}
	md := rep.Markdown()
	if !strings.Contains(md, "| DM-01 | Прямая инъекция | основная | 1 | `TestDM01_Direct` | покрыто |") {
		t.Fatalf("неверный отчёт:\n%s", md)
	}
}

func TestRunStageBounds(t *testing.T) {
	if err := run("x", 7, nil, nil, ".", t.TempDir()+"/r"); err == nil {
		t.Fatal("ожидалась ошибка этапа")
	}
}

func FuzzParseMatrix(f *testing.F) {
	f.Add(specSample)
	f.Add("### 5.16 x\n| DM-01 | a | b | c | 1; x — 2 | d | e |\n")
	f.Fuzz(func(t *testing.T, spec string) {
		rows, err := ParseMatrix(spec)
		if err != nil {
			return
		}
		seen := map[string]bool{}
		for _, r := range rows {
			if seen[r.ID] || !rowIDRe.MatchString(r.ID) {
				t.Fatalf("принята некорректная строка %+v", r)
			}
			seen[r.ID] = true
			for _, p := range r.Parts {
				if r.Stage != OnRequest && p.Stage <= r.Stage {
					t.Fatalf("часть раньше основного этапа: %+v", r)
				}
			}
		}
	})
}

func FuzzParseGoTestJSON(f *testing.F) {
	f.Add([]byte("{\"Action\":\"pass\",\"Test\":\"TestDM01\"}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, _, err := ParseGoTestJSON(data)
		if err != nil {
			return
		}
		for _, r := range res {
			if r.Name == "" {
				t.Fatal("результат без имени")
			}
		}
	})
}

func FuzzParseJUnit(f *testing.F) {
	f.Add([]byte(`<testsuites><testsuite><testcase name="a"/></testsuite></testsuites>`))
	f.Fuzz(func(t *testing.T, data []byte) {
		res, err := ParseJUnit(data)
		if err != nil {
			return
		}
		for _, r := range res {
			if len(r.Name) > len(data) {
				t.Fatalf("имя теста длиннее всего отчёта: %q", r.Name)
			}
		}
	})
}

func FuzzParseCovers(f *testing.F) {
	f.Add("Покрывает: DM-38 (оповещение), DM-40")
	f.Fuzz(func(t *testing.T, doc string) {
		covs, _ := ParseCovers(doc)
		for _, c := range covs {
			if !rowIDRe.MatchString(c.ID) {
				t.Fatalf("некорректный ID %q", c.ID)
			}
		}
	})
}

// Запятая внутри скобок — часть названия, а не разделитель перечня.
func TestParseCoversCommaInPart(t *testing.T) {
	covs, bad := ParseCovers("Покрывает: DM-15 (бюджеты, аномалии и оповещение), DM-40\n")
	if len(bad) != 0 || len(covs) != 2 || covs[0].Part != "бюджеты, аномалии и оповещение" || covs[1].ID != "DM-40" {
		t.Fatalf("%+v %v", covs, bad)
	}
}
