// Команда dast-triage сверяет отчёты OWASP ZAP baseline (JSON) с правилами и
// разметкой в docs/cert/sast-triage/dast.yaml (задача 3.30, решение Р10):
//   - находка выше порога — риск Medium и выше или правило с действием FAIL в
//     файле правил ZAP — это провал, если нет записи false_positive с
//     обоснованием;
//   - находка ниже порога не проваливает задание, но попадает в отчёт; если её
//     приняли осознанно, она размечается accepted_risk с обоснованием;
//   - запись разметки без находки — предупреждение: запись устарела.
//
// Использование: dast-triage -rules R -triage T -out O цель=отчёт.json ...
// В поставку не входит.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Ограничения размеров входных файлов.
const (
	maxReport = 64 << 20
	maxRules  = 1 << 20
	maxTriage = 4 << 20
)

// Вердикты разметки.
const (
	FalsePositive = "false_positive"
	AcceptedRisk  = "accepted_risk"
)

// medium — код риска ZAP (riskcode), с которого находка считается выше порога.
const medium = 2

// Entry — запись разметки.
type Entry struct {
	Target        string `yaml:"target"`
	PluginID      string `yaml:"plugin_id"`
	Alert         string `yaml:"alert"`
	MaxRisk       int    `yaml:"max_risk"` // наибольший риск ZAP (0–3), который запись покрывает
	Verdict       string `yaml:"verdict"`
	Justification string `yaml:"justification"`
	Author        string `yaml:"author"`
	Date          string `yaml:"date"`
}

// Triage — файл разметки.
type Triage struct {
	SchemaVersion int     `yaml:"schema_version"`
	Entries       []Entry `yaml:"entries"`
}

// Alert — находка ZAP.
type Alert struct {
	Target   string
	PluginID string
	Name     string
	Risk     int
	Count    int
}

// Above сообщает, что находка выше порога: риск Medium и выше или правило FAIL.
func (a Alert) Above(rules map[string]string) bool {
	return a.Risk >= medium || rules[a.PluginID] == "FAIL"
}

func main() {
	rules := flag.String("rules", "deploy/compose/pilot/dast/zap-rules.conf", "файл правил ZAP baseline (-c)")
	triage := flag.String("triage", "docs/cert/sast-triage/dast.yaml", "файл разметки находок")
	out := flag.String("out", "", "куда записать сводку (Markdown); по умолчанию — только вывод")
	flag.Parse()
	if err := run(*rules, *triage, *out, flag.Args(), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "dast-triage:", err)
		os.Exit(1)
	}
}

func run(rulesPath, triagePath, outPath string, reports []string, stdout, stderr io.Writer) error {
	if len(reports) == 0 {
		return errors.New("нужен хотя бы один отчёт вида цель=файл.json")
	}
	rulesData, err := readLimited(rulesPath, maxRules)
	if err != nil {
		return err
	}
	rules := ParseRules(rulesData)
	triageData, err := readLimited(triagePath, maxTriage)
	if err != nil {
		return err
	}
	tri, err := ParseTriage(triageData)
	if err != nil {
		return fmt.Errorf("%s: %w", triagePath, err)
	}
	var alerts []Alert
	for _, r := range reports {
		target, file, ok := strings.Cut(r, "=")
		if !ok || target == "" || file == "" {
			return fmt.Errorf("отчёт %q: нужен вид цель=файл.json", r)
		}
		data, err := readLimited(file, maxReport)
		if err != nil {
			return err
		}
		as, err := ParseReport(target, data)
		if err != nil {
			return fmt.Errorf("%s: %w", file, err)
		}
		alerts = append(alerts, as...)
	}
	res := Compare(alerts, rules, tri.Entries)
	for _, s := range res.Stale {
		_, _ = fmt.Fprintln(stderr, "предупреждение:", s)
	}
	summary := res.Markdown(len(alerts))
	if outPath != "" {
		if err := os.WriteFile(outPath, []byte(summary), 0o644); err != nil { //nolint:gosec // G306: отчёт CI без секретов
			return err
		}
	}
	_, _ = fmt.Fprintf(stdout, "dast-triage: находок %d (групп по правилам), выше порога без разметки %d, размечено выше порога %d, ниже порога без разметки %d, размечено ниже порога %d, пропущено правилом IGNORE %d\n",
		len(alerts), len(res.Problems), res.MarkedAbove, len(res.Unmarked), res.MarkedBelow, len(res.Ignored))
	if len(res.Problems) > 0 {
		return errors.New("не пройдено:\n" + strings.Join(res.Problems, "\n"))
	}
	return nil
}

func readLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: пути задаёт оператор CI аргументами и флагами
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() //nolint:gosec // G104: ошибка закрытия файла, открытого для чтения, не влияет на результат
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: файл больше %d байт", path, limit)
	}
	return data, nil
}

// ParseRules разбирает файл правил ZAP baseline: строки «id<TAB>ДЕЙСТВИЕ<TAB>(имя)»,
// комментарии начинаются с #. Неизвестные действия пропускаются.
func ParseRules(data []byte) map[string]string {
	rules := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[1] {
		case "FAIL", "WARN", "IGNORE", "INFO", "OUTOFSCOPE":
			rules[f[0]] = f[1]
		}
	}
	return rules
}

// ParseTriage разбирает и проверяет файл разметки.
func ParseTriage(data []byte) (Triage, error) {
	var t Triage
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&t); err != nil && !errors.Is(err, io.EOF) {
		return t, err
	}
	if t.SchemaVersion != 1 {
		return t, errors.New("schema_version должен быть 1")
	}
	seen := map[string]bool{}
	for i, e := range t.Entries {
		switch {
		case e.Target == "" || e.PluginID == "" || e.Alert == "":
			return t, fmt.Errorf("запись %d: нужны target, plugin_id и alert", i+1)
		case e.Target != "console" && e.Target != "gateway":
			return t, fmt.Errorf("запись %d: target — console или gateway", i+1)
		case e.MaxRisk < 0 || e.MaxRisk > 3:
			return t, fmt.Errorf("запись %d: max_risk — от 0 до 3", i+1)
		case e.Verdict != FalsePositive && e.Verdict != AcceptedRisk:
			return t, fmt.Errorf("запись %d: verdict — false_positive или accepted_risk", i+1)
		case len([]rune(strings.TrimSpace(e.Justification))) < 20 || e.Author == "":
			return t, fmt.Errorf("запись %d: нужны justification (не короче 20 символов) и author", i+1)
		case !validDate(e.Date):
			return t, fmt.Errorf("запись %d: date — ГГГГ-ММ-ДД", i+1)
		case seen[e.Target+"|"+e.PluginID]:
			return t, fmt.Errorf("запись %d: %s/%s повторяется", i+1, e.Target, e.PluginID)
		}
		seen[e.Target+"|"+e.PluginID] = true
	}
	return t, nil
}

func validDate(s string) bool {
	_, err := time.Parse("2006-01-02", s)
	return err == nil
}

// ParseReport разбирает отчёт ZAP (traditional-json, ключ -J).
func ParseReport(target string, data []byte) ([]Alert, error) {
	var rep struct {
		Site []struct {
			Alerts []struct {
				PluginID string `json:"pluginid"`
				Alert    string `json:"alert"`
				RiskCode string `json:"riskcode"`
				Count    string `json:"count"`
			} `json:"alerts"`
		} `json:"site"`
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	if len(rep.Site) == 0 {
		return nil, errors.New("в отчёте нет ни одного сайта: обход не состоялся")
	}
	var out []Alert
	for _, s := range rep.Site {
		for _, a := range s.Alerts {
			risk, err := strconv.Atoi(a.RiskCode)
			if err != nil || risk < 0 || risk > 3 || a.PluginID == "" {
				return nil, fmt.Errorf("находка %q: неверный pluginid или riskcode", a.Alert)
			}
			n, _ := strconv.Atoi(a.Count) //nolint:gosec // G104: пустой или неверный count — ноль, на решение не влияет
			out = append(out, Alert{Target: target, PluginID: a.PluginID, Name: a.Alert, Risk: risk, Count: n})
		}
	}
	return out, nil
}

// Result — итог сверки.
type Result struct {
	Problems    []string
	Unmarked    []Alert // ниже порога, без разметки
	Stale       []string
	Ignored     []Alert // правило IGNORE, риск ниже Medium
	MarkedAbove int
	MarkedBelow int
}

// Compare сверяет находки с разметкой. Правило IGNORE в файле правил
// исключает находку из сверки.
func Compare(alerts []Alert, rules map[string]string, entries []Entry) Result {
	var res Result
	idx := map[string]*Entry{}
	used := map[string]bool{}
	for i := range entries {
		idx[entries[i].Target+"|"+entries[i].PluginID] = &entries[i]
	}
	for _, a := range alerts {
		// IGNORE не скрывает находки Medium и выше: их закрывает только разметка.
		if (rules[a.PluginID] == "IGNORE" || rules[a.PluginID] == "OUTOFSCOPE") && a.Risk < medium {
			res.Ignored = append(res.Ignored, a)
			continue
		}
		key := a.Target + "|" + a.PluginID
		e := idx[key]
		used[key] = true
		if e != nil && (a.Risk > e.MaxRisk || a.Name != e.Alert) {
			// Запись не покрывает ни более высокий риск, ни другую находку того же правила.
			res.Problems = append(res.Problems, fmt.Sprintf("%s: %s (%s, риск %d) не покрыта записью разметки (alert %q, max_risk %d)", a.Target, a.Name, a.PluginID, a.Risk, e.Alert, e.MaxRisk))
			continue
		}
		switch {
		case a.Above(rules) && (e == nil || e.Verdict != FalsePositive):
			why := "нет разметки false_positive"
			if e != nil {
				why = "accepted_risk допустим только ниже порога"
			}
			res.Problems = append(res.Problems, fmt.Sprintf("%s: %s (%s, риск %d) выше порога: %s", a.Target, a.Name, a.PluginID, a.Risk, why))
		case a.Above(rules):
			res.MarkedAbove++
		case e == nil:
			res.Unmarked = append(res.Unmarked, a)
		default:
			res.MarkedBelow++
		}
	}
	for _, e := range entries {
		if !used[e.Target+"|"+e.PluginID] {
			res.Stale = append(res.Stale, fmt.Sprintf("запись %s/%s (%s) без находки — удалите её", e.Target, e.PluginID, e.Alert))
		}
	}
	sort.Strings(res.Problems)
	sort.Strings(res.Stale)
	return res
}

// Markdown — сводка для артефакта CI.
func (r Result) Markdown(total int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# DAST: ZAP baseline\n\nНаходок (по правилам): %d. Выше порога без разметки: %d. Ниже порога без разметки: %d.\n", total, len(r.Problems), len(r.Unmarked))
	if len(r.Problems) > 0 {
		b.WriteString("\n## Выше порога\n\n")
		for _, p := range r.Problems {
			b.WriteString("- " + p + "\n")
		}
	}
	if len(r.Unmarked) > 0 {
		b.WriteString("\n## Ниже порога, без разметки\n\n")
		for _, a := range r.Unmarked {
			fmt.Fprintf(&b, "- %s: %s (%s, риск %d)\n", a.Target, a.Name, a.PluginID, a.Risk)
		}
	}
	if len(r.Ignored) > 0 {
		b.WriteString("\n## Пропущено правилом IGNORE\n\n")
		for _, a := range r.Ignored {
			fmt.Fprintf(&b, "- %s: %s (%s, риск %d)\n", a.Target, a.Name, a.PluginID, a.Risk)
		}
	}
	return b.String()
}
