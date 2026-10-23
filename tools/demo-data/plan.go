package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/azuresong-afk/ai_railway/internal/detect/pii"
)

// Ограничения на вход: корпус и файл ключей читаются с лимитом размера.
const (
	maxCorpusFile = 10 << 20
	maxCorpusLine = 1 << 20
	maxKeysFile   = 64 << 10
)

// rng — детерминированный генератор splitmix64. Он нужен только для того,
// чтобы один и тот же план получался по одному зерну; к безопасности не
// относится, ключей и секретов из него не берётся.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// intn — число от 0 до n-1 (n > 0).
func (r *rng) intn(n int) int {
	return int(r.next() % uint64(n)) //nolint:gosec // G115: n > 0 и в планах не больше 2000, остаток меньше n и помещается в int
}

// item — один запрос к Check API.
type item struct {
	Day       int    // номер суток плана, с нуля
	App, User string // приложение и условный пользователь
	Direction string // input или output
	Source    string // user или output
	Text      string
	Kind      string // benign, pii, attack, wave, leak
}

// corpusCase — строка корпуса testdata/corpus/<детектор>/*.jsonl.
type corpusCase struct {
	ID        string   `json:"id"`
	Direction string   `json:"direction"`
	Source    string   `json:"source"`
	Text      string   `json:"text"`
	Expect    []string `json:"expect"`
}

// corpora — примеры атак по детекторам. inputs идут как запросы (user), outputs —
// как ответы модели (output).
type corpora struct {
	inputs  []corpusCase // атаки во входе: инъекции, секреты, скрытый Unicode
	outputs []corpusCase // атаки в ответе: канарейка, exfil
	leaks   []corpusCase // утечки канарейки
	injects []corpusCase // инъекции для серии «подбор обхода»
}

// loadCorpora читает корпуса из каталога testdata/corpus. Строки без
// ожидаемых находок и без текста пропускаются.
func loadCorpora(dir string) (*corpora, error) {
	c := &corpora{}
	for _, d := range []struct {
		name string
		add  func([]corpusCase)
	}{
		{"injection.heuristic", func(v []corpusCase) { c.injects = append(c.injects, v...); c.inputs = append(c.inputs, v...) }},
		{"secrets", func(v []corpusCase) { c.inputs = append(c.inputs, v...) }},
		{"unicode.hidden", func(v []corpusCase) { c.inputs = append(c.inputs, v...) }},
		{"output.exfil", func(v []corpusCase) { c.outputs = append(c.outputs, v...) }},
		{"canary", func(v []corpusCase) { c.leaks = append(c.leaks, v...) }},
	} {
		cases, err := readCorpusDir(filepath.Join(dir, d.name))
		if err != nil {
			return nil, err
		}
		d.add(cases)
	}
	if len(c.inputs) == 0 || len(c.outputs) == 0 || len(c.leaks) == 0 || len(c.injects) == 0 {
		return nil, errors.New("в корпусе нет примеров атак: проверьте -corpus")
	}
	return c, nil
}

func readCorpusDir(dir string) ([]corpusCase, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	var out []corpusCase
	for _, f := range files {
		cs, err := readCorpusFile(f)
		if err != nil {
			return nil, err
		}
		out = append(out, cs...)
	}
	return out, nil
}

func readCorpusFile(path string) ([]corpusCase, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь собран из флага -corpus, который задаёт оператор стенда
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() //nolint:gosec // G104: ошибка закрытия файла, открытого для чтения, не влияет на результат
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > maxCorpusFile {
		return nil, fmt.Errorf("%s: файл больше %d байт", path, maxCorpusFile)
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxCorpusLine)
	var out []corpusCase
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c corpusCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if c.Text == "" || len(c.Expect) == 0 {
			continue
		}
		out = append(out, c)
	}
	return out, sc.Err()
}

// benignTexts — обычные рабочие запросы без находок.
var benignTexts = []string{
	"Составь краткий план совещания по итогам квартала на пять пунктов.",
	"Объясни разницу между кредитным и дебетовым платежом простыми словами.",
	"Переведи на английский: «Прошу подтвердить получение документов до пятницы».",
	"Как правильно оформить заявление на отпуск? Приведи шаблон без реквизитов.",
	"Summarize the key risks of storing logs for more than a year.",
	"Предложи три названия для внутреннего семинара по информационной безопасности.",
	"Напиши SQL-запрос, который считает число заказов по неделям.",
	"Почему растёт время ответа сервиса при увеличении очереди? Дай чек-лист проверки.",
	"Сделай выжимку из письма: встреча перенесена на вторник, повестка прежняя.",
	"Какие вопросы задать кандидату на должность системного аналитика?",
	"Draft a polite reminder about the overdue report, two sentences.",
	"Подскажи, как структурировать инструкцию для новых сотрудников поддержки.",
}

// piiTemplates — запросы с синтетическими ПДн; %s подставляется значением из
// internal/detect/pii (контрольные суммы верны, реальным людям не принадлежат).
var piiTemplates = []struct {
	kind string
	text string
	gen  func(uint64) string
}{
	{"snils", "Мой СНИЛС %s, подготовьте справку о стаже.", pii.SynthSNILS},
	{"inn12", "Проверь, пожалуйста, контрагента с ИНН %s.", pii.SynthINN12},
	{"inn10", "Реквизиты организации: ИНН %s, подготовь договор.", pii.SynthINN10},
	{"card", "Оплата не прошла, номер карты %s, помогите разобраться.", pii.SynthCard},
	{"phone", "Перезвоните мне по номеру %s после обеда.", pii.SynthPhone},
	{"email", "Отправьте счёт на адрес %s.", pii.SynthEmail},
	{"passport", "Паспорт %s, нужно оформить доверенность.", pii.SynthPassport},
}

// planParams — вход построения плана.
type planParams struct {
	Seed         uint64
	Days         int
	EventsPerDay int
	Apps         []string
	Corpora      *corpora
}

// buildPlan строит детерминированный по зерну план запросов: по дням, от
// первых суток к последним. Ежедневный поток — обычные запросы, запросы с ПДн
// и редкие атаки; раз в неделю один пользователь пробует обход защиты серией
// подряд (правила «инъекция заблокирована» и «серия срабатываний»), раз в
// десять суток в ответе модели встречается канарейка (инцидент).
func buildPlan(p planParams) []item {
	r := &rng{s: p.Seed}
	var plan []item
	var piiN uint64 = 1 // номер синтетического значения растёт: значения не повторяются
	users := 8
	for day := range p.Days {
		perDay := max(1, p.EventsPerDay/2+r.intn(p.EventsPerDay+1)) // разброс от ½ до 1½ нормы
		for range perDay {
			app := p.Apps[r.intn(len(p.Apps))]
			user := fmt.Sprintf("demo-user-%02d", r.intn(users)+1)
			switch roll := r.intn(100); {
			case roll < 72:
				plan = append(plan, item{day, app, user, "input", "user", benignTexts[r.intn(len(benignTexts))], "benign"})
			case roll < 90:
				t := piiTemplates[r.intn(len(piiTemplates))]
				plan = append(plan, item{day, app, user, "input", "user", fmt.Sprintf(t.text, t.gen(piiN)), "pii"})
				piiN++
			case roll < 97:
				c := p.Corpora.inputs[r.intn(len(p.Corpora.inputs))]
				plan = append(plan, item{day, app, user, "input", "user", c.Text, "attack"})
			default:
				c := p.Corpora.outputs[r.intn(len(p.Corpora.outputs))]
				plan = append(plan, item{day, app, user, "output", "output", c.Text, "attack"})
			}
		}
		if day%7 == 3 {
			app := p.Apps[r.intn(len(p.Apps))]
			user := fmt.Sprintf("demo-prober-%02d", day/7+1)
			for range 12 {
				c := p.Corpora.injects[r.intn(len(p.Corpora.injects))]
				plan = append(plan, item{day, app, user, "input", "user", c.Text, "wave"})
			}
		}
		if day%10 == 5 {
			app := p.Apps[r.intn(len(p.Apps))]
			c := p.Corpora.leaks[r.intn(len(p.Corpora.leaks))]
			plan = append(plan, item{day, app, "demo-user-01", "output", "output", c.Text, "leak"})
		}
	}
	return plan
}

// readKeys читает файл ключей приложений: строки «приложение=ключ», пустые
// строки и строки с # пропускаются. Файл должен быть закрыт для остальных
// пользователей (права 0600). Ключи в аргументах командной строки не
// передаются: argv виден в списке процессов.
func readKeys(path string) (map[string]string, []string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: путь задаёт оператор стенда флагом -keys
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }() //nolint:gosec // G104: ошибка закрытия файла, открытого для чтения, не влияет на результат
	st, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > maxKeysFile {
		return nil, nil, errors.New("файл ключей: нужен обычный файл не больше 64 КиБ")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, nil, errors.New("файл ключей доступен другим пользователям: задайте права 0600")
	}
	keys := map[string]string{}
	var names []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		app, key, ok := strings.Cut(line, "=")
		app, key = strings.TrimSpace(app), strings.TrimSpace(key)
		if !ok || app == "" || key == "" {
			return nil, nil, errors.New("файл ключей: строки должны иметь вид «приложение=ключ»")
		}
		if _, dup := keys[app]; dup {
			return nil, nil, fmt.Errorf("файл ключей: приложение %q повторяется", app)
		}
		keys[app] = key
		names = append(names, app)
	}
	if err := sc.Err(); err != nil {
		return nil, nil, err
	}
	if len(names) == 0 {
		return nil, nil, errors.New("файл ключей пуст")
	}
	return keys, names, nil
}
