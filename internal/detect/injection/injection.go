// Пакет injection — детектор injection.heuristic: прямые и косвенные
// инъекции в промпт по шаблонам RU/EN (ТЗ, 5.2). Часть 1 (задача 1.15):
// отмена инструкций, смена роли со снятием ограничений, извлечение
// системного промпта, подделка структуры диалога (служебные токены,
// фальшивые системные сообщения, many-shot). Часть 2 (задача 1.16,
// obfuscation.go): декодирование кодировок, leetspeak, разрядка, склейка
// строк, транслит, ROT13, смешение языков.
//
// Скоринг, а не единичные совпадения: у каждого сигнала свой вес; оценка
// категории — вероятностное «или» её правил (у правила — самый сильный
// сигнал: повтор одного шаблона оценку не накапливает); несколько категорий
// сразу повышают оценку; разговор об атаках («как защититься от…») и шаблон
// в кавычках — понижают.
//
// Текст сначала проходит unihidden.Clean: скрытые символы, теги и
// гомоглифы не мешают шаблонам; позиции находок — в исходном тексте.
package injection

import (
	"context"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/azuresong-afk/ai_railway/internal/detect"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
)

// ID и версия детектора.
const (
	ID      = "injection.heuristic"
	Version = "1.1.0"
)

// Категории находок.
const (
	CatOverride  = "injection.override"
	CatRole      = "injection.role"
	CatLeak      = "injection.prompt_leak"
	CatStructure = "injection.structure"
	// CatObfuscation — признак найден после декодирования или
	// преобразования текста (DM-04); правило — «способ.правило».
	CatObfuscation = "injection.obfuscation"
)

// threats — строка матрицы по категории для запроса пользователя; в
// документах RAG и ответах инструментов — DM-07 (косвенная инъекция).
var threats = map[string]string{CatOverride: "DM-01", CatRole: "DM-01", CatLeak: "DM-08", CatStructure: "DM-02", CatObfuscation: "DM-04"}

// Detector — детектор injection.heuristic. Без состояния, безопасен для
// одновременного вызова.
type Detector struct{}

// New создаёт детектор.
func New() Detector { return Detector{} }

// ID — идентификатор детектора.
func (Detector) ID() string { return ID }

// Version — версия детектора.
func (Detector) Version() string { return Version }

// Directions — запрос (в том числе документы RAG и ответы инструментов).
func (Detector) Directions() []detect.Direction { return []detect.Direction{detect.Input} }

// Части текста: шаблоны локальны (окно до 400 байт вперёд, до 300 байт
// между сменой роли и снятием ограничений), поэтому текст обрабатывается
// частями с контекстом до и после — память ограничена и на больших текстах.
// Сигнал засчитывается той части, в которой он начинается.
const (
	chunkSize = 64 << 10
	overlap   = 2 << 10 // контекст после части
	back      = 1 << 10 // контекст до части: глаголы перед объектом, пары роль + снятие
)

// Detect находит признаки инъекции в тексте.
func (Detector) Detect(ctx context.Context, t detect.Text) ([]detect.Finding, error) {
	st := newState(t.Text, t.Source == detect.SourceRAG || t.Source == detect.SourceTool)
	if err := st.run(ctx); err != nil {
		return nil, err
	}
	return st.findings(), nil
}

func newState(text string, indirect bool) *state {
	return &state{text: text, indirect: indirect, best: map[ruleKey]signal{}}
}

// run разбирает текст по частям.
func (st *state) run(ctx context.Context) error {
	for cs := 0; cs < len(st.text); {
		if err := ctx.Err(); err != nil {
			return err
		}
		ce := runeAlign(st.text, min(cs+chunkSize, len(st.text)))
		we := runeAlign(st.text, min(ce+overlap, len(st.text)))
		bs := runeAlign(st.text, max(cs-back, 0))
		if err := st.chunk(ctx, bs, cs, ce, we); err != nil {
			return err
		}
		cs = ce
	}
	return nil
}

func runeAlign(s string, i int) int {
	for i < len(s) && !utf8.RuneStart(s[i]) {
		i++
	}
	return i
}

// signal — найденный признак: категория, правило, вес, позиции в исходном
// тексте.
type signal struct {
	cat, rule string
	w         float64
	s, e      int
	quoted    bool // шаблон в кавычках — скорее цитата
	dampable  bool // вес снижается, если текст обсуждает атаки
	chg       bool // задевает символы, изменённые преобразованием
}

// eff — вес с учётом кавычек.
func (sg signal) eff() float64 {
	if sg.quoted {
		return sg.w * 0.6
	}
	return sg.w
}

type ruleKey struct{ cat, rule string }

// state — состояние разбора. Память ограничена: по каждому правилу хранится
// только самый сильный сигнал.
type state struct {
	text     string
	indirect bool
	meta     bool // текст обсуждает атаки
	fmt      bool // текст обсуждает форматы чата
	best     map[ruleKey]signal
	depth    int // уровень вложенности декодированного текста
	// many-shot: метки реплик в начале строк.
	turns, userTurns, aiTurns int
	turnFirst, turnLast       int
}

// view — часть текста [bs, we) после Clean и приведения к нижнему регистру
// или её производное представление (obfuscation.go).
type view struct {
	low     string
	clean   string // после Clean, до приведения регистра (только основное)
	offs    []int
	bs      int
	cs, ce  int // своя часть [cs, ce); до и после — контекст
	lineBOL bool
	// Производное представление: способ преобразования и префиксные суммы
	// изменённых байтов.
	method string
	chg    []int32
	// Смена роли и снятие ограничений во всём окне — для пар (pairs).
	persona, removal []signal
}

func (v *view) orig(i int) int { return v.bs + v.offs[i] }

// changed — фрагмент [i, j) задевает изменённые преобразованием байты.
func (v *view) changed(i, j int) bool { return v.chg != nil && v.chg[j]-v.chg[i] > 0 }

// mark переносит сигнал производного представления в категорию обфускации.
func (v *view) mark(sg signal) signal {
	if v.method == "" {
		return sg
	}
	sg.cat, sg.rule = CatObfuscation, v.method+"."+sg.rule
	if v.method == "concat" {
		sg.quoted = false // части склейки всегда в кавычках
	}
	return sg
}

// own — позиция i относится к своей части, а не к контексту (сигнал в
// контексте достанется соседней части).
func (v *view) own(i int) bool { o := v.orig(i); return o >= v.cs && o < v.ce }

func (st *state) add(v *view, cat, rule string, w float64, i, j int, dampable bool) {
	// Название DAN-промпта пишут в кавычках в самом промпте.
	q := rule != "dan" && quoted(v.low, i, j)
	sg := signal{cat: cat, rule: rule, w: w, s: v.orig(i), e: v.orig(j), quoted: q, dampable: dampable, chg: v.changed(i, j)}
	switch rule {
	case "persona":
		v.persona = append(v.persona, sg)
	case "removal":
		v.removal = append(v.removal, sg)
	}
	// В производном представлении — только то, чего нет в основном.
	if v.own(i) && (v.method == "" || sg.chg) {
		st.keep(v.mark(sg))
	}
}

// keep запоминает сигнал, если он сильнее прежнего по тому же правилу.
func (st *state) keep(sg signal) {
	k := ruleKey{sg.cat, sg.rule}
	if old, ok := st.best[k]; !ok || sg.eff() > old.eff() {
		st.best[k] = sg
	}
}

// chunk ищет сигналы в части [cs, ce) исходного текста, окно — [bs, we):
// в основном представлении, в производных (leetspeak, транслит…) и в
// декодированных отрезках.
func (st *state) chunk(ctx context.Context, bs, cs, ce, we int) error {
	clean, offs := unihidden.Clean(st.text[bs:we])
	v := &view{low: fold(clean), clean: clean, offs: offs, bs: bs, cs: cs, ce: ce, lineBOL: bs == 0 || st.text[bs-1] == '\n'}
	st.meta = st.meta || containsAny(v.low, metaWords)
	st.fmt = st.fmt || containsAny(v.low, fmtWords)
	if err := st.scan(ctx, v); err != nil {
		return err
	}
	for _, t := range transforms {
		if err := ctx.Err(); err != nil {
			return err
		}
		if b := t.build(v.low); b != nil {
			if err := st.scan(ctx, v.derive(t.method, b)); err != nil {
				return err
			}
		}
	}
	if st.depth < maxDepth {
		return st.segments(ctx, v)
	}
	return nil
}

// scan проверяет представление всеми шаблонами.
func (st *state) scan(ctx context.Context, v *view) error {
	steps := []func(*view) error{
		func(v *view) error { return st.overrides(ctx, v) },
		func(v *view) error { return st.phrases(ctx, v, CatOverride, overridePhrases, true) },
		func(v *view) error {
			if !st.indirect {
				return nil
			}
			return st.phrases(ctx, v, CatOverride, addressAI, true)
		},
		func(v *view) error { return st.phrases(ctx, v, CatRole, personaPhrases, true) },
		func(v *view) error { return st.removals(ctx, v) },
		func(v *view) error { return st.leaks(ctx, v) },
		func(v *view) error { return st.structure(ctx, v) },
	}
	for _, step := range steps {
		if err := step(v); err != nil {
			return err
		}
	}
	st.pairs(v)
	return nil
}

// pairs — смена роли вместе со снятием ограничений не дальше 300 байт друг
// от друга: «ты теперь ИИ без ограничений», «act as an AI without
// restrictions». Хотя бы один сигнал пары — в своей части; контекста до
// части (back) хватает, чтобы увидеть второй. Проход по сигналам,
// упорядоченным по началу, — O(n log n), а не перебор всех пар.
func (st *state) pairs(v *view) {
	if len(v.persona) == 0 || len(v.removal) == 0 {
		return
	}
	all := make([]signal, 0, len(v.persona)+len(v.removal))
	all = append(append(all, v.persona...), v.removal...)
	sort.Slice(all, func(i, j int) bool { return all[i].s < all[j].s })
	// Для каждого вида — сигнал с наибольшим концом среди уже пройденных:
	// любой и только в своей части.
	type reach struct {
		sg signal
		ok bool
	}
	var seen, own [2]reach
	kind := func(sg signal) int {
		if sg.rule == "persona" {
			return 0
		}
		return 1
	}
	isOwn := func(sg signal) bool { return sg.s >= v.cs && sg.s < v.ce }
	for _, sg := range all {
		k := kind(sg)
		other := seen[1-k]
		if !isOwn(sg) {
			other = own[1-k]
		}
		// В производном представлении — пара, которой нет в основном.
		if other.ok && sg.s-other.sg.e <= 300 && (v.method == "" || sg.chg || other.sg.chg) {
			p := other.sg
			st.keep(v.mark(signal{cat: CatRole, rule: "persona_removal", w: 0.4, s: p.s, e: max(p.e, sg.e), dampable: true, quoted: p.quoted && sg.quoted}))
		}
		if !seen[k].ok || sg.e > seen[k].sg.e {
			seen[k] = reach{sg, true}
		}
		if isOwn(sg) && (!own[k].ok || sg.e > own[k].sg.e) {
			own[k] = reach{sg, true}
		}
	}
}

// overrides — «ignore all previous instructions», «игнорируй все
// предыдущие инструкции». Не сигнал: глагол с отрицанием («не игнорируйте
// правила»), английский глагол не в повелительной позиции («users ignore
// all rules»). Вес — по словам между глаголом и объектом: «мои» — 0,3
// (пользователь правит своё же указание); «твои», «системные» — 0,85;
// объект с уточнением предлогом («все фильтры в таблице», «предыдущие
// инструкции по оформлению») — 0,35; «все», «предыдущие» — 0,85; иначе 0,7.
// Шаблон с английскими и русскими словами сразу («Ignore все previous
// инструкции») — смешение языков: обфускация, правило
// «mixed.ignore_instructions».
func (st *state) overrides(ctx context.Context, v *view) error {
	for _, g := range []struct {
		anchors []string
		en      bool
	}{{overrideAnchorsEN, true}, {overrideAnchorsRU, false}} {
		for _, a := range g.anchors {
			err := indexWord(ctx, v.low, a, func(i int) {
				if negated(v.low, i) || g.en && !imperativeEN(v.low, i) {
					return
				}
				m := overrideRe.FindStringSubmatchIndex(v.low[i:min(i+400, len(v.low))])
				if m == nil {
					return
				}
				words := strings.Fields(strings.Map(sepToSpace, v.low[i+m[2]:i+m[3]]))
				w := 0.7
				switch {
				case hasPrefix(words, myWords):
					w = 0.3
				case hasPrefix(words, modelWords):
					w = 0.85
				case qualified(v.low, i+m[1]):
					w = 0.35
				case hasPrefix(words, strongWords):
					w = 0.85
				}
				if mixedScript(v.low[i : i+m[1]]) {
					st.add(v, CatObfuscation, "mixed.ignore_instructions", w, i, i+m[1], true)
					return
				}
				st.add(v, CatOverride, "ignore_instructions", w, i, i+m[1], true)
			})
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// mixedScript — во фрагменте есть и латиница, и кириллица.
func mixedScript(s string) bool {
	lat, cyr := false, false
	for _, r := range s {
		switch {
		case r < 0x80 && unicode.IsLetter(r):
			lat = true
		case unicode.Is(unicode.Cyrillic, r):
			cyr = true
		}
	}
	return lat && cyr
}

// phrases — сигналы-фразы с опорным словом и необязательным выражением.
func (st *state) phrases(ctx context.Context, v *view, cat string, list []phrase, dampable bool) error {
	for _, p := range list {
		err := indexWord(ctx, v.low, p.anchor, func(i int) {
			j := i + len(p.anchor)
			if p.re != nil {
				m := p.re.FindStringIndex(v.low[i:min(i+400, len(v.low))])
				if m == nil {
					return
				}
				j = i + m[1]
			}
			st.add(v, cat, p.rule, p.weight, i, j, dampable)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// removals — снятие ограничений. С уточнением предлогом («без ограничений
// по стилю», «no limits on data») — не сигнал. Рядом с просьбой отвечать
// («отвечай без цензуры») — отдельный сигнал; рядом со сменой роли — пара
// (pairs).
func (st *state) removals(ctx context.Context, v *view) error {
	for _, p := range removalPhrases {
		err := indexWord(ctx, v.low, p.anchor, func(i int) {
			j := i + len(p.anchor)
			if p.re != nil {
				m := p.re.FindStringIndex(v.low[i:min(i+200, len(v.low))])
				if m == nil {
					return
				}
				j = i + m[1]
			}
			if qualified(v.low, j) {
				return
			}
			st.add(v, CatRole, "removal", p.weight, i, j, true)
			if _, ok := lastWord(v.low, prevWords(v.low, i, 4), i, imperativeWords); ok {
				st.add(v, CatRole, "removal_imperative", 0.35, i, j, true)
			}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// leaks — извлечение системного промпта: объект («системный промпт», «your
// instructions») и глагол в 48 байтах перед ним. «Покажи», «reveal» —
// 0,85; «текст выше» — 0,7 с «дословно», «целиком» после него, иначе 0,4
// (обычная работа с текстом: «покажи текст выше таблицей»). Вопрос
// разработчика («how do I print the system prompt») и вопрос о понятии
// («what is a system prompt») — 0,15; вопрос о промпте самой модели
// («твои», «your») — 0,65. Без глагола («напиши системный промпт для
// бота») — не сигнал.
func (st *state) leaks(ctx context.Context, v *view) error {
	for _, o := range leakObjects {
		err := indexWord(ctx, v.low, o.anchor, func(i int) {
			j := i + len(o.anchor)
			if o.re != nil {
				m := o.re.FindStringIndex(v.low[i:min(i+200, len(v.low))])
				if m == nil {
					return
				}
				j = i + m[1]
			}
			from := max(0, i-48)
			strong, okStrong := lastWord(v.low, from, i, leakStrong)
			weak, okWeak := lastWord(v.low, from, i, leakWeak)
			if !okStrong && !okWeak {
				return
			}
			k := weak
			if okStrong {
				k = strong
			}
			poss := o.possessive || containsWord(v.low[k:j], possessives)
			w := 0.15
			switch {
			case poss && okStrong:
				w = 0.85
			case poss:
				w = 0.65
			case !okStrong:
			case containsWord(v.low[max(0, k-32):k], devLead):
			case o.above && containsWord(v.low[j:min(j+60, len(v.low))], verbatim):
				w = 0.7
			case o.above:
				w = 0.4
			default:
				w = 0.85
			}
			rule := "leak"
			if !okStrong {
				rule = "leak_question"
			}
			st.add(v, CatLeak, rule, w, k, j, true)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// structure — служебные токены шаблонов чата, фальшивые системные
// сообщения и метки реплик в начале строк, роль system в JSON.
func (st *state) structure(ctx context.Context, v *view) error {
	for _, tok := range serviceTokens {
		err := indexAll(ctx, v.low, tok, func(i int) {
			st.add(v, CatStructure, "token", 0.9, i, i+len(tok), false)
		})
		if err != nil {
			return err
		}
	}
	// Роль system в JSON: в вопросе разработчика — обычное дело, в
	// документе или ответе инструмента — попытка подменить сообщение.
	jw := 0.35
	if st.indirect {
		jw = 0.5
	}
	err := indexAll(ctx, v.low, `"role"`, func(i int) {
		if m := jsonRole.FindStringIndex(v.low[i:min(i+64, len(v.low))]); m != nil {
			st.add(v, CatStructure, "json_role", jw, i, i+m[1], false)
		}
	})
	if err != nil {
		return err
	}
	// Начала строк.
	for i, n := 0, 0; i < len(v.low); n++ {
		if n%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if i > 0 || v.lineBOL {
			st.line(v, i)
		}
		nl := strings.IndexByte(v.low[i:], '\n')
		if nl < 0 {
			break
		}
		i += nl + 1
	}
	return nil
}

// line разбирает начало строки в позиции i.
func (st *state) line(v *view, i int) {
	j := i
	for j < len(v.low) && strings.IndexByte(" \t>*-", v.low[j]) >= 0 {
		j++
	}
	rest := v.low[j:min(j+80, len(v.low))] // самая длинная метка — 52 байта
	for _, l := range turnLabels {
		if strings.HasPrefix(rest, l.label) {
			// Реплики считаются только в основном представлении.
			if !v.own(j) || v.method != "" {
				return
			}
			o := v.orig(j)
			if st.turns == 0 {
				st.turnFirst = o
			}
			st.turns++
			st.turnLast = v.orig(min(j+len(l.label), len(v.low)))
			if l.user {
				st.userTurns++
			} else {
				st.aiTurns++
			}
			return
		}
	}
	trimmed := strings.TrimLeft(rest, "# \t")
	k := j + len(rest) - len(trimmed)
	for _, p := range fakeSystemStrong {
		if strings.HasPrefix(trimmed, p) {
			st.add(v, CatStructure, "fake_system", 0.65, k, k+len(p), false)
			return
		}
	}
	for _, p := range fakeSystemWeak {
		if strings.HasPrefix(trimmed, p) {
			st.add(v, CatStructure, "fake_system", 0.4, k, k+len(p), false)
			return
		}
	}
}

// manyShot — десятки вложенных реплик пользователя и ассистента.
func (st *state) manyShot() {
	if st.userTurns == 0 || st.aiTurns == 0 {
		return
	}
	switch {
	case st.turns >= 24:
		st.keep(signal{cat: CatStructure, rule: "many_shot", w: 0.8, s: st.turnFirst, e: st.turnLast})
	case st.turns >= 8:
		st.keep(signal{cat: CatStructure, rule: "many_shot", w: 0.4, s: st.turnFirst, e: st.turnLast})
	}
}

// keys — правила по порядку: результат не зависит от порядка обхода карты
// (и в последних битах оценки).
func (st *state) keys() []ruleKey {
	keys := make([]ruleKey, 0, len(st.best))
	for k := range st.best {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].cat < keys[j].cat || keys[i].cat == keys[j].cat && keys[i].rule < keys[j].rule
	})
	return keys
}

// weight — вес сигнала с понижениями: кавычки, обсуждение атак, обсуждение
// форматов чата (для служебных токенов).
func (st *state) weight(sg signal) float64 {
	w := sg.eff()
	if st.meta && sg.dampable {
		w *= 0.7
	}
	if st.fmt && sg.rule == "token" {
		w *= 0.5
	}
	return w
}

// findings сводит сигналы в находки: одна на категорию — по самому сильному
// сигналу, оценка — вероятностное «или» правил категории.
func (st *state) findings() []detect.Finding {
	st.manyShot()
	type agg struct {
		miss float64 // Π(1 − w)
		best signal
		bw   float64
	}
	cats := map[string]*agg{}
	for _, k := range st.keys() {
		sg := st.best[k]
		w := st.weight(sg)
		a := cats[sg.cat]
		if a == nil {
			a = &agg{miss: 1}
			cats[sg.cat] = a
		}
		a.miss *= 1 - w
		if w > a.bw {
			a.best, a.bw = sg, w
		}
	}
	strong := 0
	for _, a := range cats {
		if 1-a.miss >= 0.3 {
			strong++
		}
	}
	var out []detect.Finding
	for cat, a := range cats {
		score := 1 - a.miss
		if strong >= 2 {
			score = 1 - (1-score)*0.75 // несколько категорий сразу
		}
		score = min(score, 0.99)
		if score < 0.2 {
			continue
		}
		threat := threats[cat]
		if st.indirect {
			threat = "DM-07"
		}
		out = append(out, detect.Finding{Detector: ID, Version: Version, Category: cat, Threat: threat, Score: score, Start: a.best.s, End: a.best.e, Rule: a.best.rule})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Start < out[j].Start || out[i].Start == out[j].Start && out[i].Category < out[j].Category
	})
	return out
}

// --- Помощники ---

// fold — нижний регистр латиницы и кириллицы без изменения байтовых
// позиций; «ё» — как «е» («всё» и «все» совпадают).
func fold(text string) string {
	b := []byte(text)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b[i] = c + 32
		case c == 0xD0 && i+1 < len(b):
			switch n := b[i+1]; {
			case n >= 0x90 && n <= 0x9F:
				b[i+1] = n + 0x20
			case n >= 0xA0 && n <= 0xAF:
				b[i], b[i+1] = 0xD1, n-0x20
			case n == 0x81: // Ё → е
				b[i+1] = 0xB5
			}
			i++
		case c == 0xD1 && i+1 < len(b):
			if b[i+1] == 0x91 { // ё → е
				b[i], b[i+1] = 0xD0, 0xB5
			}
			i++
		}
	}
	return string(b)
}

func sepToSpace(r rune) rune {
	if strings.ContainsRune(",;:.!?-–—\"«»'()", r) {
		return ' '
	}
	return r
}

// hasPrefix — какое-либо слово начинается с элемента set (слова — из
// закрытого списка выражения, поэтому начало слова однозначно).
func hasPrefix(words, set []string) bool {
	for _, w := range words {
		for _, s := range set {
			if strings.HasPrefix(w, s) {
				return true
			}
		}
	}
	return false
}

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// negated — перед позицией i отрицание (в 16 байтах).
func negated(s string, i int) bool {
	_, ok := lastWord(s, max(0, i-16), i, negations)
	return ok
}

// imperativeEN — английский глагол в позиции i — обращение к модели: перед
// ним начало текста или строки, знак препинания или слово из
// imperativeLead.
func imperativeEN(s string, i int) bool {
	k := i
	for k > 0 && (s[k-1] == ' ' || s[k-1] == '\t') {
		k--
	}
	if k == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:k])
	if !isLetterOrDigit(r) {
		return true
	}
	// Предыдущее слово целиком.
	b := k
	for b > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:b])
		if !isLetterOrDigit(r) {
			break
		}
		b -= size
	}
	prev := s[b:k]
	for _, w := range imperativeLead {
		if prev == w {
			return true
		}
	}
	return false
}

// prevWords — начало n-го слова перед позицией i (не дальше 64 байт).
func prevWords(s string, i, n int) int {
	from := max(0, i-64)
	k := i
	for ; n > 0 && k > from; n-- {
		for k > from {
			r, size := utf8.DecodeLastRuneInString(s[:k])
			if isLetterOrDigit(r) {
				break
			}
			k -= size
		}
		for k > from {
			r, size := utf8.DecodeLastRuneInString(s[:k])
			if !isLetterOrDigit(r) {
				break
			}
			k -= size
		}
	}
	return k
}

// qualified — после объекта (позиция j) уточнение предлогом. Окно — 32
// байта: предлоги короткие.
func qualified(s string, j int) bool {
	s = s[:min(j+32, len(s))]
	k := j
	for k < len(s) && s[k] == ' ' {
		k++
	}
	e := k
	for e < len(s) {
		r, size := utf8.DecodeRuneInString(s[e:])
		if !isLetterOrDigit(r) {
			break
		}
		e += size
	}
	next := s[k:e]
	for _, p := range prepositions {
		if next == p {
			return true
		}
	}
	return false
}

// isLetterOrDigit — буква или цифра; ASCII и основная кириллица — без
// таблиц Unicode (самый частый случай).
func isLetterOrDigit(r rune) bool {
	switch {
	case r < 0x80:
		return 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9'
	case r >= 0x410 && r <= 0x44F || r == 0x401 || r == 0x451:
		return true
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// wordStart — позиция i — начало слова (перед ней не буква и не цифра).
func wordStart(s string, i int) bool {
	if i == 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:i])
	return !isLetterOrDigit(r)
}

// wordEnd — позиция j — конец слова.
func wordEnd(s string, j int) bool {
	if j >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[j:])
	return !isLetterOrDigit(r)
}

// indexAll вызывает f для каждого вхождения sub; ctx — каждые 256 вхождений.
func indexAll(ctx context.Context, s, sub string, f func(i int)) error {
	for pos, n := 0, 0; ; n++ {
		if n%256 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		i := strings.Index(s[pos:], sub)
		if i < 0 {
			return nil
		}
		f(pos + i)
		pos += i + len(sub)
	}
}

// indexWord — вхождения sub с начала слова (для опорных слов на букву).
func indexWord(ctx context.Context, s, sub string, f func(i int)) error {
	letter := isLetterOrDigit([]rune(sub)[0])
	return indexAll(ctx, s, sub, func(i int) {
		if !letter || wordStart(s, i) {
			f(i)
		}
	})
}

// lastWord — последнее слово из words целиком в s[from:to].
func lastWord(s string, from, to int, words []string) (int, bool) {
	best := -1
	for _, w := range words {
		for k := from; k < to; {
			i := strings.Index(s[k:to], w)
			if i < 0 {
				break
			}
			i += k
			if wordStart(s, i) && wordEnd(s, i+len(w)) && i > best {
				best = i
			}
			k = i + 1
		}
	}
	return best, best >= 0
}

func containsWord(s string, words []string) bool {
	_, ok := lastWord(s, 0, len(s), words)
	return ok
}

// quoted — фрагмент [i, j) в кавычках: перед ним (через пробелы, до 16)
// открывающая кавычка, после — закрывающая в пределах 200 байт.
func quoted(s string, i, j int) bool {
	k := i
	for k > 0 && i-k < 16 && s[k-1] == ' ' {
		k--
	}
	if k == 0 {
		return false
	}
	r, _ := utf8.DecodeLastRuneInString(s[:k])
	if !strings.ContainsRune("\"'«“„`", r) {
		return false
	}
	return strings.ContainsAny(s[j:min(j+200, len(s))], "\"'»”`")
}
