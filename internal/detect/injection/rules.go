package injection

// Шаблоны: опорное слово ищется в тексте (strings.Index), выражение с «^»
// применяется к окну от него. Текст на входе — после unihidden.Clean и
// приведения к нижнему регистру (fold), «ё» — как «е».

import "regexp"

// sep — разделитель слов: пробелы и знаки препинания.
const sep = `[\s,;:.!?\-–—"«»'()]+`

// rx компилирует выражение, привязанное к началу окна.
func rx(expr string) *regexp.Regexp { return regexp.MustCompile("^(?:" + expr + ")") }

// --- Отмена инструкций (injection.override, DM-01) ---

// Отмена инструкций: глагол, слова из закрытого списка, объект — на
// английском, русском и вперемешку («Ignore все previous инструкции» —
// смешение языков, DM-04). Русские глаголы — повелительные формы и
// «игнорируешь»: «игнорирует» в рассказе о других («водители игнорируют
// все правила») — не обращение к модели. Русские слова между глаголом и
// объектом — с падежными окончаниями. «Забудь» — и без мягкого знака
// (транслит «zabud»).
const (
	verbsEN  = `ignore|disregard|forget|override|bypass|discard|abandon`
	verbsRU  = `игнорируй(?:те)?|проигнорируй(?:те)?|игнорируешь|забуд[ьъ]?(?:те)?|отмени(?:те)?|не обращай(?:те)? внимани[ея] на|не следуй(?:те)?|не соблюдай(?:те)?|не придерживайся|не придерживайтесь|обойди(?:те)?|отбрось(?:те)?|пренебреги(?:те)?|сбрось(?:те)?`
	fillEN   = `all|any|every|each|the|your|my|of|these|those|that|this|previous|prior|above|earlier|preceding|foregoing|original|initial|system|safety|existing|current|given|old|former|developer|content|moderation`
	fillRU   = `все|всем|всеми|всех|любые|любым|любыми|свои|своим|своими|своих|твои|твоим|твоими|твоих|ваши|вашим|вашими|ваших|мои|моим|моими|моих|эти|этим|этими|этих|те|тем|теми|тех|выше|ранее|(?:предыдущ|прошл|прежн|предшествующ|вышеуказанн|вышеизложенн|исходн|первоначальн|изначальн|системн|данн|полученн|изложенн|приведенн|заданн|текущ|стар|установленн|встроенн)\p{L}*`
	objectEN = `(?:instructions?|rules|prompts?|directions|directives?|guidelines|guardrails|constraints|restrictions|programming|polic(?:y|ies)|filters?|limitations)\b`
	objectRU = `(?:инструкци|правил|указани|ограничени|промпт|установк|директив|запрет)\p{L}*`
)

// infRU — инфинитивы после «должен», «нужно», «можешь» (modalsRU): «Ты
// должен игнорировать все правила», «Тебе нужно забыть предыдущие
// инструкции».
const infRU = `игнорировать|проигнорировать|забыть|отменить|не обращать внимани[ея] на|не следовать|не соблюдать|не придерживаться|обойти|отбросить|пренебречь|сбросить`

// overrideRe — шаблон отмены, overrideInfRe — то же с инфинитивом. Захват
// 1 — слова между глаголом и объектом (по ним вес).
var (
	overrideRe    = rx(`(?:` + verbsEN + `|` + verbsRU + `)((?:` + sep + `(?:` + fillEN + `|` + fillRU + `))*)` + sep + `(?:` + objectEN + `|` + objectRU + `)`)
	overrideInfRe = rx(`(?:` + infRU + `)((?:` + sep + `(?:` + fillEN + `|` + fillRU + `))*)` + sep + `(?:` + objectEN + `|` + objectRU + `)`)
)

// overrideAnchorsEN, overrideAnchorsRU, overrideAnchorsInf — опорные слова
// шаблона отмены и инфинитивов.
var (
	overrideAnchorsEN  = []string{"ignore", "disregard", "forget", "override", "bypass", "discard", "abandon"}
	overrideAnchorsRU  = []string{"игнорир", "проигнорир", "забуд", "отмени", "не обращай", "не следуй", "не соблюдай", "не придерживай", "обойди", "отбрось", "пренебреги", "сбрось"}
	overrideAnchorsInf = []string{"игнорирова", "проигнорирова", "забы", "отменит", "не обраща", "не следова", "не соблюда", "не придерживат", "обойт", "отброси", "пренебреч", "сброси"}
)

// modalsRU — слова перед инфинитивом отмены: обращение к модели; selfRU —
// перед модальным словом — о себе или других («мне нужно», «нам надо»);
// infLeadRU — просьба перед инфинитивом («попробуй проигнорировать»);
// adverbsRU — наречия между модальным словом и инфинитивом.
var (
	modalsRU  = []string{"должен", "должна", "должно", "должны", "обязан", "обязана", "обязаны", "нужно", "надо", "следует", "необходимо", "можешь", "можете", "стоит"}
	selfRU    = []string{"я", "мне", "мы", "нам", "он", "она", "они", "ему", "ей", "им", "него", "нее", "них"}
	infLeadRU = []string{"попробуй", "попробуйте", "постарайся", "постарайтесь", "попытайся", "попытайтесь", "забудь", "забудьте", "прошу"}
	adverbsRU = []string{"теперь", "сейчас", "просто", "срочно", "сразу", "немедленно", "полностью", "тогда"}
)

// Слова между глаголом и объектом (сравниваются по началу: падежи).
// modelWords указывают на инструкции самой модели («твои», «системные») —
// атака и с уточнением предлогом. strongWords — ещё «все», «любые»,
// «предыдущие»: с уточнением («предыдущие инструкции по оформлению»)
// пользователь правит свою же задачу. myWords — «мои прошлые инструкции».
var (
	modelWords = []string{"your", "original", "initial", "system", "safety", "developer", "content", "moderation",
		"тво", "сво", "ваш", "исходн", "первоначальн", "изначальн", "системн", "установленн", "встроенн"}
	strongWords = append([]string{"all", "any", "every", "previous", "prior", "above", "earlier", "preceding", "foregoing",
		"вс", "любы", "предыдущ", "прошл", "прежн", "предшествующ", "выше", "ранее"}, modelWords...)
	myWords = []string{"my", "мо"}
)

// negations — отрицание вплотную перед глаголом: «не игнорируйте правила
// техники безопасности», «do not disregard safety instructions».
var negations = []string{"not", "never", "don't", "dont", "doesn't", "mustn't", "shouldn't", "won't", "can't", "cannot",
	"не", "нельзя", "никогда", "запрещено"}

// narrativeLead — подлежащие и наречия рассказа перед английским глаголом:
// «they ignore all rules», «users often ignore all instructions»;
// negAdverbs — наречие между отрицанием и глаголом («do not ever ignore»).
var (
	narrativeLead = []string{"i", "we", "they", "he", "she", "it", "who", "that", "which", "people",
		"users", "attackers", "hackers", "models", "employees", "students", "drivers", "developers", "customers", "clients", "bots", "kids", "children",
		"often", "usually", "sometimes", "generally", "typically", "rarely", "commonly", "frequently", "regularly"}
	negAdverbs = []string{"ever", "really", "just", "even"}
)

// imperativeLead — слова, после которых английский глагол — обращение к
// модели («please ignore», «I want you to ignore»), а не рассказ («users
// ignore all rules»). Начало текста, строки и знак препинания — тоже.
var imperativeLead = []string{"please", "now", "just", "and", "so", "then", "also", "simply", "kindly", "immediately", "first", "always",
	"you", "to", "must", "should", "will", "can", "could", "may", "shall", "would", "pls", "plz", "hey", "ok", "okay", "let", "us", "let's"}

// prepositions — объект с уточнением («все фильтры в таблице», «rules of
// grammar»): речь о чём-то конкретном, а не об инструкциях модели.
var prepositions = []string{"of", "in", "for", "on", "about", "from", "inside", "within", "regarding", "at",
	"в", "во", "из", "для", "по", "о", "об", "про", "к", "на", "при", "у"}

// phraseRules — прочие сигналы отмены: опорная фраза и вес.
type phrase struct {
	anchor string
	re     *regexp.Regexp // nil — достаточно самой фразы
	rule   string
	weight float64
}

var overridePhrases = []phrase{
	{"forget everything", rx(`forget everything(?:` + sep + `(?:you|that|above|before|previously|earlier|i))`), "forget_all", 0.7},
	{"забудь все", rx(`забудь(?:те)? все,?` + sep + `(?:что|чему|ранее|выше|до этого)`), "forget_all", 0.7},
	{"new instructions", rx(`new instructions\s*:`), "new_instructions", 0.5},
	{"your new task", nil, "new_instructions", 0.45},
	{"your real task", nil, "new_instructions", 0.5},
	{"your actual task", nil, "new_instructions", 0.5},
	{"новые инструкции", rx(`новые инструкции\s*:`), "new_instructions", 0.5},
	{"твоя новая задача", nil, "new_instructions", 0.45},
	{"твоя настоящая задача", nil, "new_instructions", 0.5},
	{"from now on", rx(`from now on,?\s+(?:you|your|act|respond|answer|ignore|always|never)`), "from_now_on", 0.35},
	{"с этого момента", rx(`с этого момента,?\s+(?:ты|вы|отвечай|отвечайте|игнорируй|всегда|никогда)`), "from_now_on", 0.35},
	{"отныне", rx(`отныне,?\s+(?:ты|вы|отвечай|отвечайте|игнорируй|всегда|никогда)`), "from_now_on", 0.35},
	{"no longer", rx(`no longer\s+(?:bound|restricted|limited|have to follow|need to follow|required to follow|subject to)`), "unbound", 0.6},
	{"not bound by", nil, "unbound", 0.6},
	{"больше не", rx(`больше не\s+(?:обязан|ограничен|связан|должен соблюдать|должен следовать|подчиняешься)`), "unbound", 0.6},
	{"do anything now", nil, "dan", 0.8},
	{"dan mode", nil, "dan", 0.8},
	{"stay in character", nil, "dan", 0.35},
	{"оставайся в образе", nil, "dan", 0.35},
	{"developer mode", rx(`developer mode\s*(?:enabled|on|activated|output|\()`), "dev_mode", 0.6},
	{"режим разработчика", rx(`режим разработчика\s*(?:включен|активирован|\()`), "dev_mode", 0.6},
	{"jailbroken", nil, "jailbreak", 0.6},
	{"jailbreak", nil, "jailbreak", 0.3},
	{"джейлбрейк", nil, "jailbreak", 0.3},
}

// addressAI — обращения к модели внутри документа или ответа инструмента
// (только для источников rag и tool: в запросе пользователя это обычная
// речь).
var addressAI = []phrase{
	{"note to ai", nil, "address_ai", 0.6},
	{"note to the ai", nil, "address_ai", 0.6},
	{"note to assistant", nil, "address_ai", 0.6},
	{"note to the assistant", nil, "address_ai", 0.6},
	{"if you are an ai", nil, "address_ai", 0.5},
	{"if you are a language model", nil, "address_ai", 0.5},
	{"if you are an llm", nil, "address_ai", 0.5},
	{"to the ai reading this", nil, "address_ai", 0.6},
	{"ai assistant:", nil, "address_ai", 0.5},
	{"инструкция для ии", nil, "address_ai", 0.6},
	{"примечание для ии", nil, "address_ai", 0.6},
	{"если ты ии", nil, "address_ai", 0.5},
	{"если ты языковая модель", nil, "address_ai", 0.5},
	{"для ассистента:", nil, "address_ai", 0.5},
}

// --- Смена роли и снятие ограничений (injection.role, DM-01) ---

// personaPhrases — смена роли; сама по себе безобидна («act as a
// translator»), вес растёт вместе со снятием ограничений.
var personaPhrases = []phrase{
	{"you are now", nil, "persona", 0.15},
	{"you're now", nil, "persona", 0.15},
	{"act as", nil, "persona", 0.15},
	{"pretend", rx(`pretend(?:` + sep + `(?:to be|you are|that you are|you're))`), "persona", 0.2},
	{"roleplay as", nil, "persona", 0.15},
	{"role-play as", nil, "persona", 0.15},
	{"imagine you are", nil, "persona", 0.15},
	{"behave like", nil, "persona", 0.15},
	{"ты тепер", nil, "persona", 0.15}, // и транслит без мягкого знака («ty teper»)
	{"тепер", rx(`теперь?\s+(?:ты|вы)`), "persona", 0.15},
	{"представь", rx(`представь(?:те)?,?\s+что\s+(?:ты|вы)`), "persona", 0.15},
	{"притворись", nil, "persona", 0.2},
	{"веди себя как", nil, "persona", 0.15},
	{"играй роль", nil, "persona", 0.15},
	{"сыграй роль", nil, "persona", 0.15},
	{"выступи в роли", nil, "persona", 0.15},
	{"действуй как", nil, "persona", 0.15},
}

// removalPhrases — снятие ограничений. Вне разговора с моделью («тариф без
// ограничений») — обычная речь: сам по себе сигнал слабый.
var removalPhrases = []phrase{
	{"without", rx(`without\s+(?:any\s+|all\s+|your\s+)?(?:restrictions|limits|limitations|filters|filtering|rules|censorship|guidelines|guardrails|ethics|morals|safety)`), "removal", 0.3},
	{"no restrictions", nil, "removal", 0.3},
	{"no rules", nil, "removal", 0.3},
	{"no guidelines", nil, "removal", 0.3},
	{"no boundaries", nil, "removal", 0.3},
	{"no limits", nil, "removal", 0.3},
	{"no filters", nil, "removal", 0.3},
	{"no censorship", nil, "removal", 0.3},
	{"no ethical", nil, "removal", 0.3},
	{"no moral", nil, "removal", 0.3},
	{"unrestricted", nil, "removal", 0.3},
	{"uncensored", nil, "removal", 0.3},
	{"unfiltered", nil, "removal", 0.3},
	{"без ", rx(`без\s+(?:каких-?либо\s+|всяких\s+|любых\s+|никаких\s+)?(?:ограничени|цензур|фильтр|правил|запрет|морал|этик|рамок)\p{L}*`), "removal", 0.3},
	{"нет ", rx(`нет\s+(?:каких-?либо\s+|никаких\s+)?(?:ограничени|цензур|фильтр|правил|запрет|морал|этик|рамок)\p{L}*`), "removal", 0.3},
}

// imperativeWords — просьба отвечать: «отвечай без цензуры» — снятие
// ограничений в разговоре с моделью (не дальше 4 слов перед снятием:
// «write a story about an AI without restrictions» — не просьба).
var imperativeWords = []string{"answer", "respond", "reply", "talk", "speak", "write", "act", "behave",
	"отвечай", "ответь", "отвечать", "говори", "пиши", "действуй", "работай", "веди себя", "общайся"}

// --- Извлечение системного промпта (injection.prompt_leak, DM-08) ---

// leakObjects — что извлекают; possessive — объект уже указывает на
// инструкции модели («your instructions»).
var leakObjects = []struct {
	anchor     string
	re         *regexp.Regexp
	possessive bool
	above      bool // «текст выше» — слабее, чем «системный промпт»
}{
	{"system prompt", nil, false, false},
	{"system message", nil, false, false},
	{"system instructions", nil, false, false},
	{"initial prompt", nil, false, false},
	{"initial instructions", nil, false, false},
	{"original prompt", nil, false, false},
	{"original instructions", nil, false, false},
	{"hidden prompt", nil, false, false},
	{"hidden instructions", nil, false, false},
	{"developer message", nil, false, false},
	{"pre-prompt", nil, false, false},
	{"your instructions", nil, true, false},
	{"instructions you", rx(`instructions you(?:'ve| have| were| had)? (?:been given|were given|got|received)`), true, false},
	{"your prompt", nil, true, false},
	{"your rules", nil, true, false},
	{"your guidelines", nil, true, false},
	{"text above", nil, false, true},
	{"words above", nil, false, true},
	{"everything above", nil, false, true},
	{"системн", rx(`системн\p{L}*\s+(?:промпт|инструкци|сообщени|подсказк|настройк)\p{L}*`), false, false},
	{"исходн", rx(`исходн\p{L}*\s+(?:промпт|инструкци)\p{L}*`), false, false},
	{"первоначальн", rx(`первоначальн\p{L}*\s+(?:промпт|инструкци)\p{L}*`), false, false},
	{"скрыт", rx(`скрыт\p{L}*\s+(?:промпт|инструкци)\p{L}*`), false, false},
	{"твои инструкции", nil, true, false},
	{"инструкции тебе", nil, true, false},
	{"инструкции, которые тебе", nil, true, false},
	{"свои инструкции", nil, true, false},
	{"ваши инструкции", nil, true, false},
	{"твой промпт", nil, true, false},
	{"свой промпт", nil, true, false},
	{"твои правила", nil, true, false},
	{"текст выше", nil, false, true},
	{"все, что выше", nil, false, true},
	{"все что выше", nil, false, true},
}

// leakStrong — глаголы извлечения: «покажи», «выведи», «reveal»;
// leakWeak — вопросы и просьбы («какие», «what is», «include»): атака,
// только если речь о промпте самой модели («твои», «your»).
var (
	leakStrong = []string{"show", "reveal", "print", "output", "display", "dump", "leak", "expose", "repeat", "recite", "echo", "copy", "paste", "translate", "spell out",
		"покажи", "выведи", "раскрой", "повтори", "процитируй", "скопируй", "распечатай", "напечатай", "переведи", "вставь", "выдай"}
	leakWeak = []string{"tell", "what", "give", "list", "share", "describe", "summarize", "which", "include", "send", "email", "attach",
		"какой", "какие", "каков", "скажи", "расскажи", "дай", "перечисли", "опиши", "назови", "что"}
	possessives = []string{"your", "you were", "you've been", "тебе", "тебя", "вам",
		"твой", "твои", "твоя", "твое", "твоем", "твоего", "твоему", "твоих", "твоей", "твоим",
		"свой", "свои", "своя", "свое", "своем", "своего", "своему", "своих", "своей", "своим",
		"ваш", "ваши", "ваша", "ваше", "вашем", "вашего", "вашему", "ваших", "вашей", "вашим"}
	// verbatim — «дословно», «целиком» после объекта: «текст выше»
	// извлекают, а не цитируют в обычной работе с текстом.
	verbatim = []string{"verbatim", "word for word", "exactly", "in full", "in its entirety", "дословно", "целиком", "полностью", "слово в слово", "без изменений"}
	// devLead — вопрос разработчика о своём промпте («how do I print the
	// system prompt», «как вывести системный промпт в лог»): глагол
	// извлечения — не атака, если нет «твой», «your».
	// Вплотную перед глаголом.
	devLead = []string{"how to", "how do i", "how can i", "how should i", "function to", "code to", "script to", "как", "каким образом"}
	// leakBreak — между глаголом и объектом глагол создания: «покажи
	// пример, как написать системный промпт» — глагол не управляет объектом.
	leakBreak = []string{"напиши", "написать", "создай", "создать", "составь", "составить", "сделай", "сделать", "придумай", "придумать",
		"write", "create", "make", "generate", "draft", "design"}
)

// --- Подделка структуры диалога (injection.structure, DM-02) ---

// serviceTokens — служебные токены шаблонов чата: в тексте пользователя не
// встречаются, кроме обсуждения форматов.
var serviceTokens = []string{
	"<|im_start|>", "<|im_end|>", "<|im_sep|>", "<|system|>", "<|user|>", "<|assistant|>", "<|end|>",
	"<|endoftext|>", "<|begin_of_text|>", "<|start_header_id|>", "<|end_header_id|>", "<|eot_id|>",
	"[inst]", "[/inst]", "<<sys>>", "<</sys>>", "<start_of_turn>", "<end_of_turn>",
}

// fakeSystemStrong — начало строки, выдающее себя за системное сообщение;
// fakeSystemWeak — метка, которая бывает и в обычных логах («System: Ubuntu»).
var (
	fakeSystemStrong = []string{"system message", "system note", "system override", "system update", "system instruction", "system prompt:",
		"[system]", "(system:", "(system message", "(system note", "<system>", "admin message", "message from admin", "developer message",
		"системное сообщение", "системная инструкция", "системное уведомление", "[система]",
		"сообщение от администратора", "сообщение администратора", "сообщение разработчика"}
	fakeSystemWeak = []string{"system:", "система:", "admin:", "администратор:", "developer:", "разработчик:"}
)

// turnLabels — метки реплик для подсчёта many-shot: user — реплика
// пользователя, иначе — ассистента.
var turnLabels = []struct {
	label string
	user  bool
}{
	{"user:", true}, {"human:", true}, {"пользователь:", true}, {"юзер:", true}, {"человек:", true},
	{"### instruction", true}, {"### input", true}, {"### user", true}, {"### human", true},
	{"assistant:", false}, {"ai:", false}, {"bot:", false}, {"model:", false},
	{"ассистент:", false}, {"бот:", false}, {"модель:", false}, {"ии:", false},
	{"### response", false}, {"### assistant", false},
}

// jsonRole — роль system или developer в JSON; разработчики вставляют такие
// запросы к API в вопросы, поэтому сам по себе сигнал слабый.
var jsonRole = rx(`"role"\s*:\s*"(?:system|developer)"`)

// fmtWords — текст обсуждает форматы чата (вопрос разработчика о шаблоне):
// вес служебных токенов снижается.
var fmtWords = []string{"chatml", "chat template", "chat_template", "special token", "tokenizer", "шаблон чата", "шаблона чата",
	"служебные токен", "служебный токен", "служебных токен", "служебным токен", "служебными токен", "токенизатор", "спецтокен"}

// metaWords — рядом с сигналом разговор об атаках (вопрос специалиста по
// безопасности, статья): веса шаблонов отмены, роли и извлечения снижаются.
// Только слова об атаках на модель: «инъекция» бывает и SQL, «example of» —
// где угодно.
var metaWords = []string{"prompt injection", "промпт-инъекц", "инъекция промпт", "инъекции промпт", "injection attack", "пример атаки",
	"how to protect", "how to prevent", "how to detect", "как защит", "защититься", "обнаружить атак", "jailbreak attempt"}

// --- Обфускация (injection.obfuscation, DM-04) ---

// leetLat, leetCyr — цифры и знаки вместо букв в слове латиницей и
// кириллицей.
var (
	leetLat = map[rune]string{'0': "o", '1': "i", '3': "e", '4': "a", '5': "s", '7': "t", '8': "b", '@': "a", '$': "s"}
	leetCyr = map[rune]string{'0': "о", '3': "з", '4': "ч", '6': "б", '@': "а"}
)

// Кавычки по обе стороны стыка при склейке строк.
const (
	closeQuotes = `"'»”` + "`"
	openQuotes  = `"'«“` + "`"
)

// translitStems — основы шаблонов в транслите: без них транслит не
// строится. Только русские основы: «prompt» есть и в английском тексте.
var translitStems = []string{"ignorir", "zabud", "otmeni", "obrashch", "ne sled", "ne sobl", "pokazh", "vyvedi", "povtori", "sistemn",
	"instrukc", "instrukts", "ogranichen", "cenzur", "tsenzur", "predstav", "pritvoris", "teper", "pravil", "ukazani", "zapret"}

// translitPairs — сочетания латиницы (сначала длинные), translitOne —
// одиночные буквы. «y» — отдельно: «й» после гласной, иначе «ы».
var (
	translitPairs = [][2]string{{"shch", "щ"}, {"sch", "щ"}, {"zh", "ж"}, {"kh", "х"}, {"ch", "ч"}, {"sh", "ш"}, {"ts", "ц"},
		{"yu", "ю"}, {"ya", "я"}, {"yo", "е"}, {"ye", "е"}, {"ju", "ю"}, {"ja", "я"}, {"jo", "е"}}
	translitOne = map[byte]string{'a': "а", 'b': "б", 'v': "в", 'g': "г", 'd': "д", 'e': "е", 'z': "з", 'i': "и", 'j': "й", 'k': "к",
		'l': "л", 'm': "м", 'n': "н", 'o': "о", 'p': "п", 'r': "р", 's': "с", 't': "т", 'u': "у", 'f': "ф", 'h': "х", 'c': "ц",
		'w': "в", 'x': "кс", 'q': "к", '\'': "ь"}
)

// rot13Hints — текст просит расшифровать ROT13.
var rot13Hints = []string{"rot13", "rot-13", "rot 13", "rot_13", "caesar", "цезар"}
