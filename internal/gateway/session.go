package gateway

import (
	"container/list"
	"encoding/hex"
	"errors"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/chat"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/lists"
	"github.com/azuresong-afk/ai_railway/internal/detect/session"
	"github.com/azuresong-afk/ai_railway/internal/detect/unihidden"
	"github.com/azuresong-afk/ai_railway/internal/events"
)

// Сессии чата (ТЗ 5.1, 5.2; решение Р7 этапа 4, задачи 4.13 и 4.14).
//
// Идентификатор сессии приложение передаёт заголовком X-AISec-Session; без
// него шлюз вычисляет отпечаток начала диалога: сообщения до первой реплики
// пользователя включительно и псевдоним пользователя. Оба значения в
// события не попадают: в событии — псевдоним сессии, HMAC на ключе сессий с
// разделителем назначения и ID приложения (у одного идентификатора в
// разных приложениях — разные сессии).
//
// Ключ сессий — ключ псевдонимов пользователей шлюза (-user-hmac-key) с
// отдельным разделителем назначения; без него — случайный ключ процесса:
// после перезапуска шлюза сессии начинаются заново, а сервер принимает
// историю впервые увиденной сессии как известную (history.integrity не
// даёт ложных находок).
//
// session.risk (DM-06) — состояние в памяти шлюза: накопленная оценка
// находок сессии с затуханием. Вклад хода — наибольшая оценка находок
// детекторов атак (injection.*, unicode.hidden, lists) в новых сообщениях
// запроса — после последнего ответа модели: история повторяет прошлые ходы,
// и без этого каждая прошлая находка считалась бы заново. Содержимое
// сообщений в состоянии не хранится: только ключ (псевдоним) и числа.
// Число сессий ограничено: при переполнении вытесняется сессия, которая
// дольше всех не обновлялась, поэтому память не растёт под нагрузкой. У
// приложения — не больше доли общего предела (по умолчанию четверть,
// 4Н13 ревью 4.r2): новая сессия приложения, исчерпавшего долю, вытесняет
// его же самую давнюю, и поток новых ID одного приложения не сбрасывает
// накопленные оценки других. Вытеснения считаются и уходят в heartbeat
// («Состояние системы», задача 5.9).

// HeaderSession — идентификатор сессии от приложения.
const HeaderSession = "X-AISec-Session"

// Параметры сессий.
const (
	// MaxSessionIDLength — предел X-AISec-Session, байт.
	MaxSessionIDLength = 128
	// DefaultMaxSessions — сессий session.risk в памяти шлюза.
	DefaultMaxSessions = 100_000
	// DefaultAppShareDivisor — доля приложения по умолчанию: предел,
	// делённый на это число.
	DefaultAppShareDivisor = 4
	// DefaultSessionTTL — сессия без ходов дольше этого забывается.
	DefaultSessionTTL = 24 * time.Hour
	// DefaultRiskHalfLife — за это время накопленная оценка убывает вдвое.
	DefaultRiskHalfLife = 15 * time.Minute
	// riskSaturation — накопленная оценка, при которой session.risk = 1:
	// три сильные находки (около 1) за время меньше полураспада. Одна
	// находка даёт не больше 1/3: её решает правило самого детектора, а
	// session.risk — о серии.
	riskSaturation = 3.0
	// minRiskFinding — с какой оценки session.risk попадает в находки:
	// порог правила может быть ниже порога по умолчанию (0,5).
	minRiskFinding = 0.1
	// riskEpsilon — меньшая накопленная оценка считается нулём (затухание
	// до нуля).
	riskEpsilon = 1e-6
	// fingerprintMessages — сообщений начала диалога в отпечатке не больше.
	fingerprintMessages = 8
)

// Разделители назначения имитовставки на ключе сессий. Псевдоним
// пользователя — HMAC идентификатора без управляющих символов, поэтому
// значения с префиксом из U+0000 с ним не совпадают.
const (
	sessionDomain = "\x00aisec-session/1\x00"
	replyDomain   = "\x00aisec-reply/1\x00"
)

// riskLocation — место находки session.risk в событии: она о сессии, а не
// о фрагменте запроса.
const riskLocation = "session"

// errSessionHeader — неверный X-AISec-Session (ответ 400 без эха значения).
var errSessionHeader = errors.New("X-AISec-Session — один заголовок до 128 байт из латинских букв, цифр и символов . _ : -")

// SessionConfig — параметры сессий шлюза.
type SessionConfig struct {
	// Provider — криптопрофиль: хеш реплик, случайный ключ без MAC.
	Provider aisecCrypto.Provider
	// MAC — ключ псевдонимов пользователей шлюза; nil — случайный ключ
	// процесса.
	MAC aisecCrypto.MAC
	// MaxSessions, TTL, HalfLife — 0 — значения по умолчанию.
	MaxSessions int
	// MaxAppSessions — доля одного приложения; 0 — MaxSessions /
	// DefaultAppShareDivisor (не меньше 1), больше MaxSessions — MaxSessions.
	MaxAppSessions int
	TTL            time.Duration
	HalfLife       time.Duration
	// Now — часы; по умолчанию time.Now.
	Now func() time.Time
}

// Sessions — сессии шлюза: псевдонимы, хеши реплик и состояние
// session.risk. Общие для всех приложений и переживают смену пакета
// конфигурации; безопасны для одновременного использования.
type Sessions struct {
	mac      aisecCrypto.MAC
	hasher   aisecCrypto.Hasher
	max      int
	ttl      time.Duration
	halfLife time.Duration
	now      func() time.Time

	appMax int

	mu    sync.Mutex
	byKey map[string]*list.Element
	// lru — состояния, свежие спереди; вытесняется последнее.
	lru *list.List
	// apps — состояния каждого приложения в том же порядке (элементы —
	// *sessionState): по нему вытесняется давняя сессия своего приложения.
	apps map[string]*list.List
	// evictions — вытеснено сессий из-за общего предела (чужих приложений
	// в том числе), appEvictions — из-за доли своего приложения.
	evictions, appEvictions uint64
}

// sessionState — состояние session.risk одной сессии: только числа.
type sessionState struct {
	key   string
	app   string
	acc   float64
	at    time.Time
	turns int
	// appEl — элемент в списке приложения.
	appEl *list.Element
}

// SessionStats — заполнение и вытеснения сессий session.risk с запуска
// шлюза (heartbeat, «Состояние системы»).
type SessionStats struct {
	Sessions       int
	MaxSessions    int
	MaxAppSessions int
	// Evictions — вытеснено из-за общего предела; AppEvictions — из-за доли
	// приложения (вытесняется сессия того же приложения).
	Evictions    uint64
	AppEvictions uint64
}

// NewSessions создаёт сессии шлюза.
func NewSessions(cfg SessionConfig) (*Sessions, error) {
	if cfg.Provider == nil {
		return nil, errors.New("сессии: нет криптопрофиля")
	}
	h, err := cfg.Provider.Hasher()
	if err != nil {
		return nil, err
	}
	mac := cfg.MAC
	if mac == nil {
		rnd, err := cfg.Provider.Random()
		if err != nil {
			return nil, err
		}
		key, err := aisecCrypto.RandomBytes(rnd, aisecCrypto.MinMACKeySize)
		if err != nil {
			return nil, err
		}
		mac, err = cfg.Provider.NewMAC(key)
		clear(key)
		if err != nil {
			return nil, err
		}
	}
	s := &Sessions{mac: mac, hasher: h, max: cfg.MaxSessions, ttl: cfg.TTL, halfLife: cfg.HalfLife, now: cfg.Now,
		byKey: map[string]*list.Element{}, lru: list.New(), apps: map[string]*list.List{}}
	if s.max <= 0 {
		s.max = DefaultMaxSessions
	}
	s.appMax = cfg.MaxAppSessions
	if s.appMax <= 0 {
		s.appMax = max(1, s.max/DefaultAppShareDivisor)
	}
	s.appMax = min(s.appMax, s.max)
	if s.ttl <= 0 {
		s.ttl = DefaultSessionTTL
	}
	if s.halfLife <= 0 {
		s.halfLife = DefaultRiskHalfLife
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// reqSession — сессия запроса чата.
type reqSession struct {
	ev *events.Session
	// key — ключ состояния session.risk: приложение и псевдоним.
	key string
	// newFrom — первое сообщение нового хода: после последнего ответа
	// модели в истории запроса.
	newFrom int
	tracker *Sessions
	// shared — отпечаток без псевдонима пользователя: одинаковое начало
	// диалога у разных пользователей даёт одну сессию, поэтому состояние
	// session.risk не заводится (чужие находки не блокировали бы
	// постороннего пользователя).
	shared bool
}

// replies — нужны хеши ответов: у сессии есть правило history.integrity.
func (rs *reqSession) replies() bool { return rs != nil && rs.ev.HistoryRule != "" }

// validSessionID — X-AISec-Session: 1–128 байт из [A-Za-z0-9._:-].
func validSessionID(s string) bool {
	if s == "" || len(s) > MaxSessionIDLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

// parseSessionHeader — значение X-AISec-Session; пусто — заголовка нет.
func parseSessionHeader(vals []string) (string, error) {
	switch {
	case len(vals) == 0:
		return "", nil
	case len(vals) > 1 || !validSessionID(vals[0]):
		return "", errSessionHeader
	}
	return vals[0], nil
}

// identify — сессия запроса: из заголовка (vals — его значения) или по
// отпечатку начала диалога. user — псевдоним пользователя запроса.
func (s *Sessions) identify(appID, user string, vals []string, req *chat.Request) (*reqSession, error) {
	id, err := parseSessionHeader(vals)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(sessionDomain)
	b.WriteString(appID)
	b.WriteByte(0)
	source := events.SessionHeader
	if id != "" {
		// Пользователь — в ключе (4Н12 ревью 4.r2): ID сессии приходит от
		// клиента, и пользователь A не поднимает риск чужой сессии B.
		b.WriteString("h\x00")
		b.WriteString(user)
		b.WriteByte(0)
		b.WriteString(id)
	} else {
		source = events.SessionFingerprint
		b.WriteString("f\x00")
		b.WriteString(user)
		b.WriteByte(0)
		writeFingerprint(&b, req)
	}
	alias := hex.EncodeToString(s.mac.Sum([]byte(b.String()))[:16])
	rs := &reqSession{ev: &events.Session{ID: alias, Source: source}, key: appID + "\x00" + alias, tracker: s,
		shared: id == "" && user == ""}
	rs.newFrom = newTurnFrom(req)
	return rs, nil
}

// newTurnFrom — первое сообщение нового хода: после последнего ответа
// модели, который стоит до последней реплики пользователя. Ответ модели в
// конце запроса (заготовка начала ответа, prefill) ход не обрывает: иначе
// одна дописанная реплика ассистента выводила бы новые сообщения
// пользователя из подсчёта session.risk.
func newTurnFrom(req *chat.Request) int {
	lastUser := -1
	for i, m := range req.Messages {
		if m.Role == "user" {
			lastUser = i
		}
	}
	from := 0
	for i := 0; i < lastUser; i++ {
		if req.Messages[i].Role == "assistant" {
			from = i + 1
		}
	}
	return from
}

// writeFingerprint дописывает начало диалога: сообщения до первой реплики
// пользователя включительно, не больше fingerprintMessages, с
// нормализованными пробелами. Роль и текст — с длинами: граница между
// полями однозначна.
func writeFingerprint(b *strings.Builder, req *chat.Request) {
	for i, m := range req.Messages {
		if i >= fingerprintMessages {
			break
		}
		// Пробелы нормализуются: лишний пробел в первой реплике не
		// начинает новую сессию.
		t := session.Normalize(messageText(&m, " "))
		b.WriteString(strconv.Itoa(len(m.Role)))
		b.WriteByte(':')
		b.WriteString(m.Role)
		b.WriteString(strconv.Itoa(len(t)))
		b.WriteByte(':')
		b.WriteString(t)
		if m.Role == "user" {
			break
		}
	}
}

// messageText — текст сообщения: строка content или текстовые части через
// sep (части refusal и файлы не входят).
func messageText(m *chat.Message, sep string) string {
	if m.Content.Text != nil {
		return *m.Content.Text
	}
	var parts []string
	for _, p := range m.Content.Parts {
		if p.Text != nil {
			parts = append(parts, *p.Text)
		}
	}
	return strings.Join(parts, sep)
}

// riskDetector — находки детектора дают вклад в session.risk: признаки
// атаки (инъекции, скрытые символы, словари заказчика), а не ПДн и секреты
// в обычном диалоге.
func riskDetector(id string) bool {
	return strings.HasPrefix(id, "injection.") || id == unihidden.ID || id == lists.ID
}

// observe добавляет вклад хода turn (0–1) в накопленную оценку сессии и
// возвращает session.risk (0–1) и число ходов с первой находки. Сессия без
// состояния и без вклада состояния не заводит: память — только под сессии
// с находками.
func (s *Sessions) observe(key string, turn float64) (float64, int) {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	el, ok := s.byKey[key]
	var st *sessionState
	if ok {
		st = el.Value.(*sessionState)
		if now.Sub(st.at) > s.ttl {
			st.acc, st.turns = 0, 0
		} else if dt := now.Sub(st.at); dt > 0 {
			st.acc *= math.Exp2(-float64(dt) / float64(s.halfLife))
		}
		s.lru.MoveToFront(el)
		s.apps[st.app].MoveToFront(st.appEl)
	} else {
		if turn <= 0 {
			return 0, 0
		}
		// Сначала забываются сессии старше TTL (они в хвосте), затем при
		// исчерпании доли приложения — его самая давняя, затем при общем
		// переполнении — та, что дольше всех не обновлялась.
		for old := s.lru.Back(); old != nil && now.Sub(old.Value.(*sessionState).at) > s.ttl; old = s.lru.Back() {
			s.remove(old)
		}
		app := sessionApp(key)
		if al := s.apps[app]; al != nil && al.Len() >= s.appMax {
			s.remove(s.byKey[al.Back().Value.(*sessionState).key])
			s.appEvictions++
		}
		for s.lru.Len() >= s.max {
			s.remove(s.lru.Back())
			s.evictions++
		}
		st = &sessionState{key: key, app: app}
		s.byKey[key] = s.lru.PushFront(st)
		al := s.apps[app]
		if al == nil {
			al = list.New()
			s.apps[app] = al
		}
		st.appEl = al.PushFront(st)
	}
	st.acc += max(turn, 0)
	if st.acc < riskEpsilon {
		st.acc = 0
	}
	st.turns++
	st.at = now
	return min(1, st.acc/riskSaturation), st.turns
}

// remove убирает состояние из общего списка и списка приложения; под mu.
func (s *Sessions) remove(el *list.Element) {
	st := el.Value.(*sessionState)
	s.lru.Remove(el)
	delete(s.byKey, st.key)
	if al := s.apps[st.app]; al != nil {
		al.Remove(st.appEl)
		if al.Len() == 0 {
			delete(s.apps, st.app)
		}
	}
}

// sessionApp — приложение из ключа состояния (reqSession.key: приложение,
// U+0000, псевдоним); ключ без разделителя — сам себе приложение.
func sessionApp(key string) string {
	if i := strings.IndexByte(key, 0); i >= 0 {
		return key[:i]
	}
	return key
}

// Len — число сессий с состоянием session.risk.
func (s *Sessions) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lru.Len()
}

// Stats — заполнение и вытеснения с запуска шлюза.
func (s *Sessions) Stats() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return SessionStats{Sessions: s.lru.Len(), MaxSessions: s.max, MaxAppSessions: s.appMax,
		Evictions: s.evictions, AppEvictions: s.appEvictions}
}

// reply — хеш реплики ассистента потоком: хеш криптопрофиля от
// нормализованного текста (session.ReplyHasher, общий с самотестом), затем
// HMAC на ключе сессий, 16 байт в hex. Простой хеш не годится: реплику
// модели (часто короткую, «Да, конечно») держатель событий подобрал бы по
// словарю.
type reply struct {
	s *Sessions
	r *session.ReplyHasher
}

func (s *Sessions) newReply() *reply {
	return &reply{s: s, r: session.NewReplyHasher(s.hasher)}
}

// WriteString дописывает часть реплики.
func (r *reply) WriteString(p string) { r.r.WriteString(p) }

// Sum — хеш реплики; пусто — реплика пустая (только пробелы или вызовы
// инструментов без текста).
func (r *reply) Sum() string {
	sum := r.r.Sum()
	if r.r.Empty() {
		return ""
	}
	return hex.EncodeToString(r.s.mac.Sum(append([]byte(replyDomain), sum...))[:16])
}

// replyHash — хеш реплики целиком.
func (s *Sessions) replyHash(text string) string {
	r := s.newReply()
	r.WriteString(text)
	return r.Sum()
}

// history — хеши реплик ассистента из истории запроса: последние
// events.MaxHistoryReplies непустых по порядку диалога. Текстовые части
// реплики склеиваются без разделителя, как их склеил бы клиент из строки.
func (s *Sessions) history(req *chat.Request) []events.Reply {
	var out []events.Reply
	for i := range req.Messages {
		m := &req.Messages[i]
		if m.Role != "assistant" {
			continue
		}
		if h := s.replyHash(messageText(m, "")); h != "" {
			out = append(out, events.Reply{Message: i, Hash: h})
		}
	}
	if len(out) > events.MaxHistoryReplies {
		out = out[len(out)-events.MaxHistoryReplies:]
	}
	return out
}
