//go:build e2e && linux

package e2e

// Общий стенд сквозных сценариев этапа 5 (задача 5.49): стенд этапа 3
// (сервер, шлюз, mock-llm) и настоящий процесс aisec-media на Unix-сокете.
//
// aisec-media не запускается от root, а шлюз обязан быть тем пользователем,
// чьи UID и GID указаны в -peer-uid и -peer-gid (ADR-0032, раздел 2). От
// обычного пользователя (CI) оба процесса идут от него; от root (облачная
// среда) — от nobody, как в тестах изоляции 5.47 (test/isolation): каталог
// стенда передаётся nobody целиком, чтобы шлюз прочитал свои ключи и
// записал состояние.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// s5Nobody — пользователь процессов стенда, когда тест запущен от root.
const s5Nobody = 65534

// s5IDs — UID и GID процессов стенда с aisec-media.
func s5IDs() (uid, gid uint32) {
	if os.Getuid() == 0 {
		return s5Nobody, s5Nobody
	}
	return uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: UID и GID в Linux — 32 бита без знака
}

// s5AsNobody переводит процесс на nobody, если тест идёт от root.
func s5AsNobody(cmd *exec.Cmd) {
	if os.Getuid() != 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{ //nolint:forbidigo // по образцу теста изоляции 5.47 (ADR-0032, дополнение 03.11.2026): смена пользователя процесса стенда e2e
		Credential: &syscall.Credential{Uid: s5Nobody, Gid: s5Nobody, NoSetGroups: true}, //nolint:forbidigo // то же
	}
}

// s5Chown передаёт каталог dir со всем содержимым nobody (только от root).
func s5Chown(t *testing.T, dir string) {
	t.Helper()
	if os.Getuid() != 0 {
		return
	}
	err := filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, s5Nobody, s5Nobody)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// s5Buf — журнал процесса, который читает тест.
type s5Buf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *s5Buf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *s5Buf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// s5Media — запущенный aisec-media.
type s5Media struct {
	t    *testing.T
	cmd  *exec.Cmd
	log  *s5Buf
	sock string
	done chan struct{}
}

// stop завершает aisec-media; остановленный (SIGSTOP) сначала продолжается.
func (m *s5Media) stop() {
	select {
	case <-m.done:
		return
	default:
	}
	_ = m.cmd.Process.Signal(syscall.SIGCONT) //nolint:gosec,forbidigo // G104: процесс мог завершиться; SIGCONT — продолжение остановленного анализатора (по образцу теста 5.47)
	_ = m.cmd.Process.Signal(syscall.SIGTERM) //nolint:gosec // G104: процесс мог завершиться
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		_ = m.cmd.Process.Kill() //nolint:gosec // G104: добиваем зависший анализатор
		<-m.done
	}
}

// freeze останавливает анализатор: соединения живы, ответов нет («зависание»).
func (m *s5Media) freeze() {
	m.t.Helper()
	if err := m.cmd.Process.Signal(syscall.SIGSTOP); err != nil { //nolint:forbidigo // по образцу теста изоляции 5.47: зависание анализатора
		m.t.Fatal(err)
	}
}

// thaw продолжает остановленный анализатор.
func (m *s5Media) thaw() {
	m.t.Helper()
	if err := m.cmd.Process.Signal(syscall.SIGCONT); err != nil { //nolint:forbidigo // то же
		m.t.Fatal(err)
	}
}

// s5StartMedia запускает aisec-media на новом сокете; args — флаги сверх
// обязательных. Бинарник копируется в каталог стенда: в build/bin nobody
// может не дойти.
func s5StartMedia(t *testing.T, base string, args ...string) *s5Media {
	t.Helper()
	bin := filepath.Join(base, "aisec-media")
	s2Copy(t, filepath.Join(*binDir, "aisec-media"), bin, 0o755) //nolint:gosec // G302: исполняемая копия для nobody
	if err := os.Chmod(bin, 0o755); err != nil {                 //nolint:gosec // G302: то же
		t.Fatal(err)
	}
	// Каталог стенда целиком — nobody (от root): бинарник, ключи и состояние шлюза.
	s5Chown(t, base)
	dir, err := os.MkdirTemp("", "aisec-e2e-m")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G104: временный каталог теста
	uid, gid := s5IDs()
	if err := os.Chown(dir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: права каталога сокета по ADR-0032
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "m.sock")
	// Манифеста у копии нет: реакция на нарушение целостности — alert.
	full := append([]string{"-socket", sock, "-peer-uid", strconv.Itoa(int(uid)), "-peer-gid", strconv.Itoa(int(gid)),
		"-integrity-action", "alert"}, args...)
	cmd := exec.CommandContext(context.Background(), bin, full...) //nolint:gosec // G204: аргументы задаёт тест
	s5AsNobody(cmd)
	m := &s5Media{t: t, cmd: cmd, log: &s5Buf{}, sock: sock, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = m.log, m.log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = cmd.Wait() //nolint:gosec // G104: код выхода не нужен
		close(m.done)
	}()
	t.Cleanup(func() {
		m.stop()
		if t.Failed() {
			t.Logf("журнал aisec-media:\n%s", m.log.String())
		}
	})
	if !s2WaitFor(10*time.Second, func() bool { return strings.Contains(m.log.String(), "aisec-media готов") }) {
		t.Fatalf("aisec-media не запустился:\n%s", m.log.String())
	}
	return m
}

// s5MediaStack — стенд этапа 3 с aisec-media: шлюз стартует с -media-socket
// (startGateway после заведения приложений, как обычно).
func s5MediaStack(t *testing.T, o s3Opts, mediaArgs ...string) (*s3Stack, *s5Media) {
	t.Helper()
	st := s3NewStack(t, o)
	base := filepath.Dir(st.s.tls.dir)
	m := s5StartMedia(t, base, mediaArgs...)
	st.env.extraArgs = append(st.env.extraArgs, "-media-socket", m.sock)
	st.env.mod = s5AsNobody
	return st, m
}

// s5Corpus читает файл корпуса изображений testdata/corpus/media.
func s5Corpus(t *testing.T, name string) []byte {
	t.Helper()
	return mustRead(t, filepath.Join("..", "..", "testdata", "corpus", "media", name))
}

// s5ImageChat — тело запроса чата: текст и изображения data-URL.
func s5ImageChat(t *testing.T, text string, images ...[]byte) string {
	t.Helper()
	parts := []map[string]any{{"type": "text", "text": text}}
	for _, img := range images {
		mime := "image/png"
		if bytes.HasPrefix(img, []byte{0xff, 0xd8}) {
			mime = "image/jpeg"
		}
		parts = append(parts, map[string]any{"type": "image_url",
			"image_url": map[string]string{"url": "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(img)}})
	}
	raw, err := json.Marshal(map[string]any{"model": "mock-echo", "messages": []map[string]any{{"role": "user", "content": parts}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// s5EventCard — карточка события с проверкой изображений и находками.
type s5EventCard struct {
	ID       string         `json:"id"`
	Action   string         `json:"action"`
	Media    []s5MediaCheck `json:"media"`
	Findings []s5Finding    `json:"findings"`
	Raw      string         `json:"-"`
}

type s5MediaCheck struct {
	Location string `json:"location"`
	Mode     string `json:"mode"`
	Checked  bool   `json:"checked"`
	Reason   string `json:"reason"`
	Format   string `json:"format"`
	Texts    int    `json:"texts"`
}

type s5Finding struct {
	Detector string                      `json:"detector"`
	Category string                      `json:"category"`
	Source   string                      `json:"source"`
	Box      *struct{ X, Y, W, H int64 } `json:"box"`
}

// s5Card читает карточку события.
func s5Card(t *testing.T, c *s2Client, id string) s5EventCard {
	t.Helper()
	r := c.do("GET", "/api/v1/events/"+id, nil)
	if r.code != http.StatusOK {
		t.Fatalf("карточка события %s: %s", id, r)
	}
	var card struct {
		s5EventCard
		Details s5EventCard `json:"details"`
	}
	r.json(t, &card)
	out := card.s5EventCard
	if out.Media == nil && card.Details.Media != nil {
		out = card.Details
	}
	if out.Findings == nil && card.Details.Findings != nil {
		out.Findings = card.Details.Findings
	}
	out.Raw = string(r.body)
	return out
}

// s5PrivateIP — адрес узла из частной сети (10/8, 172.16/12, 192.168/16):
// judge.llm и другие внутренние адреса принимаются только из неё, loopback
// и прочее — нет. Без такого адреса тест пропускается, а в CI (переменная
// CI задана) — падает.
func s5PrivateIP(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if ip := n.IP.To4(); ip != nil && ip.IsPrivate() {
			return ip.String()
		}
	}
	if os.Getenv("CI") != "" {
		t.Fatal("нет частного адреса IPv4 для внутреннего сервиса стенда")
	}
	t.Skip("нет частного адреса IPv4 (10/8, 172.16/12, 192.168/16) для внутреннего сервиса стенда")
	return ""
}

// s5EventsFilter — число событий по фильтру консоли.
func s5Events(t *testing.T, c *s2Client, filter string) []s3Event {
	t.Helper()
	r := c.do("GET", "/api/v1/events?limit=100&filter="+url.QueryEscape(filter), nil)
	if r.code != http.StatusOK {
		t.Fatalf("события: %s", r)
	}
	var page struct{ Items []s3Event }
	r.json(t, &page)
	return page.Items
}

// s5App заводит приложение стенда с режимом при сбое проверки fail_mode
// (fail_open или fail_closed) на провайдере prov (пусто — mock-llm стенда).
func (st *s3Stack) s5App(slug, policy, failMode, prov string) s3App {
	if prov == "" {
		prov = st.prov
	}
	st.t.Helper()
	r := st.admin.do("POST", "/api/v1/applications", map[string]any{"slug": slug, "name": "Приложение " + slug, "env": "prod",
		"provider_id": prov, "models": []string{"mock-echo"}, "policy": policy, "policy_mode": "enforce", "fail_mode": failMode, "password": s2AdminPass})
	if r.code != http.StatusCreated {
		st.t.Fatalf("приложение %s: %s", slug, r)
	}
	var a struct{ ID string }
	r.json(st.t, &a)
	r = st.admin.do("POST", "/api/v1/applications/"+a.ID+"/keys", map[string]any{"name": "e2e", "expires_in_days": 30})
	if r.code != http.StatusCreated {
		st.t.Fatalf("ключ приложения %s: %s", slug, r)
	}
	var k struct{ Key string }
	r.json(st.t, &k)
	st.apps++
	return s3App{id: a.ID, slug: slug, key: k.Key}
}

// s5WaitCard ждёт событие по фильтру filter, карточка которого содержит sub.
func s5WaitCard(t *testing.T, c *s2Client, filter, sub string) s5EventCard {
	t.Helper()
	var found s5EventCard
	if !s2WaitFor(30*time.Second, func() bool {
		for _, e := range s5Events(t, c, filter) {
			if card := s5Card(t, c, e.ID); strings.Contains(card.Raw, sub) {
				found = card
				return true
			}
		}
		return false
	}) {
		t.Fatalf("нет события по фильтру %s с %s", filter, sub)
	}
	return found
}
