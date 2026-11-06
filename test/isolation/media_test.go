//go:build linux

// Package isolation — тесты изоляции анализатора изображений aisec-media
// (задача 5.47 этапа 5, критерий приёмки ТЗ 14, ЗИ.7; ADR-0032, раздел 3).
//
// Тесты запускают настоящий процесс aisec-media (собирается go build в
// начале прогона) и настоящий клиент шлюза (gateway.MediaClient) в
// отдельном процессе-помощнике — сам тестовый бинарник с переменной
// AISEC_ISOLATION_HELPER. От root (облачная среда) оба работают от
// nobody: aisec-media от root не запускается, а проверка собеседника
// требует, чтобы клиент был тем UID, что указан в -peer-uid.
//
// Что проверяется здесь, а что — только на живом контейнере (ручная
// проверка 6, docs/pilot/manual-checks.md):
//   - аварийное завершение (SIGKILL) и зависание (SIGSTOP) анализатора не
//     задерживают клиента шлюза сверх срока и не роняют его; после
//     перезапуска анализатора клиент снова работает — здесь;
//   - предел памяти — здесь через RLIMIT_DATA (prlimit): изображение-бомба
//     не съедает память хоста, клиент шлюза не затронут; cgroup memory.max
//     контейнера — ручная проверка;
//   - нет сети — здесь профиль seccomp compose.media.yaml через libseccomp
//     (как runc) и пустое сетевое пространство имён (unshare): сетевой
//     сокет запрещён, анализ и очистка под профилем работают; только от
//     root, иначе пропуск; network_mode: none контейнера — ручная проверка.
package isolation

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

const (
	helperEnv = "AISEC_ISOLATION_HELPER"
	socketEnv = "AISEC_ISOLATION_SOCKET"
	// nobody — пользователь процессов теста, когда он запущен от root.
	nobody = 65534
)

// bins — собранный aisec-media и копия тестового бинарника в каталоге,
// доступном nobody; общий для всех тестов прогона.
var bins struct {
	once  sync.Once
	dir   string
	media string
	self  string
	err   error
}

func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "1" {
		os.Exit(runHelper())
	}
	code := m.Run()
	if bins.dir != "" {
		_ = os.RemoveAll(bins.dir) //nolint:gosec // G104: временный каталог теста
	}
	os.Exit(code)
}

// build собирает aisec-media (без OCR: изоляция от движка не зависит) и
// копирует тестовый бинарник в каталог 0755.
func build(t *testing.T) {
	t.Helper()
	bins.once.Do(func() {
		if _, err := exec.LookPath("go"); err != nil {
			bins.err = errors.New("нет go в PATH: aisec-media не собрать")
			return
		}
		dir, err := os.MkdirTemp("", "aisec-iso-bin")
		if err != nil {
			bins.err = err
			return
		}
		bins.dir = dir
		if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: каталог бинарников должен быть доступен nobody
			bins.err = err
			return
		}
		bins.media = filepath.Join(dir, "aisec-media")
		cmd := exec.CommandContext(context.Background(), "go", "build", "-trimpath", "-o", bins.media, "./cmd/aisec-media") //nolint:gosec // G204: аргументы — константы теста
		cmd.Dir = filepath.Join("..", "..")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			bins.err = fmt.Errorf("сборка aisec-media: %w\n%s", err, out)
			return
		}
		exe, err := os.Executable()
		if err != nil {
			bins.err = err
			return
		}
		b, err := os.ReadFile(exe) //nolint:gosec // G304: собственный тестовый бинарник
		if err != nil {
			bins.err = err
			return
		}
		bins.self = filepath.Join(dir, "isolation.test")
		bins.err = os.WriteFile(bins.self, b, 0o755) //nolint:gosec // G306: исполняемая копия для помощника
	})
	if bins.err != nil {
		if strings.HasPrefix(bins.err.Error(), "нет go") {
			t.Skip(bins.err)
		}
		t.Fatal(bins.err)
	}
}

// ids — UID и GID процессов теста: nobody от root, иначе свои.
func ids() (uid, gid uint32) {
	if os.Getuid() == 0 {
		return nobody, nobody
	}
	return uint32(os.Getuid()), uint32(os.Getgid()) //nolint:gosec // G115: UID и GID в Linux — 32 бита без знака
}

// asNobody запускает процесс от nobody, если тест идёт от root: aisec-media
// от root не запускается, а клиент должен быть UID из -peer-uid. Прямые
// системные структуры — только здесь (ADR-0032, дополнение 03.11.2026).
func asNobody(cmd *exec.Cmd) {
	if os.Getuid() != 0 {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{ //nolint:forbidigo // ADR-0032, дополнение 03.11.2026 (5.47): смена пользователя процесса теста изоляции
		Credential: &syscall.Credential{Uid: nobody, Gid: nobody, NoSetGroups: true}, //nolint:forbidigo // то же
	}
}

// sigStop — «зависание» анализатора: процесс остановлен, соединения живы.
var sigStop os.Signal = syscall.SIGSTOP //nolint:forbidigo // ADR-0032, дополнение 03.11.2026 (5.47): зависание анализатора в тесте изоляции

// socketDir — каталог сокета 0750 владельца процессов теста.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "aisec-iso")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) }) //nolint:gosec // G104: временный каталог теста
	uid, gid := ids()
	if err := os.Chown(dir, int(uid), int(gid)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o750); err != nil { //nolint:gosec // G302: права каталога сокета по ADR-0032
		t.Fatal(err)
	}
	return dir
}

// syncBuffer — журнал процесса, который читают тесты.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// mediaProc — запущенный aisec-media.
type mediaProc struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
	log  *syncBuffer
}

// mediaOpts — как запускать aisec-media: wrap — команды-обёртки перед
// бинарником (prlimit, unshare, профиль seccomp); asRoot — обёртка сама
// меняет пользователя (setpriv), учётные данные процессу не ставятся.
type mediaOpts struct {
	wrap   []string
	asRoot bool
	args   []string
}

// startMedia запускает aisec-media на сокете в dir и ждёт готовности.
// Реакция на нарушение целостности — alert: манифеста у сборки теста нет
// (контроль целостности проверяют свои тесты).
func startMedia(t *testing.T, dir string, o mediaOpts) *mediaProc {
	t.Helper()
	uid, gid := ids()
	sock := filepath.Join(dir, "s.sock")
	args := append([]string{bins.media, "-socket", sock, "-peer-uid", strconv.Itoa(int(uid)), "-peer-gid", strconv.Itoa(int(gid)),
		"-integrity-action", "alert", "-workers", "1", "-cache-entries", "0"}, o.args...)
	args = append(append([]string{}, o.wrap...), args...)
	cmd := exec.CommandContext(context.Background(), args[0], args[1:]...) //nolint:gosec // G204: аргументы задаёт тест
	if !o.asRoot {
		asNobody(cmd)
	}
	p := &mediaProc{cmd: cmd, done: make(chan struct{}), log: &syncBuffer{}}
	cmd.Stdout, cmd.Stderr = p.log, p.log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		p.err = cmd.Wait()
		close(p.done)
	}()
	t.Cleanup(p.kill)
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(p.log.String(), "aisec-media готов") {
		select {
		case <-p.done:
			t.Fatalf("aisec-media завершился при запуске: %v\n%s", p.err, p.log)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("aisec-media не готов\n%s", p.log)
		}
		time.Sleep(20 * time.Millisecond)
	}
	return p
}

func (p *mediaProc) signal(t *testing.T, s os.Signal) {
	t.Helper()
	if err := p.cmd.Process.Signal(s); err != nil {
		t.Fatal(err)
	}
}

// kill завершает процесс (если ещё работает) и ждёт его.
func (p *mediaProc) kill() {
	_ = p.cmd.Process.Kill() //nolint:gosec // G104: процесс мог уже завершиться
	<-p.done
}

// exited — процесс завершился за wait.
func (p *mediaProc) exited(wait time.Duration) bool {
	select {
	case <-p.done:
		return true
	case <-time.After(wait):
		return false
	}
}

// reply — итог одной операции клиента шлюза в помощнике.
type reply struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	Error  string `json:"error,omitempty"`
	MS     int64  `json:"ms"`
	Format string `json:"format,omitempty"`
	Bytes  int    `json:"bytes,omitempty"`
}

// client — процесс-помощник с клиентом шлюза: команды в stdin, итоги в
// stdout, по строке.
type client struct {
	cmd   *exec.Cmd
	in    io.WriteCloser
	lines chan string
	log   *syncBuffer
}

func startClient(t *testing.T, dir string) *client {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), bins.self, "-test.run=^$") //nolint:gosec // G204: свой тестовый бинарник
	cmd.Env = append(os.Environ(), helperEnv+"=1", socketEnv+"="+filepath.Join(dir, "s.sock"))
	asNobody(cmd)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &client{cmd: cmd, in: in, lines: make(chan string, 16), log: &syncBuffer{}}
	cmd.Stderr = c.log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			c.lines <- sc.Text()
		}
		close(c.lines)
	}()
	t.Cleanup(func() {
		_ = in.Close() //nolint:gosec // G104: помощник завершается по закрытию stdin
		if err := cmd.Wait(); err != nil {
			t.Errorf("клиент шлюза завершился с ошибкой (упал?): %v\n%s", err, c.log)
		}
	})
	return c
}

// send отправляет команду, не дожидаясь итога.
func (c *client) send(t *testing.T, op string, timeout time.Duration, img string) {
	t.Helper()
	if _, err := fmt.Fprintf(c.in, "%s %d %s\n", op, timeout.Milliseconds(), img); err != nil {
		t.Fatal(err)
	}
}

// result ждёт итог команды.
func (c *client) result(t *testing.T) reply {
	t.Helper()
	select {
	case line, ok := <-c.lines:
		if !ok {
			t.Fatalf("клиент шлюза завершился (упал?)\n%s", c.log)
		}
		var r reply
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("итог клиента %q: %v", line, err)
		}
		return r
	case <-time.After(30 * time.Second):
		t.Fatalf("клиент шлюза не ответил за 30 с\n%s", c.log)
	}
	return reply{}
}

func (c *client) do(t *testing.T, op string, timeout time.Duration, img string) reply {
	t.Helper()
	c.send(t, op, timeout, img)
	return c.result(t)
}

// runHelper — клиент шлюза в процессе-помощнике: тот же MediaClient, что
// в aisec-gateway, с короткой отсрочкой после сбоя.
func runHelper() int {
	c, err := gateway.NewMediaClient(gateway.MediaClientConfig{Socket: os.Getenv(socketEnv), MaxInflight: 4,
		MinBackoff: 100 * time.Millisecond, MaxBackoff: 200 * time.Millisecond})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	defer c.Close()
	enc := json.NewEncoder(os.Stdout)
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 3 {
			fmt.Fprintln(os.Stderr, "команда:", sc.Text())
			return 2
		}
		ms, err := strconv.Atoi(f[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		img, err := os.ReadFile(f[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(ms)*time.Millisecond)
		start := time.Now()
		var r reply
		switch f[0] {
		case "analyze":
			rep, err := c.Analyze(ctx, img)
			r.OK, err = err == nil && rep.Result.Status == wire.StatusOK, errOr(err, rep)
			r.Reason, r.Error = reason(err)
		case "sanitize":
			out, format, err := c.Sanitize(ctx, img)
			r.OK, r.Format, r.Bytes = err == nil, string(format), len(out)
			r.Reason, r.Error = reason(err)
		default:
			fmt.Fprintln(os.Stderr, "команда:", f[0])
			cancel()
			return 2
		}
		r.MS = time.Since(start).Milliseconds()
		cancel()
		if err := enc.Encode(r); err != nil {
			return 2
		}
	}
	return 0
}

func errOr(err error, rep *gateway.MediaReply) error {
	if err != nil || rep == nil {
		return err
	}
	if rep.Result.Status != wire.StatusOK {
		return fmt.Errorf("статус %s: %s", rep.Result.Status, rep.Result.Reason)
	}
	return nil
}

func reason(err error) (string, string) {
	if err == nil {
		return "", ""
	}
	var me *gateway.MediaError
	if errors.As(err, &me) {
		return me.Reason, err.Error()
	}
	return "", err.Error()
}

// writeImage кладёт изображение в файл, доступный помощнику.
func writeImage(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o644); err != nil { //nolint:gosec // G306: файл читает помощник от nobody
		t.Fatal(err)
	}
	return p
}

// imageDir — каталог изображений, читаемый помощником.
func imageDir(t *testing.T) string {
	t.Helper()
	// t.TempDir() лежит в каталоге 0700: помощнику от nobody туда нельзя.
	dir, err := os.MkdirTemp("", "aisec-iso-img")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })  //nolint:gosec // G104: временный каталог теста
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: каталог читает помощник от nobody
		t.Fatal(err)
	}
	return dir
}

// bombPNG — PNG w×h RGBA глубины depth (8 или 16 бит) из нулей: сжат до
// сотен КиБ, а декодированный растр занимает 4·w·h или 8·w·h байт.
// Собирается без кодировщиков изображений (их нет вне internal/media).
func bombPNG(t *testing.T, w, h, depth int) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	ihdr := binary.BigEndian.AppendUint32(nil, uint32(w)) //nolint:gosec // G115: размеры теста положительны и малы
	ihdr = binary.BigEndian.AppendUint32(ihdr, uint32(h)) //nolint:gosec // G115: то же
	ihdr = append(ihdr, byte(depth), 6, 0, 0, 0)          //nolint:gosec // G115: глубина 8 или 16; RGBA, без чересстрочности
	chunk(&b, "IHDR", ihdr)
	var z bytes.Buffer
	zw, err := zlib.NewWriterLevel(&z, zlib.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	row := make([]byte, 1+4*w*depth/8) // фильтр None и нули
	for range h {
		if _, err := zw.Write(row); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	chunk(&b, "IDAT", z.Bytes())
	chunk(&b, "IEND", nil)
	return b.Bytes()
}

func chunk(b *bytes.Buffer, typ string, data []byte) {
	_ = binary.Write(b, binary.BigEndian, uint32(len(data))) //nolint:gosec // G104, G115: запись в память, длина теста мала
	crc := crc32.NewIEEE()
	_, _ = crc.Write([]byte(typ)) //nolint:gosec // G104: hash.Hash.Write не завершается ошибкой
	_, _ = crc.Write(data)        //nolint:gosec // G104: то же
	b.WriteString(typ)
	b.Write(data)
	_ = binary.Write(b, binary.BigEndian, crc.Sum32()) //nolint:gosec // G104: запись в память
}

// Зависание (SIGSTOP) и аварийное завершение (SIGKILL) aisec-media не
// задерживают клиента шлюза сверх срока и не роняют его; после
// перезапуска анализатора на том же сокете клиент снова работает (после
// отсрочки). Критерий ТЗ 14: «аварийное завершение анализатора не влияет на
// шлюз».
func TestMediaCrashAndHangDoNotAffectGateway(t *testing.T) {
	build(t)
	dir := socketDir(t)
	imgs := imageDir(t)
	png := writeImage(t, imgs, "v.png", selftest.MediaVectorPNG("Инструкция по настройке принтера"))
	p := startMedia(t, dir, mediaOpts{})
	c := startClient(t, dir)
	if r := c.do(t, "analyze", 2*time.Second, png); !r.OK {
		t.Fatalf("исправный анализатор: %+v", r)
	}
	if r := c.do(t, "sanitize", 2*time.Second, png); !r.OK || r.Format != "png" || r.Bytes == 0 {
		t.Fatalf("очистка: %+v", r)
	}

	// Зависание: процесс остановлен, соединение живо, ответа нет.
	p.signal(t, sigStop)
	const deadline = 500 * time.Millisecond
	r := c.do(t, "analyze", deadline, png)
	if r.OK || r.Reason != "timeout" || r.MS > (deadline+300*time.Millisecond).Milliseconds() {
		t.Fatalf("зависший анализатор: %+v (срок %v)", r, deadline)
	}

	// Аварийное завершение во время запроса: ответ сразу, а не по сроку.
	c.send(t, "analyze", 5*time.Second, png)
	time.Sleep(300 * time.Millisecond)
	p.signal(t, os.Kill)
	if !p.exited(5 * time.Second) {
		t.Fatal("aisec-media не завершился по SIGKILL")
	}
	r = c.result(t)
	if r.OK || r.Reason != "unavailable" || r.MS > 3000 {
		t.Fatalf("анализатор упал во время запроса: %+v", r)
	}
	// Пока анализатора нет, ответ — сразу unavailable.
	r = c.do(t, "analyze", 2*time.Second, png)
	if r.OK || r.Reason != "unavailable" || r.MS > 200 {
		t.Fatalf("анализатора нет: %+v", r)
	}

	// Перезапуск на том же сокете (как restart: unless-stopped в compose):
	// после отсрочки клиент снова получает итоги.
	startMedia(t, dir, mediaOpts{})
	time.Sleep(300 * time.Millisecond)
	if r := c.do(t, "analyze", 2*time.Second, png); !r.OK {
		t.Fatalf("после перезапуска: %+v", r)
	}
}

// Предел памяти (RLIMIT_DATA через prlimit): изображение-бомба в пределах
// пикселей не съедает память хоста — анализатор упирается в предел и
// завершается или отвечает ошибкой; клиент шлюза получает сбой не позже
// срока и не падает. Обычное изображение под тем же пределом
// анализируется. cgroup memory.max контейнера — ручная проверка 6.
func TestMediaMemoryLimit(t *testing.T) {
	build(t)
	prlimit, err := exec.LookPath("prlimit")
	if err != nil {
		t.Skip("нет prlimit (util-linux)")
	}
	dir := socketDir(t)
	imgs := imageDir(t)
	png := writeImage(t, imgs, "v.png", selftest.MediaVectorPNG("Инструкция по настройке принтера"))
	// 10 000×10 000 RGBA: растр 400 МБ — больше предела памяти. Предел
	// пикселей поднят до наибольшего (100 млн), а предел памяти растров —
	// до 8 ГиБ, чтобы бомба дошла до декодера: так проверяется предел
	// памяти, а не проверки заголовка (их проверяют тесты internal/media и
	// TestMediaDefaultsFitMemory).
	bomb := writeImage(t, imgs, "bomb.png", bombPNG(t, 10000, 10000, 8))
	p := startMedia(t, dir, mediaOpts{wrap: []string{prlimit, "--data=" + strconv.Itoa(memLimit), "--"},
		args: []string{"-max-pixels", "100000000", "-max-raster-mib", "8192"}})
	c := startClient(t, dir)
	if r := c.do(t, "analyze", 5*time.Second, png); !r.OK {
		t.Fatalf("обычное изображение под пределом памяти: %+v\n%s", r, p.log)
	}
	if p.exited(0) {
		t.Fatalf("aisec-media завершился до бомбы: %v\n%s", p.err, p.log)
	}
	r := c.do(t, "analyze", 8*time.Second, bomb)
	if r.OK || r.MS > 8500 {
		t.Fatalf("изображение-бомба: %+v\n%s", r, p.log)
	}
	died := p.exited(2 * time.Second)
	t.Logf("бомба: %+v; анализатор завершился: %v", r, died)
	if log := p.log.String(); died && !strings.Contains(log, "out of memory") && !strings.Contains(log, "cannot allocate memory") {
		t.Fatalf("aisec-media завершился не из-за предела памяти: %v\n%s", p.err, log)
	}
	if !died {
		// Анализатор пережил нехватку памяти — продолжает отвечать.
		if r := c.do(t, "analyze", 5*time.Second, png); !r.OK {
			t.Fatalf("после бомбы: %+v", r)
		}
	}
}

// Умолчания compose (два исполнителя, mem_limit 1 ГиБ) против изображений
// в пределах по умолчанию (5В4 ревью 5.r4 этапа 5): два PNG 5000×5000 с
// глубиной 16 бит одновременно (файл ~200 КБ, растр 200 МБ, с OCR — около
// 350 МиБ на каждый) получают отказ too_many_pixels по бюджету растров до
// декодирования, а два PNG RGBA 8 бит того же размера одновременно
// анализируются и очищаются под RLIMIT_DATA 1 ГиБ. Анализатор жив, клиенты
// шлюза получают итог. cgroup memory.max контейнера — ручная проверка 6.
func TestMediaDefaultsFitMemory(t *testing.T) {
	build(t)
	prlimit, err := exec.LookPath("prlimit")
	if err != nil {
		t.Skip("нет prlimit (util-linux)")
	}
	dir := socketDir(t)
	imgs := imageDir(t)
	deep := writeImage(t, imgs, "deep.png", bombPNG(t, 5000, 5000, 16))
	flat := writeImage(t, imgs, "flat.png", bombPNG(t, 5000, 5000, 8))
	p := startMedia(t, dir, mediaOpts{wrap: []string{prlimit, "--data=" + strconv.Itoa(1<<30), "--"},
		args: []string{"-workers", "2", "-mem-limit", "1g"}})
	a, b := startClient(t, dir), startClient(t, dir)
	pair := func(op, img string) (reply, reply) {
		a.send(t, op, 10*time.Second, img)
		b.send(t, op, 10*time.Second, img)
		return a.result(t), b.result(t)
	}
	r1, r2 := pair("analyze", deep)
	for _, r := range []reply{r1, r2} {
		if r.OK || !strings.Contains(r.Error, "too_many_pixels") {
			t.Fatalf("PNG 16 бит 25 Мпикс: %+v\n%s", r, p.log)
		}
	}
	r1, r2 = pair("sanitize", deep)
	for _, r := range []reply{r1, r2} {
		if r.OK || r.Reason != "rejected" {
			t.Fatalf("очистка PNG 16 бит 25 Мпикс: %+v\n%s", r, p.log)
		}
	}
	r1, r2 = pair("analyze", flat)
	for _, r := range []reply{r1, r2} {
		if !r.OK {
			t.Fatalf("PNG RGBA 25 Мпикс: %+v\n%s", r, p.log)
		}
	}
	r1, r2 = pair("sanitize", flat)
	for _, r := range []reply{r1, r2} {
		if !r.OK || r.Format != "png" {
			t.Fatalf("очистка PNG RGBA 25 Мпикс: %+v\n%s", r, p.log)
		}
	}
	if p.exited(0) {
		t.Fatalf("aisec-media завершился: %v\n%s", p.err, p.log)
	}
}

// memLimit — предел памяти данных aisec-media в тесте (RLIMIT_DATA: куча
// Go — частные записываемые отображения): хватает на запуск, обычные
// изображения и растр 100 МБ, но не на растр бомбы 400 МБ. RLIMIT_AS для Go
// не годится: среда выполнения резервирует сотни мегабайт адресов без
// памяти за ними.
const memLimit = 256 << 20

// Нет сети: профиль seccomp compose.media.yaml (libseccomp, как runc) и
// пустое сетевое пространство имён (unshare --net, как network_mode:
// none). Под профилем сетевой сокет запрещён (EPERM), у процесса только
// lo, а анализ и очистка через Unix-сокет работают. Нужны root (unshare,
// смена пользователя), python3 и libseccomp — иначе пропуск.
func TestMediaNoNetworkSeccomp(t *testing.T) {
	build(t)
	if os.Getuid() != 0 {
		t.Skip("нужен root: пространство имён сети и смена пользователя")
	}
	var tools []string
	for _, name := range []string{"unshare", "setpriv", "python3"} {
		p, err := exec.LookPath(name)
		if err != nil {
			t.Skipf("нет %s", name)
		}
		tools = append(tools, p)
	}
	if !libseccomp() {
		t.Skip("нет libseccomp.so.2")
	}
	// Скрипт и профиль — в каталог, доступный nobody.
	files := imageDir(t)
	script := writeImage(t, files, "seccomp_exec.py", mustRead(t, filepath.Join("testdata", "seccomp_exec.py")))
	profile := writeImage(t, files, "aisec-media.json", mustRead(t, filepath.Join("..", "..", "deploy", "compose", "pilot", "seccomp", "aisec-media.json")))
	png := writeImage(t, files, "v.png", selftest.MediaVectorPNG("Инструкция по настройке принтера"))
	dir := socketDir(t)
	id := strconv.Itoa(nobody)
	p := startMedia(t, dir, mediaOpts{asRoot: true, wrap: []string{
		tools[0], "--net", "--",
		tools[1], "--reuid=" + id, "--regid=" + id, "--clear-groups", "--",
		tools[2], "-I", script, profile,
	}})
	if !strings.Contains(p.log.String(), "seccomp: AF_INET errno=1") {
		t.Fatalf("сетевой сокет под профилем не запрещён:\n%s", p.log)
	}
	status := mustRead(t, fmt.Sprintf("/proc/%d/status", p.cmd.Process.Pid))
	for _, want := range []string{"Seccomp:\t2", "NoNewPrivs:\t1", "Uid:\t" + id + "\t" + id, "CapEff:\t0000000000000000"} {
		if !bytes.Contains(status, []byte(want)) {
			t.Errorf("в /proc/pid/status нет %q", want)
		}
	}
	var ifaces []string
	for i, line := range strings.Split(string(mustRead(t, fmt.Sprintf("/proc/%d/net/dev", p.cmd.Process.Pid))), "\n") {
		if f := strings.Fields(line); i >= 2 && len(f) > 0 {
			ifaces = append(ifaces, strings.TrimSuffix(f[0], ":"))
		}
	}
	if len(ifaces) != 1 || ifaces[0] != "lo" {
		t.Errorf("сетевые интерфейсы aisec-media: %v, ожидался только lo", ifaces)
	}
	c := startClient(t, dir)
	if r := c.do(t, "analyze", 5*time.Second, png); !r.OK {
		t.Fatalf("анализ под профилем: %+v\n%s", r, p.log)
	}
	if r := c.do(t, "sanitize", 5*time.Second, png); !r.OK {
		t.Fatalf("очистка под профилем: %+v\n%s", r, p.log)
	}
	if p.exited(0) {
		t.Fatalf("aisec-media завершился под профилем: %v\n%s", p.err, p.log)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // G304: пути задаёт тест
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// libseccomp — библиотека libseccomp есть в системе.
func libseccomp() bool {
	for _, dir := range []string{"/usr/lib/x86_64-linux-gnu", "/usr/lib64", "/usr/lib", "/lib/x86_64-linux-gnu"} {
		if _, err := os.Stat(filepath.Join(dir, "libseccomp.so.2")); err == nil {
			return true
		}
	}
	return false
}
