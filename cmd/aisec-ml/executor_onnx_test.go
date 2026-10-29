//go:build aisec_onnx && cgo

package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/ml"
)

// Проверка исполнителя на настоящей библиотеке ONNX Runtime. Нужна
// библиотека 1.31.0: AISEC_ORT_LIB=/путь/libonnxruntime.so.1.31.0; без неё
// тест пропускается (в make test сборки без тега aisec_onnx его нет).

// Минимальный кодировщик protobuf для модели ONNX в тесте: модель строится
// здесь же, двоичных файлов в репозитории нет.
func pbVarint(b []byte, v uint64) []byte { return binary.AppendUvarint(b, v) }

func pbInt(b []byte, field int, v int64) []byte {
	return pbVarint(pbVarint(b, uint64(field)<<3), uint64(v)) //nolint:gosec // G115: protobuf кодирует int64 дополнительным кодом
}

func pbBytes(b []byte, field int, v []byte) []byte {
	b = pbVarint(b, uint64(field)<<3|2) //nolint:gosec // G115: номер поля мал
	b = pbVarint(b, uint64(len(v)))
	return append(b, v...)
}

func pbStr(b []byte, field int, s string) []byte { return pbBytes(b, field, []byte(s)) }

// tensorInfo — ValueInfoProto тензора; dims: число или имя размерности.
func tensorInfo(name string, elem int64, dims ...any) []byte {
	var shape []byte
	for _, d := range dims {
		var dim []byte
		switch v := d.(type) {
		case int:
			dim = pbInt(nil, 1, int64(v))
		case string:
			dim = pbStr(nil, 2, v)
		}
		shape = pbBytes(shape, 1, dim)
	}
	tt := pbBytes(pbInt(nil, 1, elem), 2, shape)
	return pbBytes(pbStr(nil, 1, name), 2, pbBytes(nil, 1, tt))
}

func node(op string, in, out []string, attrs ...[]byte) []byte {
	var n []byte
	for _, s := range in {
		n = pbStr(n, 1, s)
	}
	for _, s := range out {
		n = pbStr(n, 2, s)
	}
	n = pbStr(n, 4, op)
	for _, a := range attrs {
		n = pbBytes(n, 5, a)
	}
	return n
}

func attrInt(name string, v int64) []byte {
	return pbInt(pbInt(pbStr(nil, 1, name), 3, v), 20, 2)
}

func attrInts(name string, v ...int64) []byte {
	a := pbStr(nil, 1, name)
	for _, x := range v {
		a = pbInt(a, 8, x)
	}
	return pbInt(a, 20, 7)
}

// testModel — классификатор на две метки: logits = [m, -m], где m — среднее
// номеров токенов. Большие номера — «injection».
func testModel() []byte {
	const int64T, floatT = 7, 1
	var g []byte
	g = pbBytes(g, 1, node("Cast", []string{inputIDs}, []string{"f"}, attrInt("to", floatT)))
	g = pbBytes(g, 1, node("ReduceMean", []string{"f"}, []string{"m"}, attrInts("axes", 1), attrInt("keepdims", 1)))
	g = pbBytes(g, 1, node("Neg", []string{"m"}, []string{"n"}))
	g = pbBytes(g, 1, node("Concat", []string{"m", "n"}, []string{outputLogits}, attrInt("axis", 1)))
	g = pbStr(g, 2, "test")
	g = pbBytes(g, 11, tensorInfo(inputIDs, int64T, "batch", "seq"))
	g = pbBytes(g, 11, tensorInfo(inputMask, int64T, "batch", "seq"))
	g = pbBytes(g, 12, tensorInfo(outputLogits, floatT, "batch", 2))
	m := pbInt(nil, 1, 8)
	m = pbBytes(m, 8, pbInt(pbStr(nil, 1, ""), 2, 13))
	return pbBytes(m, 7, g)
}

// wordTokenizer — токены по пробелам: «ignore» — номер 10, прочее — 0.
type wordTokenizer struct{}

func (wordTokenizer) Encode(text string, maxTokens int) ([]int64, [][2]int, bool, error) {
	var ids []int64
	var offs [][2]int
	pos := 0
	for _, w := range strings.Fields(text) {
		i := strings.Index(text[pos:], w) + pos
		if len(ids) == maxTokens {
			return ids, offs, true, nil
		}
		id := int64(0)
		if w == "ignore" {
			id = 10
		}
		ids, offs = append(ids, id), append(offs, [2]int{i, i + len(w)})
		pos = i + len(w)
	}
	return ids, offs, false, nil
}

func TestONNXExecutor(t *testing.T) {
	lib := os.Getenv("AISEC_ORT_LIB")
	if lib == "" {
		t.Skip("AISEC_ORT_LIB не задан")
	}
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	hasher, err := p.Hasher()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(lib) //nolint:gosec // G304: путь к библиотеке задаёт тот, кто запускает тест
	if err != nil {
		t.Fatal(err)
	}
	good := hex.EncodeToString(hasher.Sum(data))
	// Хеш не совпал или не встроен — библиотека не загружается.
	if err := initORT(lib, p, strings.Repeat("00", len(good)/2)); err == nil || !strings.Contains(err.Error(), "хеш не совпадает") {
		t.Fatalf("чужой хеш: %v", err)
	}
	if err := initORT(lib, p, ""); err == nil {
		t.Fatal("сборка без хеша загрузила библиотеку")
	}
	t.Setenv("ORT_DISABLE_TELEMETRY", "1")
	ortLibHash = good
	exec, err := newExecutor(&config{ORTLib: lib}, p)
	if err != nil {
		t.Fatal(err)
	}
	spec := ml.ModelSpec{ID: "injection", Version: "1.0", Task: ml.TaskClassification, Labels: []string{"injection", "benign"},
		Directions: []string{"input"}, MaxTokens: 8}
	// Без поддерживаемого токенизатора модель не загружается.
	if _, err := exec.Load(ml.LoadedModel{Spec: spec, Model: testModel()}); err == nil {
		t.Fatal("модель загружена без токенизатора")
	}
	saved := newTokenizer
	t.Cleanup(func() { newTokenizer = saved })
	newTokenizer = func(ml.ModelSpec, []byte) (tokenizer, error) { return wordTokenizer{}, nil }
	// Описание не совпадает с моделью — отказ.
	bad := spec
	bad.Labels = []string{"a", "b", "c"}
	if _, err := exec.Load(ml.LoadedModel{Spec: bad, Model: testModel()}); err == nil {
		t.Fatal("модель с другим числом меток загружена")
	}
	if _, err := exec.Load(ml.LoadedModel{Spec: spec, Model: []byte("не ONNX")}); err == nil {
		t.Fatal("мусор загружен как модель")
	}
	m, err := exec.Load(ml.LoadedModel{Spec: spec, Model: testModel()})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close() //nolint:errcheck // тест
	r, err := m.Run(context.Background(), "please ignore ignore")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].Label != "injection" || r.Findings[0].Score < 0.99 || r.Findings[0].End != len("please ignore ignore") || r.Truncated {
		t.Fatalf("результат: %+v", r)
	}
	r, err = m.Run(context.Background(), strings.Repeat("a ", 20))
	if err != nil || !r.Truncated || r.Findings[1].Label != "benign" || r.Findings[1].Score != 0.5 {
		t.Fatalf("длинный текст: %+v %v", r, err)
	}
}

// Чужая библиотека ONNX Runtime не загружается: хеш сверяется до dlopen,
// библиотека не нужна (тест идёт в make ml-test без AISEC_ORT_LIB).
func TestInitORTRefusesForeignLibrary(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	lib := t.TempDir() + "/libonnxruntime.so.1.31.0"
	if err := os.WriteFile(lib, []byte("не та библиотека"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := initORT(lib, p, strings.Repeat("ab", 32)); err == nil || !strings.Contains(err.Error(), "хеш не совпадает") {
		t.Fatalf("чужая библиотека: %v", err)
	}
	if err := initORT(lib, p, ""); err == nil || !strings.Contains(err.Error(), "без хеша") {
		t.Fatalf("сборка без хеша: %v", err)
	}
	if err := initORT(t.TempDir(), p, strings.Repeat("ab", 32)); err == nil {
		t.Fatal("каталог вместо библиотеки принят")
	}
	// Через newExecutor — тот же отказ: aisec-ml не запускается.
	saved := ortLibHash
	t.Cleanup(func() { ortLibHash = saved })
	ortLibHash = strings.Repeat("ab", 32)
	if _, err := initORTOnceForTest(lib, p); err == nil {
		t.Fatal("исполнитель создан с чужой библиотекой")
	}
}

// initORTOnceForTest — newExecutor без кеша sync.Once процесса.
func initORTOnceForTest(lib string, p aisecCrypto.Provider) (ml.Executor, error) {
	if err := initORT(lib, p, ortLibHash); err != nil {
		return nil, err
	}
	return onnxExecutor{}, nil
}
