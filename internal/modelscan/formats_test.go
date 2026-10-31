package modelscan

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Синтетические GGUF, ONNX и tokenizer_config.json (задача 5.20): только
// заголовки и нулевые байты вместо весов.

// --- GGUF ---

type ggufKV struct {
	key  string
	typ  uint32
	data []byte // значение в формате GGUF
}

type ggufTensorDef struct {
	name   string
	dims   []uint64
	typ    uint32
	offset uint64
}

func ggufStr(s string) []byte {
	return append(binary.LittleEndian.AppendUint64(nil, uint64(len(s))), s...)
}

func ggufU32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func ggufStrArray(items ...string) []byte {
	out := binary.LittleEndian.AppendUint32(nil, ggufString)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(items)))
	for _, s := range items {
		out = append(out, ggufStr(s)...)
	}
	return out
}

func ggufBytes(version uint32, kvs []ggufKV, tensors []ggufTensorDef, align, dataLen int) []byte {
	out := []byte("GGUF")
	out = binary.LittleEndian.AppendUint32(out, version)
	out = binary.LittleEndian.AppendUint64(out, uint64(len(tensors)))
	out = binary.LittleEndian.AppendUint64(out, uint64(len(kvs)))
	for _, kv := range kvs {
		out = append(out, ggufStr(kv.key)...)
		out = binary.LittleEndian.AppendUint32(out, kv.typ)
		out = append(out, kv.data...)
	}
	for _, t := range tensors {
		out = append(out, ggufStr(t.name)...)
		out = binary.LittleEndian.AppendUint32(out, uint32(len(t.dims))) //nolint:gosec // G115: в образцах до пяти размерностей
		for _, d := range t.dims {
			out = binary.LittleEndian.AppendUint64(out, d)
		}
		out = binary.LittleEndian.AppendUint32(out, t.typ)
		out = binary.LittleEndian.AppendUint64(out, t.offset)
	}
	for len(out)%align != 0 {
		out = append(out, 0)
	}
	return append(out, make([]byte, dataLen)...)
}

const testTemplate = "{% for m in messages %}<|{{ m.role }}|>{{ m.content }}{% endfor %}"

func goodGGUF() []byte {
	return ggufBytes(3, []ggufKV{
		{"general.architecture", ggufString, ggufStr("llama")},
		{"general.alignment", ggufUint32, ggufU32(32)},
		{"tokenizer.ggml.tokens", ggufArray, ggufStrArray("<s>", "</s>", "а")},
		{"tokenizer.chat_template", ggufString, ggufStr(testTemplate)},
		{"tokenizer.chat_template.tool_use", ggufString, ggufStr("{{ tools }}")},
	}, []ggufTensorDef{
		{"token_embd.weight", []uint64{4, 2}, 0, 0}, // F32: 32 байта
		{"output.weight", []uint64{32, 1}, 8, 32},   // Q8_0: 34 байта
		{"norm.weight", []uint64{4}, 99, 96},        // неизвестный тип: только начало
	}, 32, 128)
}

func TestGGUFAccepted(t *testing.T) {
	fr := scanBytes(t, "model.gguf", goodGGUF(), Limits{})
	if fr.Format != FormatGGUF || len(fr.Findings) != 0 {
		t.Fatalf("GGUF: %+v", fr)
	}
	if fr.Tensors != 3 || len(fr.ChatTemplates) != 2 {
		t.Fatalf("тензоров %d, шаблонов %d", fr.Tensors, len(fr.ChatTemplates))
	}
	if fr.ChatTemplates[0].Text != testTemplate || fr.ChatTemplates[1].Name != "tool_use" {
		t.Errorf("шаблоны: %+v", fr.ChatTemplates)
	}
}

func TestGGUFBoundaries(t *testing.T) {
	tensor := []ggufTensorDef{{"w", []uint64{4}, 0, 0}}
	nested := binary.LittleEndian.AppendUint32(nil, ggufArray)
	nested = binary.LittleEndian.AppendUint64(nested, 1)
	nested = append(nested, binary.LittleEndian.AppendUint32(nil, ggufArray)...)
	nested = binary.LittleEndian.AppendUint64(nested, 1)
	nested = append(nested, ggufStrArray("x")...)
	bigEndian := ggufBytes(3, nil, nil, 1, 0)
	copy(bigEndian[4:], []byte{0, 0, 0, 3})
	cases := []struct {
		name string
		data []byte
		lim  Limits
		code string
	}{
		{"обрезанный заголовок", goodGGUF()[:30], Limits{}, CodeMalformed},
		{"версия 1", ggufBytes(1, nil, nil, 1, 0), Limits{}, CodeMalformed},
		{"big-endian", bigEndian, Limits{}, CodeUnknownFormat},
		{"тензоров сверх предела", goodGGUF(), Limits{MaxTensors: 2}, CodeLimitExceeded},
		{"метаданных сверх предела", goodGGUF(), Limits{MaxGGUFMetadata: 4}, CodeLimitExceeded},
		{"строка сверх предела", goodGGUF(), Limits{MaxGGUFString: 3}, CodeLimitExceeded},
		{"массив сверх предела", goodGGUF(), Limits{MaxGGUFArray: 2}, CodeLimitExceeded},
		{"шаблон сверх предела", goodGGUF(), Limits{MaxChatTemplate: 16}, CodeLimitExceeded},
		{"шаблон не строка", ggufBytes(3, []ggufKV{{"tokenizer.chat_template", ggufUint32, ggufU32(1)}}, nil, 1, 0), Limits{}, CodeMalformed},
		{"смещение за концом", ggufBytes(3, nil, []ggufTensorDef{{"w", []uint64{4}, 0, 64}}, 32, 16), Limits{}, CodeMalformed},
		{"данные за концом", ggufBytes(3, nil, tensor, 32, 8), Limits{}, CodeMalformed},
		{"перекрытие", ggufBytes(3, nil, []ggufTensorDef{{"a", []uint64{16}, 0, 0}, {"b", []uint64{4}, 0, 32}}, 32, 96), Limits{}, CodeMalformed},
		{"смещение не выровнено", ggufBytes(3, nil, []ggufTensorDef{{"w", []uint64{4}, 0, 4}}, 32, 64), Limits{}, CodeMalformed},
		{"повтор ключа", ggufBytes(3, []ggufKV{{"a", ggufUint32, ggufU32(1)}, {"a", ggufUint32, ggufU32(2)}}, nil, 1, 0), Limits{}, CodeMalformed},
		{"повтор тензора", ggufBytes(3, nil, []ggufTensorDef{{"w", []uint64{4}, 0, 0}, {"w", []uint64{4}, 0, 32}}, 32, 64), Limits{}, CodeMalformed},
		{"вложенность массивов", ggufBytes(3, []ggufKV{{"a", ggufArray, nested}}, nil, 1, 0), Limits{}, CodeMalformed},
		{"неизвестный тип значения", ggufBytes(3, []ggufKV{{"a", 77, nil}}, nil, 1, 0), Limits{}, CodeMalformed},
		{"выравнивание не степень двойки", ggufBytes(3, []ggufKV{{"general.alignment", ggufUint32, ggufU32(24)}}, nil, 1, 0), Limits{}, CodeMalformed},
		{"пять размерностей", ggufBytes(3, nil, []ggufTensorDef{{"w", []uint64{1, 1, 1, 1, 1}, 0, 0}}, 32, 32), Limits{}, CodeMalformed},
		{"блок не кратен", ggufBytes(3, nil, []ggufTensorDef{{"w", []uint64{31}, 8, 0}}, 32, 64), Limits{}, CodeMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := scanBytes(t, "m.gguf", tc.data, tc.lim)
			if fr.Format != FormatGGUF || !fr.HasFinding(tc.code) {
				t.Fatalf("ожидалась находка %s: %+v", tc.code, fr)
			}
		})
	}
}

// --- ONNX ---

func pbKey(num, wt uint64) []byte { return binary.AppendUvarint(nil, num<<3|wt) }

func pbVarint(num, v uint64) []byte { return binary.AppendUvarint(pbKey(num, wireVarint), v) }

func pbLen(num uint64, parts ...[]byte) []byte {
	body := bytes.Join(parts, nil)
	out := binary.AppendUvarint(pbKey(num, wireLen), uint64(len(body)))
	return append(out, body...)
}

func pbStr(num uint64, s string) []byte { return pbLen(num, []byte(s)) }

func onnxOpset(domain string, version uint64) []byte {
	return pbLen(modelOpset, pbStr(opsetDomain, domain), pbVarint(2, version))
}

func onnxNode(domain, op string, attrs ...[]byte) []byte {
	parts := [][]byte{pbStr(1, "x"), pbStr(2, "y"), pbStr(nodeOpType, op)}
	if domain != "" {
		parts = append(parts, pbStr(nodeDomain, domain))
	}
	parts = append(parts, attrs...)
	return pbLen(graphNode, parts...)
}

func onnxExternalTensor(field uint64, entries ...[2]string) []byte {
	parts := [][]byte{pbVarint(1, 4), pbVarint(2, 1), pbStr(8, "w")}
	for _, e := range entries {
		parts = append(parts, pbLen(tensorExternal, pbStr(entryKey, e[0]), pbStr(entryValue, e[1])))
	}
	parts = append(parts, pbVarint(tensorLocation, locationExternal))
	return pbLen(field, parts...)
}

func onnxModelBytes(graphParts [][]byte, extra ...[]byte) []byte {
	out := pbVarint(1, 9) // ir_version
	out = append(out, pbStr(2, "synthetic")...)
	out = append(out, onnxOpset("", 17)...)
	out = append(out, onnxOpset("ai.onnx.ml", 3)...)
	out = append(out, pbLen(modelGraph, append([][]byte{pbStr(2, "g")}, graphParts...)...)...)
	for _, e := range extra {
		out = append(out, e...)
	}
	return out
}

func writeFiles(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func scanDirFile(t *testing.T, dir, rel string) FileReport {
	t.Helper()
	rep, err := New(Limits{}).ScanPath(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Files {
		if f.Path == rel {
			return f
		}
	}
	t.Fatalf("нет %s в отчёте: %+v", rel, rep)
	return FileReport{}
}

func TestONNXAccepted(t *testing.T) {
	raw := pbLen(graphInitializer, pbVarint(1, 2), pbVarint(2, 1), pbStr(8, "b"), pbLen(9, make([]byte, 8)))
	model := onnxModelBytes([][]byte{
		onnxNode("", "Relu"),
		onnxNode("ai.onnx.ml", "TreeEnsembleClassifier"),
		raw,
		onnxExternalTensor(graphInitializer, [2]string{"location", "weights/w.bin"}, [2]string{"offset", "0"}, [2]string{"length", "16"}),
	})
	dir := writeFiles(t, map[string][]byte{"onnx/model.onnx": model, "onnx/weights/w.bin": make([]byte, 16)})
	fr := scanDirFile(t, dir, "onnx/model.onnx")
	if fr.Format != FormatONNX || len(fr.Findings) != 0 {
		t.Fatalf("ONNX: %+v", fr)
	}
}

func TestONNXDomains(t *testing.T) {
	model := onnxModelBytes([][]byte{onnxNode("com.example", "Evil"), onnxNode("local.fn", "Gelu")},
		onnxOpset("com.example", 1),
		pbLen(modelFunctions, pbStr(funcName, "Gelu"), pbStr(funcDomain, "local.fn"), pbLen(funcNode, pbStr(nodeOpType, "Tanh"))))
	fr := scanBytes(t, "model.onnx", model, Limits{})
	if fr.Format != FormatONNX || !fr.HasFinding(CodeONNXDomain) || fr.Blocked() {
		t.Fatalf("домен: %+v", fr)
	}
	if len(fr.Findings) != 1 || !strings.Contains(fr.Findings[0].Detail, "com.example") || !strings.Contains(fr.Findings[0].Detail, "Evil") {
		t.Errorf("находка только по com.example: %+v", fr.Findings)
	}
}

func TestONNXExternalData(t *testing.T) {
	// Внешние данные во вложенном графе атрибута (If/Loop) тоже проверяются.
	inSubgraph := func(loc string) []byte {
		attr := pbLen(nodeAttribute, pbStr(1, "then_branch"), pbLen(attrG, onnxExternalTensor(graphInitializer, [2]string{"location", loc})))
		return onnxModelBytes([][]byte{onnxNode("", "If", attr)})
	}
	for _, loc := range []string{"/etc/passwd", "../secret.bin", "a/../../b", `..\b.bin`, "C:data.bin", "a//b", "a\x01b"} {
		fr := scanBytes(t, "model.onnx", inSubgraph(loc), Limits{})
		if !fr.HasFinding(CodeExternalData) || !fr.Blocked() {
			t.Errorf("%q: %+v", loc, fr.Findings)
		}
	}
	dir := writeFiles(t, map[string][]byte{
		"model.onnx":   inSubgraph("data.bin"),
		"short.onnx":   onnxModelBytes([][]byte{onnxExternalTensor(graphInitializer, [2]string{"location", "real.bin"}, [2]string{"offset", "8"}, [2]string{"length", "16"})}),
		"missing.onnx": onnxModelBytes([][]byte{onnxExternalTensor(graphInitializer, [2]string{"location", "none.bin"})}),
		"real.bin":     make([]byte, 16),
	})
	if err := os.Symlink(filepath.Join(dir, "real.bin"), filepath.Join(dir, "data.bin")); err != nil {
		t.Fatal(err)
	}
	if fr := scanDirFile(t, dir, "model.onnx"); !fr.HasFinding(CodeExternalData) {
		t.Errorf("символьная ссылка: %+v", fr.Findings)
	}
	if fr := scanDirFile(t, dir, "short.onnx"); !fr.HasFinding(CodeExternalData) {
		t.Errorf("за концом файла: %+v", fr.Findings)
	}
	if fr := scanDirFile(t, dir, "missing.onnx"); !fr.HasFinding(CodeExternalDataMissing) || fr.Blocked() {
		t.Errorf("нет файла: %+v", fr.Findings)
	}
	noLoc := onnxModelBytes([][]byte{onnxExternalTensor(graphInitializer, [2]string{"checksum", "x"})})
	if fr := scanBytes(t, "m.onnx", noLoc, Limits{}); !fr.HasFinding(CodeMalformed) {
		t.Errorf("без location: %+v", fr.Findings)
	}
}

func TestONNXBoundaries(t *testing.T) {
	good := onnxModelBytes([][]byte{onnxNode("", "Relu"), onnxNode("", "Relu")})
	if fr := scanBytes(t, "m.onnx", good[:len(good)-3], Limits{}); !fr.HasFinding(CodeMalformed) {
		t.Errorf("обрезанный: %+v", fr)
	}
	if fr := scanBytes(t, "m.onnx", good, Limits{MaxONNXItems: 2}); !fr.HasFinding(CodeLimitExceeded) {
		t.Errorf("предел узлов: %+v", fr.Findings)
	}
	deep := onnxNode("", "Relu")
	for range 10 {
		deep = onnxNode("", "If", pbLen(nodeAttribute, pbLen(attrG, deep)))
	}
	if fr := scanBytes(t, "m.onnx", onnxModelBytes([][]byte{deep}), Limits{MaxONNXDepth: 8}); !fr.HasFinding(CodeLimitExceeded) {
		t.Errorf("вложенность: %+v", fr.Findings)
	}
	long := onnxModelBytes([][]byte{onnxNode(strings.Repeat("d", maxONNXString+1), "X")})
	if fr := scanBytes(t, "m.onnx", long, Limits{}); !fr.HasFinding(CodeLimitExceeded) {
		t.Errorf("длинный домен: %+v", fr.Findings)
	}
	group := append(append(pbVarint(1, 9), pbStr(2, "x")...), pbKey(7, 3)...)
	group = append(group, 0, 0)
	if fr := scanBytes(t, "m.onnx", group, Limits{}); fr.Format != FormatONNX || !fr.HasFinding(CodeMalformed) {
		t.Errorf("группа protobuf: %+v", fr)
	}
}

// --- tokenizer_config.json ---

func TestTokenizerConfig(t *testing.T) {
	cfg := []byte(`{"bos_token":"<s>","chat_template":"` + strings.ReplaceAll(testTemplate, `"`, `\"`) + `","model_max_length":4096}`)
	fr := scanBytes(t, nameTokenizerConfig, cfg, Limits{})
	if fr.Format != FormatTokenizerConfig || len(fr.Findings) != 0 || len(fr.ChatTemplates) != 1 || fr.ChatTemplates[0].Text != testTemplate {
		t.Fatalf("tokenizer_config.json: %+v", fr)
	}
	list := []byte(`{"chat_template":[{"name":"default","template":"a"},{"name":"rag","template":"b"}]}`)
	if fr := scanBytes(t, nameTokenizerConfig, list, Limits{}); len(fr.ChatTemplates) != 2 || fr.ChatTemplates[1].Name != "rag" {
		t.Errorf("список шаблонов: %+v", fr)
	}
	if fr := scanBytes(t, nameChatTemplateJinja, []byte(testTemplate), Limits{}); fr.Format != FormatChatTemplate || len(fr.ChatTemplates) != 1 {
		t.Errorf("chat_template.jinja: %+v", fr)
	}
	if fr := scanBytes(t, "config.json", cfg, Limits{}); fr.Format != FormatJSON || len(fr.ChatTemplates) != 0 {
		t.Errorf("прочий JSON: %+v", fr)
	}
	cases := []struct {
		name string
		data string
		lim  Limits
		code string
	}{
		{"повтор ключа", `{"chat_template":"a","chat_template":"b"}`, Limits{}, CodeMalformed},
		{"данные после объекта", `{"chat_template":"a"} {}`, Limits{}, CodeMalformed},
		{"не JSON", `{"chat_template": `, Limits{}, CodeMalformed},
		{"шаблон не строка", `{"chat_template": 5}`, Limits{}, CodeMalformed},
		{"список без template", `{"chat_template": [{"name":"a"}]}`, Limits{}, CodeMalformed},
		{"не UTF-8", "{\"chat_template\":\"\xff\"}", Limits{}, CodeMalformed},
		{"шаблон сверх предела", `{"chat_template":"` + strings.Repeat("x", 100) + `"}`, Limits{MaxChatTemplate: 64}, CodeLimitExceeded},
		{"файл сверх предела", `{"chat_template":"a"}`, Limits{MaxTokenizerConfig: 8}, CodeLimitExceeded},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fr := scanBytes(t, nameTokenizerConfig, []byte(tc.data), tc.lim)
			if !fr.HasFinding(tc.code) || !fr.Blocked() {
				t.Fatalf("ожидалась находка %s: %+v", tc.code, fr)
			}
		})
	}
	// pickle под именем tokenizer_config.json остаётся pickle.
	if fr := scanBytes(t, nameTokenizerConfig, pickleProto2, Limits{}); !fr.HasFinding(CodePickle) {
		t.Errorf("pickle под именем конфигурации: %+v", fr)
	}
}

func FuzzGGUF(f *testing.F) {
	f.Add(goodGGUF())
	f.Add(ggufBytes(2, []ggufKV{{"a", ggufArray, ggufStrArray("x", "y")}}, nil, 1, 0))
	s := New(Limits{MaxTensors: 256, MaxGGUFMetadata: 256, MaxGGUFArray: 1024, MaxGGUFString: 4096})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr := FileReport{}
		s.scanGGUF(bytes.NewReader(data), int64(len(data)), &fr)
		for _, ct := range fr.ChatTemplates {
			if len(ct.Text) > s.limits.MaxChatTemplate {
				t.Fatal("шаблон сверх предела принят")
			}
		}
	})
}

func FuzzONNX(f *testing.F) {
	f.Add(onnxModelBytes([][]byte{onnxNode("", "Relu"), onnxExternalTensor(graphInitializer, [2]string{"location", "a.bin"})}))
	f.Add(onnxModelBytes([][]byte{onnxNode("x", "If", pbLen(nodeAttribute, pbLen(attrG, onnxNode("", "Relu"))))}))
	s := New(Limits{MaxONNXItems: 1024})
	f.Fuzz(func(t *testing.T, data []byte) {
		fr := FileReport{}
		s.scanONNX(bytes.NewReader(data), int64(len(data)), &fr)
		for _, ext := range fr.external {
			if badLocation(ext.location) != "" {
				t.Fatalf("принят путь %q", ext.location)
			}
		}
		_ = isONNX(data)
	})
}

func FuzzTokenizerConfig(f *testing.F) {
	f.Add([]byte(`{"chat_template":"{{ messages }}"}`))
	f.Add([]byte(`{"chat_template":[{"name":"a","template":"b"}]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseTokenizerConfig(data) //nolint:gosec // G104: в fuzz важна только паника
	})
}
