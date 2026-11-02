package gateway

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

// Разбор частей запроса с изображениями (задача 5.39): что шлюз берёт из
// запроса и что передаёт aisec-media. Сами изображения шлюз не декодирует —
// только base64.

func TestDecodeImage(t *testing.T) {
	raw := []byte{0x89, 'P', 'N', 'G', 0xfb, 0xff, 0x00, 0x01}
	for _, tc := range []struct {
		name, data string
		max        int64
		want       error
	}{
		{"стандартный с выравниванием", base64.StdEncoding.EncodeToString(raw), 64, nil},
		{"стандартный без выравнивания", base64.RawStdEncoding.EncodeToString(raw), 64, nil},
		{"URL-алфавит", base64.URLEncoding.EncodeToString(raw), 64, nil},
		{"URL-алфавит без выравнивания", base64.RawURLEncoding.EncodeToString(raw), 64, nil},
		{"ровно предел", base64.StdEncoding.EncodeToString(raw), int64(len(raw)), nil},
		{"на байт больше предела", base64.StdEncoding.EncodeToString(raw), int64(len(raw)) - 1, errImageTooLarge},
		{"пусто", "", 64, errImageMalformed},
		{"символ вне алфавита", "iVBO*w0K", 64, errImageMalformed},
		{"пробел", "iVBO w0K", 64, errImageMalformed},
		{"смешанные алфавиты", "+_AA", 64, errImageMalformed},
		{"лишние биты", "iVC=", 64, errImageMalformed},
		{"неполная группа", "i", 64, errImageMalformed},
		{"только выравнивание", "====", 64, errImageMalformed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := decodeImage(tc.data, tc.max)
			if !errors.Is(err, tc.want) {
				t.Fatalf("ошибка %v, ожидалась %v", err, tc.want)
			}
			if tc.want == nil && !bytes.Equal(b, raw) {
				t.Fatalf("данные: %x", b)
			}
		})
	}
}

// Предел проверяется до раскодирования: строка в 1 МиБ при пределе 16 байт
// отвергается без выделения памяти под результат.
func TestDecodeImageLimitBeforeDecode(t *testing.T) {
	data := strings.Repeat("A", 1<<20)
	if allocs := testing.AllocsPerRun(10, func() {
		if _, err := decodeImage(data, 16); !errors.Is(err, errImageTooLarge) {
			t.Fatal(err)
		}
	}); allocs > 1 {
		t.Fatalf("выделений памяти: %v", allocs)
	}
}

func TestChatImages(t *testing.T) {
	body := `{"model":"m","messages":[
		{"role":"system","content":"Ты помощник"},
		{"role":"user","content":[
			{"type":"text","text":"Что здесь?"},
			{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}},
			{"type":"image_url","image_url":{"url":"https://example.test/a.png","detail":"low"}},
			{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}
		]},
		{"role":"user","content":[{"type":"image_url","image_url":{"url":"DATA:image/jpeg;BASE64,/9j/"}}]}
	]}`
	req, err := chat.Parse([]byte(body), chat.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	got := chatImages(req)
	want := []mediaImage{
		{Location: "messages[1].content[1]", Message: 1, Part: 1, Data: "iVBORw0KGgo="},
		{Location: "messages[1].content[2]", Message: 1, Part: 2, URL: true},
		{Location: "messages[2].content[0]", Message: 2, Part: 0, Data: "/9j/"},
	}
	if len(got) != len(want) {
		t.Fatalf("изображения: %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("[%d]: %+v, ожидалось %+v", i, got[i], want[i])
		}
	}
}

func TestDataURLPayload(t *testing.T) {
	for u, want := range map[string]string{
		"data:image/png;base64,QUJD": "QUJD",
		"Data:image/png;Base64,QUJD": "QUJD",
		"data:;base64,":              "",
	} {
		if got, ok := dataURLPayload(u); !ok || got != want {
			t.Fatalf("%q: %q %v", u, got, ok)
		}
	}
	for _, u := range []string{"https://x.test/a.png", "data:image/png,QUJD", "data:image/png;base64QUJD", "dat", ""} {
		if _, ok := dataURLPayload(u); ok {
			t.Fatalf("%q принят как data:-адрес", u)
		}
	}
}

// FuzzMediaParts — разбор частей запроса чата с изображениями: каждая
// часть image_url из chat.Parse становится ровно одним изображением с тем
// же местом; данные base64 раскодируются только в пределах maxBytes.
func FuzzMediaParts(f *testing.F) {
	for _, s := range []string{
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,iVBORw0KGgo="}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"text","text":"x"},{"type":"image_url","image_url":{"url":"https://a.test/x.png"}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/jpeg;base64,_-8"}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:;base64,===="}}]}]}`,
		`{"model":"m","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`,
	} {
		f.Add([]byte(s), int64(64))
	}
	f.Fuzz(func(t *testing.T, body []byte, maxBytes int64) {
		req, err := chat.Parse(body, chat.Limits{MaxMediaBytes: 1 << 16})
		if err != nil {
			return
		}
		imgs := chatImages(req)
		var want []chat.Media
		for _, m := range req.Media() {
			if m.Kind == chat.MediaImage {
				want = append(want, m)
			}
		}
		if len(imgs) != len(want) {
			t.Fatalf("изображений %d, частей image_url %d", len(imgs), len(want))
		}
		for i, img := range imgs {
			if img.Message != want[i].Message || img.Part != want[i].Part || img.Location == "" {
				t.Fatalf("место: %+v, часть %+v", img, want[i])
			}
			if img.URL && img.Data != "" {
				t.Fatalf("ссылка с данными: %+v", img)
			}
			b, err := decodeImage(img.Data, maxBytes)
			if err != nil {
				if !errors.Is(err, errImageTooLarge) && !errors.Is(err, errImageMalformed) {
					t.Fatalf("ошибка без причины: %v", err)
				}
				continue
			}
			if img.URL || int64(len(b)) > maxBytes || len(b) == 0 {
				t.Fatalf("раскодировано %d байт при пределе %d: %+v", len(b), maxBytes, img)
			}
		}
	})
}
