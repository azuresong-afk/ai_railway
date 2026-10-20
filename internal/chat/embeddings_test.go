package chat

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseEmbeddings(t *testing.T) {
	r, err := ParseEmbeddings([]byte(`{"model":"emb-1","input":"привет","user":"u1","dimensions":256,"encoding_format":"float"}`))
	if err != nil || r.Model != "emb-1" || !slices.Equal(r.Input, []string{"привет"}) || *r.Dimensions != 256 || r.User != "u1" {
		t.Fatalf("%+v %v", r, err)
	}
	r, err = ParseEmbeddings([]byte(`{"model":"emb-1","input":["а","б"]}`))
	if err != nil || !slices.Equal(r.Input, []string{"а", "б"}) {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestParseEmbeddingsRejects(t *testing.T) {
	many := `["` + strings.Repeat(`a","`, MaxEmbeddingInputs) + `a"]`
	for name, c := range map[string]struct{ body, code string }{
		"токены":                  {`{"model":"m","input":[1,2]}`, CodeInvalid},
		"массивы токенов":         {`{"model":"m","input":[[1],[2]]}`, CodeInvalid},
		"пустая строка":           {`{"model":"m","input":[""]}`, CodeInvalid},
		"нет input":               {`{"model":"m"}`, CodeInvalid},
		"нет модели":              {`{"input":"x"}`, CodeInvalid},
		"плохая модель":           {`{"model":"a b","input":"x"}`, CodeInvalid},
		"base64":                  {`{"model":"m","input":"x","encoding_format":"base64"}`, CodeUnsupported},
		"неизвестное поле":        {`{"model":"m","input":"x","foo":1}`, CodeUnsupported},
		"dimensions вне пределов": {`{"model":"m","input":"x","dimensions":70000}`, CodeInvalid},
		"слишком много строк":     {`{"model":"m","input":` + many + `}`, CodeTooMany},
		"длинный user":            {`{"model":"m","input":"x","user":"` + strings.Repeat("u", 300) + `"}`, CodeInvalid},
		"не объект":               {`[]`, CodeInvalid},
		"тип поля":                {`{"model":5,"input":"x"}`, CodeInvalid},
	} {
		_, err := ParseEmbeddings([]byte(c.body))
		var ce *Error
		if !errors.As(err, &ce) || ce.Code != c.code {
			t.Errorf("%s: %v, ожидался код %s", name, err, c.code)
		}
	}
}

func TestParseEmbeddingResponse(t *testing.T) {
	good := `{"object":"list","data":[{"index":0,"embedding":[0.1,0.2]},{"index":1,"embedding":[0.3]}],"model":"m","usage":{"prompt_tokens":4,"total_tokens":4},"x":1}`
	r, err := ParseEmbeddingResponse([]byte(good), 2)
	if err != nil || r.Object != "list" || r.Data[0].Object != "embedding" || r.Usage.TotalTokens != 4 {
		t.Fatalf("%+v %v", r, err)
	}
	for name, body := range map[string]string{
		"не JSON":                      `x`,
		"мало векторов":                good[:0] + `{"data":[{"index":0,"embedding":[1]}]}`,
		"пустой вектор":                `{"data":[{"index":0,"embedding":[]},{"index":1,"embedding":[1]}]}`,
		"неверный индекс":              `{"data":[{"index":1,"embedding":[1]},{"index":0,"embedding":[1]}]}`,
		"строка вместо чисел (base64)": `{"data":[{"index":0,"embedding":"AAAA"},{"index":1,"embedding":[1]}]}`,
	} {
		if _, err := ParseEmbeddingResponse([]byte(body), 2); err == nil {
			t.Errorf("%s: принят", name)
		}
	}
}

func FuzzParseEmbeddings(f *testing.F) {
	for _, s := range []string{
		`{"model":"m","input":"x"}`, `{"model":"m","input":["a","b"],"dimensions":8}`, `{"model":"m","input":[1]}`,
		`{"model":"m","input":null}`, `{}`, `[]`, `null`, `{"model":"m","input":"x"}{}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		r, err := ParseEmbeddings(body)
		if err != nil {
			var ce *Error
			if r != nil || !errors.As(err, &ce) || ce.Code == "" || ce.Message == "" {
				t.Fatalf("ошибка не в формате: %v", err)
			}
			return
		}
		if len(r.Input) == 0 || len(r.Input) > MaxEmbeddingInputs || slices.Contains(r.Input, "") || !modelRe.MatchString(r.Model) {
			t.Fatalf("принят неверный запрос: %+v", r)
		}
	})
}

func FuzzParseEmbeddingResponse(f *testing.F) {
	f.Add([]byte(`{"data":[{"index":0,"embedding":[1,2]}]}`), 1)
	f.Add([]byte(`{}`), 0)
	f.Fuzz(func(t *testing.T, body []byte, n int) {
		r, err := ParseEmbeddingResponse(body, n)
		if err != nil {
			return
		}
		if len(r.Data) != n {
			t.Fatalf("векторов %d, строк %d", len(r.Data), n)
		}
		for i, d := range r.Data {
			if d.Index != i || len(d.Embedding) == 0 {
				t.Fatalf("вектор %d: %+v", i, d)
			}
		}
	})
}
