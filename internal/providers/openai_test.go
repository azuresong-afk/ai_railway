package providers

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/chat"
)

func newTestProvider(t *testing.T, base string, key string) *OpenAI {
	t.Helper()
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	p, err := NewOpenAI(OpenAIConfig{ID: "p", BaseURL: u, Key: key, Transport: &http.Transport{Proxy: nil}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestNewOpenAI(t *testing.T) {
	u, err := url.Parse("https://llm.example/v1/?x=1#f")
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{}
	p, err := NewOpenAI(OpenAIConfig{ID: "p", BaseURL: u, Transport: tr})
	if err != nil || p.endpoint != "https://llm.example/v1/chat/completions" || p.ID() != "p" {
		t.Fatalf("%v %s", err, p.endpoint)
	}
	for name, c := range map[string]OpenAIConfig{
		"без id":          {BaseURL: u, Transport: tr},
		"без адреса":      {ID: "p", Transport: tr},
		"без транспорта":  {ID: "p", BaseURL: u},
		"ключ с \\n":      {ID: "p", BaseURL: u, Transport: tr, Key: "a\nX-Evil: 1"},
		"ключ с пробелом": {ID: "p", BaseURL: u, Transport: tr, Key: "a b"},
	} {
		if _, err := NewOpenAI(c); err == nil {
			t.Errorf("%s: ожидалась ошибка", name)
		}
	}
}

func TestProviderErrorParsing(t *testing.T) {
	cases := []struct {
		status        int
		body          string
		wantStatus    int
		wantCode, msg string
	}{
		{429, `{"error":{"message":"Slow down","type":"requests","code":"rate_limit_exceeded"}}`, 429, "rate_limit_exceeded", "Slow down"},
		{400, `{"error":{"message":"bad\u0000\nthing","code":400}}`, 400, "upstream_error", "bad  thing"},
		{500, `<html>oops</html>`, 500, "upstream_error", "ошибка провайдера модели"},
		{400, `{"error":{"message":"x","code":"evil code with spaces"}}`, 400, "upstream_error", "x"},
		{302, ``, 502, "upstream_error", "ошибка провайдера модели"},
		{400, `{"error":{"message":"` + strings.Repeat("я", 1000) + `"}}`, 400, "upstream_error", strings.Repeat("я", maxErrorMessage) + "…"},
	}
	for _, c := range cases {
		resp := &http.Response{StatusCode: c.status, Body: io.NopCloser(strings.NewReader(c.body))}
		var e *Error
		if !errors.As(providerError(resp), &e) || e.Status != c.wantStatus || e.Code != c.wantCode || e.Message != c.msg {
			t.Errorf("%d %s: %+v", c.status, c.body, e)
		}
	}
}

func TestMetaFiltersHeaders(t *testing.T) {
	m := metaFrom(http.Header{"Retry-After": {"5"}, "Set-Cookie": {"s=1"}, "X-Ratelimit-Remaining-Tokens": {"1\r\nX: y"},
		"X-Ratelimit-Limit-Requests": {strings.Repeat("9", 200)}})
	if len(m.Header) != 1 || m.Header.Get("Retry-After") != "5" {
		t.Fatalf("%v", m.Header)
	}
}

func TestStreamEndsAndTruncation(t *testing.T) {
	body := "event: ping\ndata: {}\n\n" + `data: {"choices":[{"index":0,"delta":{"content":"a"}}]}` + "\n\n"
	for name, c := range map[string]struct {
		tail string
		want error // nil — ожидается *Error с текстом boom
	}{
		"штатно": {"data: [DONE]\n\n", io.EOF},
		"обрыв":  {"", ErrTruncated},
		"ошибка": {`data: {"error":{"message":"boom"}}` + "\n\n", nil},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, body+c.tail) //nolint:errcheck,gosec // тестовый провайдер
		}))
		p := newTestProvider(t, srv.URL, "")
		st, _, err := p.Stream(context.Background(), &chat.Request{Model: "m"})
		if err != nil {
			t.Fatal(err)
		}
		ch, err := st.Next()
		if err != nil || *ch.Choices[0].Delta.Content != "a" {
			t.Fatalf("%s: первая часть %v", name, err)
		}
		_, err = st.Next()
		var pe *Error
		if c.want == nil {
			if !errors.As(err, &pe) || pe.Message != "boom" {
				t.Errorf("%s: %v", name, err)
			}
		} else if !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
		if err := st.Close(); err != nil {
			t.Error(err)
		}
		srv.Close()
	}
}
