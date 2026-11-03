package selftest

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
)

// fakeMedia — анализатор-заглушка: текст эталона находит по байтам чанка
// tEXt (декодеров изображений вне internal/media нет). Настоящий разбор
// эталонов анализатором проверяет TestMediaSelftestVectorsReal в
// internal/media.
func fakeMedia(mod func(img []byte, r *MediaReply) error) MediaAnalyze {
	return func(_ context.Context, img []byte) (MediaReply, error) {
		r := MediaReply{OK: true, Checks: []string{"decode", "metadata", "qr"}}
		for _, v := range mediaVectors {
			if bytes.Contains(img, []byte("Description\x00"+v.Text)) {
				r.Texts = []string{v.Text}
			}
		}
		if mod != nil {
			if err := mod(img, &r); err != nil {
				return MediaReply{}, err
			}
		}
		return r, nil
	}
}

// Покрывает: DM-50
// Самотест aisec-media проходит на исправном анализаторе и отличает
// недоступный анализатор («не проверено») от неверного итога (провал).
func TestDM50_MediaSelftest(t *testing.T) {
	ctx := context.Background()
	res := RunMedia(ctx, MediaConfig{Analyze: fakeMedia(nil), Detectors: builtin.All(), Now: fixedNow})
	if res.Status != MediaOK || res.Vectors != len(mediaVectors) || len(res.Failures) != 0 || !res.At.Equal(fixedNow()) {
		t.Fatalf("исправный анализатор: %+v", res)
	}

	// Недоступный анализатор — не провал.
	down := fakeMedia(func([]byte, *MediaReply) error { return ErrMediaUnavailable })
	if res := RunMedia(ctx, MediaConfig{Analyze: down, Detectors: builtin.All()}); res.Status != MediaUnchecked || len(res.Failures) != 0 {
		t.Fatalf("недоступный анализатор: %+v", res)
	}
	if res := RunMedia(ctx, MediaConfig{Detectors: builtin.All()}); res.Status != MediaUnchecked {
		t.Fatalf("без анализатора: %+v", res)
	}
	// Анализатор прежней версии без текста метаданных — проверить нечем.
	old := fakeMedia(func(_ []byte, r *MediaReply) error { r.Checks, r.Texts = []string{"decode"}, nil; return nil })
	if res := RunMedia(ctx, MediaConfig{Analyze: old, Detectors: builtin.All()}); res.Status != MediaUnchecked {
		t.Fatalf("без metadata: %+v", res)
	}

	cases := []struct {
		name string
		mod  func([]byte, *MediaReply) error
		want Failure
	}{
		{"текст не извлечён", func(_ []byte, r *MediaReply) error { r.Texts = nil; return nil },
			Failure{Detector: MediaCheck, Vector: "media-meta-ov-ru-01", Problem: ProblemMissed, Category: "metadata"}},
		{"эталон отвергнут", func(_ []byte, r *MediaReply) error { r.OK = false; return nil },
			Failure{Detector: MediaCheck, Vector: "media-meta-ov-ru-01", Problem: ProblemError}},
		{"сбой разбора", func([]byte, *MediaReply) error { return errors.New("сбой") },
			Failure{Detector: MediaCheck, Vector: "media-meta-ov-ru-01", Problem: ProblemError}},
		{"паника", func([]byte, *MediaReply) error { panic("сбой") },
			Failure{Detector: MediaCheck, Vector: "media-meta-ov-ru-01", Problem: ProblemError}},
		{"инструкция в нейтральном", func(_ []byte, r *MediaReply) error {
			r.Texts = append(r.Texts, mediaVectors[0].Text)
			return nil
		}, Failure{Detector: MediaCheck, Vector: "media-meta-clean-01", Problem: ProblemUnexpected, Category: "injection.override"}},
	}
	for _, c := range cases {
		res := RunMedia(ctx, MediaConfig{Analyze: fakeMedia(c.mod), Detectors: builtin.All()})
		if res.Status != MediaFailed || !slices.Contains(res.Failures, c.want) {
			t.Errorf("%s: %+v", c.name, res)
		}
	}

	// Провал первого эталона сохраняется, даже если второй не проверен.
	n := 0
	mixed := fakeMedia(func(_ []byte, r *MediaReply) error {
		n++
		if n > 1 {
			return ErrMediaUnavailable
		}
		r.Texts = nil
		return nil
	})
	if res := RunMedia(ctx, MediaConfig{Analyze: mixed, Detectors: builtin.All()}); res.Status != MediaFailed || res.Vectors != 1 {
		t.Fatalf("провал и недоступность: %+v", res)
	}
}

// Эталоны aisec-media согласованы с корпусом: положительный — текст
// эталона ov-ru-01 детектора инструкций, отрицательный — без находок.
func TestMediaVectorsMatchDetectorVectors(t *testing.T) {
	var pos, neg bool
	for _, v := range mediaVectors {
		if len(v.Expect) == 0 {
			neg = true
			continue
		}
		pos = true
		if !slices.ContainsFunc(vectors, func(dv Vector) bool { return dv.Text == v.Text && slices.Equal(dv.Expect, v.Expect) }) {
			t.Errorf("%s: текст и ожидание не совпадают ни с одним эталоном детектора", v.ID)
		}
	}
	if !pos || !neg {
		t.Fatal("нужны положительный и отрицательный эталоны aisec-media")
	}
	png := MediaVectorPNG("x")
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) || !bytes.HasSuffix(png, []byte("IEND\xae\x42\x60\x82")) {
		t.Fatalf("эталон не PNG: % x", png)
	}
}
