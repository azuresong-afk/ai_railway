package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/integrity"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
	"github.com/azuresong-afk/ai_railway/internal/media/wire"
)

// mediaSelftestInterval — период самотеста aisec-media (задача 5.44): так
// сервер узнаёт и о провале после запуска, и о восстановлении анализатора.
const mediaSelftestInterval = 10 * time.Minute

// mediaAnalyze — анализ эталона самотеста клиентом aisec-media: сбой
// анализатора — ErrMediaUnavailable («не проверено»), итог — статус,
// проверки и текст.
func mediaAnalyze(c *gateway.MediaClient) selftest.MediaAnalyze {
	return func(ctx context.Context, img []byte) (selftest.MediaReply, error) {
		r, err := c.Analyze(ctx, img)
		var me *gateway.MediaError
		if errors.As(err, &me) && me.Failure() {
			return selftest.MediaReply{}, fmt.Errorf("%w: %s", selftest.ErrMediaUnavailable, me.Reason)
		}
		if err != nil {
			return selftest.MediaReply{}, err
		}
		out := selftest.MediaReply{OK: r.Result.Status == wire.StatusOK}
		for _, ch := range r.Result.Checks {
			out.Checks = append(out.Checks, string(ch))
		}
		for _, t := range r.Texts {
			out.Texts = append(out.Texts, t.Text)
		}
		return out, nil
	}
}

// runMediaSelftest — один прогон: итог в клиент (для heartbeat) и в
// технический журнал без текста эталонов.
func runMediaSelftest(ctx context.Context, c *gateway.MediaClient, logger *slog.Logger) selftest.MediaResult {
	res := selftest.RunMedia(ctx, selftest.MediaConfig{Analyze: mediaAnalyze(c), Detectors: builtin.All()})
	c.SetSelftest(gateway.MediaSelftest{Result: string(res.Status), CheckedAt: res.At, Failed: len(res.Failures)})
	attrs := []any{"class", "selftest", "check", selftest.MediaCheck, "result", string(res.Status), "vectors", res.Vectors}
	switch res.Status {
	case selftest.MediaFailed:
		logger.Error("самотест aisec-media не пройден", append(attrs, "failures", res.Failures)...)
	case selftest.MediaUnchecked:
		logger.Warn("самотест aisec-media не проверен: анализатор недоступен", attrs...)
	default:
		logger.Info("самотест aisec-media пройден", attrs...)
	}
	return res
}

// mediaSelftest — самотест aisec-media при запуске и затем каждые
// mediaSelftestInterval до отмены ctx (задача 5.44). Недоступный
// анализатор — «не проверено», не провал и не остановка запуска; неверный
// итог при запуске с реакцией stop — отказ запуска, как у ML-детекторов
// (mlSelftest). Провал после запуска — журнал и условие
// gateway_media_selftest на «Состоянии системы».
func mediaSelftest(ctx context.Context, action integrity.Action, c *gateway.MediaClient, logger *slog.Logger, interval time.Duration) error {
	res := runMediaSelftest(ctx, c, logger)
	if res.Status == selftest.MediaFailed && action == integrity.ActionStop {
		return fmt.Errorf("%w: aisec-media", selftest.ErrFailed)
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				runMediaSelftest(ctx, c, logger)
			}
		}
	}()
	return nil
}

// mediaReport — состояние клиента aisec-media для heartbeat; nil — шлюз без
// aisec-media, поле не передаётся.
func mediaReport(c *gateway.MediaClient) func() *gateway.MediaReport {
	if c == nil {
		return nil
	}
	return func() *gateway.MediaReport { return gateway.NewMediaReport(c.Stats()) }
}
