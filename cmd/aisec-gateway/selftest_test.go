package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/config"
	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/detect/builtin"
	"github.com/azuresong-afk/ai_railway/internal/gateway"
	"github.com/azuresong-afk/ai_railway/internal/integrity/selftest"
)

// 4.28, остаток ревью 4.r4: эталоны ML-детекторов прогоняются повторно с
// клиентом aisec-ml; недоступный aisec-ml — ml_unavailable, а не провал и
// не остановка запуска при реакции stop.
func TestMLSelftestRerunsWithClient(t *testing.T) {
	p, err := aisecCrypto.New(aisecCrypto.ProfileStandard)
	if err != nil {
		t.Fatal(err)
	}
	c, err := gateway.NewMLClient(gateway.MLClientConfig{Socket: filepath.Join(t.TempDir(), "ml.sock")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	first := selftest.Result{CryptoOK: true}
	if err := mlSelftest(context.Background(), &config.Gateway{SelftestAction: "stop"}, p, c, logger, &gateway.Reports{}, first); err != nil {
		t.Fatalf("недоступный aisec-ml остановил запуск: %v", err)
	}
	var rec struct {
		Msg           string `json:"msg"`
		Detectors     int    `json:"detectors"`
		MLUnavailable int    `json:"ml_unavailable"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("журнал: %v %s", err, buf.String())
	}
	if rec.Msg != "самотестирование пройдено" || rec.Detectors != len(builtin.MLSpecs()) || rec.MLUnavailable == 0 {
		t.Fatalf("итог повторного прогона: %+v", rec)
	}
}

// Задача 5.44: самотест aisec-media при недоступном анализаторе — «не
// проверено», не провал и не остановка запуска при реакции stop; итог —
// в состоянии клиента для heartbeat.
func TestMediaSelftestUncheckedDoesNotStop(t *testing.T) {
	c, err := gateway.NewMediaClient(gateway.MediaClientConfig{Socket: filepath.Join(t.TempDir(), "media.sock")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := mediaSelftest(ctx, "stop", c, slog.New(slog.DiscardHandler), time.Hour); err != nil {
		t.Fatalf("недоступный aisec-media остановил запуск: %v", err)
	}
	st := c.Stats().Selftest
	if st == nil || st.Result != gateway.MediaSelftestUnchecked || st.Failed != 0 || st.CheckedAt.IsZero() {
		t.Fatalf("итог самотеста: %+v", st)
	}
	if r := mediaReport(c)(); r.Selftest == nil || r.Selftest.Result != "unchecked" {
		t.Fatalf("отчёт heartbeat: %+v", r)
	}
	if mediaReport(nil) != nil {
		t.Fatal("шлюз без aisec-media передаёт media")
	}
}
