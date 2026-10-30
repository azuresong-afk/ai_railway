package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"

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
