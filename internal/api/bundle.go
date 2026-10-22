package api

import (
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	aisecCrypto "github.com/azuresong-afk/ai_railway/internal/crypto"
	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
	"github.com/azuresong-afk/ai_railway/internal/policy/bundle/build"
)

// Пакет конфигурации для шлюзов (решение Р7, ОЦЛ.3, задача 2.13,
// ADR-0009): GET /internal/v1/policies/bundle и отчёт шлюза о применении
// POST /internal/v1/policies/bundle/status. Только внутренний порт с mTLS:
// шлюз — из проверенного сертификата (GatewayAuthorizer). Контракт —
// api/internal-openapi.yaml.

// BundleKeyHeader — открытый ключ шлюза X25519 (base64url без
// дополнения): для него шифруются учётные данные провайдеров.
const BundleKeyHeader = "AISec-Bundle-Key"

// TrustSeqHeader — номер последнего заявления о доверии, известного шлюзу
// (ADR-0018, п. 4): сервер с более новым заявлением отдаёт пакет целиком,
// даже если версия у шлюза та же. Нет заголовка — шлюз прежней версии.
const TrustSeqHeader = "AISec-Trust-Seq"

// bundleStatusMaxBody — предел тела отчёта.
const bundleStatusMaxBody = 1 << 10

// bundleTimeout — предел сборки и выдачи пакета.
const bundleTimeout = 20 * time.Second

// BundleRoutes — маршруты пакетов для InternalOptions.Extra.
// gateways сверяет ключ получателя с закреплённым (Н27).
func BundleRoutes(svc *build.Service, gateways *gwregistry.Service, logger *slog.Logger) []Route {
	if logger == nil {
		logger = slog.Default()
	}
	return []Route{
		{Method: http.MethodGet, Path: "/internal/v1/policies/bundle", Permission: PermGatewayInternal,
			Handler: getBundle(svc, gateways, logger)},
		{Method: http.MethodPost, Path: "/internal/v1/policies/bundle/status", Permission: PermGatewayInternal,
			MaxBody: bundleStatusMaxBody, Handler: bundleStatus(svc, logger)},
	}
}

func getBundle(svc *build.Service, gateways *gwregistry.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		vals := r.Header.Values(BundleKeyHeader)
		var key []byte
		if len(vals) == 1 && len(vals[0]) <= 64 {
			key, _ = base64.RawURLEncoding.Strict().DecodeString(vals[0]) //nolint:gosec // G104: неверная запись даёт ключ не той длины, и проверка ниже отвечает 400
		}
		if len(key) != aisecCrypto.RecipientPublicKeySize {
			WriteProblem(w, Invalid("Нужен заголовок "+BundleKeyHeader+": открытый ключ шлюза X25519, 32 байта в base64url без дополнения."))
			return
		}
		trustSeq := int64(-1)
		if vals := r.Header.Values(TrustSeqHeader); len(vals) > 0 {
			n, err := strconv.ParseInt(vals[0], 10, 64)
			if len(vals) > 1 || err != nil || n < 0 || len(vals[0]) > 19 {
				WriteProblem(w, Invalid("Заголовок "+TrustSeqHeader+" — один, номер заявления о доверии, целое число от 0."))
				return
			}
			trustSeq = n
		}
		ctx, cancel := contextTimeout(r, bundleTimeout)
		defer cancel()
		// Секреты шифруются только для закреплённого ключа (Н27).
		if gateways != nil {
			err := gateways.CheckBundleKey(ctx, p.ID, key, clientAddr(r))
			switch {
			case errors.Is(err, gwregistry.ErrBundleKeyMismatch):
				WriteProblem(w, NewProblem(http.StatusConflict, CodeBundleKeyMismatch,
					"Ключ получателя шлюза не совпадает с закреплённым при регистрации. Сменить ключ можно только перерегистрацией шлюза."))
				return
			case errors.Is(err, gwregistry.ErrNotFound):
				WriteProblem(w, errUnauthorized())
				return
			case err != nil:
				logger.Error("ключ получателя шлюза не сверен", "gateway_id", p.ID, "error", err)
				WriteProblem(w, errInternal())
				return
			}
		}
		d, err := svc.Deliver(ctx, build.Gateway{ID: p.ID, IP: clientAddr(r)}, key, r.Header.Get("If-None-Match"), trustSeq)
		switch {
		case errors.Is(err, build.ErrNoBundle):
			w.Header().Set("Retry-After", "60")
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable,
				"Корректного пакета конфигурации ещё нет: проверьте приложения и политики в консоли."))
			return
		case err != nil:
			logger.Error("пакет конфигурации не выдан", "gateway_id", p.ID, "error", err)
			WriteProblem(w, errInternal())
			return
		}
		h := w.Header()
		h.Set("ETag", d.ETag)
		h.Set("Cache-Control", "no-store")
		if d.NotModified {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		h.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(d.Body) //nolint:gosec // G104: клиент ушёл — писать больше некуда
	}
}

// BundleStatusRequest — тело отчёта шлюза о пакете.
type BundleStatusRequest struct {
	Result  string `json:"result"`
	Version int64  `json:"version"`
	Reason  string `json:"reason,omitempty"`
}

func bundleStatus(svc *build.Service, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, _ := PrincipalFrom(r.Context())
		var req BundleStatusRequest
		if prob := DecodeJSON(w, r, &req, bundleStatusMaxBody); prob != nil {
			WriteProblem(w, prob)
			return
		}
		rep := build.Report{Result: req.Result, Version: req.Version, Reason: req.Reason}
		if rep.Validate() != nil {
			WriteProblem(w, Invalid("Отчёт о пакете: result — applied или rejected, version — номер версии, reason — причина отказа из перечня (только для rejected)."))
			return
		}
		ctx, cancel := contextTimeout(r, 5*time.Second)
		defer cancel()
		if err := svc.RecordReport(ctx, build.Gateway{ID: p.ID, IP: clientAddr(r)}, rep); err != nil {
			logger.Error("отчёт шлюза о пакете не записан", "gateway_id", p.ID, "error", err)
			WriteProblem(w, errInternal())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
