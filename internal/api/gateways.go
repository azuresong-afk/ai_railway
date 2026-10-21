package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/gwregistry"
)

// registerMaxBody — предел тела запроса регистрации (токен и CSR в PEM).
const registerMaxBody = 16 << 10

// gatewayRoutes — регистрация шлюза по одноразовому токену (ИАФ.10, задача
// 2.14). Маршрут открыт, как первичная настройка: у шлюза ещё нет
// сертификата, а внутренний порт без него не устанавливает TLS. Аутентификация
// — токен из aisec-cli gateway token; предел частоты — как у входа.
//
// Без Idempotency-Key: хранилище повторов запомнило бы выпущенный
// сертификат, а повтор с тем же токеном и так отклоняется.
func gatewayRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/api/v1/gateways/register", Public: true, MaxBody: registerMaxBody, Handler: d.registerGateway},
	}
}

// RegisterGatewayRequest — тело POST /api/v1/gateways/register.
type RegisterGatewayRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"`
}

// RegisterGatewayResponse — сертификат шлюза и корень внутреннего УЦ.
type RegisterGatewayResponse struct {
	GatewayID     string    `json:"gateway_id"`
	Name          string    `json:"name"`
	Certificate   string    `json:"certificate"`
	CACertificate string    `json:"ca_certificate"`
	NotAfter      time.Time `json:"not_after"`
}

func (d Deps) registerGateway(w http.ResponseWriter, r *http.Request) {
	if d.Gateways == nil {
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Регистрация шлюзов не настроена на сервере."))
		return
	}
	var req RegisterGatewayRequest
	if p := DecodeJSON(w, r, &req, registerMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	ctx, cancel := contextTimeout(r, 10*time.Second)
	defer cancel()
	reg, err := d.Gateways.Register(ctx, gwregistry.RegisterInput{Token: req.Token, CSR: []byte(req.CSR), SourceIP: clientAddr(r)})
	switch {
	case errors.Is(err, gwregistry.ErrInvalidRequest):
		WriteProblem(w, Invalid("Неверный запрос на сертификат: нужен один CSR в PEM на ключ ECDSA P-256 с верной подписью.",
			FieldError{Field: "csr", Detail: "неверный CSR"}))
	case errors.Is(err, gwregistry.ErrTokenInvalid):
		// Причина отказа (формат, срок, погашен, отозван) не раскрывается.
		WriteProblem(w, NewProblem(http.StatusForbidden, CodeForbidden, "Токен регистрации неверный, истёк или уже использован."))
	case errors.Is(err, gwregistry.ErrNoCA):
		WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Регистрация шлюзов не настроена на сервере."))
	case err != nil:
		d.Logger.Error("регистрация шлюза", "error", err)
		WriteProblem(w, errInternal())
	default:
		WriteJSON(w, http.StatusCreated, RegisterGatewayResponse{
			GatewayID: reg.Gateway.ID, Name: reg.Gateway.Name, Certificate: string(reg.CertPEM),
			CACertificate: string(reg.CAPEM), NotAfter: reg.Gateway.CertNotAfter.UTC(),
		})
	}
}
