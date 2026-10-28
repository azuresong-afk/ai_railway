package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
	"github.com/azuresong-afk/ai_railway/internal/license"
)

// licenseMaxBody — тело PUT /api/v1/license: файл лицензии (до 16 КиБ)
// строкой JSON с экранированием и поля повторной проверки.
const licenseMaxBody = 64 << 10

// licenseRoutes — лицензия (ТЗ 5.15; задача 4.27, ADR-0026, п. 6):
// сведения — администраторы и аудитор, загрузка и замена — с повторной
// проверкой паролем или кодом TOTP в сессии консоли.
func licenseRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/api/v1/license", Permission: auth.PermLicenseRead, Handler: needLicense(d, d.getLicense)},
		{Method: http.MethodPut, Path: "/api/v1/license", Permission: auth.PermLicenseManage, MaxBody: licenseMaxBody,
			Handler: needLicense(d, d.putLicense)},
	}
}

func needLicense(d Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.License == nil {
			WriteProblem(w, NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Лицензирование не подключено на сервере."))
			return
		}
		h(w, r)
	}
}

func (d Deps) getLicense(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextTimeout(r, storeCheckTimeout)
	defer cancel()
	v, err := d.License.Info(ctx)
	if err != nil {
		WriteProblem(w, licenseUploadProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// putLicenseRequest — тело PUT /api/v1/license: текст файла лицензии и
// текущий пароль или код TOTP.
type putLicenseRequest struct {
	License string `json:"license"`
	reauthFields
}

func (d Deps) putLicense(w http.ResponseWriter, r *http.Request) {
	a, ok := actorOf(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req putLicenseRequest
	if p := DecodeJSON(w, r, &req, licenseMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if req.License == "" || len(req.License) > license.MaxFileSize {
		WriteProblem(w, Invalid("Выберите файл лицензии (*.aiseclic, до 16 КиБ).",
			FieldError{Field: "license", Detail: "нет файла или больше 16 КиБ"}))
		return
	}
	by := license.By{Actor: a.Actor, IP: a.IP, Confirm: d.confirmFunc(r, req.reauthFields, "license.load", license.ErrConfirmRequired)}
	ctx, cancel := context.WithTimeout(r.Context(), storeCheckTimeout)
	defer cancel()
	v, err := d.License.Upload(ctx, by, []byte(req.License))
	if err != nil {
		WriteProblem(w, licenseUploadProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, v)
}

// licenseUploadProblem переводит ошибки лицензии в ответы API.
func licenseUploadProblem(logger *slog.Logger, err error) *Problem {
	var re *reauthError
	var rej *license.Rejected
	switch {
	case errors.As(err, &re):
		return authProblem(logger, re.err)
	case errors.Is(err, license.ErrConfirmRequired):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"Лицензию загружает администратор в консоли с вводом текущего пароля или кода: токеном API её не загрузить.")
	case errors.As(err, &rej):
		if rej.Reason == license.ReasonDuplicate || rej.Reason == license.ReasonStaleNumber || rej.Reason == license.ReasonStaleIssued {
			return NewProblem(http.StatusConflict, CodeConflict, licenseRejectText(rej))
		}
		return NewProblem(http.StatusUnprocessableEntity, CodeUnprocessable, licenseRejectText(rej))
	}
	logger.Error("лицензия: ошибка обработки запроса", "error", err)
	return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Не удалось прочитать или сохранить лицензию: повторите позже.")
}

func licenseRejectText(rej *license.Rejected) string {
	switch rej.Reason {
	case license.ReasonSignature:
		return "Подпись лицензии или заверения ключа неверна: файл изменён или выпущен не производителем."
	case license.ReasonPurpose:
		return "Файл подписан ключом не для лицензий: запросите лицензию у производителя."
	case license.ReasonSubkeyTerm:
		return "Срок ключа, которым подписана лицензия, истёк или ещё не начался: запросите лицензию, подписанную действующим ключом."
	case license.ReasonRevoked:
		return "Ключ, которым подписана лицензия, отозван производителем: запросите новую лицензию."
	case license.ReasonIssuedDate:
		return "Дата выдачи лицензии вне срока ключа, которым она подписана: запросите новую лицензию."
	case license.ReasonClock:
		return "Лицензия выдана позже текущего времени сервера: проверьте часы сервера (синхронизация времени) и повторите."
	case license.ReasonNotYetValid:
		return "Срок лицензии ещё не начался: загрузите её в первый день срока."
	case license.ReasonExpired:
		return "Срок лицензии уже истёк: загрузите действующую лицензию."
	case license.ReasonDuplicate:
		return "Эта лицензия уже загружена."
	case license.ReasonStaleNumber:
		return fmt.Sprintf("Номер лицензии меньше загруженной (№ %d): заменить лицензию можно только на более новую.", rej.Current)
	case license.ReasonStaleIssued:
		return fmt.Sprintf("Лицензия выдана раньше загруженной (№ %d): заменить лицензию можно только на более новую.", rej.Current)
	}
	return "Файл не является лицензией AISec или повреждён: выберите файл *.aiseclic, полученный от производителя."
}
