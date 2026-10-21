package api

import (
	"net/http"

	"github.com/azuresong-afk/ai_railway/internal/auth"
)

// mfaRoutes — второй фактор входа TOTP (ИАФ.5; задача 2.8). Подключение,
// подтверждение и вход вторым фактором доступны сессии до полного входа
// (право session), состояние сессии проверяет сервис. Пути под
// /api/v1/auth/ — со строгим пределом частоты входа (ЗИ.6).
func mfaRoutes(d Deps) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/api/v1/auth/mfa/setup", Permission: auth.PermSession, MaxBody: authMaxBody, Handler: needAuth(d, d.mfaSetup)},
		{Method: http.MethodPost, Path: "/api/v1/auth/mfa/setup/confirm", Permission: auth.PermSession, MaxBody: authMaxBody, Handler: needAuth(d, d.mfaConfirm)},
		{Method: http.MethodPost, Path: "/api/v1/auth/mfa/verify", Permission: auth.PermSession, MaxBody: authMaxBody, Handler: needAuth(d, d.mfaVerify)},
		{Method: http.MethodPost, Path: "/api/v1/auth/mfa/recovery-codes", Permission: auth.PermSession, MaxBody: authMaxBody, Handler: needAuth(d, d.mfaRecoveryCodes)},
		{Method: http.MethodPost, Path: "/api/v1/users/{id}/mfa/reset", Permission: auth.PermUsersManage, Handler: needAuth(d, d.mfaReset)},
	}
}

// maxCodeInput — предел полей кодов до разбора (код TOTP — 6 цифр, код
// восстановления — 16 символов с дефисами).
const maxCodeInput = 64

// MFASetup — данные для приложения-аутентификатора; показываются один раз.
type MFASetup struct {
	Secret string `json:"secret"`
	URI    string `json:"otpauth_uri"`
	// QR — матрица модулей QR-кода: строка на ряд, «1» — тёмный модуль.
	QR []string `json:"qr"`
}

// RecoveryCodes — коды восстановления (показываются один раз) и состояние сессии.
type RecoveryCodes struct {
	RecoveryCodes []string `json:"recovery_codes"`
	SessionState  string   `json:"session_state"`
}

// mfaSetupRequest — в полной сессии нужен текущий пароль; в сессии
// mfa_setup поле не нужно (пароль только что введён при входе).
type mfaSetupRequest struct {
	CurrentPassword string `json:"current_password"`
}

type mfaCodeRequest struct {
	Code string `json:"code"`
}

type mfaVerifyRequest struct {
	Code         string `json:"code"`
	RecoveryCode string `json:"recovery_code"`
}

func (d Deps) mfaSetup(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req mfaSetupRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if c.Session.State == auth.SessionActive && req.CurrentPassword == "" {
		WriteProblem(w, Invalid("Введите текущий пароль.", FieldError{"current_password", "Введите текущий пароль."}))
		return
	}
	en, err := d.Auth.StartMFA(r.Context(), c, req.CurrentPassword)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, MFASetup{Secret: en.Secret, URI: en.URI, QR: en.QR})
}

// readCode разбирает тело с кодом TOTP.
func readCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req mfaCodeRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return "", false
	}
	if req.Code == "" || len(req.Code) > maxCodeInput {
		WriteProblem(w, Invalid("Введите код из приложения.", FieldError{"code", "Введите код из приложения."}))
		return "", false
	}
	return req.Code, true
}

func (d Deps) mfaConfirm(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	code, ok := readCode(w, r)
	if !ok {
		return
	}
	res, err := d.Auth.ConfirmMFA(r.Context(), c, code)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	// Сессия до второго фактора заменена полной — новые cookie.
	if res.Token != "" {
		setSessionCookies(w, res.Token, res.CSRF)
	}
	WriteJSON(w, http.StatusOK, RecoveryCodes{RecoveryCodes: res.RecoveryCodes, SessionState: string(res.Caller.Session.State)})
}

func (d Deps) mfaVerify(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	var req mfaVerifyRequest
	if p := DecodeJSON(w, r, &req, authMaxBody); p != nil {
		WriteProblem(w, p)
		return
	}
	if (req.Code == "") == (req.RecoveryCode == "") || len(req.Code) > maxCodeInput || len(req.RecoveryCode) > maxCodeInput {
		WriteProblem(w, Invalid("Введите код из приложения или код восстановления.",
			FieldError{"code", "Нужен ровно один код: из приложения или код восстановления."}))
		return
	}
	res, err := d.Auth.VerifyMFA(r.Context(), c, req.Code, req.RecoveryCode)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	setSessionCookies(w, res.Token, res.CSRF)
	d.writeMe(w, r, res.Caller)
}

func (d Deps) mfaRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	code, ok := readCode(w, r)
	if !ok {
		return
	}
	codes, err := d.Auth.RegenerateRecoveryCodes(r.Context(), c, code)
	if err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	WriteJSON(w, http.StatusOK, RecoveryCodes{RecoveryCodes: codes, SessionState: string(c.Session.State)})
}

func (d Deps) mfaReset(w http.ResponseWriter, r *http.Request) {
	c, ok := callerFrom(r)
	if !ok {
		WriteProblem(w, errForbidden())
		return
	}
	id, ok := pathUserID(w, r)
	if !ok {
		return
	}
	if err := d.Auth.ResetMFA(r.Context(), c, id); err != nil {
		WriteProblem(w, authProblem(d.Logger, err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
