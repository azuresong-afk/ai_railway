package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/azuresong-afk/ai_railway/internal/license"
)

// Ограничения лицензии в маршрутизаторе (ТЗ 5.15; ADR-0026, п. 5). Каждый
// изменяющий маршрут консоли с проверкой прав проходит одну проверку до
// обработчика: после льготного периода и при недействительной лицензии —
// отказ license_restricted, выключенный в лицензии модуль — license_module.
// Пропускаются только маршруты из явного списка licenseExempt; новый
// изменяющий маршрут без строки в нём проверку проходит, то есть запрещён
// (TestLicenseGateNewMutatingRoute). Маршруты /internal/ (трафик шлюзов) и
// открытые (вход, первичная настройка, регистрация шлюза по токену)
// конфигурацию из консоли не меняют и не проверяются; предел шлюзов при
// регистрации проверяет реестр шлюзов.

// LicenseGate — проверка изменяющего запроса (license.Service).
type LicenseGate interface {
	// CheckMutation — nil, если изменение можно выполнить; *license.Denied —
	// отказ с причиной; другая ошибка — лицензию проверить не удалось.
	CheckMutation(ctx context.Context, module string) error
	// CheckModule — проверка только модуля (маршрут из списка исключений).
	CheckModule(ctx context.Context, module string) error
}

// licenseExempt — изменяющие маршруты, которые работают и после льготного
// периода (ADR-0026, п. 5): ключ — «МЕТОД шаблон», значение — почему.
var licenseExempt = map[string]string{ //nolint:gosec // G101: пути API и причины исключений, не учётные данные
	// Вход и своя учётная запись.
	"POST /api/v1/auth/logout":                   "выход",
	"POST /api/v1/auth/password":                 "смена своего пароля",
	"POST /api/v1/auth/mfa/setup":                "свой второй фактор",
	"POST /api/v1/auth/mfa/setup/confirm":        "свой второй фактор",
	"POST /api/v1/auth/mfa/verify":               "вход: второй фактор",
	"POST /api/v1/auth/mfa/recovery-codes":       "свои коды восстановления",
	"PUT /api/v1/me/email":                       "свой e-mail",
	"PUT /api/v1/license":                        "загрузка новой лицензии",
	"POST /api/v1/system/integrity/verify":       "проверка целостности по команде",
	"POST /api/v1/audit/verify":                  "проверка цепочки аудита по команде",
	"POST /api/v1/events/{id}/content":           "просмотр содержимого события",
	"POST /api/v1/events/export":                 "выгрузка событий",
	"POST /api/v1/events/filters":                "сохранённый фильтр событий (личная настройка просмотра)",
	"DELETE /api/v1/events/filters/{id}":         "сохранённый фильтр событий (личная настройка просмотра)",
	"PUT /api/v1/events/{id}/mark":               "отметка события аналитиком",
	"POST /api/v1/policies/test":                 "песочница политик ничего не меняет",
	"POST /api/v1/alerts/{id}/status":            "разбор оповещения",
	"POST /api/v1/incidents":                     "расследование: создание инцидента",
	"POST /api/v1/incidents/{id}/status":         "расследование: статус инцидента",
	"PUT /api/v1/incidents/{id}/assignee":        "расследование: назначение",
	"POST /api/v1/incidents/{id}/comments":       "расследование: комментарий",
	"POST /api/v1/incidents/{id}/stages/{stage}": "расследование: этап реагирования",
	"POST /api/v1/incidents/{id}/alerts":         "расследование: привязка оповещений",
	"POST /api/v1/approvals/{id}/approve":        "решение по вызову агента (трафик)",
	"POST /api/v1/approvals/{id}/deny":           "решение по вызову агента (трафик)",
	"POST /api/v1/notify-channels/{id}/test":     "тестовая отправка",
	"POST /api/v1/shadow-ai/imports":             "приём журналов прокси (данные, не настройка)",
	"POST /api/v1/users/{id}/deactivate":         "снижение доступа: деактивация пользователя",
	"DELETE /api/v1/users/{id}/sessions":         "снижение доступа: завершение сессий",
	"POST /api/v1/users/{id}/password-reset":     "восстановление доступа: сброс пароля",
	"POST /api/v1/users/{id}/mfa/reset":          "восстановление доступа: сброс второго фактора",
	"DELETE /api/v1/api-tokens/{id}":             "снижение доступа: отзыв токена API",
	"POST /api/v1/app-keys/{id}/revoke":          "снижение доступа: отзыв ключа приложения",
	"POST /api/v1/agent-tools/{id}/revoke":       "снижение доступа: снятие одобрения инструмента",
	"PUT /api/v1/providers/{id}/credentials":     "трафик: учётные данные провайдера, сменённые у него",
	"PUT /api/v1/mcp-servers/{id}/credentials":   "трафик: учётные данные MCP-сервера",
	"PUT /api/v1/gateway-certificate":            "трафик: замена истекающего сертификата заказчика",
}

// licenseModules — префиксы путей модулей (ADR-0026, п. 3, 5). Модули
// compliance и ml маршрутов пока не имеют: префиксы добавят задачи 4.24 и 4.19.
var licenseModules = []struct{ prefix, module string }{
	{"/api/v1/agents", license.ModuleAgents},
	{"/api/v1/mcp-servers", license.ModuleAgents},
	{"/api/v1/agent-tools", license.ModuleAgents},
	{"/api/v1/shadow-ai", license.ModuleShadowAI},
}

// licenseModuleExempt — изменяющие маршруты модуля, которые выключенный
// модуль не закрывает: снижение доступа и учётные данные ради трафика.
var licenseModuleExempt = map[string]bool{
	"POST /api/v1/agent-tools/{id}/revoke": true,
	// Трафик MCP-серверов идёт и без модуля: сменённый у сервера ключ
	// должен заменяться.
	"PUT /api/v1/mcp-servers/{id}/credentials": true,
}

func routeKey(r Route) string { return r.Method + " " + r.Path }

// mutating — метод меняет состояние.
func mutating(method string) bool {
	return method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch || method == http.MethodDelete
}

// licenseRule — проверять ли маршрут и с каким модулем.
func licenseRule(r Route) (gated bool, module string) {
	if r.Public || !mutating(r.Method) || !strings.HasPrefix(r.Path, "/api/") {
		return false, ""
	}
	key := routeKey(r)
	if !licenseModuleExempt[key] {
		for _, m := range licenseModules {
			if r.Path == m.prefix || strings.HasPrefix(r.Path, m.prefix+"/") {
				module = m.module
				break
			}
		}
	}
	if _, ok := licenseExempt[key]; ok {
		// Исключение из запрета изменений, но не из модуля: импорт журналов
		// теневого ИИ при выключенном модуле закрыт.
		return module != "", module
	}
	return true, module
}

// checkLicense — проверка маршрута r до обработчика; у маршрута из списка
// исключений проверяется только модуль.
func (rt *Router) checkLicense(req *http.Request, r Route, module, subject string) *Problem {
	ctx, cancel := contextTimeout(req, storeCheckTimeout)
	defer cancel()
	_, exempt := licenseExempt[routeKey(r)]
	var err error
	if exempt {
		err = rt.license.CheckModule(ctx, module)
	} else {
		err = rt.license.CheckMutation(ctx, module)
	}
	if err == nil {
		return nil
	}
	var d *license.Denied
	if errors.As(err, &d) {
		// Отказ по лицензии — в технический журнал без тела запроса: видно,
		// кто и что пытался менять после истечения.
		rt.logger.Warn("изменение отклонено лицензией", "class", "access", "code", d.Code, "method", r.Method, "route", r.Path,
			"subject", subject)
	}
	return licenseProblem(rt.logger, err)
}

// storeCheckTimeout — предел проверки лицензии в запросе.
const storeCheckTimeout = 5 * time.Second

// licenseProblem — ответ на отказ по лицензии.
func licenseProblem(logger *slog.Logger, err error) *Problem {
	var d *license.Denied
	if errors.As(err, &d) {
		return NewProblem(http.StatusForbidden, d.Code, d.Message)
	}
	logger.Error("лицензия: проверка не выполнена", "class", "status", "error", err)
	return NewProblem(http.StatusServiceUnavailable, CodeUnavailable, "Не удалось проверить лицензию: повторите запрос позже.")
}
