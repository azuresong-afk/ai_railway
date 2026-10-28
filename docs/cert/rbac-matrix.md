# Матрица «роль × эндпоинт» (УПД.3)

Файл создан командой `make rbac-matrix` (`tools/rbac-matrix`) из `api/openapi.yaml` (расширение `x-permission`) и прав предустановленных ролей (`internal/auth/permissions.go`). Руками не правится: тест `tools/rbac-matrix` падает, если файл устарел.

«да» — доступ есть; «свои» — только к своим объектам (УПД.8); «—» — отказ 403. Каждую пару проверяет тест `TestRBACMatrixDenials` (`internal/api`): для «—» — ответ 403 и запись `access.denied` в журнале аудита, для остальных — ни 401, ни 403. Тот же тест проверяет свою роль без разрешений: ей доступны только эндпоинты с `self` и `session`. Сессия с временным или истёкшим паролем получает только `self` и `session`, сессия до второго фактора — только `session`, независимо от роли.

Колонка «токен API» — можно ли выдать разрешение токену API (ИАФ.9, `auth.TokenGrantable`): функции безопасности, свои данные, сами токены и загрузка лицензии токену недоступны. Права токена — пересечение его области с правами роли владельца; эти пары проверяет `TestRBACMatrixTokenDenials`.

## Защищённые эндпоинты

| Метод | Путь | Разрешение | security_admin | system_admin | analyst | auditor | app_owner | токен API |
|---|---|---|---|---|---|---|---|---|
| GET | `/api/v1/agent-tools` | `agents.read` | да | да | да | да | свои | да |
| GET | `/api/v1/agent-tools/{id}` | `agents.read` | да | да | да | да | свои | да |
| POST | `/api/v1/agent-tools/{id}/approve` | `agents.tools.approve` | да | — | — | — | — | — |
| POST | `/api/v1/agent-tools/{id}/revoke` | `agents.tools.approve` | да | — | — | — | — | — |
| PUT | `/api/v1/agent-tools/{id}/risk` | `agents.tools.approve` | да | — | — | — | — | — |
| GET | `/api/v1/agents` | `agents.read` | да | да | да | да | свои | да |
| POST | `/api/v1/agents` | `agents.manage` | да | да | — | — | — | да |
| GET | `/api/v1/agents/{id}` | `agents.read` | да | да | да | да | свои | да |
| PUT | `/api/v1/agents/{id}` | `agents.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/agents/{id}` | `agents.manage` | да | да | — | — | — | да |
| GET | `/api/v1/alert-rules` | `alert_rules.read` | да | — | да | да | — | да |
| POST | `/api/v1/alert-rules` | `alert_rules.manage` | да | — | — | — | — | — |
| GET | `/api/v1/alert-rules/{id}` | `alert_rules.read` | да | — | да | да | — | да |
| PUT | `/api/v1/alert-rules/{id}` | `alert_rules.manage` | да | — | — | — | — | — |
| GET | `/api/v1/alert-rules/{id}/state` | `alert_rules.read` | да | — | да | да | — | да |
| GET | `/api/v1/alert-settings` | `alert_rules.read` | да | — | да | да | — | да |
| PUT | `/api/v1/alert-settings` | `alert_rules.manage` | да | — | — | — | — | — |
| GET | `/api/v1/alerts` | `alerts.read` | да | — | да | да | — | да |
| GET | `/api/v1/alerts/{id}` | `alerts.read` | да | — | да | да | — | да |
| POST | `/api/v1/alerts/{id}/status` | `alerts.manage` | да | — | да | — | — | да |
| GET | `/api/v1/api-tokens` | `api_tokens.read` | да | свои | — | да | — | — |
| POST | `/api/v1/api-tokens` | `api_tokens.manage` | да | свои | — | — | — | — |
| GET | `/api/v1/api-tokens/{id}` | `api_tokens.read` | да | свои | — | да | — | — |
| DELETE | `/api/v1/api-tokens/{id}` | `api_tokens.manage` | да | свои | — | — | — | — |
| POST | `/api/v1/app-keys/{id}/revoke` | `app_keys.manage` | да | да | — | — | — | да |
| POST | `/api/v1/app-keys/{id}/rotate` | `app_keys.manage` | да | да | — | — | — | да |
| GET | `/api/v1/applications` | `applications.read` | да | да | да | да | свои | да |
| POST | `/api/v1/applications` | `applications.manage` | да | да | — | — | — | да |
| GET | `/api/v1/applications/{id}` | `applications.read` | да | да | да | да | свои | да |
| PUT | `/api/v1/applications/{id}` | `applications.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/applications/{id}` | `applications.manage` | да | да | — | — | — | да |
| GET | `/api/v1/applications/{id}/budget` | `budgets.read` | да | да | да | да | — | да |
| PUT | `/api/v1/applications/{id}/budget` | `budgets.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/applications/{id}/budget` | `budgets.manage` | да | да | — | — | — | да |
| GET | `/api/v1/applications/{id}/keys` | `applications.read` | да | да | да | да | свои | да |
| POST | `/api/v1/applications/{id}/keys` | `app_keys.manage` | да | да | — | — | — | да |
| GET | `/api/v1/applications/{id}/prompt-baseline` | `applications.policy` | да | — | — | — | — | — |
| PUT | `/api/v1/applications/{id}/prompt-baseline` | `applications.policy` | да | — | — | — | — | — |
| DELETE | `/api/v1/applications/{id}/prompt-baseline` | `applications.policy` | да | — | — | — | — | — |
| PUT | `/api/v1/applications/{id}/protection` | `applications.policy` | да | — | — | — | — | — |
| GET | `/api/v1/applications/{id}/user-access` | `applications.read` | да | да | да | да | свои | да |
| PUT | `/api/v1/applications/{id}/user-access` | `applications.policy` | да | — | — | — | — | — |
| GET | `/api/v1/approvals` | `approvals.read` | да | — | да | да | — | да |
| GET | `/api/v1/approvals/{id}` | `approvals.read` | да | — | да | да | — | да |
| POST | `/api/v1/approvals/{id}/approve` | `approvals.decide` | да | — | да | — | — | — |
| POST | `/api/v1/approvals/{id}/deny` | `approvals.decide` | да | — | да | — | — | — |
| GET | `/api/v1/audit` | `audit.read` | да | — | — | да | — | да |
| POST | `/api/v1/audit/verify` | `audit.verify` | да | — | — | да | — | да |
| GET | `/api/v1/auth/idp` | `auth_idp.read` | да | — | — | да | — | да |
| PUT | `/api/v1/auth/idp` | `auth_idp.manage` | да | — | — | — | — | — |
| DELETE | `/api/v1/auth/idp` | `auth_idp.manage` | да | — | — | — | — | — |
| GET | `/api/v1/auth/ldap` | `auth_idp.read` | да | — | — | да | — | да |
| PUT | `/api/v1/auth/ldap` | `auth_idp.manage` | да | — | — | — | — | — |
| DELETE | `/api/v1/auth/ldap` | `auth_idp.manage` | да | — | — | — | — | — |
| POST | `/api/v1/auth/logout` | `session` | да | да | да | да | да | — |
| POST | `/api/v1/auth/mfa/recovery-codes` | `session` | да | да | да | да | да | — |
| POST | `/api/v1/auth/mfa/setup` | `session` | да | да | да | да | да | — |
| POST | `/api/v1/auth/mfa/setup/confirm` | `session` | да | да | да | да | да | — |
| POST | `/api/v1/auth/mfa/verify` | `session` | да | да | да | да | да | — |
| POST | `/api/v1/auth/password` | `self` | да | да | да | да | да | — |
| GET | `/api/v1/auth/policy` | `auth_policy.read` | да | — | — | да | — | да |
| PUT | `/api/v1/auth/policy` | `auth_policy.manage` | да | — | — | — | — | — |
| GET | `/api/v1/budgets` | `budgets.read` | да | да | да | да | — | да |
| GET | `/api/v1/dashboards/app/{id}` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/dashboards/consumption` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/dashboards/overview` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/dashboards/pii` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/dashboards/stream` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/dashboards/threats` | `dashboards.read` | да | да | да | да | свои | да |
| GET | `/api/v1/events` | `events.read` | да | — | да | да | — | да |
| POST | `/api/v1/events/export` | `events.export` | да | — | да | — | — | да |
| GET | `/api/v1/events/filters` | `events.read` | да | — | да | да | — | да |
| POST | `/api/v1/events/filters` | `events.read` | да | — | да | да | — | да |
| DELETE | `/api/v1/events/filters/{id}` | `events.read` | да | — | да | да | — | да |
| GET | `/api/v1/events/settings` | `events.read` | да | — | да | да | — | да |
| PUT | `/api/v1/events/settings` | `events.retention.manage` | да | — | — | — | — | — |
| GET | `/api/v1/events/stats` | `events.read` | да | — | да | да | — | да |
| GET | `/api/v1/events/{id}` | `events.read` | да | — | да | да | — | да |
| POST | `/api/v1/events/{id}/content` | `events.content.read` | да | — | — | — | — | — |
| GET | `/api/v1/events/{id}/exception-draft` | `events.read` | да | — | да | да | — | да |
| PUT | `/api/v1/events/{id}/mark` | `events.mark` | да | — | да | — | — | да |
| GET | `/api/v1/gateway-certificate` | `gateway_tls.read` | да | да | — | да | — | да |
| PUT | `/api/v1/gateway-certificate` | `gateway_tls.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/gateway-certificate` | `gateway_tls.manage` | да | да | — | — | — | да |
| GET | `/api/v1/incident-categories` | `incidents.read` | да | — | да | да | — | да |
| PUT | `/api/v1/incident-categories/{category}` | `incident_categories.manage` | да | — | — | — | — | — |
| GET | `/api/v1/incident-settings` | `incidents.read` | да | — | да | да | — | да |
| PUT | `/api/v1/incident-settings` | `incident_categories.manage` | да | — | — | — | — | — |
| GET | `/api/v1/incidents` | `incidents.read` | да | — | да | да | — | да |
| POST | `/api/v1/incidents` | `incidents.manage` | да | — | да | — | — | да |
| GET | `/api/v1/incidents/{id}` | `incidents.read` | да | — | да | да | — | да |
| POST | `/api/v1/incidents/{id}/alerts` | `incidents.manage` | да | — | да | — | — | да |
| PUT | `/api/v1/incidents/{id}/assignee` | `incidents.manage` | да | — | да | — | — | да |
| POST | `/api/v1/incidents/{id}/comments` | `incidents.manage` | да | — | да | — | — | да |
| GET | `/api/v1/incidents/{id}/export` | `incidents.export` | да | — | да | — | — | да |
| POST | `/api/v1/incidents/{id}/stages/{stage}` | `incidents.manage` | да | — | да | — | — | да |
| POST | `/api/v1/incidents/{id}/status` | `incidents.manage` | да | — | да | — | — | да |
| GET | `/api/v1/license` | `license.read` | да | да | — | да | — | да |
| PUT | `/api/v1/license` | `license.manage` | да | да | — | — | — | — |
| GET | `/api/v1/mcp-servers` | `agents.read` | да | да | да | да | свои | да |
| POST | `/api/v1/mcp-servers` | `agents.manage` | да | да | — | — | — | да |
| GET | `/api/v1/mcp-servers/{id}` | `agents.read` | да | да | да | да | свои | да |
| PUT | `/api/v1/mcp-servers/{id}` | `agents.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/mcp-servers/{id}` | `agents.manage` | да | да | — | — | — | да |
| PUT | `/api/v1/mcp-servers/{id}/credentials` | `agents.manage` | да | да | — | — | — | да |
| PUT | `/api/v1/mcp-servers/{id}/security` | `agents.tools.approve` | да | — | — | — | — | — |
| GET | `/api/v1/me` | `session` | да | да | да | да | да | — |
| PUT | `/api/v1/me/email` | `self` | да | да | да | да | да | — |
| GET | `/api/v1/model-prices` | `model_prices.read` | да | да | да | да | — | да |
| POST | `/api/v1/model-prices` | `model_prices.manage` | да | да | — | — | — | да |
| PUT | `/api/v1/model-prices/{id}` | `model_prices.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/model-prices/{id}` | `model_prices.manage` | да | да | — | — | — | да |
| GET | `/api/v1/notify-channels` | `notify_channels.read` | да | — | — | да | — | да |
| POST | `/api/v1/notify-channels` | `notify_channels.manage` | да | — | — | — | — | — |
| GET | `/api/v1/notify-channels/{id}` | `notify_channels.read` | да | — | — | да | — | да |
| PUT | `/api/v1/notify-channels/{id}` | `notify_channels.manage` | да | — | — | — | — | — |
| GET | `/api/v1/notify-channels/{id}/audit-stream` | `notify_channels.read` | да | — | — | да | — | да |
| GET | `/api/v1/notify-channels/{id}/deliveries` | `notify_channels.read` | да | — | — | да | — | да |
| POST | `/api/v1/notify-channels/{id}/test` | `notify_channels.manage` | да | — | — | — | — | — |
| GET | `/api/v1/permissions` | `roles.read` | да | — | — | да | — | да |
| GET | `/api/v1/policies` | `policies.read` | да | да | да | да | — | да |
| POST | `/api/v1/policies` | `policies.manage` | да | — | — | — | — | — |
| POST | `/api/v1/policies/import` | `policies.manage` | да | — | — | — | — | — |
| POST | `/api/v1/policies/test` | `policies.test` | да | да | да | — | — | да |
| GET | `/api/v1/policies/{id}` | `policies.read` | да | да | да | да | — | да |
| PUT | `/api/v1/policies/{id}` | `policies.manage` | да | — | — | — | — | — |
| GET | `/api/v1/policies/{id}/diff` | `policies.read` | да | да | да | да | — | да |
| GET | `/api/v1/policies/{id}/exceptions` | `policies.read` | да | да | да | да | — | да |
| POST | `/api/v1/policies/{id}/exceptions` | `policies.manage` | да | — | — | — | — | — |
| DELETE | `/api/v1/policies/{id}/exceptions/{exc}` | `policies.manage` | да | — | — | — | — | — |
| POST | `/api/v1/policies/{id}/exceptions/{exc}/extend` | `policies.manage` | да | — | — | — | — | — |
| GET | `/api/v1/policies/{id}/export` | `policies.read` | да | да | да | да | — | да |
| POST | `/api/v1/policies/{id}/rollback` | `policies.manage` | да | — | — | — | — | — |
| GET | `/api/v1/policies/{id}/versions` | `policies.read` | да | да | да | да | — | да |
| GET | `/api/v1/policies/{id}/versions/{n}` | `policies.read` | да | да | да | да | — | да |
| GET | `/api/v1/providers` | `providers.read` | да | да | да | да | — | да |
| POST | `/api/v1/providers` | `providers.manage` | да | да | — | — | — | да |
| GET | `/api/v1/providers/{id}` | `providers.read` | да | да | да | да | — | да |
| PUT | `/api/v1/providers/{id}` | `providers.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/providers/{id}` | `providers.manage` | да | да | — | — | — | да |
| PUT | `/api/v1/providers/{id}/credentials` | `providers.manage` | да | да | — | — | — | да |
| PUT | `/api/v1/providers/{id}/external` | `providers.external` | да | — | — | — | — | — |
| GET | `/api/v1/quota-settings` | `budgets.read` | да | да | да | да | — | да |
| PUT | `/api/v1/quota-settings` | `quota_mode.manage` | да | да | — | — | — | да |
| GET | `/api/v1/report-channels` | `reports.schedules.manage` | да | да | — | — | — | да |
| GET | `/api/v1/report-recipients` | `reports.schedules.manage` | да | да | — | — | — | да |
| GET | `/api/v1/report-schedules` | `reports.schedules.read` | да | да | — | да | — | да |
| POST | `/api/v1/report-schedules` | `reports.schedules.manage` | да | да | — | — | — | да |
| GET | `/api/v1/report-schedules/{id}` | `reports.schedules.read` | да | да | — | да | — | да |
| PUT | `/api/v1/report-schedules/{id}` | `reports.schedules.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/report-schedules/{id}` | `reports.schedules.manage` | да | да | — | — | — | да |
| GET | `/api/v1/report-schedules/{id}/runs` | `reports.schedules.read` | да | да | — | да | — | да |
| GET | `/api/v1/reports/{kind}` | `reports.read` | да | да | да | да | свои | да |
| GET | `/api/v1/roles` | `roles.read` | да | — | — | да | — | да |
| POST | `/api/v1/roles` | `roles.manage` | да | — | — | — | — | — |
| GET | `/api/v1/roles/{id}` | `roles.read` | да | — | — | да | — | да |
| PUT | `/api/v1/roles/{id}` | `roles.manage` | да | — | — | — | — | — |
| DELETE | `/api/v1/roles/{id}` | `roles.manage` | да | — | — | — | — | — |
| GET | `/api/v1/shadow-ai/catalog` | `shadow_ai.read` | да | да | да | да | — | да |
| PUT | `/api/v1/shadow-ai/catalog` | `shadow_ai.manage` | да | да | — | — | — | да |
| GET | `/api/v1/shadow-ai/exclusions` | `shadow_ai.read` | да | да | да | да | — | да |
| POST | `/api/v1/shadow-ai/exclusions` | `shadow_ai.manage` | да | да | — | — | — | да |
| DELETE | `/api/v1/shadow-ai/exclusions/{kind}/{value}` | `shadow_ai.manage` | да | да | — | — | — | да |
| GET | `/api/v1/shadow-ai/imports` | `shadow_ai.read` | да | да | да | да | — | да |
| POST | `/api/v1/shadow-ai/imports` | `shadow_ai.manage` | да | да | — | — | — | да |
| GET | `/api/v1/shadow-ai/services` | `shadow_ai.read` | да | да | да | да | — | да |
| GET | `/api/v1/shadow-ai/settings` | `shadow_ai.read` | да | да | да | да | — | да |
| PUT | `/api/v1/shadow-ai/settings` | `shadow_ai.manage` | да | да | — | — | — | да |
| GET | `/api/v1/shadow-ai/syslog` | `shadow_ai.read` | да | да | да | да | — | да |
| GET | `/api/v1/shadow-ai/timeline` | `shadow_ai.read` | да | да | да | да | — | да |
| GET | `/api/v1/shadow-ai/users` | `shadow_ai.read` | да | да | да | да | — | да |
| GET | `/api/v1/system/info` | `system.read` | да | да | да | да | — | да |
| GET | `/api/v1/system/integrity` | `system.read` | да | да | да | да | — | да |
| POST | `/api/v1/system/integrity/verify` | `integrity.verify` | да | — | — | — | — | — |
| GET | `/api/v1/system/settings` | `system.read` | да | да | да | да | — | да |
| PUT | `/api/v1/system/settings` | `settings.manage` | да | — | — | — | — | — |
| GET | `/api/v1/system/status` | `system.read` | да | да | да | да | — | да |
| GET | `/api/v1/users` | `users.read` | да | — | — | да | — | да |
| POST | `/api/v1/users` | `users.manage` | да | — | — | — | — | — |
| GET | `/api/v1/users/{id}` | `users.read` | да | — | — | да | — | да |
| POST | `/api/v1/users/{id}/activate` | `users.manage` | да | — | — | — | — | — |
| POST | `/api/v1/users/{id}/deactivate` | `users.manage` | да | — | — | — | — | — |
| PUT | `/api/v1/users/{id}/email` | `users.manage` | да | — | — | — | — | — |
| POST | `/api/v1/users/{id}/mfa/reset` | `users.manage` | да | — | — | — | — | — |
| POST | `/api/v1/users/{id}/password-reset` | `users.manage` | да | — | — | — | — | — |
| PUT | `/api/v1/users/{id}/role` | `roles.manage` | да | — | — | — | — | — |
| GET | `/api/v1/users/{id}/sessions` | `sessions.read` | да | — | — | да | — | да |
| DELETE | `/api/v1/users/{id}/sessions` | `sessions.manage` | да | — | — | — | — | — |

## Открытые эндпоинты (без аутентификации)

- POST `/api/v1/auth/login`
- GET `/api/v1/auth/oidc`
- GET `/api/v1/auth/oidc/callback`
- GET `/api/v1/auth/oidc/start`
- GET `/api/v1/auth/setup`
- POST `/api/v1/auth/setup`
- POST `/api/v1/gateways/register`
- GET `/healthz`
- GET `/readyz`

## Предустановленные роли

| Роль | Название | Второй фактор обязателен |
|---|---|---|
| security_admin | Администратор безопасности | да |
| system_admin | Администратор системы | да |
| analyst | Аналитик | нет |
| auditor | Аудитор | нет |
| app_owner | Владелец приложения | нет |
