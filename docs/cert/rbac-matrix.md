# Матрица «роль × эндпоинт» (УПД.3)

Файл создан командой `make rbac-matrix` (`tools/rbac-matrix`) из `api/openapi.yaml` (расширение `x-permission`) и прав предустановленных ролей (`internal/auth/permissions.go`). Руками не правится: тест `tools/rbac-matrix` падает, если файл устарел.

«да» — доступ есть; «свои» — только к своим объектам (УПД.8); «—» — отказ 403. Каждую пару проверяет тест `TestRBACMatrixDenials` (`internal/api`): для «—» — ответ 403 и запись `access.denied` в журнале аудита, для остальных — ни 401, ни 403. Тот же тест проверяет свою роль без разрешений: ей доступны только эндпоинты с `self` и `session`. Сессия с временным или истёкшим паролем получает только `self` и `session`, сессия до второго фактора — только `session`, независимо от роли.

## Защищённые эндпоинты

| Метод | Путь | Разрешение | security_admin | system_admin | analyst | auditor | app_owner |
|---|---|---|---|---|---|---|---|
| POST | `/api/v1/auth/logout` | `session` | да | да | да | да | да |
| POST | `/api/v1/auth/mfa/recovery-codes` | `session` | да | да | да | да | да |
| POST | `/api/v1/auth/mfa/setup` | `session` | да | да | да | да | да |
| POST | `/api/v1/auth/mfa/setup/confirm` | `session` | да | да | да | да | да |
| POST | `/api/v1/auth/mfa/verify` | `session` | да | да | да | да | да |
| POST | `/api/v1/auth/password` | `self` | да | да | да | да | да |
| GET | `/api/v1/auth/policy` | `auth_policy.read` | да | — | — | да | — |
| PUT | `/api/v1/auth/policy` | `auth_policy.manage` | да | — | — | — | — |
| GET | `/api/v1/me` | `session` | да | да | да | да | да |
| GET | `/api/v1/permissions` | `roles.read` | да | — | — | да | — |
| GET | `/api/v1/roles` | `roles.read` | да | — | — | да | — |
| POST | `/api/v1/roles` | `roles.manage` | да | — | — | — | — |
| GET | `/api/v1/roles/{id}` | `roles.read` | да | — | — | да | — |
| PUT | `/api/v1/roles/{id}` | `roles.manage` | да | — | — | — | — |
| DELETE | `/api/v1/roles/{id}` | `roles.manage` | да | — | — | — | — |
| GET | `/api/v1/system/info` | `system.read` | да | да | да | да | — |
| GET | `/api/v1/system/integrity` | `system.read` | да | да | да | да | — |
| POST | `/api/v1/system/integrity/verify` | `integrity.verify` | да | — | — | — | — |
| GET | `/api/v1/users` | `users.read` | да | — | — | да | — |
| POST | `/api/v1/users` | `users.manage` | да | — | — | — | — |
| GET | `/api/v1/users/{id}` | `users.read` | да | — | — | да | — |
| POST | `/api/v1/users/{id}/activate` | `users.manage` | да | — | — | — | — |
| POST | `/api/v1/users/{id}/deactivate` | `users.manage` | да | — | — | — | — |
| POST | `/api/v1/users/{id}/mfa/reset` | `users.manage` | да | — | — | — | — |
| POST | `/api/v1/users/{id}/password-reset` | `users.manage` | да | — | — | — | — |
| PUT | `/api/v1/users/{id}/role` | `roles.manage` | да | — | — | — | — |
| GET | `/api/v1/users/{id}/sessions` | `sessions.read` | да | — | — | да | — |
| DELETE | `/api/v1/users/{id}/sessions` | `sessions.manage` | да | — | — | — | — |

## Открытые эндпоинты (без аутентификации)

- POST `/api/v1/auth/login`
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
