# Makefile — единственное место с логикой сборки и проверок (ТЗ, 11.4).
# CI — тонкая обёртка над этими целями (ADR-0002).

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Текущий этап (ТЗ, раздел 14): строки матрицы 5.16 с этапом не выше этого
# обязаны быть покрыты тестами.
STAGE := 3

# Скрытые загрузки запрещены (ТЗ, 8.7): зависимости — только из vendor/,
# прокси модулей выключен, toolchain должен быть уже установлен. Переменные
# окружения эти запреты не снимают (override). Единственная цель, которая
# ходит в сеть явно, — make tools.
GO_VERSION := go1.27.3
override GOFLAGS := -mod=vendor
override GOPROXY := off
export GOFLAGS GOPROXY
# GOTOOLCHAIN: local (Go из сборочного образа) или точная версия уже
# скачанного toolchain — на машине разработчика без Go 1.27.
export GOTOOLCHAIN ?= local
ifeq ($(filter local $(GO_VERSION),$(GOTOOLCHAIN)),)
$(error GOTOOLCHAIN=$(GOTOOLCHAIN) не разрешён: только local или $(GO_VERSION))
endif
export CGO_ENABLED ?= 0

# Пути, где cgo разрешён по ADR (через запятую). Пока таких нет.
CGO_ALLOWED :=
# Пути, где разрешены сетевые клиенты (ЗИ.2, H-Р11): шлюз (регистрация, пакет,
# heartbeat, отправка событий), провайдеры LLM и каналы уведомлений
# internal/notify — SMTP, webhook, syslog только по адресам администратора
# (Р4, задача 3.13; обоснование — docs/cert/attack-surface.md);
# internal/auth/oidc — discovery, JWKS и обмен кода только с издателем из
# настроек IdP (ADR-0025, задача 4.17); internal/auth/ldap — поиск и bind
# только в каталоге из настроек LDAP, LDAPS или StartTLS (ADR-0025, задача 4.16).
NET_CLIENT_ALLOWED := cmd/aisec-gateway,internal/gateway,internal/providers,internal/notify,internal/auth/oidc,internal/auth/ldap

# Версии инструментов разработки (ТЗ, 8.2). Меняются только вместе с
# docs/cert/components.yaml (scope: build) и сборочным образом.
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
SBOM_UTILITY_VERSION  := v1.0.1

# Прокси модулей только для make tools; контрольные суммы сверяются с sum.golang.org.
TOOLS_GOPROXY ?= https://proxy.golang.org

# В сборочном образе инструменты лежат в /opt/aisec-tools/bin (make check-docker).
BIN   ?= $(CURDIR)/bin
BUILD := $(CURDIR)/build

# Компоненты в поставке. mock-llm и mock-mcp в поставку не входят.
PRODUCT_CMDS := aisec-gateway aisec-server aisec-cli aisec-media
DEV_CMDS     := mock-llm mock-mcp

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Время последнего коммита — для воспроизводимых артефактов (SBOM, фронтенд).
SOURCE_DATE ?= $(shell git log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)
SOURCE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

# Поставочная сборка (ADR-0012, ADR-0022): RELEASE=1 встраивает открытый
# ключ производителя internal/integrity/keys/manifest.pub вместо тестового.
# Манифест поставки собирается без подписи (make release-dir RELEASE=1) и
# подписывается отдельным шагом на машине без сети: make release-sign
# MANIFEST_KEY=… или собранный make release-signer инструмент. MANIFEST_KEY —
# путь к закрытому ключу производителя на отдельном носителе, вне
# репозитория. Без RELEASE сборка и манифест — с тестовым ключом «не для
# поставки» (testdata/integrity/).
RELEASE ?=
BUILD_TAGS := $(if $(filter 1,$(RELEASE)),aisec_release,)
MANIFEST_KEY ?=
MANIFEST_SHA256 ?=
MANIFEST_TEST_KEY := testdata/integrity/manifest-test.signkey

.PHONY: help
help: ## Список целей
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

.PHONY: check
# Проверки из CLAUDE.md, которые ещё не реализованы. Пока список не пуст,
# зелёный make check неполный — об этом печатается предупреждение.
PENDING_CHECKS :=

# Проверки фронтенда нужны Node.js и npm (ADR-0011). Пока их нет в сборочном
# образе, на такой машине проверки не запускаются молча, а попадают в
# PENDING_CHECKS с предупреждением в конце make check.
ifeq ($(shell command -v npm 2>/dev/null),)
PENDING_CHECKS += web-check web-e2e
WEB_CHECKS :=
else
WEB_CHECKS := web-check web-e2e
endif

# Тесты поставочной сборки (тег aisec_release, Н35) входят в каждую проверку:
# без RELEASE=1 — с имитацией ключа производителя (ADR-0022).
check: fmt-check vet docs-check repocheck licenses vendor-check lint lint-selftest sast test ml-test release-test build manifest e2e dm-coverage detector-quality sbom fuzz-smoke vuln $(WEB_CHECKS) ## Все проверки перед pull request
	@if [ -n "$(strip $(PENDING_CHECKS))" ]; then \
		echo "ВНИМАНИЕ: make check неполный, не выполнены: $(PENDING_CHECKS) (docs/plans/stage-0.md; для web-* нужен Node.js, web/README.md)"; fi

.PHONY: fmt-check
fmt-check: ## Форматирование Go-кода (gofmt); vendor/ — чужой код, его неизменность проверяет vendor-check
	@out="$$(gofmt -l $$(git ls-files '*.go' ':!vendor/'))"; \
	if [ -n "$$out" ]; then echo "Не отформатированы (gofmt -w):"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet (с cgo, чтобы проверялись и файлы с import "C")
	CGO_ENABLED=1 go vet ./...

.PHONY: dm-coverage
dm-coverage: build ## Покрытие матрицы обнаружения 5.16 тестами (строки с этапом не выше STAGE)
	@mkdir -p $(BUILD)
	@# Падения тестов ловит make test; здесь нужен полный отчёт, поэтому код возврата не важен.
	go test -count=1 -json ./... > $(BUILD)/dm-tests.json || true
	go test -tags e2e -count=1 -json ./test/e2e/ -bin $(BUILD)/bin > $(BUILD)/dm-e2e.json || true
	go run ./tools/dm-coverage -spec docs/SPEC.md -stage $(STAGE) \
		-gotest $(BUILD)/dm-tests.json,$(BUILD)/dm-e2e.json -out $(BUILD)/dm-coverage

.PHONY: detector-quality
detector-quality: ## Точность и полнота детекторов на корпусах против docs/detectors.md (ТЗ, 5.2)
	go run ./tools/detector-quality -doc docs/detectors.md -corpus testdata/corpus -out $(BUILD)/detector-quality.md

# Демо-данные для демо-стенда (задача 3.29, tools/demo-data/README.md): запросы
# идут в Check API шлюза, оповещения и инциденты создают правила сервера.
# Адрес по умолчанию — loopback; чужой стенд — только с DEMO_FLAGS=-allow-remote.
DEMO_GATEWAY ?= https://127.0.0.1:8443
DEMO_DAYS ?= 30
DEMO_SEED ?= 1
DEMO_FLAGS ?=
.PHONY: demo-data
demo-data: ## Наполнить демо-стенд синтетическими событиями (нужны DEMO_CA и DEMO_KEYS, см. tools/demo-data/README.md)
	@test -n "$(DEMO_CA)" -a -n "$(DEMO_KEYS)" || { echo "задайте DEMO_CA (корень УЦ стенда) и DEMO_KEYS (файл «приложение=ключ», права 0600)"; exit 2; }
	go run ./tools/demo-data -gateway $(DEMO_GATEWAY) -ca $(DEMO_CA) -keys $(DEMO_KEYS) -days $(DEMO_DAYS) -seed $(DEMO_SEED) $(DEMO_FLAGS)

.PHONY: bench
bench: ## Бенчмарки детекторов и реестра (задержка против целей ТЗ, 5.1)
	go test -run '^$$' -bench . -benchmem ./internal/detect/...

.PHONY: sbom
sbom: build $(BIN)/sbom-utility ## SBOM продукта (CycloneDX 1.6) из собранных бинарников и проверка формата
	go run ./tools/sbom -registry docs/cert/components.yaml -gosum go.sum -npm-lock web/package-lock.json -out $(BUILD)/sbom/aisec.cdx.json \
		-version '$(VERSION)' -timestamp '$(SOURCE_DATE)' $(addprefix $(BUILD)/bin/,$(PRODUCT_CMDS))
	$(BIN)/sbom-utility validate --quiet --input-file $(BUILD)/sbom/aisec.cdx.json
	go run ./tools/sbom -check $(BUILD)/sbom/aisec.cdx.json

$(BIN)/sbom-utility:
	@echo "Нет $@: выполните make tools (или используйте сборочный образ)"; exit 1

.PHONY: licenses
licenses: ## Реестр компонентов и лицензии: docs/cert/components.yaml против vendor/, go.mod, Makefile
	go run ./tools/license-check -root .

.PHONY: vendor-check
vendor-check: ## Неизменность vendor/: modules.txt, go.mod, go.sum и манифест docs/cert/vendor.sha256 (без сети)
	go run ./tools/vendor-check -root .

.PHONY: vendor-manifest
vendor-manifest: ## Пересчитать манифест vendor/ после go mod vendor (изменение смотрит ревью)
	go run ./tools/vendor-check -root . -update

.PHONY: vendor-verify
vendor-verify: ## Сверка vendor/ с go.sum: go mod vendor во временный каталог и сравнение (нужна сеть)
	go run ./tools/vendor-check -root . -verify

.PHONY: repocheck
repocheck: ## Структурные правила: один internal/crypto, cgo только по ADR, сетевые клиенты только в разрешённых путях
	go run ./tools/repocheck -root . -cgo-allowed '$(CGO_ALLOWED)' -net-client-allowed '$(NET_CLIENT_ALLOWED)'

.PHONY: docs-check
docs-check: ## Относительные ссылки в документах ведут на существующие файлы
	go run ./tools/docs-check -root .

.PHONY: rbac-matrix
rbac-matrix: ## Матрица «роль × эндпоинт» из api/openapi.yaml в docs/cert/rbac-matrix.md (УПД.3)
	go run ./tools/rbac-matrix -spec api/openapi.yaml -out docs/cert/rbac-matrix.md

.PHONY: test
test: ## Модульные тесты с детектором гонок
	CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: build
build: ## Сборка бинарников в build/bin
	@mkdir -p $(BUILD)/bin
	go build -trimpath -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(BUILD)/bin/ $(addprefix ./cmd/,$(PRODUCT_CMDS) $(DEV_CMDS))

.PHONY: lint
lint: lint-version ## Линтеры, в том числе depguard (.golangci.yml); с cgo, чтобы проверялись все файлы
	CGO_ENABLED=1 $(BIN)/golangci-lint run ./...
	# Исполнитель ONNX Runtime в aisec-ml собирается только с тегом aisec_onnx (ADR-0024).
	CGO_ENABLED=1 $(BIN)/golangci-lint run --build-tags e2e,aisec_onnx ./cmd/aisec-ml/...

# Исполнитель ONNX Runtime в aisec-ml (тег aisec_onnx, ADR-0024): проверка
# хеша библиотеки и отказ загрузить чужую — без самой библиотеки. С
# AISEC_ORT_LIB=…/libonnxruntime.so.1.31.0 (make ort-build) — и вывод модели.
.PHONY: ml-test
ml-test: ## Тесты aisec-ml с исполнителем ONNX Runtime (тег aisec_onnx, cgo)
	CGO_ENABLED=1 go test -count=1 -tags aisec_onnx ./cmd/aisec-ml/

.PHONY: sast
sast: lint-version ## Статический анализ (gosec) в SARIF и сверка с разметкой docs/cert/sast-triage/
	@mkdir -p $(BUILD)/sast
	CGO_ENABLED=1 $(BIN)/golangci-lint run --enable-only gosec --issues-exit-code 0 \
		--output.sarif.path $(BUILD)/sast/gosec.sarif --output.text.path stderr --show-stats=false ./...
	go run ./tools/sast-triage -root . -sarif build/sast/gosec.sarif \
		-triage docs/cert/sast-triage/triage.yaml -suppressed build/sast/suppressed.md

.PHONY: lint-version
lint-version: $(BIN)/golangci-lint
	@v="$$($(BIN)/golangci-lint version 2>&1)"; \
	case "$$v" in *"version $(GOLANGCI_LINT_VERSION:v%=%) "*) ;; \
	*) echo "bin/golangci-lint не той версии (нужна $(GOLANGCI_LINT_VERSION)): $$v; выполните make tools"; exit 1;; esac

.PHONY: lint-selftest
lint-selftest: lint-version ## Проверка, что запреты линтеров действительно срабатывают
	go run ./tools/lintcheck -golangci-lint $(BIN)/golangci-lint -config .golangci.yml

$(BIN)/golangci-lint:
	@echo "Нет $@: выполните make tools (или используйте сборочный образ)"; exit 1

# Время на одну fuzz-цель: короткий прогон — на каждый pull request,
# длительный — ночью (ТЗ, 8.5).
FUZZTIME      ?= 10s
FUZZTIME_LONG ?= 10m

.PHONY: fuzz-smoke
fuzz-smoke: ## Короткий прогон всех fuzz-целей (FUZZTIME на цель)
	tools/scripts/fuzz.sh $(FUZZTIME)

.PHONY: fuzz-long
fuzz-long: ## Длительный прогон всех fuzz-целей (ночной, FUZZTIME_LONG на цель)
	FUZZ_KEEP_GOING=$(FUZZ_KEEP_GOING) tools/scripts/fuzz.sh $(FUZZTIME_LONG)

# База уязвимостей Go. В закрытом контуре — локальный снимок:
# make vuln GOVULNDB=file:///opt/govulndb (ADR-0003).
GOVULNDB ?= https://vuln.go.dev

.PHONY: vuln
vuln: $(BIN)/govulncheck ## Уязвимости зависимостей (govulncheck, база GOVULNDB)
	$(BIN)/govulncheck -db '$(GOVULNDB)' ./...

$(BIN)/govulncheck:
	@echo "Нет $@: выполните make tools (или используйте сборочный образ)"; exit 1

# Фронтенд (web/, ADR-0011). Скрытых загрузок нет: зависимости ставит только
# make web-deps (сеть или кэш npm) строго по package-lock.json с проверкой
# integrity и без скриптов установки; остальные цели работают с готовым
# web/node_modules.
WEB_NPM := npm --prefix web

.PHONY: web-deps
web-deps: ## Установить зависимости фронтенда из web/package-lock.json (нужна сеть или кэш npm)
	$(WEB_NPM) ci --ignore-scripts

.PHONY: web-deps-offline
web-deps-offline: ## То же без сети: только из кэша npm
	$(WEB_NPM) ci --ignore-scripts --offline

web/node_modules/.package-lock.json:
	@echo "Нет web/node_modules: выполните make web-deps (или web-deps-offline)"; exit 1

.PHONY: web-lint
web-lint: web/node_modules/.package-lock.json ## ESLint фронтенда (запреты dangerouslySetInnerHTML, eval, new Function, localStorage)
	$(WEB_NPM) run lint

.PHONY: web-typecheck
web-typecheck: web/node_modules/.package-lock.json ## Проверка типов фронтенда
	$(WEB_NPM) run typecheck

.PHONY: web-test
web-test: web/node_modules/.package-lock.json ## Модульные тесты фронтенда (vitest)
	$(WEB_NPM) run test

.PHONY: web-api-types
web-api-types: web/node_modules/.package-lock.json ## Типы TypeScript из api/openapi.yaml (web/src/api/schema.d.ts)
	$(WEB_NPM) run gen:api

.PHONY: web-api-check
web-api-check: web-api-types ## Типы API в репозитории соответствуют api/openapi.yaml
	@git diff --exit-code -- web/src/api/schema.d.ts || { echo "web/src/api/schema.d.ts устарел: make web-api-types и закоммитьте"; exit 1; }

.PHONY: web-build
web-build: web/node_modules/.package-lock.json ## Сборка статики в web/dist (встраивается в aisec-server при go build)
	$(WEB_NPM) run build

.PHONY: web-check
web-check: web-lint web-typecheck web-test web-api-check web-build ## Все проверки фронтенда без браузера

# Браузер — из PLAYWRIGHT_BROWSERS_PATH (сборочный образ) или AISEC_CHROMIUM;
# Playwright ничего не скачивает (скрипты установки отключены).
.PHONY: web-e2e
web-e2e: web/node_modules/.package-lock.json ## Сквозные тесты консоли в Chromium при строгом CSP (ТЗ, 6.9)
	$(WEB_NPM) run build:e2e
	$(WEB_NPM) run e2e

.PHONY: tools
tools: ## Установить инструменты разработки в bin/ по зафиксированным версиям
	@mkdir -p $(BIN)
	GOFLAGS=-mod=mod GOPROXY=$(TOOLS_GOPROXY) GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOFLAGS=-mod=mod GOPROXY=$(TOOLS_GOPROXY) GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOFLAGS=-mod=mod GOPROXY=$(TOOLS_GOPROXY) GOBIN=$(BIN) go install github.com/CycloneDX/sbom-utility@$(SBOM_UTILITY_VERSION)

# Цели, которые появляются в следующих задачах плана этапа 0. До реализации
# они падают, а не проходят молча.
NOT_YET = @echo "$@: не реализовано — задача $(1) плана этапа 0 (docs/plans/stage-0.md)"; exit 1

.PHONY: manifest
manifest: build ## Подписанный тестовым ключом манифест build/aisec-manifest.json (ОЦЛ.1) и его проверка aisec-cli verify
ifeq ($(filter 1,$(RELEASE)),1)
	@echo "manifest: манифест поставки подписывается на машине без сети — make release-dir RELEASE=1, release-sign, images RELEASE=1 (ADR-0022)"; exit 1
endif
	go run ./tools/manifest build -out $(BUILD)/aisec-manifest.json -test-key $(MANIFEST_TEST_KEY) \
		-version '$(VERSION)' -created '$(SOURCE_DATE)' -bin $(BUILD)/bin -cmds '$(PRODUCT_CMDS)' \
		-static web/dist -migrations migrations
	$(BUILD)/bin/aisec-cli verify -manifest $(BUILD)/aisec-manifest.json

# Без RELEASE=1 вместо keys/manifest.pub встраивается имитация ключа
# производителя (go test -overlay): тесты проверяют приём подписи ключом
# производителя и отказы. С RELEASE=1 — настоящий открытый ключ производителя.
RELEASE_CI_OVERLAY := $(BUILD)/release-ci-overlay.json

.PHONY: release-test
release-test: ## Тесты поставочной сборки (тег aisec_release, Н35, ADR-0022): принят только ключ производителя
ifeq ($(filter 1,$(RELEASE)),1)
	@test -s internal/integrity/keys/manifest.pub || { echo "release-test: нет internal/integrity/keys/manifest.pub — открытого ключа производителя (ADR-0022)"; exit 1; }
	go test -count=1 -tags aisec_release ./internal/integrity/
else
	@mkdir -p $(BUILD)
	@printf '{"Replace":{"%s/internal/integrity/keys/manifest.pub":"%s/internal/integrity/keys/manifest-release-ci.pub"}}\n' '$(CURDIR)' '$(CURDIR)' >$(RELEASE_CI_OVERLAY)
	go test -count=1 -tags aisec_release -overlay $(RELEASE_CI_OVERLAY) ./internal/integrity/
endif

.PHONY: release-fingerprint
release-fingerprint: ## Отпечаток открытого ключа производителя — для руководства установки и README поставки (ADR-0022)
	@test -s internal/integrity/keys/manifest.pub || { echo "release-fingerprint: нет internal/integrity/keys/manifest.pub"; exit 1; }
	@go run ./tools/manifest fingerprint -pub internal/integrity/keys/manifest.pub

# Образы поставки пилота (ADR-0019): scratch, статические бинарники, манифест
# целостности внутри образа. Поставочные образы — только RELEASE=1 (Н34);
# make images-test собирает те же образы с тестовым ключом под другим именем
# и с меткой ru.aisec.build-kind=test — для CI и стендов, НЕ ДЛЯ ПОСТАВКИ.
RELEASE_DIR := $(BUILD)/release
IMAGES_DIR  := $(BUILD)/images
IMAGE_CMDS  := aisec-server aisec-gateway aisec-cli
IMAGE_KIND  := $(if $(filter 1,$(RELEASE)),release,test)
IMAGE_REPO  ?= $(if $(filter 1,$(RELEASE)),aisec,aisec-test)
IMAGE_TAG   := $(VERSION)$(if $(filter 1,$(RELEASE)),,-test)
# Бинарники каждого образа: в aisec-cli — весь выпуск (aisec-cli verify).
IMAGE_BINS_aisec-server  := aisec-server
IMAGE_BINS_aisec-gateway := aisec-gateway
IMAGE_BINS_aisec-cli     := $(PRODUCT_CMDS)
PILOT_COMPOSE := deploy/compose/pilot/compose.yaml

# Проверки дерева выпуска (RELEASE=1): консоль собрана, дерево чистое, на
# HEAD тег VERSION. Состояние дерева проверяется по git, а не по VERSION: её
# можно переопределить (3Н3 ревью 3.r1). Неотслеживаемый файл тоже меняет
# сборку.
define release-tree-check
	@test -s web/dist/index.html || { echo "выпуск: нет web/dist/index.html — сначала make web-build (консоль встраивается в aisec-server)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "выпуск: в рабочем дереве есть изменения или неотслеживаемые файлы — выпуск только из чистого дерева"; exit 1; }
	@tag=$$(git describe --exact-match --tags HEAD 2>/dev/null) || { echo "выпуск: на HEAD нет тега — выпуск только с тега"; exit 1; }; \
		test "$$tag" = '$(VERSION)' || { echo "выпуск: VERSION=$(VERSION) не совпадает с тегом $$tag на HEAD"; exit 1; }
endef

.PHONY: release-dir
release-dir: ## Каталог выпуска build/release: статические бинарники и манифест (с RELEASE=1 — без подписи, ADR-0022)
ifeq ($(filter 1,$(RELEASE)),1)
	$(release-tree-check)
endif
	rm -rf $(RELEASE_DIR)
	mkdir -p $(RELEASE_DIR)/bin
	CGO_ENABLED=0 go build -trimpath -tags '$(BUILD_TAGS)' -ldflags '$(LDFLAGS)' -o $(RELEASE_DIR)/bin/ $(addprefix ./cmd/,$(PRODUCT_CMDS))
	go run ./tools/manifest build -out $(RELEASE_DIR)/aisec-manifest.json \
		$(if $(filter 1,$(RELEASE)),-unsigned,-test-key $(MANIFEST_TEST_KEY)) \
		-version '$(VERSION)' -created '$(SOURCE_DATE)' -bin $(RELEASE_DIR)/bin -cmds '$(PRODUCT_CMDS)' \
		-static web/dist -migrations migrations
ifneq ($(filter 1,$(RELEASE)),1)
	$(RELEASE_DIR)/bin/aisec-cli verify -manifest $(RELEASE_DIR)/aisec-manifest.json
endif

# Подпись манифеста поставки — на машине без сети с ключом на отдельном
# носителе (ADR-0022). Инструмент подписи — статический tools/manifest:
# make release-signer собирает его один раз, он переносится на машину
# подписи вместе с build/release/aisec-manifest.json.
SIGNER := $(BUILD)/signer/aisec-manifest-sign

.PHONY: release-signer
release-signer: ## Статический инструмент подписи манифеста для машины без сети (ADR-0022)
	CGO_ENABLED=0 go build -trimpath -ldflags '-s -w -buildid=' -o $(SIGNER) ./tools/manifest

.PHONY: release-sign
release-sign: ## Подписать манифест поставки ключом производителя: MANIFEST_KEY=… [MANIFEST_SHA256=…], только без сети
	@test -n '$(MANIFEST_KEY)' || { echo "release-sign: задайте MANIFEST_KEY — путь к ключу производителя на отдельном носителе"; exit 1; }
	go run ./tools/manifest sign -key '$(MANIFEST_KEY)' -manifest $(RELEASE_DIR)/aisec-manifest.json \
		$(if $(MANIFEST_SHA256),-expect-sha256 '$(MANIFEST_SHA256)')

# Каталог выпуска подписан ключом производителя (ревью 4.r1, 4В11):
# verify -manifest при тестовом ключе только предупреждает, поэтому выпуск
# проверяет aisec-cli из каталога с -release, и отказ — при тестовом ключе,
# при отпечатке ключа в бинарниках, отличном от VENDOR_PUB, и при версии
# манифеста, отличной от VERSION.
VENDOR_PUB ?= internal/integrity/keys/manifest.pub

.PHONY: release-signed-check
release-signed-check: ## Каталог выпуска подписан ключом производителя VENDOR_PUB, версия манифеста — VERSION (ADR-0022)
	@mkdir -p $(BUILD)
	@$(RELEASE_DIR)/bin/aisec-cli verify -release $(RELEASE_DIR) -allow-older >$(BUILD)/release-verify.out || \
		{ cat $(BUILD)/release-verify.out; echo "release-signed-check: каталог выпуска не прошёл проверку"; exit 1; }
	@cat $(BUILD)/release-verify.out
	@! grep -q 'тестовым ключом' $(BUILD)/release-verify.out || \
		{ echo "release-signed-check: каталог выпуска собран с тестовым ключом — make release-dir RELEASE=1 и подпись ключом производителя"; exit 1; }
	@got=$$(sed -n 's/^Отпечаток ключа производителя: //p' $(BUILD)/release-verify.out | tail -n 1); \
		want=$$(go run ./tools/manifest fingerprint -pub '$(VENDOR_PUB)') || exit 1; \
		test -n "$$got" && test "$$got" = "$$want" || \
		{ echo "release-signed-check: бинарники выпуска проверяют подпись ключом $$got, а $(VENDOR_PUB) — $$want"; exit 1; }
	@v=$$(sed -n 's/^  "version": "\([^"]*\)",$$/\1/p' $(RELEASE_DIR)/aisec-manifest.json); \
		test "$$v" = '$(VERSION)' || { echo "release-signed-check: версия манифеста $$v не совпадает с VERSION=$(VERSION)"; exit 1; }

.PHONY: images
images: ## Образы поставки пилота из подписанного каталога выпуска — только RELEASE=1 (Н34, ADR-0022): сборка, SBOM, проверка (ЗИ.5)
	@test '$(RELEASE)' = 1 || { echo "images: только RELEASE=1 (Н34); образы с тестовым ключом, не для поставки — make images-test"; exit 1; }
	$(release-tree-check)
	@test -s $(RELEASE_DIR)/aisec-manifest.json.sig || { echo "images: нет $(RELEASE_DIR)/aisec-manifest.json.sig — make release-dir RELEASE=1, затем подпись на машине без сети (make release-sign)"; exit 1; }
	$(MAKE) release-test
	$(MAKE) --no-print-directory release-signed-check
ifeq ($(filter 1,$(ML)),1)
	@test -s $(ML_RELEASE_DIR)/aisec-manifest.json.sig || { echo "images: нет $(ML_RELEASE_DIR)/aisec-manifest.json.sig — make ml-release-dir RELEASE=1, затем make release-sign RELEASE_DIR=$(ML_RELEASE_DIR) на машине без сети"; exit 1; }
	@$(RELEASE_DIR)/bin/aisec-cli verify -release $(ML_RELEASE_DIR) -allow-older >$(BUILD)/release-ml-verify.out || \
		{ cat $(BUILD)/release-ml-verify.out; echo "images: выпуск aisec-ml не прошёл проверку"; exit 1; }
	@! grep -q 'тестовым ключом' $(BUILD)/release-ml-verify.out || { echo "images: выпуск aisec-ml подписан тестовым ключом"; exit 1; }
	$(MAKE) --no-print-directory ort-verify ORT_LIB_DIR=$(ML_RELEASE_DIR)/lib
endif
	$(MAKE) --no-print-directory release-fingerprint
	$(MAKE) images-build

.PHONY: images-test
images-test: ## Те же образы с тестовым ключом манифеста — НЕ ДЛЯ ПОСТАВКИ (aisec-test/…:ВЕРСИЯ-test)
	@test '$(RELEASE)' != 1 || { echo "images-test: без RELEASE=1; поставочные образы — make images"; exit 1; }
	$(MAKE) images-all

.PHONY: images-all
images-all:
	$(MAKE) release-dir
	$(MAKE) images-build

.PHONY: images-build
images-build:
	$(MAKE) images-docker
ifeq ($(filter 1,$(ML)),1)
	$(MAKE) image-ml
endif
	$(MAKE) images-sbom
	$(MAKE) images-verify

.PHONY: images-docker
images-docker: ## docker build и docker save образов из build/release (без сети и без RUN)
	@test -s $(RELEASE_DIR)/aisec-manifest.json || { echo "images-docker: нет $(RELEASE_DIR) — make release-dir"; exit 1; }
	mkdir -p $(IMAGES_DIR)
	for c in $(IMAGE_CMDS); do \
		docker build --pull=false --network=none --provenance=false --sbom=false \
			-f deploy/build/Dockerfile.release --target $$c \
			--build-arg VERSION='$(VERSION)' --build-arg BUILD_KIND=$(IMAGE_KIND) \
			--build-arg SOURCE_DATE_EPOCH=$(SOURCE_EPOCH) \
			-t $(IMAGE_REPO)/$$c:$(IMAGE_TAG) $(RELEASE_DIR); \
		docker save -o $(IMAGES_DIR)/$$c.tar $(IMAGE_REPO)/$$c:$(IMAGE_TAG); \
	done

# $(call image-sbom,ОБРАЗ): SBOM образа — его бинарники, манифест и подпись;
# npm-пакеты консоли — только у образов с aisec-server.
define image-sbom
	go run ./tools/sbom -registry docs/cert/components.yaml -gosum go.sum $(if $(filter aisec-gateway,$(1)),,-npm-lock web/package-lock.json) \
		-out $(IMAGES_DIR)/$(1).cdx.json -version '$(VERSION)' -timestamp '$(SOURCE_DATE)' -image $(IMAGE_REPO)/$(1):$(IMAGE_TAG) \
		-file $(RELEASE_DIR)/aisec-manifest.json -file $(RELEASE_DIR)/aisec-manifest.json.sig $(addprefix $(RELEASE_DIR)/bin/,$(IMAGE_BINS_$(1)))
	$(BIN)/sbom-utility validate --quiet --input-file $(IMAGES_DIR)/$(1).cdx.json
	go run ./tools/sbom -check $(IMAGES_DIR)/$(1).cdx.json

endef

.PHONY: images-sbom
images-sbom: $(BIN)/sbom-utility ## SBOM каждого образа (CycloneDX 1.6): бинарники образа, манифест и подпись
	$(foreach c,$(IMAGE_CMDS),$(call image-sbom,$(c)))

.PHONY: images-verify
images-verify: ## Проверка образов (ЗИ.5): не root, нет оболочки и пакетов ОС, только свои порты, бинарники = манифест выпуска; compose пилота
	go run ./tools/imagecheck image -release $(RELEASE_DIR) -kind $(IMAGE_KIND) $(addprefix $(IMAGES_DIR)/,$(addsuffix .tar,$(IMAGE_CMDS)))
	go run ./tools/imagecheck compose $(PILOT_COMPOSE)
	go run ./tools/imagecheck compose $(PILOT_COMPOSE) $(PILOT_ML_COMPOSE)
ifeq ($(filter 1,$(ML)),1)
	go run ./tools/imagecheck image -release $(ML_RELEASE_DIR) -kind $(IMAGE_KIND) $(IMAGES_DIR)/aisec-ml.tar
endif

# ML-детекторы (ADR-0024, задача 4.19): ONNX Runtime 1.31.0 из исходников без
# телеметрии и выпуск aisec-ml со своим манифестом целостности.
#
#   make ort-fetch            зеркало исходников по deps.lock (сеть: git и https)
#   make ort-build            библиотека ORT в Dockerfile.ml без сети; хеш — с ort.sha256
#   make ml-release-dir       каталог выпуска build/release-ml (Dockerfile.ml)
#   make images ML=1          образы поставки вместе с aisec-ml
#
# Выпуск aisec-ml — отдельный каталог и манифест: в основном выпуске нет
# библиотек с cgo, и aisec-cli verify не зависит от ML. С RELEASE=1 манифест
# выпуска aisec-ml подписывается так же, как основной: make release-sign
# RELEASE_DIR=build/release-ml на машине без сети.
ML ?=
ORT_VERSION    := 1.31.0
ORT_DIR        := deploy/build/onnxruntime
ORT_MIRROR     := $(BUILD)/ort-mirror
ORT_OUT        := $(BUILD)/ort
ORT_LIB_DIR    ?= $(ORT_OUT)/lib
ORT_JOBS       ?=
ML_RELEASE_DIR := $(BUILD)/release-ml
ML_LIB_PATH    := /opt/aisec/lib
# Подписанный пакет моделей (tools/manifest sign-models) — в образ aisec-ml;
# пусто — образ без моделей, aisec-ml отвечает «недоступен» (часть 2 задачи 4.19).
ML_MODELS_DIR  ?=
MANIFEST_MODE  ?= $(if $(filter 1,$(RELEASE)),unsigned,test)
PILOT_ML_COMPOSE := deploy/compose/pilot/compose.ml.yaml

.PHONY: ort-fetch
ort-fetch: ## Зеркало исходников ONNX Runtime и зависимостей по deps.lock с проверкой SHA-256 (сеть)
	bash $(ORT_DIR)/fetch.sh $(ORT_DIR)/deps.lock $(ORT_MIRROR)

.PHONY: ort-build
ort-build: ## Сборка ONNX Runtime без сети в Dockerfile.ml; хеш библиотеки сверяется с ort.sha256
	@test -d $(ORT_MIRROR) || { echo "ort-build: нет $(ORT_MIRROR) — сначала make ort-fetch"; exit 1; }
	docker build --pull=false -f deploy/build/Dockerfile.ml --target ort-out \
		--build-arg ORT_JOBS='$(ORT_JOBS)' -o type=local,dest=$(ORT_OUT) .
	$(MAKE) --no-print-directory ort-verify

# Эталонный хеш (ort.sha256) записывается после эталонной сборки на машине
# владельца (docs/cert/build-env.md). Пока его нет, сборка только печатает хеш;
# поставка (RELEASE=1) без эталона не собирается.
.PHONY: ort-verify
ort-verify:
	@test -f $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION) || { echo "ort-verify: нет $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION)"; exit 1; }
	@got=$$(sha256sum $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION) | cut -d' ' -f1) || exit 1; \
		echo "SHA-256 libonnxruntime.so.$(ORT_VERSION): $$got"; \
		if [ -s $(ORT_DIR)/ort.sha256 ]; then \
			want=$$(cut -d' ' -f1 $(ORT_DIR)/ort.sha256); \
			test "$$got" = "$$want" || { echo "ort-verify: хеш не совпадает с эталоном $(ORT_DIR)/ort.sha256 ($$want) — сборка невоспроизводима или подменена"; exit 1; }; \
			echo "Совпадает с эталоном $(ORT_DIR)/ort.sha256."; \
		elif [ '$(RELEASE)' = 1 ]; then \
			echo "ort-verify: нет эталона $(ORT_DIR)/ort.sha256 — поставка без эталонной сборки запрещена"; exit 1; \
		else \
			echo "Эталона $(ORT_DIR)/ort.sha256 нет: запишите хеш эталонной сборки (docs/cert/build-env.md)."; \
		fi

.PHONY: ml-release-dir
ml-release-dir: ## Каталог выпуска aisec-ml build/release-ml в Dockerfile.ml без сети (с RELEASE=1 — без подписи)
ifeq ($(filter 1,$(RELEASE)),1)
	$(release-tree-check)
endif
	@test -d $(ORT_MIRROR) || { echo "ml-release-dir: нет $(ORT_MIRROR) — сначала make ort-fetch"; exit 1; }
	rm -rf $(ML_RELEASE_DIR)
	docker build --pull=false -f deploy/build/Dockerfile.ml --target ml-release \
		--build-arg VERSION='$(VERSION)' --build-arg SOURCE_DATE='$(SOURCE_DATE)' --build-arg SOURCE_EPOCH='$(SOURCE_EPOCH)' \
		--build-arg MANIFEST_MODE=$(MANIFEST_MODE) --build-arg RELEASE='$(RELEASE)' --build-arg ORT_JOBS='$(ORT_JOBS)' \
		$(if $(ML_MODELS_DIR),--build-context ml-models=$(ML_MODELS_DIR) --build-arg ML_MODELS=1) -o type=local,dest=$(ML_RELEASE_DIR) .
	$(MAKE) --no-print-directory ort-verify ORT_LIB_DIR=$(ML_RELEASE_DIR)/lib

# Сборка выпуска aisec-ml внутри Dockerfile.ml (стадия ml): бинарник с cgo,
# загрузчиком и RPATH /opt/aisec/lib, хешем библиотеки ORT (SHA-256 —
# криптопрофиль standard aisec-ml), библиотеки из того же образа и манифест.
.PHONY: ml-release-assemble
ml-release-assemble:
	@test '$(MANIFEST_MODE)' != unsigned || test '$(RELEASE)' = 1 || { echo "ml-release-assemble: MANIFEST_MODE=unsigned — только с RELEASE=1 (иначе в aisec-ml тестовый ключ)"; exit 1; }
	@test '$(MANIFEST_MODE)' = unsigned || test '$(RELEASE)' != 1 || { echo "ml-release-assemble: RELEASE=1 — только MANIFEST_MODE=unsigned"; exit 1; }
	@test -f $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION) || { echo "ml-release-assemble: нет $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION)"; exit 1; }
	rm -rf $(ML_RELEASE_DIR)
	mkdir -p $(ML_RELEASE_DIR)/bin $(ML_RELEASE_DIR)/lib $(ML_RELEASE_DIR)/models
	$(if $(ML_MODELS_DIR),cp -R $(ML_MODELS_DIR)/. $(ML_RELEASE_DIR)/models/)
	install -m 0644 $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION) $(ML_RELEASE_DIR)/lib/
	hash=$$(sha256sum $(ML_RELEASE_DIR)/lib/libonnxruntime.so.$(ORT_VERSION) | cut -d' ' -f1) && \
	CGO_ENABLED=1 go build -trimpath -tags '$(BUILD_TAGS) aisec_onnx' \
		-ldflags "$(LDFLAGS) -X main.ortLibHash=$$hash -linkmode=external -extldflags '-Wl,--dynamic-linker=$(ML_LIB_PATH)/ld-linux-x86-64.so.2 -Wl,--disable-new-dtags -Wl,-rpath,$(ML_LIB_PATH)'" \
		-o $(ML_RELEASE_DIR)/bin/aisec-ml ./cmd/aisec-ml
	bash deploy/build/ml-libs.sh $(ML_RELEASE_DIR)
	go run ./tools/manifest build -out $(ML_RELEASE_DIR)/aisec-manifest.json \
		$(if $(filter unsigned,$(MANIFEST_MODE)),-unsigned,-test-key $(MANIFEST_TEST_KEY)) \
		-version '$(VERSION)' -created '$(SOURCE_DATE)' -bin $(ML_RELEASE_DIR)/bin -cmds aisec-ml -lib $(ML_RELEASE_DIR)/lib \
		$(if $(ML_MODELS_DIR),-models $(ML_RELEASE_DIR)/models)

.PHONY: image-ml
image-ml: ## Образ aisec-ml из build/release-ml (без сети и без RUN), SBOM
	@test -s $(ML_RELEASE_DIR)/aisec-manifest.json || { echo "image-ml: нет $(ML_RELEASE_DIR) — make ml-release-dir"; exit 1; }
	mkdir -p $(IMAGES_DIR)
	docker build --pull=false --network=none --provenance=false --sbom=false \
		-f deploy/build/Dockerfile.release --target aisec-ml \
		--build-arg VERSION='$(VERSION)' --build-arg BUILD_KIND=$(IMAGE_KIND) \
		--build-arg SOURCE_DATE_EPOCH=$(SOURCE_EPOCH) \
		-t $(IMAGE_REPO)/aisec-ml:$(IMAGE_TAG) $(ML_RELEASE_DIR)
	docker save -o $(IMAGES_DIR)/aisec-ml.tar $(IMAGE_REPO)/aisec-ml:$(IMAGE_TAG)
	go run ./tools/sbom -registry docs/cert/components.yaml -gosum go.sum -native \
		-out $(IMAGES_DIR)/aisec-ml.cdx.json -version '$(VERSION)' -timestamp '$(SOURCE_DATE)' -image $(IMAGE_REPO)/aisec-ml:$(IMAGE_TAG) \
		-file $(ML_RELEASE_DIR)/aisec-manifest.json -file $(ML_RELEASE_DIR)/aisec-manifest.json.sig \
		$(addprefix -file ,$(sort $(wildcard $(ML_RELEASE_DIR)/lib/*))) $(ML_RELEASE_DIR)/bin/aisec-ml
	$(BIN)/sbom-utility validate --quiet --input-file $(IMAGES_DIR)/aisec-ml.cdx.json
	go run ./tools/sbom -check $(IMAGES_DIR)/aisec-ml.cdx.json

# Модели aisec-ml (задача 4.19, часть 2; ADR-0024): цели для машины
# владельца, по порядку (docs/cert/build-env.md, раздел «Модели»):
#   make ml-venv            окружение Python build/ml/venv по tools/ml/requirements.txt (хеши)
#   make ml-fetch ML_LOCK=1 скачать модели и наборы; первый раз — зафиксировать коммиты и хеши
#   make ml-train           подготовка данных и дообучка injection.ml (rubert-tiny2)
#   make ml-export          ONNX, токенизаторы, эталоны и ML-BOM обеих моделей
#   make ml-verify          aisec-ml (ONNX Runtime) сверяется с эталонами Python
#   make ml-p4              замер Р4 → build/ml/p4.md (таблица для docs/detectors.md)
#   make ml-package ML_KEY=… подписанный пакет build/ml/models (машина без сети)
# Python и его пакеты — только инструменты разработки, в поставку не входят.
ML_BUILD       := $(BUILD)/ml
ML_VENV        := $(ML_BUILD)/venv
ML_PY          := $(ML_VENV)/bin/python
ML_VERSION     ?= 1.0.0
ML_ORT_LIB     ?= $(ORT_LIB_DIR)/libonnxruntime.so.$(ORT_VERSION)
ML_TORCH       := torch==2.14.1+cpu
ML_TORCH_INDEX := https://download.pytorch.org/whl/cpu
ML_LOCK        ?=
ML_KEY         ?=
ML_TEST_KEY    ?=
# Р4 меряется на 4 vCPU: замер привязывается к этим четырём процессорам.
ML_P4_CPUS     ?= 0-3

# torch — сборка только для процессора с download.pytorch.org (с PyPI тянет
# CUDA под проприетарной лицензией). Хеш колеса сверяется с
# tools/ml/torch.sha256; пока эталона нет, печатается для записи (как ort.sha256).
.PHONY: ml-venv
ml-venv: ## Окружение Python для моделей build/ml/venv: точные версии и SHA-256 пакетов (сеть)
	@test -f tools/ml/requirements.txt || { echo "ml-venv: нет tools/ml/requirements.txt — список пакетов Python ждёт решения владельца (docs/cert/build-env.md, «Модели»)"; exit 1; }
	python3 -m venv $(ML_VENV)
	rm -rf $(ML_BUILD)/wheels
	$(ML_PY) -m pip download --no-deps --only-binary=:all: --index-url $(ML_TORCH_INDEX) -d $(ML_BUILD)/wheels '$(ML_TORCH)'
	@got=$$(sha256sum $(ML_BUILD)/wheels/torch-*.whl | cut -d' ' -f1) || exit 1; \
		echo "SHA-256 колеса torch: $$got"; \
		if [ -s tools/ml/torch.sha256 ]; then \
			grep -q "^$$got " tools/ml/torch.sha256 || { echo "ml-venv: хеш torch не совпадает с tools/ml/torch.sha256 — файл подменён или другая версия Python"; exit 1; }; \
			echo "Совпадает с tools/ml/torch.sha256."; \
		else \
			echo "Эталона tools/ml/torch.sha256 нет: запишите строку «$$got  $$(basename $(ML_BUILD)/wheels/torch-*.whl)» в этот файл и зафиксируйте коммитом."; \
		fi
	$(ML_PY) -m pip install --no-deps --no-index $(ML_BUILD)/wheels/torch-*.whl
	$(ML_PY) -m pip install --no-deps --require-hashes --only-binary=:all: -r tools/ml/requirements.txt
	@echo "ГОТОВО: окружение $(ML_VENV)"

.PHONY: ml-fetch
ml-fetch: ## Скачать модели и наборы по tools/ml/sources.json с проверкой SHA-256 (сеть; ML_LOCK=1 — зафиксировать)
	@test -x $(ML_PY) || { echo "ml-fetch: нет $(ML_VENV) — сначала make ml-venv"; exit 1; }
	$(ML_PY) tools/ml/fetch.py $(if $(filter 1,$(ML_LOCK)),--lock)

.PHONY: ml-train
ml-train: ## Подготовка данных и дообучка injection.ml без сети (build/ml/train)
	@test -x $(ML_PY) || { echo "ml-train: нет $(ML_VENV) — сначала make ml-venv"; exit 1; }
	$(ML_PY) tools/ml/prepare.py
	$(ML_PY) tools/ml/train.py

.PHONY: ml-export
ml-export: ## ONNX, токенизаторы, эталоны и ML-BOM моделей без сети (build/ml/models)
	@test -x $(ML_PY) || { echo "ml-export: нет $(ML_VENV) — сначала make ml-venv"; exit 1; }
	rm -rf $(ML_BUILD)/models $(ML_BUILD)/ref $(ML_BUILD)/models.spec.json
	$(ML_PY) tools/ml/export.py --model $(ML_BUILD)/train/injection-ru-en --id injection-ru-en --version $(ML_VERSION) \
		--task classification --directions input --corpus testdata/corpus/injection.ml
	$(ML_PY) tools/ml/export.py --model $(ML_BUILD)/src/rubert-tiny-toxicity --id toxicity-ru --version $(ML_VERSION) \
		--task multilabel_classification --directions input,output --corpus testdata/corpus/toxicity.ml
	$(ML_PY) tools/ml/mlbom.py --id injection-ru-en --version $(ML_VERSION) --source rubert-tiny2 \
		--train-report $(ML_BUILD)/train/injection-ru-en/train_report.json
	$(ML_PY) tools/ml/mlbom.py --id toxicity-ru --version $(ML_VERSION) --source rubert-tiny-toxicity
	cd $(ML_BUILD)/models && sha256sum */model.onnx */tokenizer.json

# Сверка и замер — Go с ONNX Runtime (make ort-build или ML_ORT_LIB=…):
# тот же исполнитель, что в aisec-ml, на неподписанных файлах build/ml.
.PHONY: ml-verify
ml-verify: ## aisec-ml сверяет токены и выход моделей с эталонами Python (допуск 2e-3)
	@test -f $(ML_ORT_LIB) || { echo "ml-verify: нет $(ML_ORT_LIB) — make ort-build или ML_ORT_LIB=…"; exit 1; }
	CGO_ENABLED=1 AISEC_ORT_LIB=$(ML_ORT_LIB) AISEC_ML_DIR=$(ML_BUILD) \
		go test -count=1 -tags aisec_onnx,aisec_models -run TestModelsMatchReference -v ./cmd/aisec-ml/

.PHONY: ml-p4
ml-p4: ## Замер Р4 ML-детекторов против эвристик → build/ml/p4.md
	@test -f $(ML_ORT_LIB) || { echo "ml-p4: нет $(ML_ORT_LIB) — make ort-build или ML_ORT_LIB=…"; exit 1; }
	CGO_ENABLED=1 AISEC_ORT_LIB=$(ML_ORT_LIB) AISEC_ML_DIR=$(ML_BUILD) GOMAXPROCS=4 \
		taskset -c $(ML_P4_CPUS) go test -count=1 -timeout 30m -tags aisec_onnx,aisec_models -run TestP4Measure -v ./cmd/aisec-ml/
	cat $(ML_BUILD)/p4.md

# Ключ производителя — только на машине без сети (как make release-sign);
# ML_TEST_KEY=1 — тестовый ключ, пакет не для поставки. Готовый пакет:
# make ml-release-dir ML_MODELS_DIR=build/ml/models.
.PHONY: ml-package
ml-package: ## Подписанный пакет моделей build/ml/models (ML_KEY=… или ML_TEST_KEY=1)
	@test -n '$(ML_KEY)$(filter 1,$(ML_TEST_KEY))' || { echo "ml-package: нужен ML_KEY=<ключ производителя> или ML_TEST_KEY=1"; exit 1; }
	@test -z '$(ML_KEY)' || test -z '$(filter 1,$(ML_TEST_KEY))' || { echo "ml-package: ML_KEY и ML_TEST_KEY=1 вместе нельзя"; exit 1; }
	go run ./tools/manifest sign-models -dir $(ML_BUILD)/models -spec $(ML_BUILD)/models.spec.json \
		-version '$(ML_VERSION)' -created '$(SOURCE_DATE)' \
		$(if $(ML_KEY),-key '$(ML_KEY)',-test-key $(MANIFEST_TEST_KEY))

# CI: Go-шаги — в сборочном образе (точная версия Go и sbom-utility), docker
# build — на хосте.
.PHONY: images-test-docker
images-test-docker: build-image ## make images-test, где Go-шаги идут в сборочном образе (CI)
	@test '$(RELEASE)' != 1 || { echo "images-test-docker: без RELEASE=1"; exit 1; }
	$(DOCKER_RUN) $(BUILD_IMAGE) make release-dir BIN=/opt/aisec-tools/bin
	$(MAKE) images-docker
	$(DOCKER_RUN) $(BUILD_IMAGE) make images-sbom images-verify BIN=/opt/aisec-tools/bin

.PHONY: e2e
e2e: manifest ## Сквозные тесты: шлюз и mock-llm по TLS (этап 1); сервер, CLI и PostgreSQL (этап 2, нужен AISEC_TEST_DATABASE_URL — иначе пропускаются)
	go test -tags e2e -count=1 ./test/e2e/ -bin $(BUILD)/bin

# e2e пилота в docker compose (задачи 3.7 и 3.8 этапа 3): сети без выхода
# наружу и ловушка сети (test/e2e/netwatch), копия и восстановление
# (backup.sh, restore.sh). Образы — make images-test (тот же VERSION).
# Тестовый бинарник запускается от root: prepare-host.sh создаёт
# пользователей хоста; не от root — через sudo -n.
PILOT_E2E := $(BUILD)/pilot-e2e
PILOT_E2E_SUDO := $(if $(filter 0,$(shell id -u)),,sudo -n)

.PHONY: e2e-pilot-bin
e2e-pilot-bin: ## Сборка e2e пилота: тестовый бинарник, ловушка сети netwatch и mock-llm (статические)
	mkdir -p $(PILOT_E2E)
	CGO_ENABLED=0 go test -c -tags e2e -o $(PILOT_E2E)/e2e.test ./test/e2e/
	CGO_ENABLED=0 go build -trimpath -tags e2e -o $(PILOT_E2E)/ ./test/e2e/netwatch ./cmd/mock-llm

.PHONY: e2e-pilot-bin-docker
e2e-pilot-bin-docker: build-image ## make e2e-pilot-bin в сборочном образе (CI)
	$(DOCKER_RUN) $(BUILD_IMAGE) make e2e-pilot-bin BIN=/opt/aisec-tools/bin

.PHONY: e2e-pilot-run
e2e-pilot-run: ## e2e пилота на собранных образах и бинарниках (root или sudo -n, Docker); AISEC_POSTGRES_IMAGE — свой реестр
	cd test/e2e && $(PILOT_E2E_SUDO) env AISEC_E2E_PILOT=1 AISEC_VERSION='$(IMAGE_TAG)' AISEC_IMAGE_REPO='$(IMAGE_REPO)' \
		AISEC_E2E_TOOLS='$(abspath $(PILOT_E2E))' $(if $(AISEC_POSTGRES_IMAGE),AISEC_POSTGRES_IMAGE='$(AISEC_POSTGRES_IMAGE)') \
		'$(abspath $(PILOT_E2E))/e2e.test' -test.run '^TestE2EPilot' -test.v -test.count=1 -test.timeout 30m

.PHONY: e2e-pilot
e2e-pilot: e2e-pilot-bin ## e2e пилота: без интернета (3.7), копия и восстановление (3.8); сначала make images-test
	$(MAKE) e2e-pilot-run

# DAST пилота (задача 3.30, Р10): OWASP ZAP baseline против консоли и шлюза
# установки в docker compose (deploy/compose/pilot/dast). Отчёты — build/dast/.
# Находки сверяет tools/dast-triage с правилами zap-rules.conf и разметкой
# docs/cert/sast-triage/dast.yaml. Сначала make images-test; ZAP в CI.
DAST_OUT := $(BUILD)/dast

.PHONY: dast-run
dast-run: ## ZAP baseline по консоли и шлюзу собранного стенда (root или sudo -n, Docker); AISEC_POSTGRES_IMAGE — свой реестр
	mkdir -p $(DAST_OUT)
	cd test/e2e && $(PILOT_E2E_SUDO) env AISEC_E2E_PILOT=1 AISEC_E2E_DAST=1 AISEC_DAST_OUT='$(abspath $(DAST_OUT))' \
		AISEC_VERSION='$(IMAGE_TAG)' AISEC_IMAGE_REPO='$(IMAGE_REPO)' AISEC_E2E_TOOLS='$(abspath $(PILOT_E2E))' \
		$(if $(AISEC_POSTGRES_IMAGE),AISEC_POSTGRES_IMAGE='$(AISEC_POSTGRES_IMAGE)') \
		'$(abspath $(PILOT_E2E))/e2e.test' -test.run '^TestE2EPilot_DAST$$' -test.v -test.count=1 -test.timeout 30m

.PHONY: dast-triage
dast-triage: ## Сверка отчётов ZAP (build/dast) с правилами и разметкой; выше порога без разметки — провал
	go run ./tools/dast-triage -out $(DAST_OUT)/summary.md console=$(DAST_OUT)/console.json gateway=$(DAST_OUT)/gateway.json

.PHONY: dast-triage-docker
dast-triage-docker: build-image ## make dast-triage в сборочном образе (CI)
	$(DOCKER_RUN) $(BUILD_IMAGE) make dast-triage

.PHONY: dast
dast: e2e-pilot-bin ## DAST пилота: ZAP baseline и сверка находок; сначала make images-test
	$(MAKE) dast-run
	$(MAKE) dast-triage

COMPOSE_DEV := docker compose -f deploy/compose/dev/docker-compose.yml

.PHONY: dev
dev: .dev-keys/gateway.yaml ## Стенд разработки в docker compose: шлюз на https://127.0.0.1:8443 перед mock-llm
	mkdir -p -m 0700 .dev-data .dev-data/pg
	test -s .dev-keys/pg-password || (umask 077; head -c 24 /dev/urandom | base64 | tr -d '/+=\n' > .dev-keys/pg-password)
	AISEC_UID=$$(id -u) AISEC_GID=$$(id -g) $(COMPOSE_DEV) up --build

.PHONY: dev-down
dev-down: ## Остановить стенд разработки
	AISEC_UID=$$(id -u) AISEC_GID=$$(id -g) $(COMPOSE_DEV) down

# Конфигурации шлюза нет (первый запуск или каталог от этапа 0) — выпустить всё заново.
.dev-keys/gateway.yaml:
	go run ./tools/devcerts -out .dev-keys -force

.PHONY: devcerts
devcerts: ## Материалы стенда разработки в .dev-keys/: УЦ и сервер (ключ УЦ не сохраняется), ключ приложения, конфигурация шлюза
	go run ./tools/devcerts -out .dev-keys -force

# Сборочный образ (deploy/build/Dockerfile): версии инструментов — из переменных выше.
BUILD_IMAGE := aisec-build:$(GO_VERSION)-lint$(GOLANGCI_LINT_VERSION)-vuln$(GOVULNCHECK_VERSION)-sbom$(SBOM_UTILITY_VERSION)
DOCKER_RUN  := docker run --rm --user $$(id -u):$$(id -g) -v $(CURDIR):/src -w /src

.PHONY: build-image
build-image: ## Собрать сборочный образ со всеми инструментами make check
	docker build -f deploy/build/Dockerfile \
		--build-arg GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION) \
		--build-arg GOVULNCHECK_VERSION=$(GOVULNCHECK_VERSION) \
		--build-arg SBOM_UTILITY_VERSION=$(SBOM_UTILITY_VERSION) \
		-t $(BUILD_IMAGE) deploy/build

.PHONY: check-docker
check-docker: build-image ## make check в сборочном образе — «чистая машина»
	$(DOCKER_RUN) $(if $(AISEC_TEST_DATABASE_URL),--network=host -e AISEC_TEST_DATABASE_URL) $(BUILD_IMAGE) make check BIN=/opt/aisec-tools/bin

# Снимок базы уязвимостей Go для закрытого контура (ADR-0003): каталог в
# формате базы (index/, ID/). Передаётся явно: VULNDB_DIR=/путь make check-offline.
VULNDB_DIR ?=

.PHONY: fuzz-long-docker
fuzz-long-docker: build-image ## Длительный фаззинг в сборочном образе (ночной CI); все цели, даже после падения
	$(DOCKER_RUN) $(BUILD_IMAGE) make fuzz-long BIN=/opt/aisec-tools/bin FUZZ_KEEP_GOING=1

.PHONY: vuln-docker
vuln-docker: build-image ## Проверка уязвимостей в сборочном образе (ночной CI)
	$(DOCKER_RUN) $(BUILD_IMAGE) make vuln BIN=/opt/aisec-tools/bin

.PHONY: check-offline
check-offline: build-image ## make check в сборочном образе без сети (нужен VULNDB_DIR со снимком базы уязвимостей)
	@test -n "$(VULNDB_DIR)" || { echo "Укажите VULNDB_DIR — каталог со снимком базы уязвимостей Go (ADR-0003)"; exit 1; }
	$(DOCKER_RUN) --network=none -v $(abspath $(VULNDB_DIR)):/govulndb:ro $(BUILD_IMAGE) \
		make check BIN=/opt/aisec-tools/bin GOVULNDB=file:///govulndb

.PHONY: clean
clean: ## Удалить результаты сборки
	rm -rf $(BUILD)
	find web/dist -mindepth 1 ! -name .gitkeep -delete 2>/dev/null || true
