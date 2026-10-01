# Makefile — единственное место с логикой сборки и проверок (ТЗ, 11.4).
# CI — тонкая обёртка над этими целями (ADR-0002).

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Текущий этап (ТЗ, раздел 14): строки матрицы 5.16 с этапом не выше этого
# обязаны быть покрыты тестами.
STAGE := 0

# Скрытые загрузки запрещены (ТЗ, 8.7): зависимости — только из vendor/,
# прокси модулей выключен, toolchain должен быть уже установлен. Переменные
# окружения эти запреты не снимают (override). Единственная цель, которая
# ходит в сеть явно, — make tools.
GO_VERSION := go1.27.1
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

# Компоненты в поставке. mock-llm в поставку не входит.
PRODUCT_CMDS := aisec-gateway aisec-server aisec-cli aisec-media
DEV_CMDS     := mock-llm

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Время последнего коммита — для воспроизводимых артефактов (SBOM, фронтенд).
SOURCE_DATE ?= $(shell git log -1 --format=%cI 2>/dev/null || echo 1970-01-01T00:00:00Z)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: help
help: ## Список целей
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

.PHONY: check
# Проверки из CLAUDE.md, которые ещё не реализованы. Пока список не пуст,
# зелёный make check неполный — об этом печатается предупреждение.
PENDING_CHECKS :=

check: fmt-check vet docs-check repocheck licenses lint lint-selftest sast test build e2e dm-coverage sbom fuzz-smoke vuln ## Все проверки перед pull request
	@if [ -n "$(strip $(PENDING_CHECKS))" ]; then \
		echo "ВНИМАНИЕ: make check неполный, ещё не реализованы: $(PENDING_CHECKS) (docs/plans/stage-0.md)"; fi

.PHONY: fmt-check
fmt-check: ## Форматирование Go-кода (gofmt)
	@out="$$(gofmt -l $$(git ls-files '*.go'))"; \
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

.PHONY: sbom
sbom: build $(BIN)/sbom-utility ## SBOM продукта (CycloneDX 1.6) из собранных бинарников и проверка формата
	go run ./tools/sbom -registry docs/cert/components.yaml -out $(BUILD)/sbom/aisec.cdx.json \
		-version '$(VERSION)' -timestamp '$(SOURCE_DATE)' $(addprefix $(BUILD)/bin/,$(PRODUCT_CMDS))
	$(BIN)/sbom-utility validate --quiet --input-file $(BUILD)/sbom/aisec.cdx.json
	go run ./tools/sbom -check $(BUILD)/sbom/aisec.cdx.json

$(BIN)/sbom-utility:
	@echo "Нет $@: выполните make tools (или используйте сборочный образ)"; exit 1

.PHONY: licenses
licenses: ## Реестр компонентов и лицензии: docs/cert/components.yaml против vendor/, go.mod, Makefile
	go run ./tools/license-check -root .

.PHONY: repocheck
repocheck: ## Структурные правила: один internal/crypto, cgo только по ADR
	go run ./tools/repocheck -root . -cgo-allowed '$(CGO_ALLOWED)'

.PHONY: docs-check
docs-check: ## Относительные ссылки в документах ведут на существующие файлы
	go run ./tools/docs-check -root .

.PHONY: test
test: ## Модульные тесты с детектором гонок
	CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: build
build: ## Сборка бинарников в build/bin
	@mkdir -p $(BUILD)/bin
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BUILD)/bin/ $(addprefix ./cmd/,$(PRODUCT_CMDS) $(DEV_CMDS))

.PHONY: lint
lint: lint-version ## Линтеры, в том числе depguard (.golangci.yml); с cgo, чтобы проверялись все файлы
	CGO_ENABLED=1 $(BIN)/golangci-lint run ./...

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
manifest: ## Манифест целостности (ОЦЛ.1)
	@echo "manifest: манифест целостности появляется на этапе 2 (ТЗ, ОЦЛ.1)"; exit 1

.PHONY: e2e
e2e: build ## Сквозные тесты: настоящие бинарники шлюза и mock-llm по TLS
	go test -tags e2e -count=1 ./test/e2e/ -bin $(BUILD)/bin

COMPOSE_DEV := docker compose -f deploy/compose/dev/docker-compose.yml

.PHONY: dev
dev: .dev-keys/ca.pem ## Стенд разработки в docker compose: шлюз на https://127.0.0.1:8443 перед mock-llm
	AISEC_UID=$$(id -u) AISEC_GID=$$(id -g) $(COMPOSE_DEV) up --build

.PHONY: dev-down
dev-down: ## Остановить стенд разработки
	AISEC_UID=$$(id -u) AISEC_GID=$$(id -g) $(COMPOSE_DEV) down

.dev-keys/ca.pem:
	go run ./tools/devcerts -out .dev-keys

.PHONY: devcerts
devcerts: ## Сертификаты стенда разработки в .dev-keys/ (УЦ и сервер; ключ УЦ не сохраняется)
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
	$(DOCKER_RUN) $(BUILD_IMAGE) make check BIN=/opt/aisec-tools/bin

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
