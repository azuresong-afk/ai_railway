# Makefile — единственное место с логикой сборки и проверок (ТЗ, 11.4).
# CI — тонкая обёртка над этими целями (ADR-0002).

SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c
.DEFAULT_GOAL := help

# Текущий этап (ТЗ, раздел 14): строки матрицы 5.16 с этапом не выше этого
# обязаны быть покрыты тестами.
STAGE := 0

# Скрытые загрузки запрещены по умолчанию: toolchain должен быть установлен,
# зависимости берутся только из vendor/ (ТЗ, 8.7). Для разработки на машине
# без Go 1.27 можно переопределить: GOTOOLCHAIN=go1.27.1 make ...
export GOTOOLCHAIN ?= local
export GOFLAGS ?= -mod=vendor
export CGO_ENABLED ?= 0

# Версии инструментов разработки (ТЗ, 8.2). Меняются только вместе с
# docs/cert/components.yaml (scope: build) и сборочным образом.
GOLANGCI_LINT_VERSION := v2.14.0
GOVULNCHECK_VERSION   := v1.8.0
SBOM_UTILITY_VERSION  := v1.0.1

BIN   := $(CURDIR)/bin
BUILD := $(CURDIR)/build

# Компоненты в поставке. mock-llm в поставку не входит.
PRODUCT_CMDS := aisec-gateway aisec-server aisec-cli aisec-media
DEV_CMDS     := mock-llm

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)

.PHONY: help
help: ## Список целей
	@grep -E '^[a-zA-Z0-9_-]+:.*## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*## "}; {printf "  %-16s %s\n", $$1, $$2}'

.PHONY: check
check: fmt-check vet docs-check test build ## Все проверки перед pull request

.PHONY: fmt-check
fmt-check: ## Форматирование Go-кода (gofmt)
	@out="$$(gofmt -l $$(git ls-files '*.go'))"; \
	if [ -n "$$out" ]; then echo "Не отформатированы (gofmt -w):"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## go vet
	go vet ./...

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

.PHONY: tools
tools: ## Установить инструменты разработки в bin/ по зафиксированным версиям
	@mkdir -p $(BIN)
	GOFLAGS=-mod=mod GOBIN=$(BIN) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	GOFLAGS=-mod=mod GOBIN=$(BIN) go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
	GOFLAGS=-mod=mod GOBIN=$(BIN) go install github.com/CycloneDX/sbom-utility@$(SBOM_UTILITY_VERSION)

# Цели, которые появляются в следующих задачах плана этапа 0. До реализации
# они падают, а не проходят молча.
NOT_YET = @echo "$@: не реализовано — задача $(1) плана этапа 0 (docs/plans/stage-0.md)"; exit 1

.PHONY: lint sast fuzz-smoke fuzz-long vuln licenses sbom dm-coverage e2e dev manifest
lint: ## Линтеры, в том числе depguard
	$(call NOT_YET,0.4)
sast: ## Статический анализ в SARIF и сверка разметки
	$(call NOT_YET,0.5)
fuzz-smoke: ## Короткий прогон всех fuzz-целей
	$(call NOT_YET,0.6)
fuzz-long: ## Длительный прогон fuzz-целей (ночной)
	$(call NOT_YET,0.6)
vuln: ## Уязвимости зависимостей (govulncheck)
	$(call NOT_YET,0.6)
licenses: ## Лицензии и реестр компонентов
	$(call NOT_YET,0.7)
sbom: ## SBOM CycloneDX с проверкой формата
	$(call NOT_YET,0.8)
dm-coverage: ## Отчёт о покрытии матрицы обнаружения 5.16
	$(call NOT_YET,0.9)
e2e: ## Сквозные тесты: шлюз и mock-llm
	$(call NOT_YET,0.14)
dev: ## Стенд разработки в docker compose
	$(call NOT_YET,0.14)
manifest: ## Манифест целостности (ОЦЛ.1)
	@echo "manifest: манифест целостности появляется на этапе 2 (ТЗ, ОЦЛ.1)"; exit 1

.PHONY: clean
clean: ## Удалить результаты сборки
	rm -rf $(BUILD)
