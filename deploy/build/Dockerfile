# Сборочный образ: всё, что нужно для make check, в зафиксированных версиях
# (ТЗ, 8.7; ADR-0003). В нём make check работает и без сети (make check-offline).
#
# Версии инструментов передаёт Makefile (make build-image) из своих
# переменных — единственного места, где они заданы.
ARG GO_IMAGE=golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195
FROM ${GO_IMAGE}

ARG GOLANGCI_LINT_VERSION
ARG GOVULNCHECK_VERSION
ARG SBOM_UTILITY_VERSION

# Инструменты ставятся по точным версиям; контрольные суммы модулей сверяются
# с sum.golang.org (GOFLAGS=-mod=mod только на время установки).
ENV GOBIN=/opt/aisec-tools/bin \
    PATH=/opt/aisec-tools/bin:/usr/local/go/bin:$PATH \
    GOTOOLCHAIN=local
# Только прокси модулей, без загрузки прямо из VCS (direct), как в make tools.
ARG GOPROXY=https://proxy.golang.org
RUN test -n "$GOLANGCI_LINT_VERSION" && test -n "$GOVULNCHECK_VERSION" && test -n "$SBOM_UTILITY_VERSION" \
 && GOFLAGS=-mod=mod go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} \
 && GOFLAGS=-mod=mod go install golang.org/x/vuln/cmd/govulncheck@${GOVULNCHECK_VERSION} \
 && GOFLAGS=-mod=mod go install github.com/CycloneDX/sbom-utility@${SBOM_UTILITY_VERSION} \
 && go clean -cache -modcache \
 && golangci-lint version && govulncheck -version

# Кеши — во временном каталоге: контейнер запускается от UID пользователя.
ENV HOME=/tmp GOCACHE=/tmp/go-cache
WORKDIR /src
