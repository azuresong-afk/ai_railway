# Образы стенда разработки: шлюз и mock-llm. Не для поставки заказчику
# (поставка в docker compose — этап 3).
#
# Сборка — в официальном образе Go, закреплённом по digest (ТЗ, 8.7), без
# сети: зависимости из vendor/, прокси модулей выключен. Запуск — в пустом
# образе scratch: только статический бинарник, без оболочки и пакетов ОС.
ARG GO_IMAGE=golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags '-s -w -buildid=' -o /out/ ./cmd/aisec-gateway ./cmd/mock-llm

FROM scratch AS aisec-gateway
COPY --from=build /out/aisec-gateway /aisec-gateway
USER 65534:65534
ENTRYPOINT ["/aisec-gateway"]

FROM scratch AS mock-llm
COPY --from=build /out/mock-llm /mock-llm
USER 65534:65534
ENTRYPOINT ["/mock-llm"]
