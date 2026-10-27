# Образы стенда разработки: шлюз, mock-llm и mock-mcp. Не для поставки заказчику
# (поставка в docker compose — этап 3).
#
# Сборка — в официальном образе Go, закреплённом по digest (ТЗ, 8.7), без
# сети: зависимости из vendor/, прокси модулей выключен. Запуск — в пустом
# образе scratch: только статический бинарник, без оболочки и пакетов ОС.
ARG GO_IMAGE=golang:1.27.3-bookworm@sha256:21ade014faf952365b9ecbd8dbdb87176fbacb82fac9fb132d9f2a7b8cc3f132

FROM ${GO_IMAGE} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor GOPROXY=off GOTOOLCHAIN=local
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags '-s -w -buildid=' -o /out/ ./cmd/aisec-gateway ./cmd/mock-llm ./cmd/mock-mcp

FROM scratch AS aisec-gateway
COPY --from=build /out/aisec-gateway /aisec-gateway
USER 65534:65534
ENTRYPOINT ["/aisec-gateway"]

FROM scratch AS mock-llm
COPY --from=build /out/mock-llm /mock-llm
USER 65534:65534
ENTRYPOINT ["/mock-llm"]

FROM scratch AS mock-mcp
COPY --from=build /out/mock-mcp /mock-mcp
USER 65534:65534
ENTRYPOINT ["/mock-mcp"]
