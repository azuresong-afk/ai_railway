# Сборка ONNX Runtime и выпуска aisec-ml (ADR-0024, раздел 8; задача 4.19).
#
# Цели:
#   ort-out    — библиотека ONNX Runtime 1.31.0 (make ort-build):
#                lib/libonnxruntime.so.1.31.0, include/, LICENSE, ThirdPartyNotices.txt;
#   ml-release — каталог выпуска aisec-ml (make ml-release-dir): bin/aisec-ml,
#                lib/ (ONNX Runtime, загрузчик и системные библиотеки из этого
#                же образа) и манифест целостности.
#
# В сеть ходит только стадия toolchain: пакеты сборки Debian (cmake, ninja,
# python3) — из репозитория дистрибутива с проверкой подписи apt. Исходники
# ONNX Runtime и его зависимостей — из зеркала build/ort-mirror (make
# ort-fetch, SHA-256 в deps.lock), сборка ORT и aisec-ml — RUN --network=none:
# зависимость, которой нет в зеркале, не скачивается, а роняет сборку.
# Телеметрия выключена (onnxruntime_USE_TELEMETRY=OFF), build.sh проверяет,
# что в библиотеке нет адресов телеметрии и HTTP-клиента.
#
# aisec-ml собирается с cgo (ADR-0024): загрузчик и библиотеки — только из
# /opt/aisec/lib образа (-Wl,--dynamic-linker, RPATH), не из системы хоста;
# хеш библиотеки ORT встраивается в бинарник (-X main.ortLibHash), и aisec-ml
# не загружает библиотеку с другим хешем. Образ — deploy/build/Dockerfile.release,
# цель aisec-ml, из каталога build/release-ml (без RUN и без сети).
#
# Базовый образ — тот же, что у сборочного и лабораторного (закреплён по
# digest, ТЗ 8.7). cmake не ниже 3.28, которого требует ONNX Runtime 1.31, —
# из bookworm-backports (в bookworm — 3.25).
ARG GO_IMAGE=golang:1.27.3-bookworm@sha256:21ade014faf952365b9ecbd8dbdb87176fbacb82fac9fb132d9f2a7b8cc3f132

FROM ${GO_IMAGE} AS toolchain
# Если доступ в интернет идёт через прокси с проверкой TLS, его корневой
# сертификат передаётся секретом сборки build-ca: он нужен только apt и в
# результат не попадает.
RUN --mount=type=secret,id=build-ca,required=false \
    if [ -s /run/secrets/build-ca ]; then cp /run/secrets/build-ca /usr/local/share/ca-certificates/build-ca.crt && update-ca-certificates; fi \
 && echo 'deb [signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] http://deb.debian.org/debian bookworm-backports main' >/etc/apt/sources.list.d/backports.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends -t bookworm-backports cmake \
 && apt-get install -y --no-install-recommends ninja-build python3 binutils \
 && rm -rf /var/lib/apt/lists/* /usr/local/share/ca-certificates/build-ca.crt \
 && dpkg-query -W -f '${Package}=${Version}\n' cmake ninja-build python3 gcc g++ libc6 libstdc++6 binutils >/toolchain.versions

FROM toolchain AS ort
ARG ORT_JOBS=
WORKDIR /src
COPY deploy/build/onnxruntime/ deploy/build/onnxruntime/
COPY build/ort-mirror/ build/ort-mirror/
RUN --network=none ORT_JOBS="${ORT_JOBS}" ORT_WORK=/tmp/aisec-ort \
    bash deploy/build/onnxruntime/build.sh deploy/build/onnxruntime/deps.lock build/ort-mirror /out \
 && cp /toolchain.versions /out/toolchain.versions

FROM scratch AS ort-out
COPY --from=ort /out/ /

# Подписанный пакет моделей: make ml-release-dir ML_MODELS_DIR=… подменяет
# эту пустую стадию каталогом (--build-context ml-models=…).
FROM scratch AS ml-models

FROM toolchain AS ml
ARG VERSION
ARG SOURCE_DATE
ARG SOURCE_EPOCH
# test — подпись тестовым ключом (НЕ ДЛЯ ПОСТАВКИ), unsigned — манифест
# поставки без подписи: его подписывают ключом производителя на машине без
# сети (make release-sign, ADR-0022).
ARG MANIFEST_MODE=test
# RELEASE=1 — поставочная сборка: в aisec-ml встраивается ключ производителя
# (тег aisec_release), а не тестовый ключ из репозитория.
ARG RELEASE=
ARG ML_MODELS=
WORKDIR /src
ENV GOTOOLCHAIN=local HOME=/tmp GOCACHE=/tmp/go-cache
COPY . .
COPY --from=ort /out/lib/ /out/lib/
COPY --from=ml-models / /models/
RUN --network=none test -n "$VERSION" && test -n "$SOURCE_DATE" && test -n "$SOURCE_EPOCH" \
 && make ml-release-assemble VERSION="$VERSION" SOURCE_DATE="$SOURCE_DATE" SOURCE_EPOCH="$SOURCE_EPOCH" \
    ORT_LIB_DIR=/out/lib MANIFEST_MODE="$MANIFEST_MODE" RELEASE="$RELEASE" ML_MODELS_DIR="${ML_MODELS:+/models}"

FROM scratch AS ml-release
COPY --from=ml /src/build/release-ml/ /
