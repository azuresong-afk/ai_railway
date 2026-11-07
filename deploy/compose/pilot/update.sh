#!/bin/sh
# Обновление установки в docker compose с носителя (ОБН.1–ОБН.3, ADR-0036,
# раздел 7, задача 6.21).
#
#   sudo ./update.sh check КАТАЛОГ_ВЫПУСКА   проверить выпуск, ничего не меняя
#   sudo ./update.sh apply КАТАЛОГ_ВЫПУСКА   обновить: копия БД, остановка,
#                                            образы, миграции, запуск,
#                                            проверка здоровья; при сбое — откат
#   sudo ./update.sh apply                   довести или откатить прерванное
#   sudo ./update.sh status                  состояние незавершённого обновления
#
# Флаги aisec-cli update (-allow-older, -health-url, -health-ca, -settle,
# -health-timeout) пишутся после check или apply и до каталога выпуска.
#
# Сценарий достаёт aisec-cli УСТАНОВЛЕННОЙ версии (AISEC_VERSION из .env)
# из её образа и запускает его на хосте от root: ключ проверки подписи
# берётся из действующей установки, а не из нового выпуска. Всё остальное —
# в aisec-cli update: подпись, составы и хеши образов проверяются до
# docker load, шаги, журнал и откат те же, что у установки без Docker.
# Сценарий ничего не загружает из сети.
#
# Каталог выпуска — как для verify-release.sh: aisec-manifest.json, подпись,
# bin/, images/*.tar и необязательный media/. Выпуск должен лежать на
# локальном диске или носителе, не на сетевой файловой системе.
set -eu

die() {
	echo "update.sh: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo ./update.sh …)"
[ $# -ge 1 ] || die "укажите команду: check, apply или status"
sub=$1
case "$sub" in
check | apply | status) shift ;;
*) die "команда: check, apply или status" ;;
esac

# aisec-cli работает с чистым окружением, то есть со стандартным демоном
# docker: сценарий обязан обращаться к тому же демону.
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG DOCKER_TLS_VERIFY DOCKER_CERT_PATH

cd "$(dirname "$0")"
here=$(pwd)
[ -f compose.yaml ] && [ -f .env ] || die "нет compose.yaml или .env рядом со скриптом"

env_value() {
	sed -n "s/^$1=//p" .env | tail -n 1 | tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}
installed=$(env_value AISEC_VERSION)
repo=$(env_value AISEC_IMAGE_REPO)
[ -n "$repo" ] || repo=aisec
case "$repo" in
aisec | aisec-test) ;;
*) die "AISEC_IMAGE_REPO: ожидается aisec или aisec-test, а не $repo" ;;
esac
[ -n "$installed" ] || die "в .env нет AISEC_VERSION — версии установленных образов"
image="$repo/aisec-cli:$installed"
docker image inspect "$image" >/dev/null 2>&1 || die "нет образа $image установленной версии"

work=$(mktemp -d)
chmod 0700 "$work"
trap 'rm -rf "$work"' EXIT

# Копия aisec-cli из образа: контейнер создаётся, но не запускается.
id=$(docker create --pull never "$image") || die "не создать контейнер из $image"
docker cp -q "$id:/opt/aisec/bin/aisec-cli" "$work/aisec-cli" || {
	docker rm "$id" >/dev/null 2>&1 || true
	die "в образе $image нет /opt/aisec/bin/aisec-cli"
}
docker rm "$id" >/dev/null
[ -f "$work/aisec-cli" ] && [ ! -h "$work/aisec-cli" ] || die "в образе $image /opt/aisec/bin/aisec-cli — не обычный файл"
chmod 0700 "$work/aisec-cli"

# Чистое окружение: переменные AISEC_* из оболочки root не должны
# переопределять .env (docker compose берёт окружение раньше .env).
rc=0
env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C.UTF-8 AISEC_UPDATE_HOST=compose \
	"$work/aisec-cli" update "$sub" -compose-dir "$here" "$@" || rc=$?
exit "$rc"
