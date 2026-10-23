#!/bin/sh
# Резервная копия установки пилота (задача 3.8 этапа 3): БД, ключи,
# секреты и состояние шлюза.
#
#   sudo ./backup.sh КАТАЛОГ
#
# Запускается от root в каталоге с compose.yaml при работающей установке.
# КАТАЛОГ — абсолютный путь вне AISEC_DATA_DIR; он и все каталоги над ним
# принадлежат root, писать в них может только root (у общих каталогов вроде
# /tmp допускается бит sticky). Скрипт создаёт в нём подкаталог
# aisec-ГГГГММДДTччммссZ (права 0700):
#   files.tar  — ключи установки (keys/), сертификаты и пароли (secrets/),
#                сертификат и состояние шлюза (gateway/reg, gateway/state);
#   env        — копия .env (секретов в нём нет);
#   db.dump    — копия БД aisec (pg_dump, формат custom) из сервиса postgres;
#   SHA256SUMS — контрольные суммы файлов.
# В files.tar лежат мастер-ключ и закрытые ключи: вместе с db.dump они
# раскрывают учётные данные провайдеров и содержимое событий. Храните их
# раздельно (docs/user/admin-guide.md, раздел 12).
#
# Своя СУБД заказчика (в COMPOSE_PROFILES нет db): db.dump не снимается,
# копию БД делайте средствами СУБД сразу после этого скрипта.
#
# Порядок — сначала файлы, затем БД: состояние шлюза в копии не новее БД, и
# после восстановления шлюз принимает пакет сервера (иначе отказ «откат»,
# DM-42). Не выполняйте ротацию ключей (aisec-cli keys …) во время копии.
set -eu
umask 077
cd "$(dirname "$0")"

die() {
	echo "backup.sh: $*" >&2
	exit 1
}

# env_value КЛЮЧ — последнее значение из .env без кавычек и CR.
env_value() {
	sed -n "s/^$1=//p" .env | tail -n 1 | tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

# root_only КАТАЛОГ — каталог и все каталоги над ним принадлежат root, и
# никто, кроме root, не может в них писать (у каталогов выше — разве что с
# битом sticky: тогда чужой не переименует наш каталог). Иначе владелец
# каталога мог бы подменить файлы копии ссылками между шагами скрипта.
root_only() {
	p=$1
	first=1
	while :; do
		# shellcheck disable=SC2046 # два поля stat
		set -- $(stat -L -c '%u %a' "$p") || die "не удалось проверить $p"
		[ "$1" -eq 0 ] || die "владелец $p — не root: копию в такой каталог класть нельзя"
		w=$((0$2 & 022))
		sticky=$((0$2 & 01000))
		if [ "$w" -ne 0 ] && { [ "$first" -eq 1 ] || [ "$sticky" -eq 0 ]; }; then
			die "в $p может писать не только root: копию в такой каталог класть нельзя"
		fi
		[ "$p" != / ] || break
		p=$(dirname "$p")
		first=0
	done
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo ./backup.sh КАТАЛОГ)"
[ $# -eq 1 ] || die "укажите каталог для копий: sudo ./backup.sh КАТАЛОГ"
[ -f compose.yaml ] && [ -f .env ] || die "нет compose.yaml или .env рядом со скриптом"

data_dir=$(env_value AISEC_DATA_DIR)
[ -n "$data_dir" ] || data_dir=/srv/aisec
# docker compose берёт переменную окружения раньше .env: значения должны совпадать.
[ -z "${AISEC_DATA_DIR:-}" ] || [ "$AISEC_DATA_DIR" = "$data_dir" ] ||
	die "AISEC_DATA_DIR в окружении ($AISEC_DATA_DIR) не совпадает с .env ($data_dir)"
case "$data_dir" in
/*) ;;
*) die "AISEC_DATA_DIR должен быть абсолютным путём: $data_dir" ;;
esac
[ -s "$data_dir/keys/master.key" ] || die "нет $data_dir/keys/master.key — установка не инициализирована"

out=$1
case "$out" in
/*) ;;
*) die "каталог копий — абсолютный путь: $out" ;;
esac
case "$out/" in
"$data_dir"/*) die "каталог копий внутри AISEC_DATA_DIR: копия должна лежать вне установки" ;;
esac
[ ! -L "$out" ] || die "$out — символьная ссылка"
if [ ! -d "$out" ]; then
	root_only "$(dirname "$out")"
	mkdir -m 0700 "$out" || die "не удалось создать $out"
fi
root_only "$out"
dst="$out/aisec-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -m 0700 "$dst" || die "не удалось создать $dst"

# Есть ли в установке сервис postgres (профиль db).
own_db=1
if docker compose config --services | grep -qx postgres; then
	own_db=0
	docker compose ps --status running --services | grep -qx postgres ||
		die "сервис postgres не запущен: docker compose up -d postgres"
fi

# 1. Файлы. tar хранит имена владельцев: на новом хосте они совпадут с
# пользователями, которых создаст prepare-host.sh, даже при других UID.
# Код 1 — файл изменился во время чтения (шлюз записал новый пакет):
# архив снимается заново, до трёх попыток.
try=1
while :; do
	rc=0
	tar -C "$data_dir" -cf "$dst/files.tar" keys secrets gateway/reg gateway/state || rc=$?
	[ "$rc" -ne 0 ] || break
	[ "$rc" -eq 1 ] && [ "$try" -lt 3 ] || die "не удалось архивировать файлы установки (tar, код $rc)"
	try=$((try + 1))
	sleep 2
done
cp .env "$dst/env"

# 2. БД. Пароль владельца схемы — в passfile во временном каталоге
# контейнера (tmpfs), не в окружении и не в аргументах.
if [ "$own_db" -eq 0 ]; then
	# shellcheck disable=SC2016 # переменные раскрывает оболочка контейнера
	docker compose exec -T postgres sh -c 'set -eu; umask 077; f=$(mktemp); trap "rm -f \"$f\"" EXIT
printf "*:*:*:aisec_owner:%s\n" "$(cat /run/secrets/db-owner-password)" >"$f"
PGPASSFILE=$f pg_dump --no-password -h 127.0.0.1 -U aisec_owner -d aisec -Fc' >"$dst/db.dump.tmp"
	# Оглавление читается — архив не обрезан.
	docker compose exec -T postgres pg_restore -l >/dev/null <"$dst/db.dump.tmp" ||
		die "копия БД не читается: $dst/db.dump.tmp"
	mv "$dst/db.dump.tmp" "$dst/db.dump"
fi

# 3. Контрольные суммы.
(
	cd "$dst"
	if [ "$own_db" -eq 0 ]; then
		sha256sum files.tar env db.dump >SHA256SUMS
	else
		sha256sum files.tar env >SHA256SUMS
	fi
)

echo "Копия: $dst"
echo "  files.tar — ключи и секреты: храните отдельно от копии БД, доступ — только у администраторов."
if [ "$own_db" -eq 0 ]; then
	echo "  db.dump — БД (события, журнал аудита, учётные записи)."
else
	echo "  Своя СУБД: снимите копию БД aisec средствами СУБД сейчас (руководство администратора, раздел 12)."
fi
