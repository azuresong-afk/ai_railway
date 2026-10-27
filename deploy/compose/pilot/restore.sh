#!/bin/sh
# Восстановление установки пилота из копии backup.sh в пустую установку
# (задача 3.8 этапа 3).
#
#   sudo ./restore.sh /абсолютный/путь/к/копии
#
# До запуска: загружены образы той же или более новой версии, что в копии;
# выполнен prepare-host.sh; в .env те же AISEC_CONSOLE_HOST и COMPOSE_PROFILES,
# что в файле env копии (версия может быть новее). Сервисы остановлены,
# каталоги ключей и БД пусты. Скрипт:
#   1. копирует копию во временный каталог root и дальше работает только с
#      ним: сверяет контрольные суммы, состав и права архива, файл env;
#   2. разворачивает ключи, секреты и каталоги шлюза;
#   3. запускает postgres (роли и пустая БД создаются с паролями из копии) и
#      восстанавливает БД одной транзакцией;
#   4. применяет миграции, завершает все сессии консоли и отзывает токены API
#      копии (aisec-cli restore-finish, запись system.restored), проверяет
#      цепочку журнала аудита.
# После него: docker compose up -d (руководство администратора, раздел 12).
#
# Своя СУБД заказчика: шаги 3 и 4 выполняются вручную — восстановите БД
# средствами СУБД, затем docker compose run --rm aisec-cli migrate,
# restore-finish и audit verify.
set -eu
umask 077
cd "$(dirname "$0")"

die() {
	echo "restore.sh: $*" >&2
	exit 1
}

# env_value ФАЙЛ КЛЮЧ — последнее значение из файла переменных без кавычек и CR.
env_value() {
	sed -n "s/^$2=//p" "$1" | tail -n 1 | tr -d '\r' | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo ./restore.sh КАТАЛОГ_КОПИИ)"
[ $# -eq 1 ] || die "укажите каталог копии: sudo ./restore.sh КАТАЛОГ_КОПИИ"
[ -f compose.yaml ] && [ -f .env ] || die "нет compose.yaml или .env рядом со скриптом"
src=$1
case "$src" in
/*) ;;
*) die "каталог копии — абсолютный путь: $src" ;;
esac
for f in files.tar env SHA256SUMS; do
	[ -f "$src/$f" ] && [ ! -L "$src/$f" ] || die "в $src нет обычного файла $f — это не копия backup.sh"
done

# Имя каталога копии — только для записи system.restored: необычное имя
# (пробелы, кириллица) не передаётся и не прерывает восстановление.
copy_name=$(basename "$src")
printf '%s\n' "$copy_name" | LC_ALL=C grep -Eqx '[A-Za-z0-9._-]{1,128}' || copy_name=
finish_args="-confirm${copy_name:+ -copy-dir $copy_name}"

data_dir=$(env_value .env AISEC_DATA_DIR)
[ -n "$data_dir" ] || data_dir=/srv/aisec
# docker compose берёт переменную окружения раньше .env: значения должны совпадать.
[ -z "${AISEC_DATA_DIR:-}" ] || [ "$AISEC_DATA_DIR" = "$data_dir" ] ||
	die "AISEC_DATA_DIR в окружении ($AISEC_DATA_DIR) не совпадает с .env ($data_dir)"
case "$data_dir" in
/*) ;;
*) die "AISEC_DATA_DIR должен быть абсолютным путём: $data_dir" ;;
esac
for d in keys secrets gateway/reg gateway/state pg; do
	[ -d "$data_dir/$d" ] && [ ! -L "$data_dir/$d" ] || die "нет каталога $data_dir/$d — запустите prepare-host.sh"
done
# Только пустая установка: восстановление не смешивает две установки.
[ -z "$(ls -A "$data_dir/keys")" ] || die "в $data_dir/keys уже есть ключи — восстановление только в пустую установку"
[ -z "$(ls -A "$data_dir/pg")" ] || die "каталог БД $data_dir/pg не пуст — восстановление только в пустую установку"
[ -z "$(docker compose ps -q)" ] || die "сервисы установки запущены: docker compose down"

own_db=1
want="env files.tar"
if docker compose config --services | grep -qx postgres; then
	own_db=0
	want="db.dump env files.tar"
	[ -f "$src/db.dump" ] && [ ! -L "$src/db.dump" ] || die "в копии нет db.dump, а установка использует сервис postgres"
fi

# 1. Копия во временный каталог root: каталогом копии может владеть не root,
# и файлы в нём могли бы подменить между проверкой и распаковкой.
work=$(mktemp -d)
done_ok=0
extracted=0
cleanup() {
	rm -rf "$work"
	if [ "$extracted" -eq 1 ] && [ "$done_ok" -eq 0 ]; then
		echo "restore.sh: восстановление не завершено. Перед повтором верните установку к пустой:" >&2
		echo "  docker compose down; rm -rf $data_dir/keys/* $data_dir/gateway/reg/* $data_dir/gateway/state/* $data_dir/pg/*" >&2
	fi
}
trap cleanup EXIT
for f in $want SHA256SUMS; do
	# -P: ссылку, подложенную после проверки выше, копируем как ссылку и отвергаем.
	cp -P -- "$src/$f" "$work/$f"
	[ -f "$work/$f" ] && [ ! -L "$work/$f" ] || die "$src/$f — не обычный файл"
done

# Контрольные суммы ловят порчу носителя, но не подмену: копию храните там,
# куда пишут только администраторы. В списке — ровно файлы копии.
names=$(awk '{print $2}' "$work/SHA256SUMS" | sort | tr '\n' ' ')
[ "$names" = "$want " ] || die "в SHA256SUMS не тот список файлов: $names(ожидается: $want)"
(cd "$work" && sha256sum --quiet --strict -c SHA256SUMS) || die "контрольные суммы копии не совпадают"

# Совпадение установки с копией: имя консоли (сертификаты) и профиль БД.
for k in AISEC_CONSOLE_HOST COMPOSE_PROFILES; do
	a=$(env_value "$work/env" "$k")
	b=$(env_value .env "$k")
	[ "$a" = "$b" ] || die "$k в .env ($b) не совпадает с копией ($a)"
done

# Только обычные файлы и каталоги внутри четырёх каталогов установки: без
# ссылок, устройств, абсолютных путей и «..»; без битов setuid, setgid и
# sticky и без записи для группы и остальных.
listing=$(tar -tvf "$work/files.tar") || die "архив files.tar не читается"
bad=$(printf '%s\n' "$listing" | grep -v '^[-d]' | head -n 1 || true)
[ -z "$bad" ] || die "в архиве не обычный файл: $bad"
bad=$(printf '%s\n' "$listing" | awk '{m=$1; if (m ~ /[sStT]/ || substr(m,6,1)=="w" || substr(m,9,1)=="w") {print; exit}}')
[ -z "$bad" ] || die "в архиве недопустимые права: $bad"
bad=$(tar -tf "$work/files.tar" | grep -Ev '^(keys|secrets|gateway/reg|gateway/state)(/[A-Za-z0-9._-]+)*/?$' | head -n 1 || true)
[ -z "$bad" ] || die "в архиве лишний путь: $bad"
bad=$(tar -tf "$work/files.tar" | grep -E '(^|/)\.\.(/|$)' | head -n 1 || true)
[ -z "$bad" ] || die "в архиве путь с «..»: $bad"

# 2. Файлы. Владельцы — по именам из архива (пользователи prepare-host.sh);
# каталоги ключей и шлюза — их сервисам явно, на случай другого tar.
extracted=1
tar -C "$data_dir" --same-owner --same-permissions --no-overwrite-dir -xf "$work/files.tar"
chown -R aisec:aisec "$data_dir/keys"
chown -R aisec-gw:aisec-gw "$data_dir/gateway/reg" "$data_dir/gateway/state"
echo "Ключи, секреты и каталоги шлюза восстановлены в $data_dir."

if [ "$own_db" -eq 1 ]; then
	done_ok=1
	echo "Своя СУБД: восстановите БД aisec средствами СУБД, затем:"
	echo "  docker compose run --rm aisec-cli migrate"
	echo "  docker compose run --rm aisec-cli restore-finish $finish_args"
	echo "  docker compose run --rm aisec-cli audit verify -keys /etc/aisec/keys"
	echo "  docker compose up -d"
	exit 0
fi

# 3. БД. При первом запуске на пустом каталоге initdb создаёт роли и пустую
# базу aisec; данные — pg_restore владельцем схемы одной транзакцией.
docker compose up -d --wait postgres
# shellcheck disable=SC2016 # переменные раскрывает оболочка контейнера
docker compose exec -T postgres sh -c 'set -eu; umask 077; f=$(mktemp); trap "rm -f \"$f\"" EXIT
printf "*:*:*:aisec_owner:%s\n" "$(cat /run/secrets/db-owner-password)" >"$f"
PGPASSFILE=$f pg_restore --no-password -h 127.0.0.1 -U aisec_owner -d aisec --exit-on-error --single-transaction' <"$work/db.dump" ||
	die "pg_restore не выполнен"
echo "БД восстановлена."

# 4. Миграции (если версия новее копии), отзыв сессий и токенов копии и
# цепочка журнала аудита. restore-finish — до audit verify и до запуска
# сервера: давность копии он считает по последней записи журнала.
docker compose run --rm aisec-cli migrate || die "миграции не применены"
# shellcheck disable=SC2086 # finish_args — «-confirm» и, может быть, «-copy-dir ИМЯ» из проверенных символов
docker compose run --rm aisec-cli restore-finish $finish_args ||
	die "сессии и токены API копии не отозваны (aisec-cli restore-finish)"
docker compose run --rm aisec-cli audit verify -keys /etc/aisec/keys ||
	die "цепочка журнала аудита не сходится (код 3 — нарушение): копия БД неполная или изменена"
done_ok=1
echo "Установка восстановлена. Запустите: docker compose up -d"
echo "Пользователи входят заново, владельцы токенов API выпускают их заново. Изменения после даты копии повторите по журналу аудита (руководство администратора, раздел 12.2)."
