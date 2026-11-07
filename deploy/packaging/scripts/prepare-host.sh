#!/bin/sh
# Подготовка хоста к установке без Docker (ADR-0034, раздел 7; ЗИ.5).
# Ставится пакетом aisec как /usr/sbin/aisec-prepare-host.
#
#   sudo aisec-prepare-host                   пароли ролей БД, файлы pgpass, проверка файлов
#   sudo aisec-prepare-host --create-roles    то же и роли с БД в локальном PostgreSQL
#   sudo aisec-prepare-host --write-sql ФАЙЛ  то же и SQL ролей в ФАЙЛ (0600) для СУБД на другом узле
#   sudo aisec-prepare-host --bundle-anchor   якорь пакетов шлюза из ключей aisec-cli init
#
# Повторный запуск безопасен: существующие пароли не меняются. Пароли
# создаются из /dev/urandom, лежат только в /etc/aisec/credentials (0700
# root, файлы 0600) и не выводятся. Сеть не используется. Сертификаты TLS
# кладёт администратор — список недостающих в конце вывода.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

cred=/etc/aisec/credentials
keys=/var/lib/aisec/keys

die() {
	echo "aisec-prepare-host: $*" >&2
	exit 1
}

usage() {
	sed -n '5,9p' "$0" | sed 's/^# \{0,1\}//'
	exit 2
}

create_roles=0
sql_out=
anchor=0
while [ "$#" -gt 0 ]; do
	case "$1" in
	--create-roles) create_roles=1 ;;
	--write-sql)
		[ "$#" -ge 2 ] || usage
		sql_out=$2
		shift
		;;
	--bundle-anchor) anchor=1 ;;
	-h | --help) usage ;;
	*) usage ;;
	esac
	shift
done

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo aisec-prepare-host)"
for u in aisec aisec-gw; do
	id -u "$u" >/dev/null 2>&1 || die "нет пользователя $u — переустановите пакет aisec"
done
if [ -L "$cred" ] || [ ! -d "$cred" ]; then
	die "$cred — нет каталога или это символьная ссылка; переустановите пакет aisec"
fi
chown root:root "$cred"
chmod 0700 "$cred"

# new_secret ФАЙЛ — 32 случайных байта в шестнадцатеричном виде, если файла
# ещё нет. Только [0-9a-f]: значение без экранирования годится для SQL и
# pgpass.
new_secret() {
	[ -s "$1" ] && return 0
	tmp=$(mktemp "$cred/.tmp.XXXXXX")
	head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' >"$tmp"
	[ "$(wc -c <"$tmp")" -eq 64 ] || {
		rm -f "$tmp"
		die "не удалось получить случайные байты из /dev/urandom"
	}
	chmod 0600 "$tmp"
	mv -f "$tmp" "$1"
	echo "Создан $1."
}

# read_secret ФАЙЛ — содержимое файла пароля; только 64 шестнадцатеричных
# символа, иначе файл подменён или повреждён.
read_secret() {
	v=$(cat "$1")
	case "$v" in
	*[!0-9a-f]*) die "$1: недопустимые символы; удалите файл и запустите снова" ;;
	esac
	[ "${#v}" -eq 64 ] || die "$1: ожидается 64 символа; удалите файл и запустите снова"
	printf '%s' "$v"
}

# write_pgpass РОЛЬ ФАЙЛ_ПАРОЛЯ ФАЙЛ_PGPASS — файл паролей pgx/libpq для
# роли (любой узел, порт и БД). Перезаписывается при каждом запуске.
write_pgpass() {
	# Отдельное присваивание: die внутри $(…) в аргументе команды не
	# остановил бы сценарий, и в файл попал бы пустой пароль.
	pw=$(read_secret "$2")
	tmp=$(mktemp "$cred/.tmp.XXXXXX")
	printf '*:*:*:%s:%s\n' "$1" "$pw" >"$tmp"
	pw=
	chmod 0600 "$tmp"
	mv -f "$tmp" "$3"
}

new_secret "$cred/db-owner-password"
new_secret "$cred/db-server-password"
write_pgpass aisec_owner "$cred/db-owner-password" "$cred/db-owner.pgpass"
write_pgpass aisec_server "$cred/db-server-password" "$cred/db-server.pgpass"

# Пароли читаются и проверяются здесь, до конвейеров: die в левой части
# «roles_sql | psql» сценарий не останавливает.
owner=$(read_secret "$cred/db-owner-password")
server=$(read_secret "$cred/db-server-password")

# roles_sql — роли и БД установки (тот же состав, что
# deploy/compose/pilot/initdb/10-aisec-roles.sql), повторное выполнение не
# меняет существующие роли. Пароли — только в потоке, не в аргументах; текст
# с паролем не пишется в журнал СУБД и в pg_stat_statements (pgaudit на СУБД
# заказчика настраивается отдельно — руководство администратора, 2.1).
roles_sql() {
	cat <<EOF
\\set ON_ERROR_STOP on
SET log_min_error_statement = panic;
SET log_statement = none;
SET log_min_duration_statement = -1;
SET pg_stat_statements.track_utility = off;
DO \$\$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_app') THEN
    CREATE ROLE aisec_app NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_audit_archiver') THEN
    CREATE ROLE aisec_audit_archiver NOLOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_owner') THEN
    CREATE ROLE aisec_owner LOGIN PASSWORD '$owner' IN ROLE aisec_audit_archiver;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aisec_server') THEN
    CREATE ROLE aisec_server LOGIN PASSWORD '$server' IN ROLE aisec_app;
  END IF;
END
\$\$;
SELECT 'CREATE DATABASE aisec OWNER aisec_owner' WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'aisec')\\gexec
REVOKE ALL ON DATABASE aisec FROM PUBLIC;
GRANT CONNECT ON DATABASE aisec TO aisec_app;
EOF
}

if [ -n "$sql_out" ]; then
	case "$sql_out" in
	/*) ;;
	*) die "--write-sql: нужен абсолютный путь" ;;
	esac
	[ ! -e "$sql_out" ] && [ ! -L "$sql_out" ] || die "$sql_out уже существует — укажите новый файл"
	# Каталог файла — root и без записи для группы и остальных: иначе между
	# проверкой и записью на месте файла может появиться чужая ссылка.
	dir=$(dirname "$sql_out")
	[ -d "$dir" ] && [ ! -L "$dir" ] || die "--write-sql: нет каталога $dir"
	case "$(stat -c '%u %A' "$dir")" in
	0\ d????-??-*) ;;
	*) die "--write-sql: каталог $dir должен принадлежать root и быть закрыт на запись для группы и остальных" ;;
	esac
	# set -C: файл создаётся с O_EXCL, существующий файл или ссылка — отказ.
	(
		set -C
		roles_sql >"$sql_out"
	) || die "--write-sql: не удалось создать $sql_out"
	chmod 0600 "$sql_out"
	echo "SQL ролей записан в $sql_out (0600, в нём пароли): выполните его psql от суперпользователя СУБД и удалите файл."
fi

if [ "$create_roles" -eq 1 ]; then
	id -u postgres >/dev/null 2>&1 || die "--create-roles: нет пользователя postgres — PostgreSQL не установлен на этом узле; используйте --write-sql"
	command -v psql >/dev/null 2>&1 || die "--create-roles: нет psql"
	roles_sql | runuser -u postgres -- psql -X -q -d postgres -f -
	echo "Роли aisec_owner и aisec_server и БД aisec готовы. Проверьте, что pg_hba.conf разрешает им вход по scram-sha-256."
fi

if [ "$anchor" -eq 1 ]; then
	# Ключ читает пользователь aisec, а не root: если в каталоге ключей вместо
	# файла окажется ссылка на чужой файл, root её не прочитает за него.
	pub=$keys/bundle-signing.pub
	tmp=$(mktemp "$cred/.tmp.XXXXXX")
	runuser -u aisec -- sh -c 'f=$1; [ -f "$f" ] && [ ! -L "$f" ] && head -c 65536 "$f"' sh "$pub" >"$tmp" ||
		{
			rm -f "$tmp"
			die "нет $pub — сначала aisec-cli init -dir $keys"
		}
	grep -q '^-----BEGIN PUBLIC KEY-----' "$tmp" || {
		rm -f "$tmp"
		die "$pub — не открытый ключ PEM"
	}
	chmod 0600 "$tmp"
	mv -f "$tmp" "$cred/gateway-bundle-anchor.pub"
	echo "Якорь пакетов шлюза: $cred/gateway-bundle-anchor.pub."
fi

# Файлы, которые кладёт администратор. Права восстанавливаются: каталог
# доступен только root, поэтому chmod здесь безопасен.
missing=
for f in console.crt console.key console-ca.crt gateway.crt gateway.key gateway-bundle-anchor.pub; do
	if [ -f "$cred/$f" ] && [ ! -L "$cred/$f" ]; then
		chown root:root "$cred/$f"
		chmod 0600 "$cred/$f"
	else
		missing="$missing $f"
	fi
done
if [ -n "$missing" ]; then
	echo "Положите в $cred (0600 root):$missing"
	echo "  console.* — сертификат и ключ консоли; console-ca.crt — корень, которым шлюз проверяет сервер;"
	echo "  gateway.* — сертификат и ключ шлюза для приложений; gateway-bundle-anchor.pub — aisec-prepare-host --bundle-anchor после aisec-cli init."
fi
if grep -q '^AISEC_GATEWAY_SERVER=https://aisec.example.test:' /etc/aisec/aisec-gateway.env 2>/dev/null; then
	echo "Задайте адрес сервера управления AISEC_GATEWAY_SERVER в /etc/aisec/aisec-gateway.env."
fi
echo "Готово."
