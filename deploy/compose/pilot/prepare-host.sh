#!/bin/sh
# Подготовка хоста к установке пилота (ADR-0019, ЗИ.5): пользователи ОС,
# каталоги с правами, пароли БД, UID и GID в .env.
#
#   sudo ./prepare-host.sh
#
# Запускается от root в каталоге с compose.yaml. Повторный запуск безопасен:
# существующие пользователи и пароли не меняются, права каталогов
# восстанавливаются. Пароли создаются из /dev/urandom и не выводятся;
# сертификаты TLS кладёт администратор (список — в конце вывода).
set -eu
umask 077
cd "$(dirname "$0")"

die() {
	echo "prepare-host.sh: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo ./prepare-host.sh)"
[ -f compose.yaml ] || die "нет compose.yaml рядом со скриптом"
if [ ! -f .env ]; then
	cp .env.example .env
	echo "Создан .env из .env.example — проверьте AISEC_VERSION, AISEC_CONSOLE_HOST и адреса."
fi
# В .env нет секретов: его читает docker compose от имени администратора.
chmod 0644 .env

data_dir=$(sed -n 's/^AISEC_DATA_DIR=//p' .env | tail -n 1)
[ -n "$data_dir" ] || data_dir=/srv/aisec
case "$data_dir" in
/*) ;;
*) die "AISEC_DATA_DIR должен быть абсолютным путём: $data_dir" ;;
esac

nologin=$(command -v nologin || echo /usr/sbin/nologin)
# aisec-ml — процесс ML-детекторов (ADR-0024): создаётся всегда, работает
# только с дополнением compose.ml.yaml.
for user in aisec aisec-gw aisec-db aisec-ml; do
	if ! id -u "$user" >/dev/null 2>&1; then
		useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$nologin" "$user"
		echo "Создан пользователь $user."
	fi
	# Уже существующий пользователь с таким именем должен быть служебным: не
	# root и без входа в систему.
	[ "$(id -u "$user")" -ne 0 ] || die "пользователь $user — root"
	case "$(getent passwd "$user" | cut -d: -f7)" in
	*/nologin | */false) ;;
	*) die "у пользователя $user есть вход в систему — задайте оболочку $nologin или удалите его" ;;
	esac
done

# Каталоги: владелец — пользователь сервиса, права 0700. Секреты — в каталоге
# root: docker монтирует каждый файл в контейнер его владельца. Каталог сервиса
# лежит только в каталоге root (gateway/ — root, 0755), поэтому сервис не может
# подменить его символьной ссылкой, а install -d не пойдёт по чужой ссылке.
dir() {
	owner=$1 mode=$2
	shift 2
	for d in "$@"; do
		[ ! -L "$d" ] || die "$d — символьная ссылка; удалите её и повторите"
		install -d -o "$owner" -g "$owner" -m "$mode" "$d"
	done
}
dir root 0755 "$data_dir" "$data_dir/gateway" "$data_dir/ml"
dir root 0700 "$data_dir/secrets"
dir aisec 0700 "$data_dir/keys" "$data_dir/backups"
dir aisec-gw 0700 "$data_dir/gateway/reg" "$data_dir/gateway/state"
dir aisec-db 0700 "$data_dir/pg"
# Каталог сокета aisec-ml: создаёт сокет aisec-ml, подключается шлюз (группа
# aisec-gw, только чтение каталога), остальные пользователи хоста его не видят.
[ ! -L "$data_dir/ml/run" ] || die "$data_dir/ml/run — символьная ссылка; удалите её и повторите"
install -d -o aisec-ml -g aisec-gw -m 0750 "$data_dir/ml/run"

# put ФАЙЛ ВЛАДЕЛЕЦ СОДЕРЖИМОЕ — новый секрет 0400; printf — встроенная
# команда, содержимое не попадает в список процессов.
put() {
	tmp="$1.tmp.$$"
	printf '%s\n' "$3" >"$tmp"
	chown "$2:$2" "$tmp"
	chmod 0400 "$tmp"
	mv "$tmp" "$1"
}

# Пароли ролей: копия для PostgreSQL (initdb) и passfile для того, кто
# входит под ролью (pgx читает passfile, пароль не нужен в строке подключения).
secrets="$data_dir/secrets"
password() {
	head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
}
if [ ! -s "$secrets/db-postgres-password" ]; then
	put "$secrets/db-postgres-password" aisec-db "$(password)"
fi
for role in owner server; do
	if [ ! -s "$secrets/db-$role-password" ]; then
		[ ! -s "$data_dir/pg/pgdata/PG_VERSION" ] || die "БД уже создана, а пароля роли aisec_$role нет — восстановите $secrets/db-$role-password"
		put "$secrets/db-$role-password" aisec-db "$(password)"
		echo "Создан пароль роли aisec_$role."
	fi
	# passfile собирается из сохранённого пароля: если прошлый запуск прервался
	# между двумя файлами, повторный его восстановит.
	if [ ! -s "$secrets/db-$role.pgpass" ]; then
		pw=$(cat "$secrets/db-$role-password")
		put "$secrets/db-$role.pgpass" aisec "*:*:*:aisec_$role:$pw"
		pw=
	fi
done

# UID и GID пользователей — в .env (compose запускает сервисы от них).
set_env() {
	if grep -q "^$1=" .env; then
		sed -i "s|^$1=.*|$1=$2|" .env
	else
		printf '%s=%s\n' "$1" "$2" >>.env
	fi
}
set_env AISEC_UID "$(id -u aisec)"
set_env AISEC_GID "$(id -g aisec)"
set_env AISEC_GW_UID "$(id -u aisec-gw)"
set_env AISEC_GW_GID "$(id -g aisec-gw)"
set_env AISEC_DB_UID "$(id -u aisec-db)"
set_env AISEC_DB_GID "$(id -g aisec-db)"
# Группа aisec-ml в контейнере — aisec-gw (AISEC_GW_GID): сокет получает
# группу шлюза.
set_env AISEC_ML_UID "$(id -u aisec-ml)"

missing=0
check() {
	if [ ! -s "$secrets/$1" ]; then
		[ "$missing" -eq 1 ] || echo "Положите сертификаты TLS (README.md, шаг 2):"
		missing=1
		echo "  $secrets/$1 — $2"
	fi
}
check console.crt "сертификат консоли с именем AISEC_CONSOLE_HOST (владелец aisec, 0644)"
check console.key "его закрытый ключ (владелец aisec, 0600)"
check console-ca.crt "корневой сертификат УЦ, выпустившего console.crt (0644)"
check gateway.crt "сертификат шлюза для приложений (владелец aisec-gw, 0644)"
check gateway.key "его закрытый ключ (владелец aisec-gw, 0600)"
# Закрытые ключи: владелец — пользователь сервиса, никаких прав у остальных.
key_mode() {
	[ -f "$secrets/$1" ] || return 0
	case "$(stat -c '%U %a' "$secrets/$1")" in
	"$2 600" | "$2 400") ;;
	*) echo "  $secrets/$1: нужен владелец $2 и права 0600 (сейчас: $(stat -c '%U %a' "$secrets/$1"))" ; missing=1 ;;
	esac
}
key_mode console.key aisec
key_mode gateway.key aisec-gw
# Якорь проверки пакетов шлюза — отдельная копия ключа подписи после
# aisec-cli init (3В6 ревью 3.r1). Существующий файл не перезаписывается:
# при компрометации ключа подписи его заменяет администратор.
anchor="$secrets/gateway-bundle-anchor.pub"
if [ ! -s "$anchor" ]; then
	if [ -s "$data_dir/keys/bundle-signing.pub" ]; then
		# Каталог keys/ принадлежит aisec: файл читается от его имени, чтобы
		# символьная ссылка не открыла root чужой файл.
		tmp="$anchor.tmp.$$"
		runuser -u aisec -- head -c 8192 "$data_dir/keys/bundle-signing.pub" >"$tmp" ||
			die "не прочитать $data_dir/keys/bundle-signing.pub"
		grep -q '^-----BEGIN AISEC SIGNING PUBLIC KEY-----$' "$tmp" || {
			rm -f "$tmp"
			die "$data_dir/keys/bundle-signing.pub — не открытый ключ подписи"
		}
		chmod 0644 "$tmp"
		mv "$tmp" "$anchor"
		echo "Якорь шлюза: $anchor — копия keys/bundle-signing.pub."
	else
		echo "После aisec-cli init запустите prepare-host.sh ещё раз: он положит якорь шлюза $anchor."
	fi
fi
echo "Хост подготовлен: $data_dir."
echo "ML-детекторы (необязательно): в .env COMPOSE_FILE=compose.yaml:compose.ml.yaml и ml в COMPOSE_PROFILES (README.md)."
