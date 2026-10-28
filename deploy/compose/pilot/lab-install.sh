#!/bin/sh
# Установка для лаборатории и стенда одной командой (задача 4.32 этапа 4):
# на хосте нужен только Docker. Скрипт собирает образы в Docker из исходников
# репозитория (тестовый ключ манифеста, aisec-test/…:ВЕРСИЯ-test — НЕ ДЛЯ
# ПОСТАВКИ), готовит хост (prepare-host.sh), выпускает сертификаты TLS от
# собственного УЦ установки (aisec-cli tls init) или берёт готовые
# сертификаты УЦ заказчика (--tls-dir, задача 4.33) и проверяет их
# (aisec-cli tls check), создаёт ключи установки, регистрирует шлюз и
# запускает всё. Шаги — те же, что в docs/user/install-pilot.md, разделы 3–4.
#
#   sudo ./lab-install.sh --host 192.168.1.50 [--host lab.example.ru] [параметры]
#
# Запускается от root в каталоге deploy/compose/pilot репозитория. Повторный
# запуск безопасен: готовые шаги (сертификаты, ключи, регистрация шлюза)
# пропускаются, образы пересобираются из текущих исходников. Имена в
# сертификатах задаются при первом выпуске: сменить имя консоли повторным
# запуском нельзя (скрипт откажет), адрес интерфейса без --bind остаётся
# прежним из .env. Источник сертификатов (свой УЦ установки или --tls-dir)
# тоже задаётся первым запуском: сменить его повторным запуском нельзя.
set -eu
umask 077
cd "$(dirname "$0")"

usage() {
	cat <<'EOF'
Использование: sudo ./lab-install.sh --host АДРЕС [--host АДРЕС …] [параметры]

  --host АДРЕС         IP-адрес или имя, по которому открывают консоль и
                       обращаются к шлюзу; можно несколько раз или через запятую
  --console-name ИМЯ   имя консоли внутри установки (AISEC_CONSOLE_HOST); по
                       умолчанию — первое имя из --host, без имён — aisec-console
  --tls-dir КАТАЛОГ    сертификаты УЦ заказчика: console.crt, console.key,
                       gateway.crt, gateway.key и ca.crt (корень); каталог —
                       владелец root, без записи для группы и остальных. Без
                       параметра — собственный УЦ установки (aisec-cli tls init)
  --bind АДРЕС         адрес интерфейса для портов 8444 и 8443 (по умолчанию
                       0.0.0.0 — все интерфейсы; при повторном запуске — как в .env)
  --mirror РЕЕСТР      зеркало Docker Hub для базовых образов и PostgreSQL,
                       например mirror.gcr.io/library (digest не меняется)
  --build-ca ФАЙЛ      корневой сертификат прокси с проверкой TLS — нужен npm
                       при сборке консоли; в образы не попадает
  --no-build           не собирать образы: взять AISEC_IMAGE_REPO и AISEC_VERSION из .env
EOF
	exit 2
}

die() {
	echo "lab-install.sh: $*" >&2
	exit 1
}

step() {
	echo
	echo "==> $*"
}

hosts= console_name= bind= mirror= build_ca= build=1 tls_dir=
while [ $# -gt 0 ]; do
	case "$1" in
	--host)
		[ $# -ge 2 ] || usage
		hosts="${hosts:+$hosts,}$2"
		shift 2
		;;
	--console-name)
		[ $# -ge 2 ] || usage
		console_name=$2
		shift 2
		;;
	--tls-dir)
		[ $# -ge 2 ] || usage
		tls_dir=${2%/}
		[ -n "$tls_dir" ] || die "--tls-dir: укажите каталог с сертификатами, например /root/aisec-tls"
		shift 2
		;;
	--bind)
		[ $# -ge 2 ] || usage
		bind=$2
		shift 2
		;;
	--mirror)
		[ $# -ge 2 ] || usage
		mirror=${2%/}
		shift 2
		;;
	--build-ca)
		[ $# -ge 2 ] || usage
		build_ca=$2
		shift 2
		;;
	--no-build)
		build=
		shift
		;;
	*) usage ;;
	esac
done
[ -n "$hosts" ] || usage
[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo ./lab-install.sh …)"
[ -f compose.yaml ] && [ -x prepare-host.sh ] || die "запустите из каталога deploy/compose/pilot"
[ -z "$build_ca" ] || [ -s "$build_ca" ] || die "нет файла $build_ca"
# check_tls_dir — каталог сертификатов заказчика подменить может только
# root: сам каталог — root без записи для группы и остальных, каждый каталог
# пути до него — настоящий каталог (не ссылка) root, без записи для группы и
# остальных или с битом sticky (как /tmp). Тогда между проверкой файла и его
# копированием никто, кроме root, не подставит ссылку на чужой файл. Ключи —
# без доступа для группы и остальных. Вызывается до сборки (чтобы ошибка не
# всплыла через 15 минут) и ещё раз перед копированием.
check_tls_dir() {
	# Скрипт работает из своего каталога: относительный путь указывал бы не туда.
	case "$tls_dir" in
	/*) ;;
	*) die "--tls-dir: укажите абсолютный путь, например /root/aisec-tls" ;;
	esac
	[ -n "$(find "$tls_dir" -maxdepth 0 -type d -user 0 ! -perm /022 2>/dev/null)" ] ||
		die "--tls-dir: $tls_dir — нужен каталог (не ссылка) с владельцем root без записи для группы и остальных: chown root:root $tls_dir && chmod 0700 $tls_dir"
	d=$(dirname "$tls_dir")
	while :; do
		[ -n "$(find "$d" -maxdepth 0 -type d -user 0 \( ! -perm /022 -o -perm -1000 \) 2>/dev/null)" ] ||
			die "--tls-dir: в пути к $tls_dir каталог $d — символьная ссылка, не принадлежит root или открыт на запись другим пользователям; положите сертификаты, например, в /root/aisec-tls"
		[ "$d" != / ] || break
		d=$(dirname "$d")
	done
	for f in console.crt console.key gateway.crt gateway.key ca.crt; do
		[ -e "$tls_dir/$f" ] || die "--tls-dir: нет файла $tls_dir/$f (нужны console.crt, console.key, gateway.crt, gateway.key, ca.crt)"
	done
	for f in console.key gateway.key; do
		[ -z "$(find "$tls_dir/$f" -prune -perm /077)" ] ||
			die "--tls-dir: $tls_dir/$f доступен группе или остальным: chmod 0600 $tls_dir/$f"
	done
}
[ -z "$tls_dir" ] || check_tls_dir
case "$console_name$bind$mirror" in
*[!A-Za-z0-9.:/_-]*) die "недопустимые символы в --console-name, --bind или --mirror" ;;
esac
# Полная проверка имён — в aisec-cli tls init; здесь — набор символов, чтобы
# ошибка в --host не всплыла только после сборки.
case "$hosts" in
*[!A-Za-z0-9.:,\ -]*) die "--host: IP-адрес или DNS-имя из латиницы, цифр, «.» и «-»: $hosts" ;;
esac

# Имя консоли: первое имя из --host (не IP-адрес), иначе aisec-console. Это
# имя должно быть DNS-именем: по нему шлюз находит сервер в сети Docker.
if [ -z "$console_name" ]; then
	console_name=aisec-console
	old_ifs=$IFS
	IFS=,
	set -f
	for h in $hosts; do
		h=$(printf '%s' "$h" | tr -d ' ')
		case "$h" in
		*[!0-9.]* | '') ;;
		*) continue ;;
		esac
		case "$h" in
		*:* | '') continue ;;
		esac
		console_name=$h
		break
	done
	set +f
	IFS=$old_ifs
fi
console_name=$(printf '%s' "$console_name" | tr 'A-Z' 'a-z')
case "$console_name" in
*[!a-z0-9.-]* | *[!0-9.]*) ;;
*) die "--console-name: нужно DNS-имя, а не IP-адрес: $console_name" ;;
esac
case "$console_name" in
*[!a-z0-9.-]* | .* | *. | *..* | -* | *- | *.-* | *-.*)
	die "--console-name: DNS-имя из латиницы, цифр, «.» и «-», метки не пустые и не начинаются и не кончаются на «-»: $console_name"
	;;
esac
first_host=$(printf '%s' "$hosts" | cut -d, -f1 | tr -d ' ')

step "1/8 Проверка Docker"
command -v docker >/dev/null 2>&1 || die "нет docker: установите Docker Engine 24 или новее"
server=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || die "Docker не отвечает: запущен ли dockerd?"
[ "${server%%.*}" -ge 24 ] 2>/dev/null || die "нужен Docker Engine 24 или новее (сейчас $server)"
compose=$(docker compose version --short 2>/dev/null) || die "нет docker compose: установите плагин Compose 2.20 или новее"
compose=${compose#v}
c_major=${compose%%.*} c_minor=${compose#*.}
c_minor=${c_minor%%.*}
if [ "$c_major" -lt 2 ] 2>/dev/null || { [ "$c_major" -eq 2 ] && [ "$c_minor" -lt 20 ]; }; then
	die "нужен Docker Compose 2.20 или новее (сейчас $compose)"
fi
if [ -n "$build" ]; then
	docker buildx version >/dev/null 2>&1 || die "нет docker buildx (пакет docker-buildx-plugin): он нужен для сборки"
fi
echo "Docker $server, Compose $compose."

set_env() {
	if grep -q "^$1=" .env; then
		sed -i "s|^$1=.*|$1=$2|" .env
	else
		printf '%s=%s\n' "$1" "$2" >>.env
	fi
}

env_get() {
	sed -n "s/^$1=//p" .env | tail -n 1
}

repo=$(cd ../../.. && pwd)
if [ -n "$build" ]; then
	step "2/8 Сборка образов в Docker (первый раз — 5–15 минут)"
	[ -f "$repo/deploy/build/Dockerfile.lab" ] || die "нет $repo/deploy/build/Dockerfile.lab: скрипт работает в репозитории (git clone или архив)"
	# Версия и дата — из git, если он есть; без git — по текущему времени.
	# Дата сборки манифеста ведёт контроль отката (DM-42): новая сборка
	# должна быть не старше прежней.
	if command -v git >/dev/null 2>&1 && version=$(git -c safe.directory="$repo" -C "$repo" describe --tags --always --dirty 2>/dev/null); then
		source_date=$(git -c safe.directory="$repo" -C "$repo" log -1 --format=%cI)
		source_epoch=$(git -c safe.directory="$repo" -C "$repo" log -1 --format=%ct)
	else
		version=lab-$(date -u +%Y%m%d%H%M)
		source_date=$(date -u +%Y-%m-%dT%H:%M:%SZ)
		source_epoch=$(date -u +%s)
	fi
	tag=$version-test
	image_repo=aisec-test
	# Каталог выпуска — вне репозитория: при umask 077 он принадлежал бы root
	# и мешал сборке от имени разработчика. Удаляется при любом выходе.
	release=$(mktemp -d "${TMPDIR:-/var/tmp}/aisec-lab-release.XXXXXX")
	trap 'rm -rf "$release"' EXIT
	trap 'exit 130' INT TERM
	set -- --build-arg VERSION="$version" --build-arg SOURCE_DATE="$source_date" --build-arg SOURCE_EPOCH="$source_epoch"
	if [ -n "$mirror" ]; then
		# Зеркало — перед образами по умолчанию из Dockerfile.lab (digest тот же).
		for a in NODE_IMAGE GO_IMAGE; do
			img=$(sed -n "s/^ARG $a=//p" "$repo/deploy/build/Dockerfile.lab")
			[ -n "$img" ] || die "в Dockerfile.lab нет ARG $a"
			set -- "$@" --build-arg "$a=$mirror/$img"
		done
	fi
	[ -z "$build_ca" ] || set -- "$@" --secret id=build-ca,src="$build_ca"
	docker build -f "$repo/deploy/build/Dockerfile.lab" --target release "$@" -o type=local,dest="$release" "$repo"
	# Образы — как make images-docker: без сети, из каталога выпуска.
	for c in aisec-server aisec-gateway aisec-cli; do
		docker build --pull=false --network=none --provenance=false --sbom=false -q \
			-f "$repo/deploy/build/Dockerfile.release" --target "$c" \
			--build-arg VERSION="$version" --build-arg BUILD_KIND=test --build-arg SOURCE_DATE_EPOCH="$source_epoch" \
			-t "aisec-test/$c:$tag" "$release" >/dev/null
		echo "Образ aisec-test/$c:$tag."
	done
	# Целостность собранного выпуска — по подписанному манифесту в образе.
	docker run --rm --network none "aisec-test/aisec-cli:$tag" verify
	rm -rf "$release"
	trap - EXIT
else
	step "2/8 Сборка пропущена (--no-build)"
	[ -f .env ] || die "нет .env: без сборки возьмите AISEC_VERSION собранных образов из прошлого запуска"
	tag=$(env_get AISEC_VERSION)
	image_repo=$(env_get AISEC_IMAGE_REPO)
	for c in aisec-server aisec-gateway aisec-cli; do
		docker image inspect "$image_repo/$c:$tag" >/dev/null 2>&1 || die "нет образа $image_repo/$c:$tag"
	done
fi

step "3/8 Подготовка хоста"
env_existed=
[ ! -f .env ] || env_existed=1
./prepare-host.sh >/dev/null
data_dir=$(env_get AISEC_DATA_DIR)
[ -n "$data_dir" ] || data_dir=/srv/aisec
secrets="$data_dir/secrets"
tls_files="console.crt console.key console-ca.crt gateway.crt gateway.key"
have=0
for f in $tls_files; do
	[ ! -s "$secrets/$f" ] || have=$((have + 1))
done
# Источник сертификатов: local — собственный УЦ установки (tls init),
# customer — УЦ заказчика (--tls-dir). Установки 4.32 без отметки — local.
tls_source=local
[ -z "$tls_dir" ] || tls_source=customer
old_source=$(env_get AISEC_TLS_SOURCE)
[ -n "$old_source" ] || old_source=local
if [ "$have" -eq 5 ] && [ "$old_source" != "$tls_source" ]; then
	if [ "$old_source" = customer ]; then
		die "сертификаты в $secrets — от УЦ заказчика (прежний запуск с --tls-dir). Повторите запуск с --tls-dir КАТАЛОГ или, чтобы перейти на собственный УЦ установки, удалите пять файлов ($tls_files) из $secrets и запустите без --tls-dir"
	fi
	die "сертификаты в $secrets выпущены собственным УЦ установки. Чтобы перейти на сертификаты УЦ заказчика, удалите пять файлов ($tls_files) из $secrets и запустите снова с --tls-dir; клиентам и приложениям нужен корень УЦ заказчика вместо прежнего ca.crt"
fi
if [ "$have" -eq 5 ] && [ -n "$tls_dir" ]; then
	check_tls_dir
	for f in console.crt console.key gateway.crt gateway.key ca.crt; do
		g=$f
		[ "$f" != ca.crt ] || g=console-ca.crt
		cmp -s "$tls_dir/$f" "$secrets/$g" ||
			die "в $secrets уже другие сертификаты УЦ заказчика ($g не совпадает с $tls_dir/$f). Чтобы заменить их, удалите пять файлов ($tls_files) из $secrets и запустите снова с --tls-dir"
	done
fi
# Готовые сертификаты выпущены на прежнее имя консоли: с другим именем шлюз
# не прошёл бы проверку сертификата консоли. Проверка — до записи в .env.
old_name=$(env_get AISEC_CONSOLE_HOST)
if [ "$have" -eq 5 ] && [ -n "$old_name" ] && [ "$old_name" != "$console_name" ]; then
	die "сертификаты в $secrets выпущены для имени консоли $old_name, а сейчас имя $console_name. Запустите с --console-name $old_name или удалите пять файлов ($tls_files) из $secrets и запустите снова — сертификаты и корень УЦ будут выпущены заново"
fi
set_env AISEC_IMAGE_REPO "$image_repo"
set_env AISEC_VERSION "$tag"
set_env AISEC_CONSOLE_HOST "$console_name"
# Без --bind адрес интерфейса меняется только в новом .env (в образце —
# 127.0.0.1, для лаборатории — все интерфейсы); прежний .env не трогается.
if [ -n "$bind" ] || [ -z "$env_existed" ]; then
	set_env AISEC_CONSOLE_BIND "${bind:-0.0.0.0}"
	set_env AISEC_GATEWAY_BIND "${bind:-0.0.0.0}"
fi
[ -z "$mirror" ] || set_env AISEC_POSTGRES_IMAGE "$mirror/postgres"
echo "Хост подготовлен: $data_dir, .env заполнен."

# Каталог для aisec-cli tls check: root:aisec 0750, файлы root:aisec 0440 —
# aisec-cli (пользователь aisec) читает их, но подменить не может; root
# ставит в secrets ровно то, что проверено. Удаляется при любом выходе.
stage_open() {
	stage=$(mktemp -d "$data_dir/tls-check.XXXXXX")
	trap 'rm -rf "$stage"' EXIT
	trap 'exit 130' INT TERM
	chown root:aisec "$stage"
	chmod 0750 "$stage"
}

# stage_file ИСТОЧНИК ИМЯ — только обычный файл без символьных и жёстких
# ссылок (как в 4.32) и не больше 64 КиБ; окончательная проверка — tls check.
stage_file() {
	[ "$(find "$1" -prune -type f -links 1)" = "$1" ] || die "$1: нужен обычный файл без символьных и жёстких ссылок"
	[ "$(wc -c <"$1")" -le 65536 ] || die "$1: больше 64 КиБ — это не сертификат и не ключ"
	install -o root -g aisec -m 0440 "$1" "$stage/$2"
}

# stage_check ПОДСКАЗКА — tls check; при ошибке — отказ с подсказкой.
stage_check() {
	docker compose run --rm --no-deps -T -v "$stage:/in:ro" aisec-cli tls check -dir /in -hosts "$hosts" -console-name "$console_name" ||
		die "сертификаты не прошли проверку (пункты выше): $1"
}

# Перед заменой сертификатов сервер и шлюз останавливаются: шлюз сверяет
# console-ca.crt с прочитанным при запуске (контроль целостности), сервер со
# старым сертификатом шлюз уже не узнал бы. Без контейнеров — ничего не делает.
stop_services() {
	docker compose stop aisec-gateway aisec-server
}

stage_close() {
	rm -rf "$stage"
	trap - EXIT
}

# install_tls КАТАЛОГ — пять файлов в secrets с владельцами и правами шага 3.4.
install_tls() {
	install -o aisec -g aisec -m 0644 "$1/console.crt" "$secrets/console.crt"
	install -o aisec -g aisec -m 0600 "$1/console.key" "$secrets/console.key"
	install -o root -g root -m 0644 "$1/ca.crt" "$secrets/console-ca.crt"
	install -o aisec-gw -g aisec-gw -m 0600 "$1/gateway.key" "$secrets/gateway.key"
	install -o aisec-gw -g aisec-gw -m 0644 "$1/gateway.crt" "$secrets/gateway.crt"
}

if [ "$tls_source" = customer ]; then
	step "4/8 Сертификаты TLS УЦ заказчика"
else
	step "4/8 Сертификаты TLS от собственного УЦ установки"
fi
fingerprint= tls_new=
if [ "$have" -eq 5 ]; then
	echo "Сертификаты уже есть в $secrets — проверяю и не меняю (имена и адреса в них — с первой установки)."
	stage_open
	for f in console.crt console.key gateway.crt gateway.key; do
		stage_file "$secrets/$f" "$f"
	done
	stage_file "$secrets/console-ca.crt" ca.crt
	stage_check "запустите с прежними --host (без новых имён и адресов) или замените сертификаты — удалите пять файлов ($tls_files) из $secrets и запустите снова"
	stage_close
elif [ "$have" -ne 0 ]; then
	die "в $secrets есть только часть сертификатов: положите недостающие сами (install-pilot.md, шаг 3.4) или удалите все пять и запустите снова"
elif [ -n "$tls_dir" ]; then
	check_tls_dir
	stage_open
	for f in console.crt console.key gateway.crt gateway.key ca.crt; do
		stage_file "$tls_dir/$f" "$f"
	done
	stage_check "исправьте сертификаты в $tls_dir (или попросите новые у УЦ) и запустите снова"
	stop_services
	install_tls "$stage"
	stage_close
	tls_new=1
else
	tmp=$(mktemp -d "$data_dir/tls.XXXXXX")
	# Закрытые ключи во временном каталоге удаляются при любом выходе.
	trap 'rm -rf "$tmp"' EXIT
	trap 'exit 130' INT TERM
	chown aisec:aisec "$tmp"
	chmod 0700 "$tmp"
	out=$(docker compose run --rm --no-deps -T -v "$tmp:/out" aisec-cli tls init -out /out -hosts "$console_name,$hosts") ||
		die "aisec-cli tls init: ${out:-нет вывода}"
	printf '%s\n' "$out"
	fingerprint=$(printf '%s\n' "$out" | grep -o '[0-9A-F][0-9A-F]\(:[0-9A-F][0-9A-F]\)\{31\}' | head -n 1)
	out=
	# Команда закончилась: каталог снова у root, подменить файлы пользователь
	# aisec уже не может, и root копирует из него только обычные файлы без
	# символьных и жёстких ссылок — не чужой файл под видом ключа.
	chown root:root "$tmp"
	for f in console.crt console.key ca.crt gateway.key gateway.crt; do
		[ "$(find "$tmp/$f" -prune -type f -links 1)" = "$tmp/$f" ] || die "$f: aisec-cli tls init не создал обычный файл"
	done
	stop_services
	install_tls "$tmp"
	rm -rf "$tmp"
	trap - EXIT
	tls_new=1
fi
set_env AISEC_TLS_SOURCE "$tls_source"
# Копия корня для администраторов и приложений — вне каталога секретов.
install -o root -g root -m 0644 "$secrets/console-ca.crt" "$data_dir/ca.crt"

step "5/8 PostgreSQL и миграции"
docker compose up -d --wait postgres
docker compose run --rm -T aisec-cli migrate

step "6/8 Ключи установки"
setup_token=
if [ -e "$data_dir/keys/master.key" ]; then
	echo "Ключи уже созданы в $data_dir/keys — не меняю."
else
	out=$(docker compose run --rm -T aisec-cli init -dir /etc/aisec/keys)
	printf '%s\n' "$out"
	setup_token=$(printf '%s\n' "$out" | grep -o 'aisec_setup_[A-Za-z0-9_-]*' | head -n 1)
	out=
fi
# Второй запуск кладёт якорь шлюза — копию ключа подписи пакетов.
./prepare-host.sh >/dev/null

step "7/8 Сервер и регистрация шлюза"
# Новые сертификаты — пересоздать контейнер: файлы секретов читаются при
# запуске (после удаления пяти файлов и повторного запуска работает прежний).
docker compose up -d ${tls_new:+--force-recreate} aisec-server
if [ -s "$data_dir/gateway/reg/gateway.crt" ]; then
	echo "Шлюз уже зарегистрирован — не меняю."
else
	out=$(docker compose run --rm -T aisec-cli gateway token -name gw-1 -ttl 30m 2>&1) ||
		out=$(docker compose run --rm -T aisec-cli gateway token -name gw-1 -ttl 30m -reregister) ||
		die "не удалось выпустить токен регистрации шлюза"
	AISEC_GATEWAY_REGISTRATION_TOKEN=$(printf '%s\n' "$out" | grep -o 'aisec_gwreg_[A-Za-z0-9_-]*' | head -n 1)
	out=
	[ -n "$AISEC_GATEWAY_REGISTRATION_TOKEN" ] || die "в выводе aisec-cli нет токена регистрации шлюза"
	export AISEC_GATEWAY_REGISTRATION_TOKEN
	# Сервер поднимается несколько секунд: регистрация повторяется, пока он
	# не ответит (не дольше двух минут).
	i=0
	until reg=$(docker compose run --rm --no-deps -T -e AISEC_GATEWAY_REGISTRATION_TOKEN aisec-gateway register \
		-console "https://$console_name:8444" -console-ca /run/secrets/console-ca \
		-out-dir /var/lib/aisec-gateway/reg -state-dir /var/lib/aisec-gateway/state 2>&1); do
		i=$((i + 1))
		if [ "$i" -ge 40 ]; then
			unset AISEC_GATEWAY_REGISTRATION_TOKEN
			printf '%s\n' "$reg" >&2
			die "шлюз не зарегистрировался за 2 минуты; журнал сервера: docker compose logs aisec-server"
		fi
		sleep 3
	done
	unset AISEC_GATEWAY_REGISTRATION_TOKEN
	echo "Шлюз gw-1 зарегистрирован."
fi

step "8/8 Запуск"
# После замены сертификатов шлюз пересоздаётся: файлы секретов читаются
# при запуске (остановлен он ещё на шаге 4).
[ -z "$tls_new" ] || docker compose up -d --no-deps --force-recreate aisec-gateway
docker compose up -d
console_port=$(env_get AISEC_CONSOLE_PORT)
gateway_port=$(env_get AISEC_GATEWAY_PORT)
echo
echo "Готово. Это тестовая сборка (aisec-test, тестовый ключ манифеста) — НЕ ДЛЯ ПОСТАВКИ заказчику."
echo "  Консоль: https://$first_host:${console_port:-8444}"
echo "  Шлюз:    https://$first_host:${gateway_port:-8443}/v1 (OpenAI-совместимый API)"
if [ "$tls_source" = customer ]; then
	echo "  Корень УЦ заказчика: $data_dir/ca.crt — если его ещё нет в доверенных у администраторов и приложений, добавьте"
else
	echo "  Корень УЦ установки: $data_dir/ca.crt — добавьте его в доверенные в браузере и у приложений"
fi
if [ -n "$fingerprint" ]; then
	echo "  Отпечаток SHA-256 корня (сверьте при импорте): $fingerprint"
else
	echo "  Отпечаток корня: openssl x509 -noout -fingerprint -sha256 -in $data_dir/ca.crt"
fi
echo "  Адрес интерфейса: консоль — $(env_get AISEC_CONSOLE_BIND), шлюз — $(env_get AISEC_GATEWAY_BIND) (параметр --bind)"
if [ -n "$setup_token" ]; then
	echo "  Токен первичной настройки (24 часа, показан один раз): $setup_token"
fi
echo "Дальше: первичная настройка в консоли, провайдер LLM и первое приложение — docs/user/install-pilot.md, разделы 4.5, 5 и 6."
