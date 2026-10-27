#!/bin/sh
# Установка для лаборатории и стенда одной командой (задача 4.32 этапа 4):
# на хосте нужен только Docker. Скрипт собирает образы в Docker из исходников
# репозитория (тестовый ключ манифеста, aisec-test/…:ВЕРСИЯ-test — НЕ ДЛЯ
# ПОСТАВКИ), готовит хост (prepare-host.sh), выпускает сертификаты TLS без
# корпоративного УЦ (aisec-cli tls init), создаёт ключи установки,
# регистрирует шлюз и запускает всё. Шаги — те же, что в
# docs/user/install-pilot.md, разделы 3–4.
#
#   sudo ./lab-install.sh --host 192.168.1.50 [--host lab.example.ru] [параметры]
#
# Запускается от root в каталоге deploy/compose/pilot репозитория. Повторный
# запуск безопасен: готовые шаги (сертификаты, ключи, регистрация шлюза)
# пропускаются, образы пересобираются из текущих исходников. Имена в
# сертификатах задаются при первом выпуске: сменить имя консоли повторным
# запуском нельзя (скрипт откажет), адрес интерфейса без --bind остаётся
# прежним из .env.
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

hosts= console_name= bind= mirror= build_ca= build=1
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

step "4/8 Сертификаты TLS без корпоративного УЦ"
fingerprint=
if [ "$have" -eq 5 ]; then
	echo "Сертификаты уже есть в $secrets — не меняю (имена и адреса в них — с первого выпуска)."
elif [ "$have" -ne 0 ]; then
	die "в $secrets есть только часть сертификатов: положите недостающие сами (install-pilot.md, шаг 3.4) или удалите все пять и запустите снова"
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
	install -o aisec -g aisec -m 0644 "$tmp/console.crt" "$secrets/console.crt"
	install -o aisec -g aisec -m 0600 "$tmp/console.key" "$secrets/console.key"
	install -o root -g root -m 0644 "$tmp/ca.crt" "$secrets/console-ca.crt"
	install -o aisec-gw -g aisec-gw -m 0600 "$tmp/gateway.key" "$secrets/gateway.key"
	install -o aisec-gw -g aisec-gw -m 0644 "$tmp/gateway.crt" "$secrets/gateway.crt"
	rm -rf "$tmp"
	trap - EXIT
fi
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
docker compose up -d aisec-server
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
docker compose up -d
console_port=$(env_get AISEC_CONSOLE_PORT)
gateway_port=$(env_get AISEC_GATEWAY_PORT)
echo
echo "Готово. Это тестовая сборка (aisec-test, тестовый ключ манифеста) — НЕ ДЛЯ ПОСТАВКИ заказчику."
echo "  Консоль: https://$first_host:${console_port:-8444}"
echo "  Шлюз:    https://$first_host:${gateway_port:-8443}/v1 (OpenAI-совместимый API)"
echo "  Корень УЦ установки: $data_dir/ca.crt — добавьте его в доверенные в браузере и у приложений"
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
