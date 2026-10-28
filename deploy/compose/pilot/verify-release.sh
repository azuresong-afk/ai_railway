#!/bin/sh
# Проверка поставки и нового выпуска перед обновлением (ОБН.1 в части MVP,
# ADR-0019, ADR-0022).
#
#   ./verify-release.sh КАТАЛОГ_ВЫПУСКА           обновление
#   ./verify-release.sh -first КАТАЛОГ_ВЫПУСКА    первая установка
#
# Каталог выпуска: aisec-manifest.json, aisec-manifest.json.sig, bin/ и
# images/aisec-server.tar, aisec-gateway.tar, aisec-cli.tar. Запускается от
# root (или группы docker с правом записи во временный каталог).
#
# 0. Выпуск копируется во временный каталог (владелец root, запись только
#    владельцу), и дальше скрипт работает только с копией: файлы нельзя
#    подменить между проверкой и загрузкой (3Н6 ревью 3.r1).
# 1. Подпись манифеста и все файлы выпуска проверяет aisec-cli УСТАНОВЛЕННОЙ
#    версии (AISEC_VERSION из .env): ключ производителя берётся из
#    действующей установки, а не из нового выпуска. Выпуск, собранный раньше
#    установленного, отвергается (откат — прежние образы, README.md).
#    Отпечаток ключа, которым проверена подпись, сверяется с
#    AISEC_VENDOR_FINGERPRINT из .env — отпечатком из руководства установки
#    (ADR-0022). При первой установке (-first) установленной версии нет:
#    образ aisec-cli нового выпуска загружается после проверки архива и
#    проверяет выпуск сам; доверие держится на отпечатке, полученном по
#    другому каналу (руководство, письмо производителя), а не из поставки.
# 2. До загрузки в архиве каждого образа проверяется состав: ровно один образ
#    с тегом новой версии, никаких других имён. Установленные образы этим
#    тегом не перезаписываются: новая версия обязана отличаться.
# 3. После загрузки сверяются настройки образа (пользователь, точка входа,
#    порты, окружение, тома) и полный список файлов (без символьных ссылок),
#    затем бинарники, манифест и подпись побайтно сравниваются с уже
#    проверенными файлами выпуска. При любом расхождении загруженные образы
#    удаляются.
#
# Только после строки «Выпуск проверен» меняйте AISEC_VERSION в .env и
# выполняйте docker compose up -d (README.md, «Обновление»). Скрипт ничего не
# запускает из нового выпуска и не меняет установку, кроме загрузки образов.
set -eu

die() {
	echo "verify-release.sh: $*" >&2
	exit 1
}

first=
if [ $# -eq 2 ] && [ "$1" = -first ]; then
	first=1
	shift
fi
[ $# -eq 1 ] || die "укажите каталог выпуска: verify-release.sh [-first] КАТАЛОГ"
[ -d "$1" ] || die "нет каталога $1"
# Путь выпуска разбирается до перехода в каталог скрипта: относительный путь
# считается от текущего каталога.
release=$(cd "$1" && pwd)
cd "$(dirname "$0")"

[ -f .env ] || die "нет .env рядом с compose.yaml"
for f in aisec-manifest.json aisec-manifest.json.sig; do
	[ -f "$release/$f" ] || die "в выпуске нет $f"
done

env_value() {
	sed -n "s/^$1=//p" .env | tail -n 1
}
installed=$(env_value AISEC_VERSION)
repo=$(env_value AISEC_IMAGE_REPO)
[ -n "$repo" ] || repo=aisec
# Отпечаток ключа производителя из руководства установки (ADR-0022).
vendor_fp=$(env_value AISEC_VENDOR_FINGERPRINT | tr 'A-F' 'a-f')
[ -n "$first" ] || [ -n "$installed" ] || die "в .env нет AISEC_VERSION — версии установленного aisec-cli (первая установка — с -first)"
case "$repo" in
aisec) suffix= ;;
aisec-test) suffix=-test ;;
*) die "AISEC_IMAGE_REPO: ожидается aisec или aisec-test, а не $repo" ;;
esac
case "$vendor_fp" in
'') [ "$repo" = aisec-test ] || die "в .env нет AISEC_VENDOR_FINGERPRINT — отпечатка ключа производителя из руководства установки" ;;
*[!0-9a-f:]*) die "AISEC_VENDOR_FINGERPRINT: ожидаются группы шестнадцатеричных цифр через двоеточие" ;;
esac

work=$(mktemp -d)
loaded=
cleanup() {
	status=$?
	rm -rf "$work"
	if [ "$status" -ne 0 ] && [ -n "$loaded" ]; then
		# shellcheck disable=SC2086 # имена без пробелов: проверены выше
		docker rmi $loaded >/dev/null 2>&1 || true
		echo "verify-release.sh: загруженные образы удалены:$loaded" >&2
	fi
}
trap cleanup EXIT

echo "0. Копия выпуска во временном каталоге."
case "$work" in
*,*) die "временный каталог не должен содержать запятую: $work (задайте TMPDIR)" ;;
esac
# Каталог проходим для 65534 (проверяющий контейнер), писать может только
# владелец. Символьные ссылки копируются как ссылки: шаг 1 их отвергает.
chmod 0755 "$work"
rel="$work/release"
mkdir -p "$rel/images"
for f in aisec-manifest.json aisec-manifest.json.sig bin images/aisec-server.tar images/aisec-gateway.tar images/aisec-cli.tar; do
	[ ! -L "$release/$f" ] || die "в выпуске $f — символьная ссылка"
done
cp -P "$release/aisec-manifest.json" "$release/aisec-manifest.json.sig" "$rel/"
[ -d "$release/bin" ] || die "в выпуске нет bin/"
cp -RP "$release/bin" "$rel/bin"
for c in aisec-server aisec-gateway aisec-cli; do
	[ -f "$release/images/$c.tar" ] || die "в выпуске нет images/$c.tar"
	cp -P "$release/images/$c.tar" "$rel/images/"
done
chown -R "$(id -u):$(id -g)" "$rel"
chmod -R u=rwX,go=rX "$rel"

# Состав архива docker save до загрузки: только метаданные OCI и блобы, одно
# имя образа. Обратная косая черта запрещена, чтобы имя нельзя было спрятать
# экранированием JSON.
check_archive() {
	archive=$1 image=$2
	extra=$(tar -tf "$archive" | grep -Ev '^(blobs/|blobs/sha256/|blobs/sha256/[0-9a-f]{64}|index\.json|manifest\.json|oci-layout)$' || true)
	[ -z "$extra" ] || die "$archive: лишние записи в архиве: $(echo "$extra" | head -n 3 | tr '\n' ' ')"
	tar -xOf "$archive" manifest.json | head -c 65536 >"$work/manifest.json"
	tar -xOf "$archive" index.json | head -c 65536 >"$work/index.json"
	if grep -q '\\' "$work/manifest.json" "$work/index.json"; then
		die "$archive: экранирование в метаданных архива"
	fi
	[ "$(grep -o '"RepoTags":\[[^]]*\]' "$work/manifest.json")" = "\"RepoTags\":[\"$image\"]" ] ||
		die "$archive: в архиве не ровно один образ $image"
	[ "$(grep -o 'RepoTags' "$work/manifest.json" | wc -l)" -eq 1 ] || die "$archive: несколько образов в архиве"
	[ "$(grep -o 'name"' "$work/index.json" | wc -l)" -eq 2 ] || die "$archive: лишние имена в index.json"
	grep -q "\"io.containerd.image.name\":\"docker.io/$image\"" "$work/index.json" ||
		die "$archive: в index.json другое имя образа"
	grep -q "\"org.opencontainers.image.ref.name\":\"${image##*:}\"" "$work/index.json" ||
		die "$archive: в index.json другой тег"
}

manifest_version() {
	sed -n 's/^  "version": "\([A-Za-z0-9._-]*\)",$/\1/p' "$rel/aisec-manifest.json"
}

if [ -n "$first" ]; then
	# Первая установка: версия из ещё не проверенного манифеста задаёт только
	# имя образа aisec-cli; его архив проверяется до загрузки, затем этот
	# aisec-cli проверяет выпуск, и версия читается заново.
	version=$(manifest_version)
	[ -n "$version" ] || die "в манифесте нет версии"
	checker="$repo/aisec-cli:$version$suffix"
	check_archive "$rel/images/aisec-cli.tar" "$checker"
	! docker image inspect "$checker" >/dev/null 2>&1 || die "$checker уже загружен — это не первая установка: проверяйте без -first"
	loaded="$checker"
	docker load -q -i "$rel/images/aisec-cli.tar" >/dev/null || die "images/aisec-cli.tar: не загрузить"
	echo "1. Подпись и файлы выпуска — aisec-cli из поставки (первая установка), отпечаток ключа сверяется с AISEC_VENDOR_FINGERPRINT."
	verify_flags=-allow-older
else
	checker="$repo/aisec-cli:$installed"
	# Проверяет только уже установленный образ: без него docker run скачал
	# бы aisec-cli из реестра, и сверка отпечатка ничего бы не доказала
	# (ревью 4.r1, 4В10).
	docker image inspect "$checker" >/dev/null 2>&1 ||
		die "нет образа $checker установленной версии; первая установка — с -first"
	echo "1. Подпись и файлы выпуска — aisec-cli $installed (установленная версия)."
	verify_flags=
fi
# shellcheck disable=SC2086 # флаг без пробелов
docker run --rm --pull never --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
	--user 65534:65534 --mount "type=bind,source=$rel,target=/release,readonly" \
	"$checker" verify -release /release $verify_flags >"$work/verify.out" || {
	cat "$work/verify.out"
	die "выпуск не прошёл проверку подписи и файлов — не устанавливайте его"
}
cat "$work/verify.out"

# Отпечаток ключа, которым проверена подпись (ADR-0022).
got_fp=$(sed -n 's/^Отпечаток ключа производителя: \([0-9a-f:]*\)$/\1/p' "$work/verify.out" | tail -n 1)
if [ -n "$vendor_fp" ]; then
	[ -n "$got_fp" ] || die "aisec-cli не сообщил отпечаток ключа — сверить его с AISEC_VENDOR_FINGERPRINT нельзя"
	[ "$got_fp" = "$vendor_fp" ] ||
		die "подпись проверена ключом с отпечатком $got_fp, а в руководстве (AISEC_VENDOR_FINGERPRINT) — $vendor_fp: это не ключ производителя, не устанавливайте выпуск"
	echo "   Отпечаток ключа производителя совпадает с AISEC_VENDOR_FINGERPRINT."
else
	echo "   ВНИМАНИЕ: AISEC_VENDOR_FINGERPRINT не задан, отпечаток не сверен (сборка aisec-test, НЕ ДЛЯ ПОСТАВКИ)." >&2
fi

# Манифест проверен: версия и список бинарников берутся из копии.
version=$(manifest_version)
[ -n "$version" ] || die "в манифесте нет версии"
tag="$version$suffix"
[ -z "$first" ] || [ "$checker" = "$repo/aisec-cli:$tag" ] || die "версия манифеста изменилась во время проверки"
[ -n "$first" ] || [ "$tag" != "$installed" ] || die "выпуск $tag уже установлен — проверять нечего"
bins=$(sed -n 's/^      "path": "bin\/\([a-z0-9-]*\)",$/\1/p' "$rel/aisec-manifest.json" | sort)
[ -n "$bins" ] || die "в манифесте нет бинарников"

# Ожидаемые файлы образа (tar -tv без размеров и дат). Файлы, которые Docker
# сам создаёт в контейнере (/dev, /proc, /sys, /etc/hosts и т. п.), не
# сравниваются: при запуске их закрывают монтирования Docker.
expected_files() {
	printf '%s\n' 'drwxr-xr-x 0/0 opt/' 'drwxr-xr-x 0/0 opt/aisec/' \
		'-rw-r--r-- 0/0 opt/aisec/aisec-manifest.json' '-rw-r--r-- 0/0 opt/aisec/aisec-manifest.json.sig' \
		'drwxr-xr-x 0/0 opt/aisec/bin/'
	for b in $1; do
		printf '%s\n' "-rwxr-xr-x 0/0 opt/aisec/bin/$b"
	done
}

echo "2. Образы выпуска $tag совпадают с проверенными файлами."
for c in aisec-server aisec-gateway aisec-cli; do
	archive="$rel/images/$c.tar"
	image="$repo/$c:$tag"
	case "$c" in
	aisec-server) want_bins=aisec-server ports='{"8444/tcp":{},"8445/tcp":{}}' ;;
	aisec-gateway) want_bins=aisec-gateway ports='{"8443/tcp":{}}' ;;
	aisec-cli) want_bins=$bins ports=null ;;
	esac
	# Бинарник каждого образа обязан быть в проверенном манифесте.
	for b in $want_bins; do
		printf '%s\n' "$bins" | grep -qx "$b" || die "в проверенном манифесте нет bin/$b для $image"
	done
	# При первой установке aisec-cli уже проверен и загружен на шаге 1.
	if [ "$image" != "$checker" ] || [ -z "$first" ]; then
		check_archive "$archive" "$image"
		! docker image inspect "$image" >/dev/null 2>&1 || die "$image уже загружен — удалите его (docker rmi) и повторите"
		loaded="$loaded $image"
		docker load -q -i "$archive" >/dev/null || die "$archive: не загрузить"
	fi

	got=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Env}} {{json .Config.Volumes}} {{json .Config.ExposedPorts}} {{json .Config.Healthcheck}} {{json .Config.OnBuild}} {{json .Config.Shell}}' "$image")
	want="linux/amd64 65534:65534 [\"/opt/aisec/bin/$c\"] null [\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"] null $ports null null null"
	[ "$got" = "$want" ] || die "$image: настройки образа отличаются от ожидаемых: $got"

	id=$(docker create --pull never "$image")
	docker export "$id" | tar -tv | awk '{ $3 = $4 = $5 = ""; print }' | tr -s ' ' |
		grep -Ev '^[^ ]+ [^ ]+ (\.dockerenv|dev/.*|proc/|sys/|etc/|etc/(hostname|hosts|resolv\.conf)|etc/mtab -> /proc/mounts)$' |
		sort >"$work/$c.files" || true
	expected_files "$want_bins" | sort >"$work/$c.want"
	if ! cmp -s "$work/$c.files" "$work/$c.want"; then
		docker rm "$id" >/dev/null
		die "$image: состав файлов отличается от ожидаемого: $(diff "$work/$c.want" "$work/$c.files" | grep '^[<>]' | head -n 3 | tr '\n' ' ')"
	fi
	mkdir "$work/$c"
	docker cp -q "$id:/opt/aisec/." "$work/$c/" || {
		docker rm "$id" >/dev/null
		die "$image: не скопировать /opt/aisec"
	}
	docker rm "$id" >/dev/null
	cmp -s "$work/$c/aisec-manifest.json" "$rel/aisec-manifest.json" || die "$image: манифест отличается от проверенного"
	cmp -s "$work/$c/aisec-manifest.json.sig" "$rel/aisec-manifest.json.sig" || die "$image: подпись отличается от проверенной"
	for b in $want_bins; do
		cmp -s "$work/$c/bin/$b" "$rel/bin/$b" || die "$image: bin/$b отличается от проверенного"
	done
	echo "   $image — совпадает ($(echo "$want_bins" | wc -w) бинарн.)"
done
loaded=
if [ -n "$first" ]; then
	echo "Выпуск проверен. Теперь: AISEC_VERSION=$tag в .env и шаги установки (docs/user/install-pilot.md)."
else
	echo "Выпуск проверен. Теперь: AISEC_VERSION=$tag в .env и docker compose up -d."
fi
