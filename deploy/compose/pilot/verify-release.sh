#!/bin/sh
# Проверка нового выпуска перед обновлением (ОБН.1 в части MVP, ADR-0019).
#
#   ./verify-release.sh КАТАЛОГ_ВЫПУСКА
#
# Каталог выпуска: aisec-manifest.json, aisec-manifest.json.sig, bin/ и
# images/aisec-server.tar, aisec-gateway.tar, aisec-cli.tar. Каталог и файлы
# должны быть доступны на чтение пользователю 65534: от него работает
# проверяющий контейнер.
#
# 1. Подпись манифеста и все файлы выпуска проверяет aisec-cli УСТАНОВЛЕННОЙ
#    версии (AISEC_VERSION из .env): ключ производителя берётся из
#    действующей установки, а не из нового выпуска.
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

[ $# -eq 1 ] || die "укажите каталог выпуска"
[ -d "$1" ] || die "нет каталога $1"
# Путь выпуска разбирается до перехода в каталог скрипта: относительный путь
# считается от текущего каталога.
release=$(cd "$1" && pwd)
case "$release" in
*,*) die "путь выпуска не должен содержать запятую: $release" ;;
esac
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
[ -n "$installed" ] || die "в .env нет AISEC_VERSION — версии установленного aisec-cli"
case "$repo" in
aisec) suffix= ;;
aisec-test) suffix=-test ;;
*) die "AISEC_IMAGE_REPO: ожидается aisec или aisec-test, а не $repo" ;;
esac

echo "1. Подпись и файлы выпуска — aisec-cli $installed (установленная версия)."
docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges:true \
	--user 65534:65534 --mount "type=bind,source=$release,target=/release,readonly" \
	"$repo/aisec-cli:$installed" verify -release /release ||
	die "выпуск не прошёл проверку подписи и файлов — не устанавливайте его"

# Манифест проверен: версия и список бинарников берутся из него.
version=$(sed -n 's/^  "version": "\([A-Za-z0-9._-]*\)",$/\1/p' "$release/aisec-manifest.json")
[ -n "$version" ] || die "в манифесте нет версии"
tag="$version$suffix"
[ "$tag" != "$installed" ] || die "выпуск $tag уже установлен — проверять нечего"
bins=$(sed -n 's/^      "path": "bin\/\([a-z0-9-]*\)",$/\1/p' "$release/aisec-manifest.json" | sort)
[ -n "$bins" ] || die "в манифесте нет бинарников"

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
	archive="$release/images/$c.tar"
	image="$repo/$c:$tag"
	[ -f "$archive" ] || die "в выпуске нет images/$c.tar"
	case "$c" in
	aisec-server) want_bins=aisec-server ports='{"8444/tcp":{},"8445/tcp":{}}' ;;
	aisec-gateway) want_bins=aisec-gateway ports='{"8443/tcp":{}}' ;;
	aisec-cli) want_bins=$bins ports=null ;;
	esac
	check_archive "$archive" "$image"
	! docker image inspect "$image" >/dev/null 2>&1 || die "$image уже загружен — удалите его (docker rmi) и повторите"
	loaded="$loaded $image"
	docker load -q -i "$archive" >/dev/null || die "$archive: не загрузить"

	got=$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Config.User}} {{json .Config.Entrypoint}} {{json .Config.Cmd}} {{json .Config.Env}} {{json .Config.Volumes}} {{json .Config.ExposedPorts}} {{json .Config.Healthcheck}} {{json .Config.OnBuild}} {{json .Config.Shell}}' "$image")
	want="linux/amd64 65534:65534 [\"/opt/aisec/bin/$c\"] null [\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"] null $ports null null null"
	[ "$got" = "$want" ] || die "$image: настройки образа отличаются от ожидаемых: $got"

	id=$(docker create "$image")
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
	cmp -s "$work/$c/aisec-manifest.json" "$release/aisec-manifest.json" || die "$image: манифест отличается от проверенного"
	cmp -s "$work/$c/aisec-manifest.json.sig" "$release/aisec-manifest.json.sig" || die "$image: подпись отличается от проверенной"
	for b in $want_bins; do
		cmp -s "$work/$c/bin/$b" "$release/bin/$b" || die "$image: bin/$b отличается от проверенного"
	done
	echo "   $image — совпадает ($(echo "$want_bins" | wc -w) бинарн.)"
done
loaded=
echo "Выпуск проверен. Теперь: AISEC_VERSION=$tag в .env и docker compose up -d."
