#!/usr/bin/env bash
# Шаг с сетью сборки ONNX Runtime (ADR-0024, раздел 8): исходники ORT и его
# зависимостей из deps.lock — в локальное зеркало, с проверкой SHA-256.
#
#   fetch.sh deps.lock КАТАЛОГ_ЗЕРКАЛА
#
# Вызывает make ort-fetch. Сеть нужна только здесь; сборка (build.sh) идёт
# без сети из зеркала. Готовый файл с верным хешем повторно не скачивается.
# Хеш, который не совпал, — ошибка: файл не попадает в зеркало. Строка с
# хешем «-» (новая зависимость) — ошибка с вычисленным хешем: его вносят в
# deps.lock после проверки источника, вместе с ревью.
set -euo pipefail
umask 022

die() {
	echo "fetch.sh: $*" >&2
	exit 1
}

[ $# -eq 2 ] || die "использование: fetch.sh deps.lock КАТАЛОГ_ЗЕРКАЛА"
lock=$1 mirror=$2
[ -f "$lock" ] || die "нет файла $lock"
mkdir -p "$mirror"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# mirror_file ИМЯ ВИД ИСТОЧНИК — имя файла в зеркале.
mirror_file() {
	case $2 in
	git) echo "$1.tar" ;;
	url) basename "$3" ;;
	esac
}

sha256() { sha256sum "$1" | cut -d' ' -f1; }

failed=0
declare -A seen
while IFS=';' read -r name kind src ref want license; do
	case $name in '' | '#'*) continue ;; esac
	[[ $name =~ ^[a-z0-9_-]{1,64}$ ]] || die "неверное имя: $name"
	[[ $src == https://* ]] || die "$name: источник только https"
	[ -n "$license" ] || die "$name: нет лицензии"
	file=$mirror/$(mirror_file "$name" "$kind" "$src")
	# Два источника с одним именем файла перезаписали бы друг друга.
	[ -z "${seen[$file]:-}" ] || die "$name: файл зеркала $file уже занят записью ${seen[$file]}"
	seen[$file]=$name
	if [ -f "$file" ] && [ "$want" != - ] && [ "$(sha256 "$file")" = "$want" ]; then
		echo "есть: $name"
		continue
	fi
	part=$work/$name.part
	case $kind in
	git)
		[[ $ref =~ ^[0-9a-f]{40}$ ]] || die "$name: версия git — полный коммит"
		repo=$work/$name.git
		git init -q --bare "$repo"
		# Только нужный коммит; GitHub отдаёт коммит по хешу.
		git -C "$repo" fetch -q --depth 1 "$src" "$ref"
		[ "$(git -C "$repo" rev-parse "$ref^{commit}")" = "$ref" ] || die "$name: получен не тот коммит"
		git -C "$repo" archive --format=tar --prefix="$name/" "$ref" >"$part"
		rm -rf "$repo"
		;;
	url)
		[ "$ref" = - ] || die "$name: у вида url версия «-»"
		curl -fsSL --proto '=https' --tlsv1.2 --max-time 600 -o "$part" "$src"
		;;
	*) die "$name: неизвестный вид $kind" ;;
	esac
	got=$(sha256 "$part")
	if [ "$want" = - ]; then
		echo "fetch.sh: $name: хеш в deps.lock не задан, вычислен $got" >&2
		failed=1
		continue
	fi
	if [ "$got" != "$want" ]; then
		echo "fetch.sh: $name: SHA-256 $got, в deps.lock $want" >&2
		failed=1
		continue
	fi
	mv "$part" "$file"
	echo "получен: $name"
done <"$lock"
[ "$failed" -eq 0 ] || die "зеркало неполное"
echo "Зеркало готово: $mirror"
