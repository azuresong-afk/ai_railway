#!/usr/bin/env bash
# Библиотеки выпуска aisec-ml (ADR-0024, раздел 8): копирует в lib/ каталога
# выпуска загрузчик и системные библиотеки, нужные bin/aisec-ml и
# lib/libonnxruntime.so.*, из того же сборочного образа, где собраны они сами.
#
#   ml-libs.sh КАТАЛОГ_ВЫПУСКА
#
# Вызывает make ml-release-assemble (Dockerfile.ml, цель ml-release). Только
# x86-64. Зависимости собираются замыканием по NEEDED (readelf): в образе нет
# ни одной библиотеки сверх нужных, и ни одна нужная не берётся из системы
# хоста — загрузчик aisec-ml и RPATH указывают на /opt/aisec/lib.
set -euo pipefail
umask 022
export LC_ALL=C

die() {
	echo "ml-libs.sh: $*" >&2
	exit 1
}

[ $# -eq 1 ] || die "использование: ml-libs.sh КАТАЛОГ_ВЫПУСКА"
rel=$1
lib=$rel/lib
loader=ld-linux-x86-64.so.2
[ -x "$rel/bin/aisec-ml" ] || die "нет $rel/bin/aisec-ml"

interp=$(readelf -l "$rel/bin/aisec-ml" | sed -n 's/.*Requesting program interpreter: \(.*\)\]$/\1/p')
[ "$interp" = "/opt/aisec/lib/$loader" ] || die "загрузчик aisec-ml: «$interp», ожидается /opt/aisec/lib/$loader"

# copy ИМЯ — системная библиотека из путей компилятора образа.
copy() {
	local src mode=0644
	src=$(gcc -print-file-name="$1")
	[ "$src" != "$1" ] && [ -f "$src" ] || die "не найдена системная библиотека $1"
	[ "$1" != "$loader" ] || mode=0755
	install -m "$mode" "$(realpath "$src")" "$lib/$1"
	queue+=("$lib/$1")
}

queue=("$rel/bin/aisec-ml")
for f in "$lib"/libonnxruntime.so.*; do
	[ -f "$f" ] || die "нет библиотеки ONNX Runtime в $lib"
	queue+=("$f")
done
copy "$loader"
while [ ${#queue[@]} -gt 0 ]; do
	f=${queue[0]}
	queue=("${queue[@]:1}")
	for n in $(readelf -d "$f" | sed -n 's/.*(NEEDED).*\[\(.*\)\]$/\1/p'); do
		case $n in */*) die "$f: зависимость с путём $n" ;; esac
		[ -e "$lib/$n" ] || copy "$n"
	done
done
echo "Библиотеки aisec-ml:"
(cd "$lib" && sha256sum -- *)
