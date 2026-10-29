#!/usr/bin/env bash
# Шаг без сети сборки ONNX Runtime (ADR-0024, раздел 8): библиотека CPU без
# телеметрии, тестов и Python из проверенного зеркала fetch.sh.
#
#   build.sh deps.lock КАТАЛОГ_ЗЕРКАЛА КАТАЛОГ_РЕЗУЛЬТАТА
#
# Вызывает make ort-build внутри контейнера с --network none (Dockerfile.ml,
# цель ort-toolchain). Хеши файлов зеркала сверяются ещё раз: зеркало могло
# измениться после fetch.sh. В cmake/deps.txt ORT подставляются пути к
# файлам зеркала и их SHA-1 (формат ORT); зависимость не из deps.lock
# остаётся адресом https и без сети не скачивается — ошибка сборки.
# Результат: lib/libonnxruntime.so.1.31.0, include/ (заголовки C API),
# LICENSE и ThirdPartyNotices.txt. Хеш библиотеки сверяет make ort-build.
set -euo pipefail
umask 022
export LC_ALL=C TZ=UTC
# Воспроизводимость: время и пути сборки не попадают в библиотеку.
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}

die() {
	echo "build.sh: $*" >&2
	exit 1
}

[ $# -eq 3 ] || die "использование: build.sh deps.lock КАТАЛОГ_ЗЕРКАЛА КАТАЛОГ_РЕЗУЛЬТАТА"
lock=$(realpath "$1") mirror=$(realpath "$2") out=$3
jobs=${ORT_JOBS:-$(nproc)}
[[ $jobs =~ ^[0-9]+$ ]] || die "ORT_JOBS — число"
# Каталог сборки фиксирован: пути попадают в отладочные строки, а
# -ffile-prefix-map убирает их только при одинаковом начале.
work=${ORT_WORK:-/tmp/aisec-ort}
rm -rf "$work"
mkdir -p "$work" "$out"

declare -A file sha
while IFS=';' read -r name kind src _ want _; do
	case $name in '' | '#'*) continue ;; esac
	case $kind in
	git) f=$mirror/$name.tar ;;
	url) f=$mirror/$(basename "$src") ;;
	*) die "$name: неизвестный вид $kind" ;;
	esac
	[ -f "$f" ] || die "$name: нет файла зеркала $f — сначала make ort-fetch"
	got=$(sha256sum "$f" | cut -d' ' -f1)
	[ "$got" = "$want" ] || die "$name: SHA-256 $got, в deps.lock $want"
	file[$name]=$f
	sha[$name]=$(sha1sum "$f" | cut -d' ' -f1)
done <"$lock"
[ -n "${file[onnxruntime]:-}" ] || die "в deps.lock нет onnxruntime"

tar -xf "${file[onnxruntime]}" -C "$work"
src=$work/onnxruntime
[ "$(cat "$src/VERSION_NUMBER")" = 1.31.0 ] || die "в архиве не ONNX Runtime 1.31.0"

# deps.txt: имя;адрес;SHA-1 — адрес и SHA-1 из зеркала для зависимостей из
# deps.lock, остальные строки без изменений (они не нужны этой сборке).
deps=$src/cmake/deps.txt
tmp=$deps.new
while IFS= read -r line; do
	name=${line%%;*}
	if [[ $line != '#'* && -n ${file[$name]:-} && $name != onnxruntime ]]; then
		echo "$name;${file[$name]};${sha[$name]}"
		unset "file[$name]"
	else
		echo "$line"
	fi
done <"$deps" >"$tmp"
mv "$tmp" "$deps"
unset "file[onnxruntime]"
[ ${#file[@]} -eq 0 ] || die "в deps.txt ORT нет зависимостей: ${!file[*]}"

build=$work/build
# EIGEN_MPL2_ONLY: части Eigen под LGPL не компилируются (ошибка сборки, если
# ORT их использует) — внутри только код MPL-2.0 (ADR-0024).
map="-ffile-prefix-map=$src=/ort/src -ffile-prefix-map=$build=/ort/build -DEIGEN_MPL2_ONLY"
cmake -S "$src/cmake" -B "$build" -G Ninja \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_C_FLAGS="$map" -DCMAKE_CXX_FLAGS="$map" \
	-DCMAKE_SHARED_LINKER_FLAGS="-Wl,--build-id=sha1" \
	-DFETCHCONTENT_TRY_FIND_PACKAGE_MODE=NEVER \
	-DFETCHCONTENT_QUIET=ON \
	-Donnxruntime_BUILD_SHARED_LIB=ON \
	-Donnxruntime_BUILD_UNIT_TESTS=OFF \
	-Donnxruntime_BUILD_BENCHMARKS=OFF \
	-Donnxruntime_ENABLE_PYTHON=OFF \
	-Donnxruntime_USE_TELEMETRY=OFF \
	-Donnxruntime_TELEMETRY_BACKEND=AUTO \
	-Donnxruntime_USE_XNNPACK=OFF \
	-Donnxruntime_USE_KLEIDIAI=OFF \
	-Donnxruntime_DISABLE_EXTERNAL_INITIALIZERS=ON \
	-Donnxruntime_DISABLE_DEVICE_DISCOVERY=ON \
	-Donnxruntime_ENABLE_LTO=OFF
cmake --build "$build" --parallel "$jobs" --target onnxruntime

lib=$build/libonnxruntime.so.1.31.0
[ -f "$lib" ] || die "нет $lib"
strip --strip-unneeded -o "$work/libonnxruntime.so.1.31.0" "$lib"
lib=$work/libonnxruntime.so.1.31.0

# Телеметрии и HTTP-клиента в библиотеке быть не должно (ADR-0024).
for s in mobile.events.data.microsoft.com libcurl mbedtls 'Microsoft.ML.ONNXRuntime.Telemetry'; do
	! grep -aqF "$s" "$lib" || die "в библиотеке найдено «$s»: сборка с телеметрией"
done
# Динамические зависимости — только системные библиотеки (ADR-0024).
needed=$(readelf -d "$lib" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ')
for n in $needed; do
	case $n in
	libc.so.6 | libm.so.6 | libdl.so.2 | libpthread.so.0 | librt.so.1 | libstdc++.so.6 | libgcc_s.so.1 | ld-linux-x86-64.so.2) ;;
	*) die "неожиданная зависимость библиотеки: $n" ;;
	esac
done

rm -rf "${out:?}/lib" "$out/include"
mkdir -p "$out/lib" "$out/include"
install -m 0644 "$lib" "$out/lib/"
install -m 0644 "$src/include/onnxruntime/core/session/onnxruntime_c_api.h" "$out/include/"
install -m 0644 "$src/LICENSE" "$src/ThirdPartyNotices.txt" "$out/"
echo "Динамические зависимости: $needed"
sha256sum "$out/lib/libonnxruntime.so.1.31.0"
