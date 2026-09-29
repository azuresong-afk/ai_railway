#!/usr/bin/env bash
# Прогон всех fuzz-целей репозитория (ТЗ, 8.5).
# Использование: tools/scripts/fuzz.sh <время на цель, например 10s или 10m>
# Go запускает за один вызов только одну fuzz-цель, поэтому цели
# перебираются по пакетам. Найденные падения Go сохраняет в
# testdata/fuzz/<цель>/ каталога пакета — их нужно закоммитить.
set -euo pipefail

fuzztime="${1:?укажите время на цель, например 10s}"
total=0

while IFS= read -r pkg; do
	# go test -list печатает имена целей и строку "ok ..." в конце.
	targets="$(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true)"
	for t in $targets; do
		echo "fuzz: $pkg $t ($fuzztime)"
		go test -run='^$' -fuzz="^${t}\$" -fuzztime="$fuzztime" "$pkg"
		total=$((total + 1))
	done
done < <(go list ./...)

if [ "$total" -eq 0 ]; then
	echo "fuzz: не найдено ни одной fuzz-цели" >&2
	exit 1
fi
echo "fuzz: прогнано целей: $total"
