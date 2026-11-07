#!/bin/sh
# Проверка юнитов и сценариев установки без Docker (ADR-0034, задача 6.16):
# цель make packaging-check. Ничего не устанавливает и не запускает службы.
#
#   1. tools/imagecheck units — ограничения юнитов и сверка списка системных
#      вызовов aisec-media с seccomp/aisec-media.json (то же — в make test);
#   2. systemd-analyze verify и security --offline по каждому юниту во
#      временном корне с заглушками бинарников (если systemd-analyze есть);
#   3. сценарии — shellcheck, если есть, иначе sh -n и dash -n.
#
# Запуск юнитов, LoadCredential=, RootDirectory= и пределы на целевых ОС —
# ручная проверка 7 в docs/pilot/manual-checks.md и e2e 6.17.
set -eu
cd "$(dirname "$0")/../.."

pkg=deploy/packaging
units="aisec-server aisec-gateway aisec-ml aisec-media"
fail=0

echo "== imagecheck units"
go run ./tools/imagecheck units "$pkg/systemd" deploy/compose/pilot/seccomp/aisec-media.json || fail=1

if command -v systemd-analyze >/dev/null 2>&1; then
	root=$(mktemp -d)
	trap 'rm -rf "$root"' EXIT INT TERM
	mkdir -p "$root/etc/systemd/system" "$root/usr/lib/systemd" "$root/opt/aisec/bin"
	# Цели и юниты systemd хоста — для зависимостей (multi-user.target).
	cp -R /usr/lib/systemd/system "$root/usr/lib/systemd/"
	cp -R "$pkg/systemd/." "$root/etc/systemd/system/"
	# verify ищет ExecStart= от --root, не учитывая RootDirectory=: заглушки
	# всех бинарников кладутся в /opt/aisec/bin временного корня.
	for b in aisec-server aisec-gateway aisec-cli aisec-ml aisec-media; do
		printf '#!/bin/true\n' >"$root/opt/aisec/bin/$b"
		chmod 0755 "$root/opt/aisec/bin/$b"
	done
	for u in $units; do
		echo "== systemd-analyze verify $u.service"
		(cd "$root/etc/systemd/system" && systemd-analyze verify --man=no --root="$root" "$u.service") || fail=1
		echo "== systemd-analyze security $u.service"
		# Порог 1.5 (шкала --threshold — десятые доли): сейчас 1.2 у сервера и
		# шлюза и 0.6 у анализаторов; рост — ослабление юнита.
		out=$(cd "$root/etc/systemd/system" && systemd-analyze security --offline=yes --root="$root" --threshold=15 "$u.service") || fail=1
		printf '%s\n' "$out" | tail -n 1
	done
	# Список @default, который юнит aisec-media получает сверх профиля Docker,
	# совпадает с перечнем в tools/imagecheck/systemd.go (systemdDefaultSyscalls).
	echo "== systemd-analyze syscall-filter @default"
	got=$(systemd-analyze syscall-filter @default | sed -n 's/^    \([a-z_0-9]*\)$/\1/p' | sort | tr '\n' ' ')
	known=$(sed -n '/^var systemdDefaultSyscalls/,/^}/p' tools/imagecheck/systemd.go | grep -o '"[a-z_0-9]*"' | tr -d '"' | sort | tr '\n' ' ')
	for n in $got; do
		case " $known " in
		*" $n "*) ;;
		*)
			# Вызовы других архитектур (32-битные, riscv, cacheflush) на x86-64 не действуют.
			case "$n" in
			*32 | *time64 | riscv_* | cacheflush | sigreturn | ugetrlimit | mmap2 | set_tls) ;;
			*) echo "@default systemd содержит $n, которого нет в systemdDefaultSyscalls"; fail=1 ;;
			esac
			;;
		esac
	done
else
	echo "== systemd-analyze нет: verify и security пропущены (ручная проверка 7)"
fi

echo "== сценарии"
for f in "$pkg"/scripts/*.sh "$pkg"/check.sh; do
	if command -v shellcheck >/dev/null 2>&1; then
		shellcheck -s sh "$f" || fail=1
	else
		sh -n "$f" || fail=1
		if command -v dash >/dev/null 2>&1; then
			dash -n "$f" || fail=1
		fi
	fi
done
command -v shellcheck >/dev/null 2>&1 || echo "shellcheck нет: только sh -n и dash -n"

[ "$fail" -eq 0 ] || {
	echo "packaging-check: есть нарушения"
	exit 1
}
echo "packaging-check: нарушений нет"
