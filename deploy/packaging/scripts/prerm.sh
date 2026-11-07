#!/bin/sh
# Перед удалением или обновлением пакета (ADR-0034, раздел 7). Общий
# сценарий для deb (prerm remove|upgrade) и rpm (%preun):
#
#   prerm.sh ПАКЕТ remove|upgrade
#
# Останавливает службы пакета в обоих случаях: при обновлении иначе
# самопроверка целостности работающих процессов сочла бы заменённые файлы
# нарушением, а aisec-media с integrity-action=stop перезапустился бы новым
# бинарником раньше шлюза. При удалении службы ещё и выключаются. Данные,
# ключи и настройки не трогает.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
	echo "aisec prerm: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "ожидается: ПАКЕТ remove|upgrade"
pkg=$1
action=$2
case "$action" in
remove | upgrade) ;;
*) die "неизвестное действие $action" ;;
esac

case "$pkg" in
aisec) units="aisec-gateway.service aisec-server.service" ;;
aisec-ml) units="aisec-ml.service" ;;
aisec-media) units="aisec-media.service" ;;
*) die "неизвестный пакет $pkg" ;;
esac

# Без работающего systemd (сборка образа, chroot) останавливать нечего.
[ -d /run/systemd/system ] || exit 0

for u in $units; do
	if ! systemctl stop "$u"; then
		# При обновлении файлы под работающей службой не меняются.
		[ "$action" = remove ] || die "не удалось остановить $u — обновление прервано, проверьте systemctl status $u"
		echo "aisec prerm: не удалось остановить $u — проверьте systemctl status $u" >&2
	fi
	if [ "$action" = remove ]; then
		systemctl disable "$u" >/dev/null 2>&1 || true
	fi
done
exit 0
