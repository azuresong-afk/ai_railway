#!/bin/sh
# После удаления пакета (ADR-0034, раздел 7). Общий сценарий для deb (postrm
# remove|purge|upgrade) и rpm (%postun):
#
#   postrm.sh ПАКЕТ remove|purge|upgrade
#
# Остаются всегда: /etc/aisec/credentials (секреты), /var/lib/aisec (ключи и
# копии), /var/lib/aisec-gateway (регистрация и состояние шлюза), журналы
# journald и пользователи (чтобы новый пользователь с тем же UID не получил
# чужие файлы). purge удаляет только peers.env; файлы конфигурации пакета
# удаляет сам менеджер пакетов. Ключи, секреты и данные администратор
# уничтожает явно (руководство администратора, «Установка без Docker»).
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
	echo "aisec postrm: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "ожидается: ПАКЕТ remove|purge|upgrade"
pkg=$1
action=$2
case "$action" in
remove | purge | upgrade) ;;
*) die "неизвестное действие $action" ;;
esac
case "$pkg" in
aisec | aisec-ml | aisec-media) ;;
*) die "неизвестный пакет $pkg" ;;
esac

if [ "$action" = purge ] && [ "$pkg" = aisec ]; then
	# Обычный файл, а не ссылка: удаляется только он сам.
	if [ -f /etc/aisec/peers.env ] && [ ! -L /etc/aisec/peers.env ]; then
		rm -f /etc/aisec/peers.env
	fi
fi

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi

if [ "$action" != upgrade ] && [ "$pkg" = aisec ]; then
	echo "Данные AISec сохранены: /etc/aisec/credentials, /var/lib/aisec, /var/lib/aisec-gateway."
	echo "Удаляйте их только явно (руководство администратора, «Установка без Docker»)."
fi
exit 0
