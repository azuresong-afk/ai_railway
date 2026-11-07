#!/bin/sh
# Настройка после установки пакета (ADR-0034, раздел 7). Общий сценарий для
# deb (postinst configure) и rpm (%post): обёртки пакета вызывают его как
#
#   postinst.sh ПАКЕТ install|upgrade
#
# Выполняется от root, поэтому: только фиксированные пути, без сети, без
# чтения файлов из каталогов, куда пишут службы, без chown -R и без перехода
# по символьным ссылкам. Создаёт пользователей, каталоги из раздела 2 ADR и
# /etc/aisec/peers.env, перечитывает юниты. Службы не включает и не
# запускает; миграции не выполняет — это шаги администратора.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
	echo "aisec postinst: $*" >&2
	exit 1
}

[ "$#" -eq 2 ] || die "ожидается: ПАКЕТ install|upgrade"
pkg=$1
action=$2
case "$action" in
install | upgrade) ;;
*) die "неизвестное действие $action" ;;
esac

nologin=$(command -v nologin || echo /usr/sbin/nologin)

# ensure_user ИМЯ — системный пользователь с одноимённой группой, без входа и
# домашнего каталога. Существующий пользователь не меняется.
ensure_user() {
	if ! id -u "$1" >/dev/null 2>&1; then
		useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$nologin" "$1"
		echo "Создан пользователь $1."
	fi
}

# ensure_dir ПУТЬ ВЛАДЕЛЕЦ ГРУППА ПРАВА — каталог с заданными владельцем и
# правами. Символьная ссылка или не каталог на этом месте — ошибка: сценарий
# от root по ней не идёт.
ensure_dir() {
	if [ -L "$1" ] || { [ -e "$1" ] && [ ! -d "$1" ]; }; then
		die "$1 — не каталог или символьная ссылка; проверьте хост"
	fi
	install -d -o "$2" -g "$3" -m "$4" "$1"
}

case "$pkg" in
aisec)
	ensure_user aisec
	ensure_user aisec-gw
	ensure_dir /etc/aisec root root 0755
	ensure_dir /etc/aisec/credentials root root 0700
	ensure_dir /var/lib/aisec root root 0755
	ensure_dir /var/lib/aisec/keys aisec aisec 0700
	ensure_dir /var/lib/aisec/backups aisec aisec 0700
	ensure_dir /var/lib/aisec-gateway root root 0755
	# reg/ и state/ systemd создаёт и сам (StateDirectory=), но регистрация
	# шлюза идёт до первого запуска службы.
	ensure_dir /var/lib/aisec-gateway/reg aisec-gw aisec-gw 0700
	ensure_dir /var/lib/aisec-gateway/state aisec-gw aisec-gw 0700
	# UID и GID шлюза для -peer-uid и -peer-gid анализаторов (SO_PEERCRED):
	# известны только после useradd, поэтому пишутся при каждой настройке.
	tmp=$(mktemp /etc/aisec/.peers.env.XXXXXX)
	{
		echo "# Создаёт postinst пакета aisec: UID и GID шлюза для aisec-ml и aisec-media (SO_PEERCRED). Не редактируйте."
		echo "AISEC_GW_UID=$(id -u aisec-gw)"
		echo "AISEC_GW_GID=$(id -g aisec-gw)"
	} >"$tmp"
	chmod 0644 "$tmp"
	mv -f "$tmp" /etc/aisec/peers.env
	;;
aisec-ml)
	ensure_user aisec-ml
	;;
aisec-media)
	ensure_user aisec-media
	;;
*)
	die "неизвестный пакет $pkg"
	;;
esac

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload
fi

if [ "$action" = upgrade ]; then
	echo "Пакет $pkg обновлён. Службы остановлены и не запускаются автоматически."
	echo "Порядок: шлюзы, затем aisec-cli migrate, сервер, aisec-ml и aisec-media (руководство администратора, «Установка без Docker»)."
fi
exit 0
