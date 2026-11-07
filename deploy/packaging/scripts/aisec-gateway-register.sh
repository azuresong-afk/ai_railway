#!/bin/sh
# Регистрация шлюза на установке без Docker (ADR-0034, раздел 7). Ставится
# пакетом aisec как /usr/sbin/aisec-gateway-register; только для root.
#
#   sudo aisec-gateway-register https://ИМЯ_КОНСОЛИ:8444
#
# Токен (aisec-cli gateway token) вводится без отображения и не попадает
# ни в аргументы, ни в историю оболочки. aisec-gateway register работает от
# пользователя aisec-gw и пишет сертификат, ключ и ключ секретов пакета в
# /var/lib/aisec-gateway/reg и state (0700 aisec-gw). Корень консоли берётся
# из /etc/aisec/credentials/console-ca.crt: это открытый сертификат, шлюзу
# передаётся его копия во временном каталоге.
set -eu
umask 077
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

die() {
	echo "aisec-gateway-register: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "запустите от root (sudo aisec-gateway-register https://ИМЯ_КОНСОЛИ:8444)"
[ "$#" -eq 1 ] || die "ожидается адрес консоли: https://ИМЯ_КОНСОЛИ:8444"
case "$1" in
https://*) ;;
*) die "адрес консоли должен начинаться с https://" ;;
esac
ca=/etc/aisec/credentials/console-ca.crt
[ -f "$ca" ] && [ ! -L "$ca" ] || die "нет $ca — положите корень, которым шлюз проверяет консоль"
[ -t 0 ] || die "токен вводится с терминала"

tmp=$(mktemp -d)
trap 'stty echo 2>/dev/null; rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM
# Каталог остаётся у root (0711): aisec-gw только читает копию корня.
install -m 0644 "$ca" "$tmp/console-ca.crt"
chmod 0711 "$tmp"

printf 'Токен регистрации шлюза (ввод не отображается): '
stty -echo
IFS= read -r token || token=
stty echo
echo
[ -n "$token" ] || die "пустой токен"
AISEC_GATEWAY_REGISTRATION_TOKEN=$token
export AISEC_GATEWAY_REGISTRATION_TOKEN
unset token

runuser -u aisec-gw -- /opt/aisec/bin/aisec-gateway register \
	-console "$1" -console-ca "$tmp/console-ca.crt" \
	-out-dir /var/lib/aisec-gateway/reg -state-dir /var/lib/aisec-gateway/state </dev/null
