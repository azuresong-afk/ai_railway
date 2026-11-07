#!/bin/sh
# Запуск aisec-cli на установке без Docker (ADR-0034, раздел 5). Ставится
# пакетом aisec как /usr/sbin/aisec-cli; только для root.
#
#   sudo aisec-cli migrate
#   sudo aisec-cli init -dir /var/lib/aisec/keys
#   sudo aisec-cli backup -out /var/lib/aisec/backups/…
#
# aisec-cli работает от пользователя aisec во временной службе systemd с
# ограничениями сервера; отличия — /home только для чтения (файлы выпуска
# для verify) и запись в каталоги ключей и копий. Рабочий каталог —
# /var/lib/aisec: пути в аргументах — абсолютные. Пароль владельца схемы
# (db-owner.pgpass) передаётся только этому процессу через LoadCredential=,
# у службы сервера его нет. Остаточный риск (ADR-0034, раздел 5): сервер и
# aisec-cli — один пользователь aisec, и взломанный сервер, пока aisec-cli
# работает, может прочитать его учётные данные через /proc. Аргументы
# передаются aisec-cli как есть, без разбора.
set -eu
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

[ "$(id -u)" -eq 0 ] || {
	echo "aisec-cli: запустите от root (sudo aisec-cli …)" >&2
	exit 1
}

# Имя службы известно заранее, поэтому известен и каталог учётных данных.
unit=aisec-cli-$$
pty=--pipe
[ -t 0 ] && [ -t 1 ] && pty=--pty

exec systemd-run --quiet --wait --collect "$pty" --working-directory=/var/lib/aisec \
	--unit="$unit" \
	--uid=aisec --gid=aisec \
	--property=EnvironmentFile=/etc/aisec/aisec-cli.env \
	--setenv=PGPASSFILE="/run/credentials/$unit.service/db-owner-pgpass" \
	--property=LoadCredential=db-owner-pgpass:/etc/aisec/credentials/db-owner.pgpass \
	--property=UMask=0077 \
	--property=NoNewPrivileges=yes \
	--property=CapabilityBoundingSet= \
	--property=AmbientCapabilities= \
	--property=RestrictSUIDSGID=yes \
	--property=ProtectSystem=strict \
	--property=ProtectHome=read-only \
	--property=ReadWritePaths="/var/lib/aisec/keys /var/lib/aisec/backups" \
	--property=PrivateTmp=yes \
	--property=PrivateDevices=yes \
	--property=DevicePolicy=closed \
	--property=ProtectKernelTunables=yes \
	--property=ProtectKernelModules=yes \
	--property=ProtectKernelLogs=yes \
	--property=ProtectControlGroups=yes \
	--property=ProtectClock=yes \
	--property=ProtectHostname=yes \
	--property=ProtectProc=invisible \
	--property=ProcSubset=pid \
	--property=KeyringMode=private \
	--property=RemoveIPC=yes \
	--property=LockPersonality=yes \
	--property=MemoryDenyWriteExecute=yes \
	--property=RestrictRealtime=yes \
	--property=RestrictNamespaces=yes \
	--property=RestrictAddressFamilies="AF_UNIX AF_INET AF_INET6" \
	--property=SystemCallArchitectures=native \
	--property=SystemCallFilter=@system-service \
	--property="SystemCallFilter=~@privileged @resources" \
	--property=SystemCallErrorNumber=EPERM \
	--property=MemoryMax=512M \
	--property=MemorySwapMax=0 \
	--property=TasksMax=256 \
	/opt/aisec/bin/aisec-cli "$@"
