# Файлы развёртывания: compose/ — стенды разработки и демо, packaging/ — пакеты deb, rpm, systemd (этап 6).

`compose/pilot/` — установка пилота в docker compose ([README](compose/pilot/README.md), ADR-0019); `build/Dockerfile.release` — образы поставки (`make images`), `build/Dockerfile` — сборочный образ.

`time/` — шаблон chrony для хоста (порядок настройки — [`docs/install/time-sync.md`](../docs/install/time-sync.md)).
