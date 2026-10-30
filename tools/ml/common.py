"""Общее для скриптов tools/ml (задачи 4.19, 4.20): пути, хеши, JSONL.

Только для разработки, в поставку не входит. Скрипты запускаются из корня
репозитория целями make (docs/cert/build-env.md, раздел «Модели»).
"""

import hashlib
import json
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
# AISEC_ML_SOURCES — другой файл источников (проверка скриптов на игрушечных данных).
SOURCES = os.environ.get("AISEC_ML_SOURCES") or os.path.join(ROOT, "tools", "ml", "sources.json")
BUILD = os.path.join(ROOT, "build", "ml")
SRC = os.path.join(BUILD, "src")

# ID модели и метки — как в протоколе aisec-ml (internal/ml/messages.go).
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


def offline():
    """Запрещает сетевые обращения библиотекам Hugging Face: после make
    ml-fetch всё берётся только с диска."""
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["HF_DATASETS_OFFLINE"] = "1"
    no_telemetry()


def no_telemetry():
    os.environ["HF_HUB_DISABLE_TELEMETRY"] = "1"
    os.environ["HF_HUB_DISABLE_IMPLICIT_TOKEN"] = "1"
    os.environ["DO_NOT_TRACK"] = "1"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_sources():
    with open(SOURCES, encoding="utf-8") as f:
        return json.load(f)


def source(name):
    for kind in ("models", "datasets"):
        for s in load_sources()[kind]:
            if s["name"] == name:
                return s
    die(f"в {SOURCES} нет источника {name}")


def read_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write("\n")


def die(msg):
    print("ОШИБКА: " + msg, file=sys.stderr)
    sys.exit(1)


def ok(msg):
    print("ГОТОВО: " + msg)
