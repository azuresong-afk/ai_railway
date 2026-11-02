"""Загрузка моделей кандидатов OCR по tools/ocr-eval/models.json (задача 5.40).

Только инструмент разработки. Файл сохраняется, только если SHA-256
совпал с models.json; иначе пробуется следующий источник, а при неудаче —
ошибка. Уже скачанный файл с верным хешем не скачивается заново.
"""

import argparse
import hashlib
import io
import json
import pathlib
import urllib.request
import zipfile

MAX_BYTES = 64 << 20  # больше моделей кандидатов не бывает
TIMEOUT = 120


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def get(url):
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:  # noqa: S310 — адреса только из models.json (https)
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{url}: больше {MAX_BYTES} байт")
    return data


def fetch(entry):
    if "wheel" in entry:
        w = entry["wheel"]
        whl = get(w["url"])
        if sha256(whl) != w["sha256"]:
            raise ValueError(f"{w['url']}: SHA-256 колеса не совпадает")
        with zipfile.ZipFile(io.BytesIO(whl)) as z:
            return z.read(w["member"])
    errors = []
    for url in entry["urls"]:
        if not url.startswith("https://"):
            errors.append(f"{url}: только https")
            continue
        try:
            data = get(url)
        except (OSError, ValueError) as e:
            errors.append(f"{url}: {e}")
            continue
        if sha256(data) == entry["sha256"]:
            return data
        errors.append(f"{url}: SHA-256 не совпадает")
    raise ValueError("; ".join(errors))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-list", default=str(pathlib.Path(__file__).with_name("models.json")))
    ap.add_argument("-out", required=True)
    a = ap.parse_args()
    out = pathlib.Path(a.out)
    for entry in json.loads(pathlib.Path(a.list).read_text(encoding="utf-8"))["files"]:
        path = out / entry["name"]
        if path.exists() and sha256(path.read_bytes()) == entry["sha256"]:
            print("есть:", entry["name"])
            continue
        data = fetch(entry)
        if sha256(data) != entry["sha256"]:
            raise SystemExit(f"{entry['name']}: SHA-256 не совпадает")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print("скачан:", entry["name"])


if __name__ == "__main__":
    main()
