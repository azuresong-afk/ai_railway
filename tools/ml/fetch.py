#!/usr/bin/env python3
"""Скачивание моделей и наборов данных с Hugging Face по tools/ml/sources.json.

Только для разработки, в поставку не входит. Единственный шаг tools/ml с
сетью (make ml-fetch). Файлы кладутся в build/ml/src/<name>/ и сверяются с
SHA-256 из sources.json; несовпадение — ошибка, файл удаляется.

Первый запуск (make ml-fetch ML_LOCK=1): у источников без revision берётся
текущий коммит ветки main, скачиваются файлы по шаблонам patterns, их SHA-256
и коммит записываются в sources.json. Этот файл фиксируется в репозитории
(git diff tools/ml/sources.json покажет, что именно записано), и дальше
make ml-fetch скачивает ровно эти файлы этого коммита.
"""

import argparse
import fnmatch
import os
import shutil
import sys

import common

# Предел одного файла: модель до 2 ГиБ, как у пакета моделей aisec-ml.
MAX_FILE = 2 << 30


def list_files(api, src, kind):
    info = (api.model_info if kind == "models" else api.dataset_info)(src["repo"], revision="main", files_metadata=True)
    names = []
    for s in info.siblings:
        if any(fnmatch.fnmatch(s.rfilename, p) for p in src["patterns"]):
            if s.size is not None and s.size > MAX_FILE:
                common.die(f"{src['repo']}: {s.rfilename} больше {MAX_FILE} байт")
            names.append(s.rfilename)
    # Веса: safetensors предпочтительнее pickle (pytorch_model.bin).
    if "model.safetensors" in names and "pytorch_model.bin" in names:
        names.remove("pytorch_model.bin")
    if not names:
        common.die(f"{src['repo']}: нет файлов по шаблонам {src['patterns']}; файлы репозитория: "
                   + ", ".join(s.rfilename for s in info.siblings[:40]))
    return info.sha, sorted(names)


def download(src, kind, name, revision):
    from huggingface_hub import hf_hub_download

    dest = os.path.join(common.SRC, src["name"])
    path = hf_hub_download(src["repo"], name, repo_type="model" if kind == "models" else "dataset",
                           revision=revision, local_dir=dest)
    if os.path.getsize(path) > MAX_FILE:
        os.remove(path)
        common.die(f"{src['repo']}: {name} больше {MAX_FILE} байт")
    return path


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--lock", action="store_true", help="зафиксировать коммит и хеши у источников без revision")
    ap.add_argument("--only", nargs="*", default=[], help="только эти источники (name)")
    args = ap.parse_args()
    common.no_telemetry()
    from huggingface_hub import HfApi

    api = HfApi()
    data = common.load_sources()
    changed = False
    for kind in ("models", "datasets"):
        for src in data[kind]:
            if args.only and src["name"] not in args.only:
                continue
            if not src.get("revision"):
                if not args.lock:
                    common.die(f"{src['name']}: ревизия не зафиксирована — первый запуск: make ml-fetch ML_LOCK=1")
                rev, names = list_files(api, src, kind)
                files = {}
                for n in names:
                    files[n] = common.sha256_file(download(src, kind, n, rev))
                src["revision"], src["files"] = rev, files
                changed = True
                print(f"{src['name']}: зафиксирован коммит {rev}, файлов {len(files)}")
                continue
            for n, want in sorted(src["files"].items()):
                p = download(src, kind, n, src["revision"])
                got = common.sha256_file(p)
                if got != want:
                    os.remove(p)
                    common.die(f"{src['name']}/{n}: SHA-256 {got}, ожидался {want} — файл удалён")
            # Лишних файлов в каталоге источника быть не должно.
            dest = os.path.join(common.SRC, src["name"])
            for root, _, fs in os.walk(dest):
                for f in fs:
                    rel = os.path.relpath(os.path.join(root, f), dest).replace(os.sep, "/")
                    if rel not in src["files"] and not rel.startswith(".cache/"):
                        common.die(f"{src['name']}: лишний файл {rel} — удалите каталог {dest} и повторите")
            shutil.rmtree(os.path.join(dest, ".cache"), ignore_errors=True)
            print(f"{src['name']}: {len(src['files'])} файлов, SHA-256 совпадают")
    if changed:
        common.write_json(common.SOURCES, data)
        print("\nЗаписан tools/ml/sources.json: передайте его в репозиторий (git diff tools/ml/sources.json).")
    common.ok("модели и наборы в build/ml/src/")


if __name__ == "__main__":
    sys.exit(main())
