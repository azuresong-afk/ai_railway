#!/usr/bin/env python3
"""Обучающий набор injection.ml из скачанных наборов и нашей синтетики.

Только для разработки, в поставку не входит; без сети. Читает наборы
build/ml/src/<name>/ (parquet, jsonl, csv), синтетику
testdata/ml/injection-train/*.jsonl и пишет build/ml/data/injection/:
train.jsonl, dev.jsonl (10% — для выбора эпохи) и stats.json (сколько
примеров из какого источника — для ML-BOM).

Проверочный корпус testdata/corpus/injection.ml/ в обучение не попадает:
тексты, совпадающие с проверочными или похожие на них (сходство триграмм
слов от 0,5), удаляются, их число печатается.
"""

import argparse
import glob
import json
import os
import random
import re

import common

SEED = 4190
BENIGN, INJECTION = "benign", "injection"
TEXT_CANDIDATES = ["text", "prompt", "input", "query", "content", "sentence", "instruction"]
LABEL_CANDIDATES = ["label", "is_injection", "injection", "is_malicious", "malicious", "type", "category", "class"]
POS_VALUES = {"1", "true", "injection", "prompt_injection", "jailbreak", "malicious", "attack", "unsafe", "harmful"}
NEG_VALUES = {"0", "false", "benign", "safe", "legit", "legitimate", "normal", "clean"}
MAX_TEXT = 8000  # символов; длиннее — обрезается (обучение идёт на окне 256 токенов)


def read_table(path):
    import pyarrow.csv as pacsv
    import pyarrow.json as pajson
    import pyarrow.parquet as pq

    if path.endswith(".parquet"):
        return pq.read_table(path).to_pylist()
    if path.endswith(".csv"):
        return pacsv.read_csv(path).to_pylist()
    if path.endswith(".jsonl") or path.endswith(".json"):
        return pajson.read_json(path).to_pylist()
    common.die(f"{path}: неизвестный формат")


def pick(cols, configured, candidates, what, name):
    if configured:
        if configured not in cols:
            common.die(f"{name}: нет поля {configured}; поля: {sorted(cols)}")
        return configured
    for c in candidates:
        if c in cols:
            print(f"{name}: поле {what} — {c} (выбрано автоматически)")
            return c
    common.die(f"{name}: не найдено поле {what}; поля: {sorted(cols)} — укажите {what}_field в tools/ml/sources.json")


def label_of(v, name):
    s = str(v).strip().lower()
    if s in POS_VALUES:
        return INJECTION
    if s in NEG_VALUES:
        return BENIGN
    common.die(f"{name}: неизвестное значение метки {v!r} — допишите его в POS_VALUES или NEG_VALUES tools/ml/prepare.py")


def load_dataset(src):
    name = src["name"]
    files = []
    for rel in sorted(src.get("files", {})):
        p = os.path.join(common.SRC, name, rel)
        if not os.path.exists(p):
            common.die(f"{name}: нет {p} — сначала make ml-fetch")
        if rel.endswith((".parquet", ".csv", ".jsonl", ".json")):
            files.append(p)
    rows = []
    for p in files:
        rows += read_table(p)
    if not rows:
        common.die(f"{name}: пусто")
    cols = set(rows[0].keys())
    tf = pick(cols, src.get("text_field"), TEXT_CANDIDATES, "text", name)
    lf = None if src.get("benign_only") else pick(cols, src.get("label_field"), LABEL_CANDIDATES, "label", name)
    flt = src.get("filter", {})
    out = []
    for r in rows:
        if any((r.get(k) not in v) if isinstance(v, list) else (r.get(k) != v) for k, v in flt.items()):
            continue
        t = r.get(tf)
        if not isinstance(t, str) or not t.strip():
            continue
        out.append({"text": t[:MAX_TEXT], "label": BENIGN if lf is None else label_of(r.get(lf), name),
                    "source": name, "lang": r.get("lang") or ""})
    rnd = random.Random(SEED)
    rnd.shuffle(out)
    if src.get("limit"):
        out = out[: src["limit"]]
    return out


WORD = re.compile(r"\w+", re.UNICODE)


def norm(t):
    return " ".join(WORD.findall(t.lower().replace("ё", "е")))


def trigrams(t):
    w = norm(t).split()
    return {tuple(w[i:i + 3]) for i in range(max(1, len(w) - 2))}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(common.BUILD, "data", "injection"))
    ap.add_argument("--validation", default=os.path.join(common.ROOT, "testdata", "corpus", "injection.ml"))
    ap.add_argument("--synthetic", default=os.path.join(common.ROOT, "testdata", "ml", "injection-train"))
    args = ap.parse_args()

    rows = []
    for src in common.load_sources()["datasets"]:
        if src.get("task", "injection") != "injection":  # наборы pii.ner — prepare_ner.py
            continue
        part = load_dataset(src)
        print(f"{src['name']}: {len(part)} примеров")
        rows += part
    for p in sorted(glob.glob(os.path.join(args.synthetic, "*.jsonl"))):
        part = [{"text": r["text"], "label": INJECTION if r["expect"] else BENIGN, "source": "synthetic-ru",
                 "lang": r.get("lang", "")} for r in common.read_jsonl(p)]
        print(f"{os.path.relpath(p, common.ROOT)}: {len(part)} примеров")
        rows += part

    # Проверочный корпус не участвует в обучении.
    val = [r["text"] for p in sorted(glob.glob(os.path.join(args.validation, "*.jsonl"))) for r in common.read_jsonl(p)]
    if not val:
        common.die(f"нет проверочного корпуса {args.validation}")
    val_norm = {norm(t) for t in val}
    val_tri = [trigrams(t) for t in val]
    index = {}
    for i, tg in enumerate(val_tri):
        for g in tg:
            index.setdefault(g, set()).add(i)
    seen, kept, leaked, dups = set(), [], 0, 0
    for r in rows:
        n = norm(r["text"])
        if not n or n in seen:
            dups += 1
            continue
        seen.add(n)
        if n in val_norm:
            leaked += 1
            continue
        tg = trigrams(r["text"])
        cand = set().union(*(index.get(g, set()) for g in tg)) if tg else set()
        if any(len(tg & val_tri[i]) / len(tg | val_tri[i]) >= 0.5 for i in cand):
            leaked += 1
            continue
        kept.append(r)
    print(f"повторы: {dups}; похожие на проверочный корпус и удалённые: {leaked}")

    rnd = random.Random(SEED)
    rnd.shuffle(kept)
    by_label = {BENIGN: [r for r in kept if r["label"] == BENIGN], INJECTION: [r for r in kept if r["label"] == INJECTION]}
    if not by_label[INJECTION] or not by_label[BENIGN]:
        common.die("в наборе нет одного из классов")
    train, dev = [], []
    for lab, rs in by_label.items():
        k = max(1, len(rs) // 10)
        dev += rs[:k]
        train += rs[k:]
    rnd.shuffle(train)
    rnd.shuffle(dev)
    common.write_jsonl(os.path.join(args.out, "train.jsonl"), train)
    common.write_jsonl(os.path.join(args.out, "dev.jsonl"), dev)
    stats = {"seed": SEED, "train": len(train), "dev": len(dev), "removed_similar_to_validation": leaked,
             "by_source": {}}
    for r in train + dev:
        s = stats["by_source"].setdefault(r["source"], {BENIGN: 0, INJECTION: 0})
        s[r["label"]] += 1
    common.write_json(os.path.join(args.out, "stats.json"), stats)
    print(json.dumps(stats["by_source"], ensure_ascii=False, indent=1))
    common.ok(f"обучающий набор {len(train)}, проверка эпох {len(dev)} -> {os.path.relpath(args.out, common.ROOT)}")


if __name__ == "__main__":
    main()
