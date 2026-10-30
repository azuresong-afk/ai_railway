#!/usr/bin/env python3
"""Обучающий набор pii.ner из нашей синтетики и factRuEval-2016 (задача 4.20).

Только для разработки, в поставку не входит; без сети, только стандартная
библиотека. Читает:
  build/ml/data/ner-synth.jsonl — синтетика tools/synth-pii -kind ner -split
      train -format spans (вымышленные люди, организации, адреса);
  build/ml/src/factrueval-2016/ — factRuEval-2016 (make ml-fetch): devset —
      обучение, testset — проверка на живом тексте (в обучение не идёт).
      Источник вносится в sources.json после согласия владельца (ADR-0024,
      дополнение 4.20); пока его нет, набор — только синтетика, и
      stats.json это показывает (factru: false).
Пишет build/ml/data/ner/: train.jsonl, dev.jsonl (10% каждого источника —
выбор эпохи), check-factru.jsonl (testset factRuEval), stats.json (сколько
примеров и сущностей из какого источника — для ML-BOM).

Строка: {"text": ..., "entities": [[начало, конец, метка], ...], "source": ...};
границы — в символах. Метки: per, org, loc, addr. В factRuEval Person → per,
Org → org, Location и LocOrg → loc; Facility и Project не размечаются;
из вложенных сущностей берётся внешняя (самая длинная).

Проверочный корпус testdata/corpus/pii.ner в обучение не попадает: его
словари не пересекаются со словарями обучения (tools/synth-pii, проверено
тестом), а совпадающие тексты дополнительно удаляются.
"""

import argparse
import glob
import json
import os
import random
import re

import common

SEED = 4200
FACTRU = "factrueval-2016"
SYNTH = "synthetic-ru-ner"
FACTRU_TYPES = {"Person": "per", "Org": "org", "Location": "loc", "LocOrg": "loc"}
MAX_CHARS = 600  # длина части документа factRuEval (окно обучения — 256 токенов)


def factru_docs(root):
    """Документы factRuEval: текст и сущности [начало, конец, метка] в символах."""
    docs = []
    for txt in sorted(glob.glob(os.path.join(root, "book_*.txt"))):
        base = txt[:-4]
        with open(txt, encoding="utf-8") as f:
            text = f.read()
        spans = {}
        with open(base + ".spans", encoding="utf-8") as f:
            for line in f:
                head = line.split("#", 1)[0].split()
                if len(head) >= 4:
                    spans[head[0]] = (int(head[2]), int(head[2]) + int(head[3]))
        ents = []
        with open(base + ".objects", encoding="utf-8") as f:
            for line in f:
                head = line.split("#", 1)[0].split()
                if len(head) < 3 or head[1] not in FACTRU_TYPES:
                    continue
                parts = [spans[s] for s in head[2:] if s in spans]
                if not parts:
                    continue
                s, e = min(p[0] for p in parts), max(p[1] for p in parts)
                if 0 <= s < e <= len(text):
                    ents.append([s, e, FACTRU_TYPES[head[1]]])
        docs.append((os.path.basename(base), text, outermost(ents)))
    if not docs:
        common.die(f"нет документов factRuEval в {root} — сначала make ml-fetch")
    return docs


def outermost(ents):
    """Без вложенных и пересекающихся: длинные первыми, затем по началу."""
    out = []
    for s, e, lab in sorted(ents, key=lambda x: (-(x[1] - x[0]), x[0])):
        if all(e <= a or s >= b for a, b, _ in out):
            out.append([s, e, lab])
    return sorted(out)


def chunks(text, ents):
    """Части документа не длиннее MAX_CHARS по границам предложений вне
    сущностей; границы сущностей пересчитываются."""
    inside = [False] * (len(text) + 1)
    for s, e, _ in ents:
        for i in range(s + 1, e):
            inside[i] = True
    cuts = [m.end() for m in re.finditer(r"[.!?…]\s+|\n+", text) if not inside[m.end()]]
    out, start = [], 0
    for c in cuts + [len(text)]:
        if c - start >= MAX_CHARS or c == len(text):
            part = text[start:c]
            lead = len(part) - len(part.lstrip())
            body = part.strip()
            if body:
                off = start + lead
                es = [[s - off, e - off, lab] for s, e, lab in ents if s >= off and e <= off + len(body)]
                out.append({"text": body, "entities": es})
            start = c
    return out


def norm(t):
    return " ".join(re.findall(r"\w+", t.lower().replace("ё", "е")))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--synthetic", default=os.path.join(common.BUILD, "data", "ner-synth.jsonl"))
    ap.add_argument("--factru", default=os.path.join(common.SRC, FACTRU))
    ap.add_argument("--validation", default=os.path.join(common.ROOT, "testdata", "corpus", "pii.ner"))
    ap.add_argument("--out", default=os.path.join(common.BUILD, "data", "ner"))
    ap.add_argument("--factru-repeat", type=int, default=3,
                    help="сколько раз повторить части factRuEval в обучении: живого текста в 15 раз меньше синтетики")
    args = ap.parse_args()

    if not os.path.exists(args.synthetic):
        common.die(f"нет {args.synthetic} — make ml-train создаёт его через tools/synth-pii")
    synth = [{"text": r["text"], "entities": r["entities"], "source": SYNTH} for r in common.read_jsonl(args.synthetic)]
    fr_train, fr_check = [], []
    if os.path.isdir(args.factru):
        fr_train = [dict(c, source=FACTRU) for _, t, es in factru_docs(os.path.join(args.factru, "devset")) for c in chunks(t, es)]
        fr_check = [dict(c, source=FACTRU) for _, t, es in factru_docs(os.path.join(args.factru, "testset")) for c in chunks(t, es)]
    else:
        print(f"внимание: нет {os.path.relpath(args.factru, common.ROOT)} — factRuEval не скачан (ADR-0024), "
              "обучение только на синтетике, проверки на живом тексте не будет")
    print(f"синтетика: {len(synth)}, factRuEval devset: {len(fr_train)} частей, testset: {len(fr_check)} частей")

    val = {norm(r["text"]) for p in sorted(glob.glob(os.path.join(args.validation, "*.jsonl"))) for r in common.read_jsonl(p)}
    if not val:
        common.die(f"нет проверочного корпуса {args.validation}")
    check = {norm(r["text"]) for r in fr_check}
    train, dev, uniq, leaked = [], [], [], 0
    rnd = random.Random(SEED)
    for rows, repeat in ((synth, 1), (fr_train, max(1, args.factru_repeat))):
        if not rows:
            continue
        kept = []
        for r in rows:
            n = norm(r["text"])
            if n in val or n in check:
                leaked += 1
                continue
            kept.append(r)
        rnd.shuffle(kept)
        k = max(1, len(kept) // 10)
        dev += kept[:k]
        train += kept[k:] * repeat
        uniq += kept
    rnd.shuffle(train)
    common.write_jsonl(os.path.join(args.out, "train.jsonl"), train)
    common.write_jsonl(os.path.join(args.out, "dev.jsonl"), dev)
    common.write_jsonl(os.path.join(args.out, "check-factru.jsonl"), fr_check)
    stats = {"seed": SEED, "factru": bool(fr_train), "train": len(train), "dev": len(dev), "check_factru": len(fr_check),
             "removed_same_as_check": leaked, "factru_repeat": args.factru_repeat, "by_source": {}}
    for r in uniq:  # без повторов factRuEval
        s = stats["by_source"].setdefault(r["source"], {"examples": 0})
        s["examples"] += 1
        for _, _, lab in r["entities"]:
            s[lab] = s.get(lab, 0) + 1
    common.write_json(os.path.join(args.out, "stats.json"), stats)
    print(json.dumps(stats["by_source"], ensure_ascii=False, indent=1))
    common.ok(f"набор pii.ner: обучение {len(train)}, проверка эпох {len(dev)}, проверка factRuEval {len(fr_check)} "
              f"-> {os.path.relpath(args.out, common.ROOT)}")


if __name__ == "__main__":
    main()
