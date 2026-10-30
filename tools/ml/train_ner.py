#!/usr/bin/env python3
"""Дообучка rubert-tiny2 на разметку токенов для pii.ner (задача 4.20).

Только для разработки, в поставку не входит; без сети, на процессоре.
Берёт основу build/ml/src/rubert-tiny2 и набор build/ml/data/ner
(prepare_ner.py), учит разметку по схеме BIO (метки LABELS — как в пакете
моделей aisec-ml) и сохраняет лучшую по проверке эпох модель в
build/ml/train/pii-ner-ru вместе с отчётом train_report.json (параметры,
версии, метрики по сущностям на проверке эпох и на testset factRuEval — для
ML-BOM и docs/detectors.md).

Метки ставятся всем кускам слова: первому куску сущности — «b-», остальным —
«i-»; служебные токены в потерю не входят. Фрагменты из меток собираются
так же, как в aisec-ml (internal/ml/ner.go, MergeTokens): метрики считаются
по тем фрагментам, которые увидит шлюз.

Результат воспроизводим: фиксированный seed, детерминированные алгоритмы
torch, один и тот же порядок примеров. Время — порядка получаса на 4–8 ядрах.
"""

import argparse
import json
import os
import platform
import random
import time

import common

ENTITIES = ["per", "org", "loc", "addr"]
LABELS = ["o"] + [p + e for e in ENTITIES for p in ("b-", "i-")]
# Сущности, которые дают находки pii.ner (loc — нет): по ним выбирается эпоха.
PII = ["per", "org", "addr"]
MAX_SPAN_CHARS = 512  # как ml.MaxSpanBytes (в байтах; для оценки — в символах, с запасом)


def token_labels(offsets, entities):
    """Номера меток токенов по сущностям: первый токен, задевающий сущность, —
    «b-», следующие — «i-»; служебные токены (пустые границы) — -100."""
    out, started = [], set()
    for s, e in offsets:
        if e <= s:
            out.append(-100)
            continue
        lab = "o"
        for k, (es, ee, el) in enumerate(entities):
            if s < ee and e > es:
                lab = ("i-" if k in started else "b-") + el
                started.add(k)
                break
        out.append(LABELS.index(lab))
    return out


def aligned(offsets, entities):
    """Сущности по границам токенов (как их может найти модель); сущность за
    пределами окна (обрезка) не считается."""
    out = set()
    for es, ee, el in entities:
        ts = [(s, e) for s, e in offsets if e > s and s < ee and e > es]
        if ts:
            out.add((el, ts[0][0], ts[-1][1]))
    return out


def merge(tokens):
    """Фрагменты из токенов (метка, начало, конец) — как MergeTokens в aisec-ml."""
    out, cur, pos = [], None, 0
    for lab, s, e in tokens:
        if lab == "o" or e <= s or s < pos:
            cur = None
            pos = max(pos, e)
            continue
        pos = e
        begin = lab.startswith("b-")
        ent = lab[2:] if lab[:2] in ("b-", "i-") else lab
        if cur is not None and cur[0] == ent and e - cur[1] <= MAX_SPAN_CHARS and (not begin or s == cur[2]):
            cur[2] = e
            continue
        cur = [ent, s, e]
        out.append(cur)
    return {(a, b, c) for a, b, c in out}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=os.path.join(common.SRC, "rubert-tiny2"))
    ap.add_argument("--data", default=os.path.join(common.BUILD, "data", "ner"))
    ap.add_argument("--out", default=os.path.join(common.BUILD, "train", "pii-ner-ru"))
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--max-len", type=int, default=256, help="токенов на пример при обучении")
    ap.add_argument("--seed", type=int, default=4200)
    ap.add_argument("--threads", type=int, default=0, help="потоков torch; 0 — по числу ядер")
    ap.add_argument("--limit", type=int, default=0, help="только первые N примеров (проверка скрипта)")
    args = ap.parse_args()
    common.offline()

    import numpy as np
    import torch
    import transformers
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if args.threads:
        torch.set_num_threads(args.threads)

    train = common.read_jsonl(os.path.join(args.data, "train.jsonl"))
    dev = common.read_jsonl(os.path.join(args.data, "dev.jsonl"))
    check = common.read_jsonl(os.path.join(args.data, "check-factru.jsonl"))
    if args.limit:
        train, dev, check = train[: args.limit], dev[: max(8, args.limit // 10)], check[: max(8, args.limit // 10)]
    tok = AutoTokenizer.from_pretrained(args.base, local_files_only=True)
    if not tok.is_fast:
        common.die("нужен быстрый токенизатор (tokenizer.json)")
    # Служебные токены в тексте — обычный текст, как в aisec-ml (wordpiece.go).
    tok.backend_tokenizer.encode_special_tokens = True
    model = AutoModelForTokenClassification.from_pretrained(
        args.base, local_files_only=True, num_labels=len(LABELS),
        id2label=dict(enumerate(LABELS)), label2id={l: i for i, l in enumerate(LABELS)})

    def encode(rows):
        enc = tok([r["text"] for r in rows], truncation=True, max_length=args.max_len, padding=True,
                  return_offsets_mapping=True, return_tensors="pt")
        offs = enc.pop("offset_mapping").tolist()
        y = torch.tensor([token_labels(o, r["entities"]) for o, r in zip(offs, rows)])
        return enc, y, offs

    def batches(rows, epoch=None):
        idx = list(range(len(rows)))
        if epoch is not None:
            random.Random(args.seed + epoch).shuffle(idx)
        for i in range(0, len(idx), args.batch):
            part = [rows[j] for j in idx[i:i + args.batch]]
            enc, y, offs = encode(part)
            yield part, enc, y, offs

    def evaluate(rows):
        """Точность, полнота и F1 по фрагментам: всего и по сущностям."""
        model.eval()
        tp, fp, fn = {}, {}, {}
        with torch.no_grad():
            for part, enc, _, offs in batches(rows):
                pred = model(**enc).logits.argmax(-1).tolist()
                for r, p, o in zip(part, pred, offs):
                    got = merge([(LABELS[k], s, e) for k, (s, e) in zip(p, o)])
                    want = aligned(o, r["entities"])
                    for ent in ENTITIES:
                        g, w = {x for x in got if x[0] == ent}, {x for x in want if x[0] == ent}
                        tp[ent] = tp.get(ent, 0) + len(g & w)
                        fp[ent] = fp.get(ent, 0) + len(g - w)
                        fn[ent] = fn.get(ent, 0) + len(w - g)
        model.train()

        def prf(a, b, c):
            p, r = a / max(1, a + b), a / max(1, a + c)
            return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(2 * p * r / max(1e-9, p + r), 4)}

        m = {ent: prf(tp[ent], fp[ent], fn[ent]) for ent in ENTITIES if tp.get(ent, 0) + fn.get(ent, 0) > 0}
        m["pii"] = prf(sum(tp.get(e, 0) for e in PII), sum(fp.get(e, 0) for e in PII), sum(fn.get(e, 0) for e in PII))
        return m

    steps = args.epochs * ((len(train) + args.batch - 1) // args.batch)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = transformers.get_linear_schedule_with_warmup(opt, max(1, steps // 10), steps)
    model.train()
    history, best = [], None
    started = time.time()
    for epoch in range(args.epochs):
        total, n = 0.0, 0
        for _, enc, y, _ in batches(train, epoch):
            logits = model(**enc).logits
            loss = torch.nn.functional.cross_entropy(logits.reshape(-1, len(LABELS)), y.reshape(-1), ignore_index=-100)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            total, n = total + loss.item(), n + 1
        m = {"epoch": epoch + 1, "loss": total / max(1, n), "dev": evaluate(dev),
             "minutes": round((time.time() - started) / 60, 1)}
        history.append(m)
        print(json.dumps(m, ensure_ascii=False))
        # Лучшая эпоха — по F1 сущностей ПДн на проверке эпох (dev), не на testset.
        key = m["dev"]["pii"]["f1"]
        if best is None or key > best[0]:
            best = (key, m["epoch"])
            model.save_pretrained(args.out, safe_serialization=True)
            tok.save_pretrained(args.out)
    # Проверка на живом тексте — один раз, лучшей эпохой; без factRuEval
    # (не скачан) — нет и проверки.
    model = AutoModelForTokenClassification.from_pretrained(args.out, local_files_only=True)
    factru = evaluate(check) if check else None
    report = {
        "base": common.source("rubert-tiny2"), "labels": LABELS, "best_epoch": best[1], "history": history,
        "check_factru": factru,
        "params": {k: v for k, v in vars(args).items() if k not in ("base", "data", "out")},
        "data": json.load(open(os.path.join(args.data, "stats.json"), encoding="utf-8")),
        "versions": {"python": platform.python_version(), "torch": torch.__version__,
                     "transformers": transformers.__version__},
    }
    common.write_json(os.path.join(args.out, "train_report.json"), report)
    common.ok(f"модель {os.path.relpath(args.out, common.ROOT)}, лучшая эпоха {best[1]}; testset factRuEval: "
              + json.dumps(factru, ensure_ascii=False))


if __name__ == "__main__":
    main()
