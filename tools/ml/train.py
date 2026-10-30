#!/usr/bin/env python3
"""Дообучка rubert-tiny2 для injection.ml (задача 4.19, ADR-0024).

Только для разработки, в поставку не входит; без сети, на процессоре.
Берёт основу build/ml/src/rubert-tiny2 и набор build/ml/data/injection
(prepare.py), учит классификатор на две метки (benign, injection) и сохраняет
лучшую по проверке эпох модель в build/ml/train/injection-ru-en вместе с
отчётом train_report.json (параметры, версии, метрики — для ML-BOM).

Результат воспроизводим: фиксированный seed, детерминированные алгоритмы
torch, один и тот же порядок примеров. Время — порядка часа на 4–8 ядрах.
"""

import argparse
import json
import os
import platform
import random
import time

import common

LABELS = ["benign", "injection"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", default=os.path.join(common.SRC, "rubert-tiny2"))
    ap.add_argument("--data", default=os.path.join(common.BUILD, "data", "injection"))
    ap.add_argument("--out", default=os.path.join(common.BUILD, "train", "injection-ru-en"))
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=5e-5)
    ap.add_argument("--max-len", type=int, default=256, help="токенов на пример при обучении")
    ap.add_argument("--seed", type=int, default=4190)
    ap.add_argument("--threads", type=int, default=0, help="потоков torch; 0 — по числу ядер")
    ap.add_argument("--limit", type=int, default=0, help="только первые N примеров (проверка скрипта)")
    args = ap.parse_args()
    common.offline()

    import numpy as np
    import torch
    import transformers
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    random.seed(args.seed)
    np.random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    if args.threads:
        torch.set_num_threads(args.threads)

    train = common.read_jsonl(os.path.join(args.data, "train.jsonl"))
    dev = common.read_jsonl(os.path.join(args.data, "dev.jsonl"))
    if args.limit:
        train, dev = train[: args.limit], dev[: max(8, args.limit // 10)]
    tok = AutoTokenizer.from_pretrained(args.base, local_files_only=True)
    # Служебные токены в тексте — обычный текст, как в aisec-ml (wordpiece.go).
    tok.backend_tokenizer.encode_special_tokens = True
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base, local_files_only=True, num_labels=len(LABELS),
        id2label=dict(enumerate(LABELS)), label2id={l: i for i, l in enumerate(LABELS)})

    def batches(rows, epoch=None):
        idx = list(range(len(rows)))
        if epoch is not None:
            random.Random(args.seed + epoch).shuffle(idx)
        for i in range(0, len(idx), args.batch):
            part = [rows[j] for j in idx[i:i + args.batch]]
            enc = tok([r["text"] for r in part], truncation=True, max_length=args.max_len, padding=True,
                      return_tensors="pt")
            y = torch.tensor([LABELS.index(r["label"]) for r in part])
            yield enc, y

    def evaluate():
        model.eval()
        tp = fp = fn = tn = 0
        with torch.no_grad():
            for enc, y in batches(dev):
                p = model(**enc).logits.softmax(-1)[:, 1] >= 0.5
                tp += int(((p == 1) & (y == 1)).sum())
                fp += int(((p == 1) & (y == 0)).sum())
                fn += int(((p == 0) & (y == 1)).sum())
                tn += int(((p == 0) & (y == 0)).sum())
        model.train()
        return {"recall": tp / max(1, tp + fn), "fpr": fp / max(1, fp + tn), "precision": tp / max(1, tp + fp),
                "accuracy": (tp + tn) / max(1, tp + fp + fn + tn)}

    steps = args.epochs * ((len(train) + args.batch - 1) // args.batch)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01)
    sched = transformers.get_linear_schedule_with_warmup(opt, max(1, steps // 10), steps)
    model.train()
    history, best = [], None
    started = time.time()
    for epoch in range(args.epochs):
        total, n = 0.0, 0
        for enc, y in batches(train, epoch):
            loss = torch.nn.functional.cross_entropy(model(**enc).logits, y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            sched.step()
            opt.zero_grad()
            total, n = total + loss.item(), n + 1
        m = evaluate()
        m.update(epoch=epoch + 1, loss=total / max(1, n), minutes=round((time.time() - started) / 60, 1))
        history.append(m)
        print(json.dumps(m, ensure_ascii=False))
        # Лучшая эпоха — по полноте при доле ложных не выше 2%, иначе по точности.
        key = (m["fpr"] <= 0.02, m["recall"], -m["fpr"])
        if best is None or key > best[0]:
            best = (key, m["epoch"])
            model.save_pretrained(args.out, safe_serialization=True)
            tok.save_pretrained(args.out)
    report = {
        "base": common.source("rubert-tiny2"), "labels": LABELS, "best_epoch": best[1], "history": history,
        "params": {k: v for k, v in vars(args).items() if k not in ("base", "data", "out")},
        "data": json.load(open(os.path.join(args.data, "stats.json"), encoding="utf-8")),
        "versions": {"python": platform.python_version(), "torch": torch.__version__,
                     "transformers": transformers.__version__},
    }
    common.write_json(os.path.join(args.out, "train_report.json"), report)
    common.ok(f"модель {os.path.relpath(args.out, common.ROOT)}, лучшая эпоха {best[1]}: "
              + json.dumps(history[best[1] - 1], ensure_ascii=False))


if __name__ == "__main__":
    main()
