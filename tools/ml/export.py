#!/usr/bin/env python3
"""Экспорт модели в ONNX для пакета моделей aisec-ml (задача 4.19, ADR-0024).

Только для разработки, в поставку не входит; без сети. Из каталога модели
transformers (дообученной или скачанной) делает build/ml/models/<id>/:
  model.onnx     — веса и граф одним файлом (без внешних данных: сборка ORT
                   их запрещает), входы input_ids, attention_mask,
                   token_type_ids, выход logits;
  tokenizer.json — токенизатор (WordPiece, разбирает aisec-ml);
и дописывает описание модели в build/ml/models.spec.json (для
tools/manifest sign-models). Для проверки на машине владельца пишет эталоны
в build/ml/ref/: <id>.tokref.jsonl — токены и границы эталонного
токенизатора, <id>.logits.jsonl — выход исходной модели torch на текстах
проверочного корпуса (make ml-verify сверяет с ними aisec-ml).
"""

import argparse
import glob
import os

import common
import tokref


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--model", required=True, help="каталог модели transformers")
    ap.add_argument("--id", required=True, help="ID модели в пакете (injection-ru-en, toxicity-ru)")
    ap.add_argument("--version", required=True)
    ap.add_argument("--task", required=True, choices=["classification", "multilabel_classification"])
    ap.add_argument("--directions", default="input", help="input, output или input,output")
    ap.add_argument("--corpus", required=True, help="каталог проверочного корпуса (тексты эталонов)")
    ap.add_argument("--out", default=os.path.join(common.BUILD, "models"))
    ap.add_argument("--max-tokens", type=int, default=512)
    args = ap.parse_args()
    common.offline()
    if not common.ID_RE.match(args.id):
        common.die(f"ID модели {args.id!r}")

    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    torch.manual_seed(0)
    tok = AutoTokenizer.from_pretrained(args.model, local_files_only=True)
    if not tok.is_fast:
        common.die("нужен быстрый токенизатор (tokenizer.json)")
    tok.backend_tokenizer.encode_special_tokens = True
    model = AutoModelForSequenceClassification.from_pretrained(args.model, local_files_only=True).eval()
    cfg = model.config
    labels = [str(cfg.id2label[i]).lower() for i in range(cfg.num_labels)]
    for lab in labels:
        if not common.ID_RE.match(lab):
            common.die(f"метка {lab!r} не подходит протоколу aisec-ml")
    dest = os.path.join(args.out, args.id)
    os.makedirs(dest, exist_ok=True)

    # Токенизатор — тот же, что видит transformers, без обрезки и выравнивания.
    bt = tok.backend_tokenizer
    bt.no_truncation()
    bt.no_padding()
    bt.save(os.path.join(dest, "tokenizer.json"))

    sample = tok(["пример текста", "второй пример"], return_tensors="pt", padding=True)
    names = [n for n in ("input_ids", "attention_mask", "token_type_ids") if n in sample]
    onnx_path = os.path.join(dest, "model.onnx")

    class Wrapped(torch.nn.Module):
        def __init__(self, m):
            super().__init__()
            self.m = m

        def forward(self, *xs):
            return self.m(**dict(zip(names, xs))).logits

    dyn = {n: {0: "batch", 1: "seq"} for n in names}
    dyn["logits"] = {0: "batch"}
    # Обёртка — тоже в режиме вывода: экспорт возвращает модулю прежний режим,
    # и обёртка в режиме обучения включила бы dropout у модели.
    torch.onnx.export(Wrapped(model).eval(), tuple(sample[n] for n in names), onnx_path, input_names=names,
                      output_names=["logits"], dynamic_axes=dyn, opset_version=17, do_constant_folding=True,
                      dynamo=False)
    extra = [f for f in os.listdir(dest) if f not in ("model.onnx", "tokenizer.json", "mlbom.cdx.json")]
    if extra:
        common.die(f"экспорт оставил лишние файлы (внешние данные?): {extra}")

    spec_path = os.path.join(common.BUILD, "models.spec.json")
    spec = {"models": []}
    if os.path.exists(spec_path):
        import json
        spec = json.load(open(spec_path, encoding="utf-8"))
    spec["models"] = [m for m in spec["models"] if m["id"] != args.id] + [{
        "id": args.id, "version": args.version, "task": args.task, "labels": labels,
        "directions": args.directions.split(","), "max_tokens": args.max_tokens}]
    spec["models"].sort(key=lambda m: m["id"])
    common.write_json(spec_path, spec)

    # Эталоны: токены и выход torch на текстах проверочного корпуса, которые
    # помещаются в одно окно ([CLS] + до max_tokens-2 токенов + [SEP]).
    texts = [r["text"] for p in sorted(glob.glob(os.path.join(args.corpus, "*.jsonl"))) for r in common.read_jsonl(p)]
    ref = os.path.join(common.BUILD, "ref")
    os.makedirs(ref, exist_ok=True)
    tokref.write_reference(bt, texts, os.path.join(ref, f"{args.id}.tokref.jsonl"))
    rows = []
    model.eval()
    with torch.no_grad():
        for t in texts:
            enc = tok(t, return_tensors="pt")
            if enc["input_ids"].shape[1] > args.max_tokens:
                continue
            rows.append({"text": t, "logits": [round(float(x), 6) for x in model(**enc).logits[0]]})
    common.write_jsonl(os.path.join(ref, f"{args.id}.logits.jsonl"), rows)
    common.ok(f"{args.id}: {os.path.relpath(onnx_path, common.ROOT)} ({os.path.getsize(onnx_path)} байт), метки {labels}, "
              f"эталонов {len(rows)}")


if __name__ == "__main__":
    main()
