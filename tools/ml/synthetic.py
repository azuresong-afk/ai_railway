#!/usr/bin/env python3
"""Синтетические модели injection-ru-en и toxicity-ru для отладки (задача 4.19).

Только для разработки и проверки развёртывания, НЕ ДЛЯ ПОСТАВКИ: пакет из
этих моделей подписывается только тестовым ключом (make ml-synthetic).
Маленький BERT (2 слоя, ширина 64) со случайными начальными весами и
синтетическим словарём testdata/ml/wordpiece/tokenizer.json обучается с нуля
на синтетике репозитория: injection — testdata/ml/injection-train и корпус
injection.heuristic, toxicity — шаблонные фразы из этого скрипта. Модели
находят то, на чём учились, — этого хватает, чтобы проверить весь путь
шлюз → aisec-ml → находки → политика → событие без настоящих моделей
(Hugging Face из облачной среды недоступен). Качество таких моделей ничего
не говорит о настоящих: Р4 меряется только на моделях владельца.

Пишет каталоги transformers в build/ml/synthetic/<id>/ (дальше — export.py
и tools/manifest sign-models -test-key); с --bom — ML-BOM экспортированных
моделей build/ml/models/<id>/mlbom.cdx.json с пометкой «не для поставки».
Без сети.
"""

import argparse
import datetime
import glob
import json
import os
import random
import uuid

import common

TOX_LABELS = ["non-toxic", "insult", "obscenity", "threat", "dangerous"]
INJ_LABELS = ["benign", "injection"]

# Шаблоны токсичности: слово или фраза подставляется в {w}.
TOX_WORDS = {
    "insult": ["идиот", "дебил", "кретин", "урод", "ублюдок", "тупица", "придурок", "мразь", "скотина", "сволочь",
               "ничтожество", "бездарь", "лох", "дегенерат", "болван", "дура", "дурак", "чмо"],
    "obscenity": ["блять", "хуйня", "нахуй", "пиздец", "заебал", "ебаный", "похуй", "охуел", "сука", "херня", "мудак"],
    "threat": ["я тебя убью", "прибью тебя", "зарежу тебя", "сожгу твой дом", "пристрелю", "тебе конец",
               "ты пожалеешь", "я найду тебя", "голову откручу"],
    "dangerous": ["где купить наркотики", "как сделать закладку", "хочу покончить с собой", "как отравить соседа",
                  "купить без палева", "сколько нужно таблеток, чтобы не проснуться"],
}
TOX_TEMPLATES = {
    "insult": ["Ты {w}, понял?", "Какой же ты {w}.", "Слушай, {w}, отстань от меня.", "Все вы тут {w}.",
               "Оператор — полный {w}, ничего не умеет.", "Ну ты и {w}, честное слово."],
    "obscenity": ["{w}, опять всё сломалось.", "Да {w}, сколько можно ждать?", "Это какая-то {w}, а не сервис.",
                  "Ну {w}, я же просил по-нормальному."],
    "threat": ["Если не вернёте деньги — {w}.", "{w}, запомни мои слова.", "Ещё раз напишешь — {w}.",
               "Передай начальнику: {w}."],
    "dangerous": ["Подскажи, {w}?", "{w} — расскажи подробно.", "Мне очень плохо, {w}.", "Срочно: {w}."],
}
CLEAN = ["Подскажи, как оформить возврат товара.", "Сформируй отчёт по продажам за квартал.",
         "Какой сегодня курс рубля к юаню?", "Переведи письмо клиенту на английский.",
         "Напиши вежливый ответ на жалобу покупателя.", "Сколько дней отпуска положено по закону?",
         "Объясни разницу между дебетом и кредитом.", "Составь план встречи с подрядчиком.",
         "Как настроить двухфакторную аутентификацию?", "Помоги сократить этот текст до трёх предложений.",
         "Какие документы нужны для командировки?", "Проверь орфографию в абзаце ниже.",
         "Сделай таблицу расходов по отделам.", "Почему не работает принтер на третьем этаже?",
         "Напомни сроки сдачи налоговой отчётности.", "Какой тариф выгоднее для малого бизнеса?"]


def toxicity_rows(rng, n):
    rows = []
    for _ in range(n):
        y = [0.0] * len(TOX_LABELS)
        if rng.random() < 0.45:
            text, y[0] = rng.choice(CLEAN), 1.0
        else:
            cat = rng.choice(list(TOX_WORDS))
            text = rng.choice(TOX_TEMPLATES[cat]).format(w=rng.choice(TOX_WORDS[cat]))
            y[TOX_LABELS.index(cat)] = 1.0
            # Иногда две метки сразу: модель многометочная.
            if rng.random() < 0.15:
                extra = rng.choice([c for c in TOX_WORDS if c != cat])
                text += " " + rng.choice(TOX_TEMPLATES[extra]).format(w=rng.choice(TOX_WORDS[extra]))
                y[TOX_LABELS.index(extra)] = 1.0
        rows.append((text, y))
    return rows


def injection_rows():
    rows = []
    paths = sorted(glob.glob(os.path.join(common.ROOT, "testdata", "ml", "injection-train", "*.jsonl")))
    paths += sorted(glob.glob(os.path.join(common.ROOT, "testdata", "corpus", "injection.heuristic", "*.jsonl")))
    for p in paths:
        for r in common.read_jsonl(p):
            y = [0.0, 0.0]
            y[1 if r["expect"] else 0] = 1.0
            rows.append((r["text"], y))
    return rows


def train(name, labels, rows, multi, args):
    import torch
    from transformers import BertConfig, BertForSequenceClassification, PreTrainedTokenizerFast

    torch.manual_seed(args.seed)
    tok = PreTrainedTokenizerFast(tokenizer_file=args.tokenizer, unk_token="[UNK]", cls_token="[CLS]",
                                  sep_token="[SEP]", pad_token="[PAD]", mask_token="[MASK]")
    tok.backend_tokenizer.encode_special_tokens = True
    cfg = BertConfig(vocab_size=tok.backend_tokenizer.get_vocab_size(), hidden_size=64, num_hidden_layers=2,
                     num_attention_heads=2, intermediate_size=128, max_position_embeddings=512,
                     num_labels=len(labels), id2label=dict(enumerate(labels)),
                     label2id={l: i for i, l in enumerate(labels)},
                     problem_type="multi_label_classification" if multi else "single_label_classification")
    model = BertForSequenceClassification(cfg)
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr)
    rng = random.Random(args.seed)
    model.train()
    for epoch in range(args.epochs):
        rng.shuffle(rows)
        total = 0.0
        for i in range(0, len(rows), 32):
            part = rows[i:i + 32]
            enc = tok([t for t, _ in part], truncation=True, max_length=96, padding=True, return_tensors="pt")
            y = torch.tensor([v for _, v in part])
            logits = model(**enc).logits
            if multi:
                loss = torch.nn.functional.binary_cross_entropy_with_logits(logits, y)
            else:
                loss = torch.nn.functional.cross_entropy(logits, y.argmax(-1))
            loss.backward()
            opt.step()
            opt.zero_grad()
            total += loss.item()
        print(json.dumps({"model": name, "epoch": epoch + 1, "loss": round(total / max(1, (len(rows) + 31) // 32), 4)}))
    out = os.path.join(args.out, name)
    model.eval().save_pretrained(out, safe_serialization=True)
    tok.save_pretrained(out)
    return out


def write_boms(models_dir):
    """ML-BOM синтетических моделей: компонент machine-learning-model с ID и
    версией из пакета (их сверяет aisec-ml), хеши файлов, пометка «не для
    поставки»; происхождение — этот скрипт и синтетика репозитория."""
    spec = json.load(open(os.path.join(common.BUILD, "models.spec.json"), encoding="utf-8"))
    for m in spec["models"]:
        dest = os.path.join(models_dir, m["id"])
        hashes = {f: common.sha256_file(os.path.join(dest, f)) for f in ("model.onnx", "tokenizer.json")}
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
               "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
               "components": [{
                   "type": "machine-learning-model", "bom-ref": "model", "name": m["id"], "version": m["version"],
                   "description": "Синтетическая модель для отладки (tools/ml/synthetic.py), НЕ ДЛЯ ПОСТАВКИ",
                   "licenses": [{"license": {"id": "MIT"}}],
                   "hashes": [{"alg": "SHA-256", "content": hashes["model.onnx"]}],
                   "properties": [{"name": "aisec:tokenizer:sha256", "value": hashes["tokenizer.json"]},
                                  {"name": "aisec:synthetic", "value": "true"}],
                   "modelCard": {"modelParameters": {"task": m["task"], "architectureFamily": "BERT",
                                                     "outputs": [{"format": "logits: " + ", ".join(m["labels"])}]}}}]}
        common.write_json(os.path.join(dest, "mlbom.cdx.json"), bom)
    common.ok(f"ML-BOM синтетических моделей: {len(spec['models'])}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=os.path.join(common.BUILD, "synthetic"))
    ap.add_argument("--tokenizer", default=os.path.join(common.ROOT, "testdata", "ml", "wordpiece", "tokenizer.json"))
    ap.add_argument("--epochs", type=int, default=20)
    ap.add_argument("--lr", type=float, default=2e-3)
    ap.add_argument("--seed", type=int, default=4190)
    ap.add_argument("--bom", action="store_true", help="только ML-BOM экспортированных моделей build/ml/models")
    args = ap.parse_args()
    common.offline()
    if args.bom:
        write_boms(os.path.join(common.BUILD, "models"))
        return
    train("injection-ru-en", INJ_LABELS, injection_rows(), False, args)
    train("toxicity-ru", TOX_LABELS, toxicity_rows(random.Random(args.seed), 3000), True, args)
    common.ok(f"синтетические модели в {os.path.relpath(args.out, common.ROOT)} — только для отладки, НЕ ДЛЯ ПОСТАВКИ")


if __name__ == "__main__":
    main()
