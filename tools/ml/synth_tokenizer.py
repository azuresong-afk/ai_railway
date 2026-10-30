#!/usr/bin/env python3
"""Синтетический tokenizer.json для тестов токенизатора на Go (задача 4.19).

Только для разработки, в поставку не входит. Обучает маленький словарь
WordPiece (как у BERT: без перевода в нижний регистр и без снятия
диакритики, как у rubert-tiny2) на текстах корпусов testdata/corpus и пишет
testdata/ml/wordpiece/tokenizer.json. Эталон к нему — tools/ml/tokref.py.
Модели и сети не нужны.

    python3 tools/ml/synth_tokenizer.py --out testdata/ml/wordpiece/tokenizer.json \
        testdata/corpus/injection.heuristic/corpus.jsonl testdata/corpus/pii.ru/part1.jsonl
"""

import argparse
import json

from tokenizers import BertWordPieceTokenizer
from tokenizers.processors import TemplateProcessing


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", required=True)
    ap.add_argument("--vocab-size", type=int, default=800)
    ap.add_argument("texts", nargs="+", help="файлы JSONL с полем text")
    args = ap.parse_args()

    texts = []
    for path in args.texts:
        with open(path, encoding="utf-8") as f:
            texts += [json.loads(line)["text"] for line in f if line.strip()]
    tok = BertWordPieceTokenizer(clean_text=True, handle_chinese_chars=True, strip_accents=False, lowercase=False)
    tok.train_from_iterator(texts, vocab_size=args.vocab_size, min_frequency=2, limit_alphabet=300,
                            special_tokens=["[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]"])
    # Как у tokenizer.json, сохранённого transformers: «[CLS] $A [SEP]».
    cls, sep = tok.token_to_id("[CLS]"), tok.token_to_id("[SEP]")
    tok.post_processor = TemplateProcessing(single="[CLS] $A [SEP]", pair="[CLS] $A [SEP] $B:1 [SEP]:1",
                                            special_tokens=[("[CLS]", cls), ("[SEP]", sep)])
    tok.save(args.out, pretty=False)


if __name__ == "__main__":
    main()
