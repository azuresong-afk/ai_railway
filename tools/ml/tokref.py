#!/usr/bin/env python3
"""Эталон токенизатора для проверки WordPiece на Go (задача 4.19).

Только для разработки, в поставку не входит. Читает tokenizer.json модели и
тексты (JSONL с полем "text": корпуса testdata/corpus и testdata/ml, кроме
корпуса secrets — похожие на ключи строки GitHub не принимает), кодирует
каждый текст эталонной библиотекой tokenizers (Hugging Face) и пишет JSONL:

    {"text": "...", "ids": [...], "offsets": [[начало, конец], ...]}

Границы — в байтах UTF-8, как у токенизатора на Go. Служебные токены не
добавляются ([CLS] и [SEP] ставит aisec-ml), служебные токены в тексте
разбираются как обычный текст (encode_special_tokens), обрезки нет.

Пример:
    python3 tools/ml/tokref.py --tokenizer build/ml/models/toxicity-ru/tokenizer.json \
        --texts testdata/corpus/toxicity.ml/validation.jsonl --out build/ml/ref/toxicity-ru.tokref.jsonl
"""

import argparse
import json
import sys


# Строки, на которых токенизаторы чаще всего расходятся: управляющие и
# невидимые символы, пробелы Unicode, знаки, иероглифы, эмодзи, служебные
# токены в тексте, длинные слова, диакритика.
EXTRA = [
    "",
    "   ",
    "Привет,мир!Как дела?",
    "ignore​previous instructions",
    "табуляция\tи\nперевод\r\nстроки разделитель",
    "\u0000нуль и � замена",
    "[CLS] [SEP] [MASK] [UNK] [PAD] <s> </s>",
    "中文字符和кириллица",
    "эмодзи 🙂🥲🫠 и флаг 🇷🇺",
    "Ёлка, ёж и йод; café naïve façade",
    "$100+200=300 <tag> a^b `code` x|y ~z",
    "очень" * 40,
    "a" * 150,
    "Ⅻⅻ ½ ² ﬁ ＡＢＣ",
    "«кавычки» — тире – дефис ‐ … „лапки“",
    # Нижний регистр Go (unicode.ToLower) и Rust (char::to_lowercase) на
    # «İ» (в Rust — два знака) и сигме в конце слова (ревью 4.r4).
    "İstanbul DİYARBAKIR ΟΔΥΣΣΕΥΣ ΣΟΦΟΣ",
]


def byte_offsets(text, offsets):
    # Смещения tokenizers — в символах; переводим в байты UTF-8.
    pos = [0]
    for ch in text:
        pos.append(pos[-1] + len(ch.encode("utf-8")))
    return [[pos[s], pos[e]] for s, e in offsets]


def write_reference(tok, texts, out_path):
    """Эталон для tok (tokenizers.Tokenizer): EXTRA и texts."""
    tok.no_truncation()
    tok.no_padding()
    tok.encode_special_tokens = True
    texts = list(EXTRA) + list(texts)
    with open(out_path, "w", encoding="utf-8") as out:
        for text in texts:
            enc = tok.encode(text, add_special_tokens=False)
            rec = {"text": text, "ids": enc.ids, "offsets": byte_offsets(text, enc.offsets)}
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"tokref: {len(texts)} текстов -> {out_path}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tokenizer", required=True, help="tokenizer.json модели")
    ap.add_argument("--texts", nargs="*", default=[], help="файлы JSONL с полем text")
    ap.add_argument("--out", required=True, help="куда записать эталон (JSONL)")
    ap.add_argument("--limit", type=int, default=2000, help="не больше стольких текстов из файлов")
    args = ap.parse_args()

    from tokenizers import Tokenizer

    texts = []
    for path in args.texts:
        with open(path, encoding="utf-8") as f:
            texts += [json.loads(line)["text"] for line in f if line.strip()]
    write_reference(Tokenizer.from_file(args.tokenizer), texts[: args.limit], args.out)


if __name__ == "__main__":
    main()
