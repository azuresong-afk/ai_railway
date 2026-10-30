#!/usr/bin/env python3
"""ML-BOM модели (CycloneDX 1.6, ТЗ 8.12) для пакета моделей aisec-ml.

Только для разработки, в поставку не входит (в поставку входит результат —
mlbom.cdx.json); только стандартная библиотека. Пишет
build/ml/models/<id>/mlbom.cdx.json: модель (компонент
machine-learning-model с ID и версией из пакета — их сверяет aisec-ml),
хеши model.onnx и tokenizer.json, происхождение весов (репозиторий и коммит
из tools/ml/sources.json), лицензию, наборы данных обучения и дообучения
с лицензиями, параметры и метрики дообучки (train_report.json), если есть.
"""

import argparse
import datetime
import json
import os
import uuid

import common

# Наборы, на которых обучали исходную rubert-tiny-toxicity (карточка модели);
# лицензии в карточке не указаны.
TOXICITY_DATA = [
    ("2ch и pikabu: оскорбительные комментарии (Kaggle)", "https://www.kaggle.com/blackmoon/russian-language-toxic-comments"),
    ("ok.ru: токсичные комментарии (Kaggle)", "https://www.kaggle.com/alexandersemiletov/toxic-russian-comments"),
    ("Сколтех: неуместные сообщения (inappropriate messages)", "https://github.com/s-nlp/inappropriate-sensitive-topics"),
]


def hf_ref(src):
    kind = "datasets/" if src in common.load_sources()["datasets"] else ""
    return {"type": "distribution", "url": f"https://huggingface.co/{kind}{src['repo']}",
            "comment": f"коммит {src.get('revision') or 'не зафиксирован'}"}


def lic(spdx):
    return [{"license": {"id": spdx}}] if spdx else [{"license": {"name": "не указана"}}]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--id", required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--source", required=True, help="исходная модель из sources.json (rubert-tiny2, rubert-tiny-toxicity)")
    ap.add_argument("--train-report", default="", help="train_report.json дообучки")
    ap.add_argument("--dir", default=os.path.join(common.BUILD, "models"))
    args = ap.parse_args()

    dest = os.path.join(args.dir, args.id)
    src = common.source(args.source)
    spec = json.load(open(os.path.join(common.BUILD, "models.spec.json"), encoding="utf-8"))
    mspec = next((m for m in spec["models"] if m["id"] == args.id), None)
    if mspec is None or mspec["version"] != args.version:
        common.die(f"{args.id} {args.version} нет в build/ml/models.spec.json — сначала экспорт")
    hashes = {f: common.sha256_file(os.path.join(dest, f)) for f in ("model.onnx", "tokenizer.json")}

    base = {"type": "machine-learning-model", "bom-ref": "base", "name": src["repo"],
            "version": src.get("revision") or "не зафиксирован", "licenses": lic(src["license"]),
            "externalReferences": [hf_ref(src)],
            "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(src.get("files", {}).values())]}
    datasets, components = [], [base]
    report = None
    if args.train_report:
        report = json.load(open(args.train_report, encoding="utf-8"))
        for name, cnt in sorted(report["data"]["by_source"].items()):
            if name == "synthetic-ru":
                d = {"type": "data", "bom-ref": "data-synthetic-ru", "name": "Синтетический русский корпус AISec",
                     "licenses": [{"license": {"id": "MIT"}}],
                     "description": "testdata/ml/injection-train (tools/ml/gen_synthetic.py), без ПДн"}
            else:
                s = common.source(name)
                d = {"type": "data", "bom-ref": "data-" + name, "name": s["repo"], "licenses": lic(s["license"]),
                     "externalReferences": [hf_ref(s)],
                     "hashes": [{"alg": "SHA-256", "content": h} for h in sorted(s.get("files", {}).values())]}
            d["properties"] = [{"name": "aisec:examples:" + k, "value": str(v)} for k, v in sorted(cnt.items())]
            components.append(d)
            datasets.append({"ref": d["bom-ref"]})
    else:
        for i, (name, url) in enumerate(TOXICITY_DATA):
            ref = f"data-upstream-{i}"
            components.append({"type": "data", "bom-ref": ref, "name": name, "licenses": lic(""),
                               "externalReferences": [{"type": "website", "url": url}],
                               "description": "набор обучения исходной модели по её карточке; лицензия в карточке не указана"})
            datasets.append({"ref": ref})

    card = {"modelParameters": {"task": mspec["task"], "architectureFamily": "BERT",
                                "modelArchitecture": "BertForSequenceClassification", "datasets": datasets,
                                "outputs": [{"format": "logits: " + ", ".join(mspec["labels"])}]},
            "considerations": {"useCases": ["детектор " + ("injection.ml (DM-01)" if "injection" in args.id else "toxicity.ml (DM-18)")
                                            + " в процессе aisec-ml"],
                               "technicalLimitations": ["окно 512 токенов, не больше 16 окон на запрос",
                                                        "качество — docs/detectors.md, раздел «Замер Р4»"]}}
    if report:
        best = report["history"][report["best_epoch"] - 1]
        card["quantitativeAnalysis"] = {"performanceMetrics": [
            {"type": k, "value": f"{best[k]:.4f}", "slice": "проверка эпох (dev), порог 0,5"} for k in ("recall", "fpr", "precision")]}
    model = {"type": "machine-learning-model", "bom-ref": "model", "name": args.id, "version": args.version,
             "licenses": [{"license": {"id": "MIT"}}] if report else lic(src["license"]),
             "hashes": [{"alg": "SHA-256", "content": hashes["model.onnx"]}],
             "pedigree": {"ancestors": [{"type": "machine-learning-model", "name": src["repo"],
                                          "version": src.get("revision") or ""}]},
             "properties": [{"name": "aisec:tokenizer:sha256", "value": hashes["tokenizer.json"]},
                            {"name": "aisec:format", "value": "ONNX, opset 17"}],
             "modelCard": card}
    if report:
        model["properties"].append({"name": "aisec:train:params", "value": json.dumps(report["params"], ensure_ascii=False)})
        model["properties"].append({"name": "aisec:train:versions", "value": json.dumps(report["versions"], ensure_ascii=False)})
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
           "metadata": {"timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
           "components": [model] + components,
           "dependencies": [{"ref": "model", "dependsOn": ["base"] + [d["ref"] for d in datasets]}]}
    common.write_json(os.path.join(dest, "mlbom.cdx.json"), bom)
    common.ok(f"ML-BOM {os.path.relpath(os.path.join(dest, 'mlbom.cdx.json'), common.ROOT)}")


if __name__ == "__main__":
    main()
