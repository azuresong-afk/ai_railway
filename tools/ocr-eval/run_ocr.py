"""Прогон кандидатов OCR на корпусе изображений (задача 5.40, ADR-0033).

Только инструмент разработки: в поставку не входит. Кандидаты:
  * paddle-eslav, paddle-cyrillic, paddle-v6 — модели PaddleOCR в ONNX
    (детектор строк PP-OCRv6 small и распознавание), запуск через
    onnxruntime на процессоре; пред- и постобработка — свой код на numpy,
    как её придётся написать на Go в aisec-media (5.42);
  * tesseract — Tesseract 5 из командной строки с tessdata_best rus+eng.

Каждое изображение — два прохода: обычный и с повышенной контрастностью
(бледный текст, DM-45). Растр готовит headless Chromium (AISEC_CHROMIUM):
декодеры изображений в Go вне internal/media запрещены (depguard
media-decoders), Pillow и OpenCV не согласованы. Итог — JSON для
tools/ocr-eval (CER, находки детекторов, время).

Запуск: make ocr-eval (taskset на 4 ядра, см. Makefile).
"""

import argparse
import base64
import json
import math
import os
import pathlib
import subprocess
import tempfile
import time

import numpy as np
import onnxruntime as ort
import pyclipper

PROVIDERS = ["CPUExecutionProvider"]  # только процессор: без Azure и прочих удалённых
DET_LIMIT = 960  # предел большей стороны для детектора, кратно 32
DET_THRESH, BOX_THRESH, UNCLIP = 0.3, 0.6, 1.5
REC_H, REC_MAX_W = 48, 3200
CONTRAST_GAMMA = 10.0  # 238 → 128: бледный #eeeeee на белом становится читаемым


# --- растр -----------------------------------------------------------------

PAGE = """<!doctype html><html><body><img id="i" src="data:%s;base64,%s"><pre id="o"></pre><script>
window.addEventListener("load",function(){var i=document.getElementById("i"),c=document.createElement("canvas");
c.width=i.naturalWidth;c.height=i.naturalHeight;var x=c.getContext("2d");x.drawImage(i,0,0);
var d=x.getImageData(0,0,c.width,c.height).data,s="",n=0x8000;
for(var k=0;k<d.length;k+=n){s+=String.fromCharCode.apply(null,d.subarray(k,k+n));}
document.getElementById("o").textContent=c.width+"x"+c.height+":"+btoa(s);i.remove();});
</script></body></html>"""


def raster(chromium, path, work):
    """RGB-растр uint8 [h, w, 3]: декодирует Chromium через canvas."""
    mime = "image/jpeg" if path.suffix == ".jpg" else "image/png"
    page = pathlib.Path(work, path.stem + "-raster.html")
    page.write_text(PAGE % (mime, base64.b64encode(path.read_bytes()).decode()), encoding="utf-8")
    home = os.path.join(work, "home")
    args = [chromium, "--headless", "--disable-gpu", "--no-first-run", "--disable-extensions",
            "--disable-background-networking", "--disable-component-update", "--force-color-profile=srgb",
            "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=127.0.0.1:9",
            "--virtual-time-budget=5000", "--dump-dom", "file://" + str(page)]
    if os.geteuid() == 0:
        args.insert(1, "--no-sandbox")
    env = dict(os.environ, HOME=home, XDG_CONFIG_HOME=home, XDG_CACHE_HOME=home)
    dom = subprocess.run(args, capture_output=True, check=True, timeout=120, env=env).stdout.decode()
    start = dom.index('<pre id="o">') + len('<pre id="o">')
    body = dom[start:dom.index("</pre>", start)]
    size, data = body.split(":", 1)
    w, h = (int(v) for v in size.split("x"))
    rgba = np.frombuffer(base64.b64decode(data), dtype=np.uint8).reshape(h, w, 4)
    return np.ascontiguousarray(rgba[:, :, :3])


def contrast(rgb):
    """Проход с повышенной контрастностью: серый и степенная кривая у белого."""
    gray = rgb.astype(np.float32) @ np.array([0.299, 0.587, 0.114], dtype=np.float32)
    out = 255.0 * np.power(gray / 255.0, CONTRAST_GAMMA)
    g = np.clip(out, 0, 255).astype(np.uint8)
    return np.repeat(g[:, :, None], 3, axis=2)


def resize(img, h, w):
    """Билинейное масштабирование numpy (как cv2.INTER_LINEAR, углы пикселей)."""
    sh, sw = img.shape[:2]
    ys = (np.arange(h, dtype=np.float32) + 0.5) * sh / h - 0.5
    xs = (np.arange(w, dtype=np.float32) + 0.5) * sw / w - 0.5
    ys, xs = np.clip(ys, 0, sh - 1), np.clip(xs, 0, sw - 1)
    y0, x0 = np.floor(ys).astype(int), np.floor(xs).astype(int)
    y1, x1 = np.minimum(y0 + 1, sh - 1), np.minimum(x0 + 1, sw - 1)
    wy, wx = (ys - y0)[:, None, None], (xs - x0)[None, :, None]
    f = img.astype(np.float32)
    top = f[y0][:, x0] * (1 - wx) + f[y0][:, x1] * wx
    bot = f[y1][:, x0] * (1 - wx) + f[y1][:, x1] * wx
    return top * (1 - wy) + bot * wy


def write_pnm(path, rgb):
    h, w = rgb.shape[:2]
    with open(path, "wb") as f:
        f.write(b"P6\n%d %d\n255\n" % (w, h))
        f.write(rgb.tobytes())


# --- PaddleOCR в ONNX -----------------------------------------------------------

def components(mask):
    """Связные области бинарной карты (4-связность): списки (y, x) по меткам."""
    h, w = mask.shape
    labels = np.zeros((h, w), dtype=np.int32)
    out, n = [], 0
    ys, xs = np.nonzero(mask)
    for y, x in zip(ys, xs):
        if labels[y, x]:
            continue
        n += 1
        stack, pts = [(y, x)], []
        labels[y, x] = n
        while stack:
            cy, cx = stack.pop()
            pts.append((cy, cx))
            for ny, nx in ((cy - 1, cx), (cy + 1, cx), (cy, cx - 1), (cy, cx + 1)):
                if 0 <= ny < h and 0 <= nx < w and mask[ny, nx] and not labels[ny, nx]:
                    labels[ny, nx] = n
                    stack.append((ny, nx))
        out.append(np.array(pts))
    return out


def hull(points):
    """Выпуклая оболочка (монотонная цепь Эндрю), против часовой стрелки."""
    pts = sorted(set(map(tuple, points)))
    if len(pts) < 3:
        return np.array(pts, dtype=np.float64)

    def half(seq):
        out = []
        for p in seq:
            while len(out) >= 2 and (out[-1][0] - out[-2][0]) * (p[1] - out[-2][1]) - (out[-1][1] - out[-2][1]) * (p[0] - out[-2][0]) <= 0:
                out.pop()
            out.append(p)
        return out[:-1]
    return np.array(half(pts) + half(pts[::-1]), dtype=np.float64)


def min_area_rect(points):
    """Прямоугольник наименьшей площади вокруг точек (как cv2.minAreaRect): 4 угла."""
    hp = hull(points)
    if len(hp) < 3:
        x0, y0 = points.min(axis=0)
        x1, y1 = points.max(axis=0) + 1
        return np.array([[x0, y0], [x1, y0], [x1, y1], [x0, y1]], dtype=np.float64)
    best = None
    for i in range(len(hp)):
        e = hp[(i + 1) % len(hp)] - hp[i]
        u = e / np.linalg.norm(e)
        v = np.array([-u[1], u[0]])
        a, b = hp @ u, hp @ v
        area = (a.max() - a.min()) * (b.max() - b.min())
        if best is None or area < best[0]:
            best = (area, u, v, a.min(), a.max(), b.min(), b.max())
    _, u, v, a0, a1, b0, b1 = best
    return np.array([u * a0 + v * b0, u * a1 + v * b0, u * a1 + v * b1, u * a0 + v * b1])


def order(q):
    """Углы по порядку: левый верхний, правый верхний, правый нижний, левый нижний."""
    s, d = q.sum(axis=1), q[:, 1] - q[:, 0]
    return np.array([q[s.argmin()], q[d.argmin()], q[s.argmax()], q[d.argmax()]])


def warp(img, q):
    """Вырезка повёрнутой строки в прямоугольник (билинейная выборка)."""
    w = int(round(max(np.linalg.norm(q[1] - q[0]), np.linalg.norm(q[2] - q[3]))))
    h = int(round(max(np.linalg.norm(q[3] - q[0]), np.linalg.norm(q[2] - q[1]))))
    if w < 3 or h < 3:
        return None
    u = (np.arange(w) + 0.5) / w
    v = (np.arange(h) + 0.5) / h
    top = q[0][None, :] + u[:, None] * (q[1] - q[0])[None, :]
    bot = q[3][None, :] + u[:, None] * (q[2] - q[3])[None, :]
    grid = top[None, :, :] + v[:, None, None] * (bot - top)[None, :, :] - 0.5
    sh, sw = img.shape[:2]
    gx, gy = np.clip(grid[..., 0], 0, sw - 1), np.clip(grid[..., 1], 0, sh - 1)
    x0, y0 = np.floor(gx).astype(int), np.floor(gy).astype(int)
    x1, y1 = np.minimum(x0 + 1, sw - 1), np.minimum(y0 + 1, sh - 1)
    wx, wy = (gx - x0)[..., None], (gy - y0)[..., None]
    f = img.astype(np.float32)
    out = (f[y0, x0] * (1 - wx) + f[y0, x1] * wx) * (1 - wy) + (f[y1, x0] * (1 - wx) + f[y1, x1] * wx) * wy
    if h >= 1.5 * w:
        out = np.rot90(out)  # вертикальная строка, как в PaddleOCR
    return out.astype(np.uint8)


class Paddle:
    def __init__(self, det, rec, threads, upscale=1, det_limit=DET_LIMIT):
        so = ort.SessionOptions()
        so.intra_op_num_threads = threads
        so.inter_op_num_threads = 1
        self.det = ort.InferenceSession(det, so, providers=PROVIDERS)
        self.rec = ort.InferenceSession(rec, so, providers=PROVIDERS)
        # Таблица символов в метаданных модели (RapidOCR); последняя пустая
        # строка — место пробела (use_space_char в PaddleOCR).
        chars = self.rec.get_modelmeta().custom_metadata_map["character"].rstrip("\n").split("\n")
        classes = self.rec.get_outputs()[0].shape[-1]
        if classes == len(chars) + 2:
            chars.append(" ")
        if classes != len(chars) + 1:
            raise SystemExit(f"{rec}: классов {classes}, символов {len(chars)}")
        self.chars = chars
        self.ort = 0.0  # время в onnxruntime (без пред- и постобработки на Python)
        # upscale — увеличение растра перед распознаванием (мелкий текст 7 px,
        # small-01); рамки возвращаются в пикселях исходного растра.
        self.upscale, self.det_limit = upscale, det_limit

    def boxes(self, rgb):
        """Строки текста: повёрнутые прямоугольники (4 угла в пикселях исходного растра)."""
        h, w = rgb.shape[:2]
        r = min(1.0, self.det_limit / max(h, w))
        rh, rw = max(32, int(round(h * r / 32)) * 32), max(32, int(round(w * r / 32)) * 32)
        x = resize(rgb[:, :, ::-1], rh, rw) / 255.0  # BGR, как cv2 в PaddleOCR
        x = (x - np.array([0.485, 0.456, 0.406])) / np.array([0.229, 0.224, 0.225])
        t0 = time.perf_counter()
        prob = self.det.run(None, {"x": x.transpose(2, 0, 1)[None].astype(np.float32)})[0][0, 0]
        self.ort += time.perf_counter() - t0
        out = []
        for pts in components(prob > DET_THRESH):
            if len(pts) < 10 or prob[pts[:, 0], pts[:, 1]].mean() < BOX_THRESH:
                continue
            rect = min_area_rect(pts[:, ::-1].astype(np.float64))
            e1, e2 = np.linalg.norm(rect[1] - rect[0]), np.linalg.norm(rect[3] - rect[0])
            if min(e1, e2) < 2:
                continue
            pc = pyclipper.PyclipperOffset()
            pc.AddPath([tuple(p) for p in np.round(rect).astype(int)], pyclipper.JT_ROUND, pyclipper.ET_CLOSEDPOLYGON)
            poly = pc.Execute(e1 * e2 * UNCLIP / (2 * (e1 + e2)))
            if not poly:
                continue
            quad = min_area_rect(np.array(poly[0], dtype=np.float64)) / [rw / w, rh / h]
            quad[:, 0], quad[:, 1] = np.clip(quad[:, 0], 0, w), np.clip(quad[:, 1], 0, h)
            out.append(order(quad))
        return out

    def run(self, rgb):
        if self.upscale > 1:
            h, w = rgb.shape[:2]
            rgb = np.clip(resize(rgb, h * self.upscale, w * self.upscale), 0, 255).astype(np.uint8)
        lines = []
        for q in self.boxes(rgb):
            crop = warp(rgb, q)
            if crop is None:
                continue
            text, score = self.recognize(crop)
            if text.strip():
                x0, y0 = q.min(axis=0)
                x1, y1 = q.max(axis=0)
                k = self.upscale
                lines.append({"text": text, "score": round(score, 3),
                              "box": [int(x0 / k), int(y0 / k), int(math.ceil((x1 - x0) / k)), int(math.ceil((y1 - y0) / k))]})
        return lines

    def recognize(self, crop):
        h, w = crop.shape[:2]
        rw = min(REC_MAX_W, max(8, int(math.ceil(REC_H * w / h))))
        x = resize(crop[:, :, ::-1], REC_H, rw) / 255.0
        x = (x - 0.5) / 0.5
        t0 = time.perf_counter()
        p = self.rec.run(None, {"x": x.transpose(2, 0, 1)[None].astype(np.float32)})[0][0]
        self.ort += time.perf_counter() - t0
        idx, conf = p.argmax(axis=1), p.max(axis=1)
        text, scores, prev = [], [], 0
        for i, c in zip(idx, conf):
            if i != 0 and i != prev:
                text.append(self.chars[i - 1])
                scores.append(float(c))
            prev = i
        return "".join(text), (sum(scores) / len(scores) if scores else 0.0)


# --- Tesseract -------------------------------------------------------------------

def tesseract(rgb, work, tessdata, threads):
    path = os.path.join(work, "t.ppm")
    write_pnm(path, rgb)
    env = dict(os.environ, OMP_THREAD_LIMIT=str(threads))
    tsv = subprocess.run(["tesseract", path, "stdout", "--tessdata-dir", tessdata, "-l", "rus+eng", "--psm", "3",
                          "-c", "tessedit_create_tsv=1"],
                         capture_output=True, check=True, timeout=120, env=env).stdout.decode()
    words = {}
    for row in tsv.splitlines()[1:]:
        f = row.split("\t")
        if len(f) < 12 or f[0] != "5" or not f[11].strip():
            continue
        key = (int(f[2]), int(f[3]), int(f[4]))  # блок, абзац, строка
        x, y, w, h = (int(v) for v in f[6:10])
        words.setdefault(key, []).append((x, y, w, h, f[11], float(f[10])))
    lines = []
    for key in sorted(words):
        ws = sorted(words[key])
        x0, y0 = min(w[0] for w in ws), min(w[1] for w in ws)
        x1, y1 = max(w[0] + w[2] for w in ws), max(w[1] + w[3] for w in ws)
        lines.append({"text": " ".join(w[4] for w in ws), "score": round(sum(w[5] for w in ws) / len(ws) / 100, 3),
                      "box": [x0, y0, x1 - x0, y1 - y0]})
    return lines


# --- прогон ----------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-corpus", default="testdata/corpus/media")
    ap.add_argument("-models", required=True, help="каталог моделей ONNX")
    ap.add_argument("-tessdata", required=True, help="каталог tessdata_best")
    ap.add_argument("-chromium", default=os.environ.get("AISEC_CHROMIUM", ""))
    ap.add_argument("-threads", type=int, default=4)
    ap.add_argument("-repeat", type=int, default=3, help="повторов для замера времени (берётся медиана)")
    ap.add_argument("-engines", default="", help="кандидаты через запятую (пусто — все)")
    ap.add_argument("-out", required=True)
    a = ap.parse_args()
    if not a.chromium:
        raise SystemExit("нужен -chromium или AISEC_CHROMIUM")
    det = os.path.join(a.models, "PP-OCRv6_det_small.onnx")
    engines = {
        "paddle-eslav": Paddle(det, os.path.join(a.models, "eslav_PP-OCRv5_rec_mobile.onnx"), a.threads),
        "paddle-cyrillic": Paddle(det, os.path.join(a.models, "cyrillic_PP-OCRv5_rec_mobile.onnx"), a.threads),
        "paddle-v6": Paddle(det, os.path.join(a.models, "PP-OCRv6_rec_small.onnx"), a.threads),
        "paddle-eslav-x2": Paddle(det, os.path.join(a.models, "eslav_PP-OCRv5_rec_mobile.onnx"), a.threads,
                                  upscale=2, det_limit=2 * DET_LIMIT),
        "paddle-cyrillic-x2": Paddle(det, os.path.join(a.models, "cyrillic_PP-OCRv5_rec_mobile.onnx"), a.threads,
                                     upscale=2, det_limit=2 * DET_LIMIT),
    }
    names = list(engines) + ["tesseract"]
    if a.engines:
        names = [n for n in names if n in a.engines.split(",")]
    manifest = json.loads(pathlib.Path(a.corpus, "manifest.json").read_text(encoding="utf-8"))
    result = {"threads": a.threads, "cpus": sorted(os.sched_getaffinity(0)), "images": []}
    with tempfile.TemporaryDirectory() as work:
        for img in manifest["images"]:
            path = pathlib.Path(a.corpus, img["file"])
            rgb = raster(a.chromium, path, work)
            passes = {"ocr": rgb, "ocr_contrast": contrast(rgb)}
            entry = {"id": img["id"], "width": rgb.shape[1], "height": rgb.shape[0], "engines": {}}
            for name in names:
                runs = {}
                for p, r in passes.items():
                    times, ort_times = [], []
                    for _ in range(a.repeat):
                        t0 = time.perf_counter()
                        if name in engines:
                            engines[name].ort = 0.0
                            lines = engines[name].run(r)
                            ort_times.append(engines[name].ort)
                        else:
                            lines = tesseract(r, work, a.tessdata, a.threads)
                        times.append(time.perf_counter() - t0)
                    med = lambda v: round(sorted(v)[len(v) // 2] * 1000, 1)  # noqa: E731
                    runs[p] = {"lines": lines, "ms": med(times)}
                    if ort_times:
                        runs[p]["model_ms"] = med(ort_times)
                entry["engines"][name] = runs
            result["images"].append(entry)
            print(img["id"], {n: e["ocr"]["ms"] for n, e in entry["engines"].items()}, flush=True)
    pathlib.Path(a.out).write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
