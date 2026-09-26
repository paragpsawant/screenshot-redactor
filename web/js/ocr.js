// Text detection + recognition with PP-OCRv6 (same models as RapidOCR), ported to JS.
// `ort` is injected so this runs with onnxruntime-web (browser) or onnxruntime-node (tests).

import { cropImage, resizeRegion, rotateImage90, writeBGR } from "./image.js";

const DET = { limitSideLen: 736, maxSideLen: 2000, thresh: 0.3, boxThresh: 0.5, unclipRatio: 1.6, minSize: 3 };
const REC = { height: 48, baseWidth: 320, batch: 6, minScore: 0.5 };
const TILE = { size: 1800, overlap: 96 };

export class OCR {
  constructor(ort, det, rec, keys) {
    this.ort = ort;
    this.det = det;
    this.rec = rec;
    this.keys = ["blank", ...keys, " "];
  }

  static async create(ort, loadBytes, loadJson, options = {}) {
    const [detBytes, recBytes, keys] = await Promise.all([
      loadBytes("ocr_det.onnx"), loadBytes("ocr_rec.onnx"), loadJson("ocr_keys.json"),
    ]);
    const opts = { executionProviders: ["wasm"], graphOptimizationLevel: "all", ...options };
    const [det, rec] = await Promise.all([
      ort.InferenceSession.create(detBytes, opts), ort.InferenceSession.create(recBytes, opts),
    ]);
    return new OCR(ort, det, rec, keys);
  }

  /** Returns [{text, score, box:{x0,y0,x1,y1}, bounds:[[t0,t1] per UTF-16 unit]}] in image pixels. */
  async run(img) {
    const lines = [];
    const tiles = imageTiles(img);
    const rotateTiles = tiles.length <= 4;
    for (const tile of tiles) {
      lines.push(...(await this.runSingle(tile)).map((l) => offsetLine(l, tile.offsetX, tile.offsetY)));
      if (!rotateTiles) continue;
      for (const clockwise of [true, false]) {
        const rotated = rotateImage90(tile, clockwise);
        const rotatedLines = await this.runSingle(rotated);
        lines.push(...rotatedLines.map((l) => offsetLine(mapRotatedLine(l, tile.width, tile.height, clockwise),
          tile.offsetX, tile.offsetY)));
      }
    }
    return dedupeLines(lines);
  }

  async runSingle(img) {
    const boxes = await this.detect(img);
    if (!boxes.length) return [];
    const lines = await this.recognize(img, boxes);
    return lines.filter((l) => l.text.trim() && l.score >= REC.minScore);
  }

  async detect(img) {
    const { width: w, height: h } = img;
    let ratio = Math.min(1, DET.maxSideLen / Math.max(w, h));
    if (Math.min(w, h) * ratio < DET.limitSideLen) {
      // Upscale short images so small text is detectable, but keep the long side bounded for speed.
      ratio = Math.max(ratio, Math.min(DET.limitSideLen / Math.min(w, h), DET.maxSideLen / Math.max(w, h)));
    }

    const rw = Math.max(32, Math.round(Math.trunc(w * ratio) / 32) * 32);
    const rh = Math.max(32, Math.round(Math.trunc(h * ratio) / 32) * 32);
    const rgba = resizeRegion(img, 0, 0, w, h, rw, rh);
    const input = new Float32Array(3 * rw * rh);
    writeBGR(input, 0, rgba, rw, rh, rw);
    const out = await this.det.run({ [this.det.inputNames[0]]: new this.ort.Tensor("float32", input, [1, 3, rh, rw]) });
    const pred = out[this.det.outputNames[0]].data;
    return sortBoxes(dbPostprocess(pred, rw, rh, w, h));
  }

  async recognize(img, boxes) {
    const crops = boxes.map((b) => ({ ...b, w: b.x1 - b.x0, h: b.y1 - b.y0 }));
    const order = crops.map((c, i) => i).sort((a, b) => crops[a].w / crops[a].h - crops[b].w / crops[b].h);
    const results = new Array(crops.length);
    const H = REC.height;
    for (let s = 0; s < order.length; s += REC.batch) {
      const idx = order.slice(s, s + REC.batch);
      const maxRatio = Math.max(REC.baseWidth / H, ...idx.map((i) => crops[i].w / crops[i].h));
      const W = Math.trunc(H * maxRatio);
      const input = new Float32Array(idx.length * 3 * H * W);
      const resizedW = idx.map((i, n) => {
        const c = crops[i];
        const rw = Math.min(W, Math.ceil(H * (c.w / c.h)));
        const rgba = resizeRegion(img, c.x0, c.y0, c.w, c.h, rw, H);
        writeBGR(input, n * 3 * H * W, rgba, rw, H, W);
        return rw;
      });
      const out = await this.rec.run({ [this.rec.inputNames[0]]: new this.ort.Tensor("float32", input, [idx.length, 3, H, W]) });
      const probs = out[this.rec.outputNames[0]];
      const [, T, C] = probs.dims;
      idx.forEach((i, n) => {
        const dec = ctcDecode(probs.data, n * T * C, T, C, this.keys);
        const c = crops[i];
        results[i] = {
          text: dec.text,
          score: dec.score,
          box: { x0: c.x0, y0: c.y0, x1: c.x1, y1: c.y1 },
          bounds: charBounds(dec, T, W, resizedW[n]),
        };
      });
    }
    return results;
  }
}

function imageTiles(img) {
  if (Math.max(img.width, img.height) <= DET.maxSideLen) return [{ ...img, offsetX: 0, offsetY: 0 }];
  const xs = tileStarts(img.width);
  const ys = tileStarts(img.height);
  const out = [];
  for (const y of ys) {
    for (const x of xs) {
      const w = Math.min(TILE.size, img.width - x);
      const h = Math.min(TILE.size, img.height - y);
      out.push(cropImage(img, x, y, w, h));
    }
  }
  return out;
}

function tileStarts(total) {
  if (total <= TILE.size) return [0];
  const step = TILE.size - TILE.overlap;
  const out = [];
  for (let v = 0; v + TILE.size < total; v += step) out.push(v);
  const last = total - TILE.size;
  if (out.at(-1) !== last) out.push(last);
  return out;
}

function offsetLine(line, dx, dy) {
  if (!dx && !dy) return line;
  return { ...line, box: { x0: line.box.x0 + dx, y0: line.box.y0 + dy, x1: line.box.x1 + dx, y1: line.box.y1 + dy } };
}

function mapRotatedLine(line, w, h, clockwise) {
  const b = line.box;
  const box = clockwise
    ? { x0: b.y0, y0: h - b.x1, x1: b.y1, y1: h - b.x0 }
    : { x0: w - b.y1, y0: b.x0, x1: w - b.y0, y1: b.x1 };
  return { ...line, box: normalizeBox(box, w, h), orientation: clockwise ? "cw" : "ccw" };
}

function normalizeBox(b, w, h) {
  return {
    x0: clamp(Math.min(b.x0, b.x1), 0, w),
    y0: clamp(Math.min(b.y0, b.y1), 0, h),
    x1: clamp(Math.max(b.x0, b.x1), 0, w),
    y1: clamp(Math.max(b.y0, b.y1), 0, h),
  };
}

function dedupeLines(lines) {
  const kept = [];
  for (const line of lines.sort((a, b) => b.score - a.score)) {
    if (!kept.some((k) => k.text === line.text && overlapRatio(k.box, line.box) > 0.75)) kept.push(line);
  }
  return kept.sort((a, b) => a.box.y0 - b.box.y0 || a.box.x0 - b.box.x0);
}

function overlapRatio(a, b) {
  const x = Math.max(0, Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0));
  const y = Math.max(0, Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0));
  const inter = x * y;
  const area = Math.min((a.x1 - a.x0) * (a.y1 - a.y0), (b.x1 - b.x0) * (b.y1 - b.y0));
  return area > 0 ? inter / area : 0;
}

/** DB (differentiable binarization) post-processing for axis-aligned screen text. */
export function dbPostprocess(pred, pw, ph, srcW, srcH, opts = DET) {
  const n = pw * ph;
  const bin = new Uint8Array(n);
  for (let i = 0; i < n; i++) bin[i] = pred[i] > opts.thresh ? 1 : 0;
  // 2×2 dilation (OpenCV anchor at the kernel centre → neighbours to the top-left).
  const mask = new Uint8Array(n);
  for (let y = 0; y < ph; y++) {
    for (let x = 0; x < pw; x++) {
      const i = y * pw + x;
      mask[i] = bin[i] | (x > 0 ? bin[i - 1] : 0) | (y > 0 ? bin[i - pw] : 0) | (x > 0 && y > 0 ? bin[i - pw - 1] : 0);
    }
  }
  // Integral image of the probability map for O(1) box scores.
  const integ = new Float64Array((pw + 1) * (ph + 1));
  for (let y = 0; y < ph; y++) {
    let row = 0;
    for (let x = 0; x < pw; x++) {
      row += pred[y * pw + x];
      integ[(y + 1) * (pw + 1) + x + 1] = integ[y * (pw + 1) + x + 1] + row;
    }
  }
  const boxMean = (x0, y0, x1, y1) => {
    const a = integ[y0 * (pw + 1) + x0], b = integ[y0 * (pw + 1) + x1 + 1];
    const c = integ[(y1 + 1) * (pw + 1) + x0], d = integ[(y1 + 1) * (pw + 1) + x1 + 1];
    return (d - b - c + a) / ((x1 - x0 + 1) * (y1 - y0 + 1));
  };

  const seen = new Uint8Array(n);
  const stack = new Int32Array(n);
  const boxes = [];
  for (let start = 0; start < n && boxes.length < 1000; start++) {
    if (!mask[start] || seen[start]) continue;
    let top = 0, minX = pw, minY = ph, maxX = 0, maxY = 0;
    stack[top++] = start;
    seen[start] = 1;
    while (top) {
      const i = stack[--top];
      const x = i % pw, y = (i - x) / pw;
      if (x < minX) minX = x;
      if (x > maxX) maxX = x;
      if (y < minY) minY = y;
      if (y > maxY) maxY = y;
      for (let dy = -1; dy <= 1; dy++) {
        const yy = y + dy;
        if (yy < 0 || yy >= ph) continue;
        for (let dx = -1; dx <= 1; dx++) {
          const xx = x + dx;
          if (xx < 0 || xx >= pw) continue;
          const j = yy * pw + xx;
          if (mask[j] && !seen[j]) {
            seen[j] = 1;
            stack[top++] = j;
          }
        }
      }
    }
    const bw = maxX - minX, bh = maxY - minY;
    if (Math.min(bw, bh) < opts.minSize) continue;
    const score = boxMean(minX, minY, maxX, maxY);
    if (score < opts.boxThresh) continue;
    const dist = (bw * bh * opts.unclipRatio) / (2 * (bw + bh));
    if (Math.min(bw, bh) + 2 * dist < opts.minSize + 2) continue;
    const sx = srcW / pw, sy = srcH / ph;
    const x0 = clamp(Math.round((minX - dist) * sx), 0, srcW - 1);
    const x1 = clamp(Math.round((maxX + dist) * sx), 0, srcW - 1);
    const y0 = clamp(Math.round((minY - dist) * sy), 0, srcH - 1);
    const y1 = clamp(Math.round((maxY + dist) * sy), 0, srcH - 1);
    if (x1 - x0 <= 3 || y1 - y0 <= 3) continue;
    boxes.push({ x0, y0, x1, y1, score });
  }
  return boxes;
}

/** Top-to-bottom, then left-to-right within a text row (RapidOCR's ordering). */
export function sortBoxes(boxes) {
  const byY = [...boxes].sort((a, b) => a.y0 - b.y0);
  let line = 0;
  byY.forEach((b, i) => {
    if (i > 0 && b.y0 - byY[i - 1].y0 >= 10) line++;
    b.line = line;
  });
  return byY.sort((a, b) => a.line - b.line || a.x0 - b.x0).map(({ line: _, ...b }) => b);
}

/** Greedy CTC decode of one sequence; keeps the timestep of every emitted character. */
export function ctcDecode(data, offset, T, C, keys) {
  let text = "";
  let probSum = 0;
  const cols = [];
  const lens = [];
  let prev = -1;
  for (let t = 0; t < T; t++) {
    const base = offset + t * C;
    let best = 0, bestP = data[base];
    for (let c = 1; c < C; c++) {
      if (data[base + c] > bestP) {
        bestP = data[base + c];
        best = c;
      }
    }
    if (best !== 0 && best !== prev) {
      const ch = keys[best] ?? "";
      text += ch;
      probSum += bestP;
      cols.push(t);
      lens.push(ch.length);
    }
    prev = best;
  }
  return { text, score: cols.length ? probSum / cols.length : 0, cols, lens };
}

/** Fractional [t0, t1] along the crop width for every UTF-16 unit of the decoded text. */
export function charBounds(dec, T, paddedW, resizedW) {
  const { cols, lens } = dec;
  if (!cols.length) return [];
  const stride = paddedW / T;
  const centers = cols.map((c) => clamp(((c + 0.5) * stride) / resizedW, 0, 1));
  const gaps = centers.slice(1).map((c, i) => c - centers[i]).filter((g) => g > 0).sort((a, b) => a - b);
  const half = (gaps.length ? gaps[Math.floor(gaps.length / 2)] : 1 / cols.length) / 2;
  const out = [];
  centers.forEach((c, i) => {
    const t0 = i === 0 ? Math.max(0, c - half) : (centers[i - 1] + c) / 2;
    const t1 = i === centers.length - 1 ? Math.min(1, c + half) : (c + centers[i + 1]) / 2;
    for (let k = 0; k < lens[i]; k++) out.push([t0, t1]);
  });
  return out;
}

const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
