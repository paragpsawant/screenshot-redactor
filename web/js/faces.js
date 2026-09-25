// Face detection with YuNet (OpenCV Zoo, MIT) — same model as the Python app.

import { resizeRegion, writeBGR } from "./image.js";

const SIZE = 640;
const STRIDES = [8, 16, 32];

export class FaceDetector {
  constructor(ort, session) {
    this.ort = ort;
    this.session = session;
  }

  static async create(ort, loadBytes, options = {}) {
    const session = await ort.InferenceSession.create(await loadBytes("yunet.onnx"),
      { executionProviders: ["wasm"], ...options });
    return new FaceDetector(ort, session);
  }

  /**
   * Returns [{x0, y0, x1, y1, score}] in image pixels, padded to cover hair and chin.
   * Runs once on the whole (downscaled) image for large faces, then on full-resolution
   * tiles so small faces — e.g. 40px chat avatars in a screenshot — are found too.
   */
  async detect(img, { scoreThreshold = 0.7, nmsThreshold = 0.3, pad = 0.35 } = {}) {
    const { width: w, height: h } = img;
    const found = await this.detectRegion(img, 0, 0, w, h, scoreThreshold);
    if (Math.max(w, h) > SIZE) {
      // Very large (e.g. 4K) screenshots: tile at half resolution to bound the work.
      const scale = Math.max(w, h) > 2600 ? 2 : 1;
      const tile = SIZE * scale, step = tile - 128 * scale;
      for (const y of tileStarts(h, tile, step)) {
        for (const x of tileStarts(w, tile, step)) {
          found.push(...await this.detectRegion(img, x, y, Math.min(tile, w - x), Math.min(tile, h - y), scoreThreshold));
        }
      }
    }
    return nms(found, nmsThreshold).map((f) => {
      // Small faces are usually chat/profile avatars: cover the whole avatar, not just the face.
      const p = f.w < 64 ? Math.max(pad, 0.55) : pad;
      return {
        x0: Math.max(0, f.x - f.w * p), y0: Math.max(0, f.y - f.h * p * 1.3),
        x1: Math.min(w, f.x + f.w * (1 + p)), y1: Math.min(h, f.y + f.h * (1 + p)), score: f.score,
      };
    });
  }

  /** Faces inside the region (sx, sy, sw, sh), in full-image pixel coordinates. */
  async detectRegion(img, sx, sy, sw, sh, scoreThreshold) {
    const scale = SIZE / Math.max(sw, sh);
    const rw = Math.max(1, Math.round(sw * scale));
    const rh = Math.max(1, Math.round(sh * scale));
    const input = new Float32Array(3 * SIZE * SIZE);
    writeBGR(input, 0, resizeRegion(img, sx, sy, sw, sh, rw, rh), rw, rh, SIZE, { scale: 1, mean: 0, std: 1, dstH: SIZE });
    const out = await this.session.run({ [this.session.inputNames[0]]: new this.ort.Tensor("float32", input, [1, 3, SIZE, SIZE]) });
    return decodeYuNet(out, scoreThreshold)
      .map((f) => ({ x: sx + f.x / scale, y: sy + f.y / scale, w: f.w / scale, h: f.h / scale, score: f.score }))
      // A tile edge can cut a face in half; the neighbouring tile (or the full pass) sees it whole.
      .filter((f) => f.w > 4 && f.h > 4);
  }
}

/** Start offsets covering [0, length) with windows of `tile` advancing by `step`. */
export function tileStarts(length, tile, step) {
  if (length <= tile) return [0];
  const starts = [];
  for (let s = 0; s + tile < length; s += step) starts.push(s);
  starts.push(length - tile);
  return starts;
}

export function decodeYuNet(out, scoreThreshold) {
  const faces = [];
  for (const s of STRIDES) {
    const cls = out[`cls_${s}`].data, obj = out[`obj_${s}`].data, bbox = out[`bbox_${s}`].data;
    const cols = SIZE / s, rows = SIZE / s;
    for (let r = 0; r < rows; r++) {
      for (let c = 0; c < cols; c++) {
        const i = r * cols + c;
        const score = Math.sqrt(Math.min(1, Math.max(0, cls[i])) * Math.min(1, Math.max(0, obj[i])));
        if (score < scoreThreshold) continue;
        const cx = (c + bbox[i * 4]) * s, cy = (r + bbox[i * 4 + 1]) * s;
        const bw = Math.exp(bbox[i * 4 + 2]) * s, bh = Math.exp(bbox[i * 4 + 3]) * s;
        faces.push({ x: cx - bw / 2, y: cy - bh / 2, w: bw, h: bh, score });
      }
    }
  }
  return faces;
}

export function nms(boxes, threshold) {
  const sorted = [...boxes].sort((a, b) => b.score - a.score);
  const kept = [];
  for (const b of sorted) {
    if (kept.every((k) => iou(k, b) <= threshold)) kept.push(b);
  }
  return kept;
}

function iou(a, b) {
  const ix = Math.max(0, Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x));
  const iy = Math.max(0, Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y));
  const inter = ix * iy;
  return inter / (a.w * a.h + b.w * b.h - inter || 1);
}
