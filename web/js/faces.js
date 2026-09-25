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

  /** Returns [{x0, y0, x1, y1, score}] in image pixels, padded to cover hair and chin. */
  async detect(img, { scoreThreshold = 0.7, nmsThreshold = 0.3, pad = 0.35 } = {}) {
    const { width: w, height: h } = img;
    const scale = SIZE / Math.max(w, h);
    const rw = Math.max(1, Math.round(w * scale));
    const rh = Math.max(1, Math.round(h * scale));
    const input = new Float32Array(3 * SIZE * SIZE);
    writeBGR(input, 0, resizeRegion(img, 0, 0, w, h, rw, rh), rw, rh, SIZE, { scale: 1, mean: 0, std: 1, dstH: SIZE });
    const out = await this.session.run({ [this.session.inputNames[0]]: new this.ort.Tensor("float32", input, [1, 3, SIZE, SIZE]) });
    const faces = decodeYuNet(out, scoreThreshold);
    return nms(faces, nmsThreshold).map((f) => {
      const x = f.x / scale, y = f.y / scale, fw = f.w / scale, fh = f.h / scale;
      return {
        x0: Math.max(0, x - fw * pad), y0: Math.max(0, y - fh * pad * 1.5),
        x1: Math.min(w, x + fw * (1 + pad)), y1: Math.min(h, y + fh * (1 + pad)), score: f.score,
      };
    });
  }
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
