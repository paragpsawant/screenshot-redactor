// Scan pipeline: OCR → rules + NER → pixel boxes; faces. Environment-agnostic (browser worker or Node).

import { findSpans, mergeSpans } from "./rules.js";

export const TEXT_CATEGORIES = new Set(["secrets", "contact", "financial", "government_id", "network",
  "person", "location", "dates"]);
const NER_CATEGORIES = new Set(["person", "location", "government_id", "financial"]);

/**
 * @param img        {data: RGBA, width, height}
 * @param engines    {ocr, faces?, ner?}
 * @param options    {categories: string[], customTerms: string[], useNer: boolean, onProgress?}
 * @returns {detections, lines, timings}
 */
export async function scan(img, engines, { categories, customTerms = [], useNer = true, onProgress = () => {} }) {
  const cats = new Set(categories);
  const terms = customTerms.filter((t) => t && t.trim());
  const timings = {};
  const detections = [];
  const add = (d) => detections.push({ id: detections.length + 1, ...d });
  let lines = [];

  if ([...cats].some((c) => TEXT_CATEGORIES.has(c)) || terms.length) {
    onProgress("Reading text…");
    let t = now();
    lines = await engines.ocr.run(img);
    timings.ocr = now() - t;

    const nerCats = new Set([...cats].filter((c) => NER_CATEGORIES.has(c)));
    const useModel = useNer && engines.ner && nerCats.size;
    if (useModel) onProgress("Looking for names and addresses…");
    t = now();
    for (const line of lines) {
      const ruleSpans = findSpans(line.text, [...cats], terms);
      const nerSpans = useModel ? await engines.ner.find(line.text, nerCats) : [];
      for (const s of mergeSpans(ruleSpans, nerSpans)) {
        add({ category: s.category, label: s.label, box: spanBox(line, s.start, s.end), score: s.score,
          source: s.source, text: line.text.slice(s.start, s.end) });
      }
    }
    timings.rules = now() - t;
  }

  if (cats.has("faces") && engines.faces) {
    onProgress("Looking for faces…");
    const t = now();
    for (const f of await engines.faces.detect(img)) {
      add({ category: "faces", label: "FACE", box: { x0: f.x0, y0: f.y0, x1: f.x1, y1: f.y1 }, score: f.score,
        source: "yunet", text: "" });
    }
    timings.faces = now() - t;
  }
  return { detections, lines, timings };
}

/** Pixel box covering line.text[start:end] with a small safety margin. */
export function spanBox(line, start, end, padChars = 0.35, padY = 0.08) {
  const { bounds, box } = line;
  const n = bounds.length || line.text.length;
  const b = bounds.length ? bounds : [...line.text].map((_, i) => [i / n, (i + 1) / n]);
  start = Math.max(0, Math.min(start, n - 1));
  end = Math.max(start + 1, Math.min(end, n));
  let t0 = b[start][0], t1 = b[end - 1][1];
  const charW = (t1 - t0) / Math.max(1, end - start);
  t0 = start > 0 ? Math.max(0, t0 - padChars * charW) : Math.min(0, t0 - padChars * charW);
  t1 = end < n ? Math.min(1, t1 + padChars * charW) : Math.max(1, t1 + padChars * charW);
  const w = box.x1 - box.x0, h = box.y1 - box.y0;
  return { x0: box.x0 + t0 * w, x1: box.x0 + t1 * w, y0: box.y0 - padY * h, y1: box.y1 + padY * h };
}

const now = () => (globalThis.performance ?? Date).now();
