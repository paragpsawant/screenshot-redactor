// Scan pipeline: OCR → rules + NER → pixel boxes; faces. Environment-agnostic (browser worker or Node).

import { SECRET_LABEL_ONLY, findSpans, mergeSpans } from "./rules.js";

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
    for (const row of groupRows(lines)) {
      const ruleSpans = findSpans(row.text, [...cats], terms);
      const nerSpans = useModel ? await engines.ner.find(row.text, nerCats) : [];
      for (const s of mergeSpans(ruleSpans, nerSpans)) {
        add({ category: s.category, label: s.label, box: rowSpanBox(row, s.start, s.end), score: s.score,
          source: s.source, text: row.text.slice(s.start, s.end) });
      }
    }
    if (cats.has("secrets")) {
      for (const { line } of labelledValues(lines, SECRET_LABEL_ONLY)) {
        if (!detections.some((d) => overlaps(d.box, line.box))) {
          add({ category: "secrets", label: "PASSWORD_OR_SECRET", box: spanBox(line, 0, line.text.length), score: 0.9,
            source: "rule", text: line.text });
        }
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

/**
 * For OCR boxes that are only a label (e.g. "Password:"), return the value box: the nearest box
 * to the right on the same row. Handles form layouts where label and field are far apart.
 */
export function labelledValues(lines, labelRe, maxGapInHeights = 20) {
  const out = [];
  for (const label of lines) {
    if (!labelRe.test(label.text)) continue;
    const h = label.box.y1 - label.box.y0;
    const candidates = lines.filter((l) => l !== label && l.box.x0 >= label.box.x1 - 0.5 * h &&
      l.box.x0 - label.box.x1 <= maxGapInHeights * h &&
      Math.min(l.box.y1, label.box.y1) - Math.max(l.box.y0, label.box.y0) >= 0.5 * Math.min(h, l.box.y1 - l.box.y0));
    candidates.sort((a, b) => a.box.x0 - b.box.x0);
    if (candidates[0] && candidates[0].text.trim().length >= 3) out.push({ label, line: candidates[0] });
  }
  return out;
}

const overlaps = (a, b) => Math.min(a.x1, b.x1) > Math.max(a.x0, b.x0) && Math.min(a.y1, b.y1) > Math.max(a.y0, b.y0);

/**
 * Join OCR boxes that sit on the same text row and are close together into one logical line,
 * so a value split from its label ("password:" | "hK3#9vLp") or a name split from its
 * timestamp is still read as one phrase. Returns [{text, parts: [{line, offset}]}].
 */
export function groupRows(lines, maxGapInHeights = 2.5) {
  const order = [...lines].sort((a, b) => a.box.x0 - b.box.x0);
  const rows = [];
  for (const line of order) {
    const h = line.box.y1 - line.box.y0;
    const row = rows.find((r) => {
      const last = r.parts.at(-1).line.box;
      const lh = last.y1 - last.y0;
      const overlap = Math.min(last.y1, line.box.y1) - Math.max(last.y0, line.box.y0);
      const gap = line.box.x0 - last.x1;
      return overlap >= 0.6 * Math.min(h, lh) && Math.abs(h - lh) <= 0.4 * Math.max(h, lh) &&
        gap >= -0.5 * h && gap <= maxGapInHeights * Math.max(h, lh);
    });
    if (row) {
      row.parts.push({ line, offset: row.text.length + 1 });
      row.text += " " + line.text;
    } else {
      rows.push({ text: line.text, parts: [{ line, offset: 0 }] });
    }
  }
  return rows.sort((a, b) => a.parts[0].line.box.y0 - b.parts[0].line.box.y0 || a.parts[0].line.box.x0 - b.parts[0].line.box.x0);
}

/** Pixel box covering row.text[start:end], which may span several OCR boxes. */
export function rowSpanBox(row, start, end) {
  let box = null;
  for (const { line, offset } of row.parts) {
    const s = Math.max(start, offset) - offset;
    const e = Math.min(end, offset + line.text.length) - offset;
    if (e <= s) continue;
    const b = spanBox(line, s, e);
    box = box ? { x0: Math.min(box.x0, b.x0), y0: Math.min(box.y0, b.y0), x1: Math.max(box.x1, b.x1), y1: Math.max(box.y1, b.y1) } : b;
  }
  return box ?? spanBox(row.parts[0].line, 0, 1);
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
