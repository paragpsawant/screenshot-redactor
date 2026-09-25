// Names / addresses / ID numbers with a small on-device PII token classifier
// (onnx-community/bert-small-pii-detection-ONNX, int8, bundled with the app).

const LABELS = {
  PERSON: ["PERSON", "person"],
  LOCATION: ["ADDRESS", "location"],
  US_SSN: ["US_SSN", "government_id"],
  US_PASSPORT: ["PASSPORT", "government_id"],
  US_DRIVER_LICENSE: ["DRIVER_LICENSE", "government_id"],
  US_BANK_NUMBER: ["BANK_ACCOUNT", "financial"],
};

export async function createNer(transformers, { localModelPath, wasmPaths, device } = {}) {
  const { pipeline, env } = transformers;
  env.allowRemoteModels = false;
  env.allowLocalModels = true;
  if (localModelPath) env.localModelPath = localModelPath;
  if (wasmPaths && env.backends?.onnx?.wasm) env.backends.onnx.wasm.wasmPaths = wasmPaths;
  const pipe = await pipeline("token-classification", "pii", { dtype: "q8", ...(device ? { device } : {}) });
  return new Ner(pipe);
}

export class Ner {
  constructor(pipe) {
    this.pipe = pipe;
  }

  /** Spans for one line of text, restricted to `categories`. */
  async find(text, categories, threshold = 0.5) {
    if (!text.trim()) return [];
    const tokens = this.pipe.tokenizer.tokenize(text);
    const offsets = alignTokens(text, tokens);
    const preds = await this.pipe(text);
    return groupEntities(preds, offsets, text)
      .filter((g) => g.score >= threshold && LABELS[g.type])
      .map((g) => ({ ...g, label: LABELS[g.type][0], category: LABELS[g.type][1] }))
      .filter((g) => categories.has(g.category))
      .filter((g) => g.category !== "location" || /\d/.test(text.slice(g.start, g.end))) // street addresses, not bare city names
      .map(({ start, end, label, category, score }) => ({ start, end, label, category, score, source: "ner" }));
  }
}

/** Map WordPiece tokens (lowercased, accent-stripped) back to [start, end) offsets in `text`. */
export function alignTokens(text, tokens) {
  const norm = [];
  for (let i = 0; i < text.length; i++) {
    for (const ch of text[i].toLowerCase().normalize("NFD")) {
      if (!/\p{Mn}/u.test(ch)) norm.push({ ch, i });
    }
  }
  let cursor = 0;
  return tokens.map((tok) => {
    const piece = tok.startsWith("##") ? tok.slice(2) : tok;
    while (cursor < norm.length && /\s/.test(norm[cursor].ch)) cursor++;
    if (piece === "[UNK]" || !piece) {
      const start = cursor;
      while (cursor < norm.length && !/\s/.test(norm[cursor].ch)) cursor++;
      return start < cursor ? [norm[start].i, norm[cursor - 1].i + 1] : null;
    }
    for (let skip = 0; skip <= 3 && cursor + skip < norm.length; skip++) {
      let ok = true;
      for (let k = 0; k < piece.length; k++) {
        if (norm[cursor + skip + k]?.ch !== piece[k]) {
          ok = false;
          break;
        }
      }
      if (ok) {
        const s = cursor + skip;
        cursor = s + piece.length;
        return [norm[s].i, norm[cursor - 1].i + 1];
      }
    }
    return null;
  });
}

/** Merge B-/I- token predictions into entity spans. */
export function groupEntities(preds, offsets, text) {
  const groups = [];
  let cur = null;
  for (const p of [...preds].sort((a, b) => a.index - b.index)) {
    const off = offsets[p.index - 1];
    if (!off) continue;
    const [prefix, type] = p.entity.includes("-") ? p.entity.split(/-(.+)/) : ["B", p.entity];
    const continues = cur && cur.type === type && p.index === cur.lastIndex + 1 &&
      (prefix === "I" || p.word.startsWith("##"));
    if (continues) {
      cur.end = off[1];
      cur.scores.push(p.score);
      cur.lastIndex = p.index;
    } else {
      cur = { type, start: off[0], end: off[1], scores: [p.score], lastIndex: p.index };
      groups.push(cur);
    }
  }
  // The model sometimes drops a token mid-entity ("CA [94]043"); rejoin pieces split by a tiny gap.
  const merged = [];
  for (const g of groups) {
    const prev = merged.at(-1);
    if (prev && prev.type === g.type && g.start - prev.end <= 3 && /^[\s\w,.'-]*$/.test(text.slice(prev.end, g.start))) {
      prev.end = g.end;
      prev.scores.push(...g.scores);
    } else merged.push({ ...g, scores: [...g.scores] });
  }
  return merged.map((g) => {
    let { start, end } = g;
    if (g.type === "LOCATION") ({ start, end } = extendAddress(text, start, end));
    while (end > start && /[\s,.;:]/.test(text[end - 1])) end--;
    return { type: g.type, start, end, score: g.scores.reduce((a, b) => a + b, 0) / g.scores.length };
  });
}

/** Grow an address span over partially-tagged numbers and a trailing "ST 12345" / ZIP code. */
export function extendAddress(text, start, end) {
  while (start > 0 && /\d/.test(text[start - 1])) start--;
  while (end < text.length && /[\dA-Za-z]/.test(text[end]) && /[\dA-Za-z]/.test(text[end - 1])) end++;
  const tail = /^,?\s*(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b/.exec(text.slice(end));
  if (tail) end += tail[0].length;
  return { start, end };
}
