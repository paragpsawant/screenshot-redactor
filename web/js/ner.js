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
    const spans = groupEntities(preds, offsets, text)
      .map((g) => (g.type === "ORGANIZATION" && looksLikePersonInContext(text, g.start, g.end) ? { ...g, type: "PERSON" } : g));
    return [...spans, ...coordinatedNames(text, spans.filter((g) => g.type === "PERSON" && g.score >= threshold))]
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
    ({ start, end } = toWordBoundaries(text, start, end)); // "Saw" (subword) -> "Sawant"
    if (g.type === "LOCATION") ({ start, end } = extendAddress(text, start, end));
    if (g.type === "PERSON") ({ start, end } = trimToNameWords(text, start, end)); // "ping Priya Raman" -> "Priya Raman"
    while (end > start && /[\s,.;:]/.test(text[end - 1])) end--;
    return { type: g.type, start, end, score: g.scores.reduce((a, b) => a + b, 0) / g.scores.length };
  }).filter((g) => g.end > g.start);
}

/**
 * Title-case names listed right next to a detected person ("Mei-Ling or Kwame", "Chen, Olga and
 * Sid") are people too; the model often tags only some items of such lists.
 */
export function coordinatedNames(text, persons) {
  const TITLE = String.raw`\p{Lu}[\p{Ll}\p{M}'’\-]+`;
  const next = new RegExp(String.raw`^(?:\s*,\s*|\s+(?:and|or|&)\s+|\s*,\s*(?:and|or)\s+)(${TITLE}(?:\s+${TITLE})?)`, "u");
  const found = [];
  const taken = (s, e) => [...persons, ...found].some((p) => s < p.end && e > p.start);
  for (const p of persons) {
    let end = p.end;
    for (let i = 0; i < 4; i++) {
      const m = next.exec(text.slice(end));
      if (!m || ORG_SUFFIX.test(m[1])) break;
      const s = end + m[0].length - m[1].length, e = end + m[0].length;
      const tail = text.slice(e);
      if (/^\s+(?:Ltd|Inc|LLC|Corp|GmbH)\b/.test(tail)) break;
      if (!taken(s, e)) found.push({ type: "PERSON", start: s, end: e, score: p.score });
      end = e;
    }
  }
  return found;
}

const WORD_CHAR = /[\p{L}\p{M}\p{N}'’\-]/u;

const PERSON_CUES = new Set(["with", "and", "or", "ask", "asked", "ping", "cc", "tell", "told", "call", "called",
  "meet", "met", "thanks", "thank", "from", "by", "dear", "hi", "hey", "hello", "via", "for", "to", "per", "@"]);
const ORG_SUFFIX = /\b(?:Inc|LLC|Ltd|Corp|Corporation|Co|GmbH|AG|SA|PLC|University|College|Bank|Group|Labs?|Team|Foundation|Institute|Hospital|Clinic|Agency|Department|Dept|Ministry|Services|Solutions|Technologies|Systems|Software)\b\.?/;

/**
 * The small PII model often tags uncommon first names ("Aarav", "Mei-Ling") as ORGANIZATION.
 * Treat such a span as a person when it is 1–3 title-case words right after a person cue word.
 */
export function looksLikePersonInContext(text, start, end) {
  const span = text.slice(start, end).trim();
  const words = span.split(/\s+/);
  if (!words.length || words.length > 3 || ORG_SUFFIX.test(span)) return false;
  if (!words.every((w) => /^\p{Lu}[\p{Ll}\p{M}'’\-]+$/u.test(w) || /^\p{Lo}+$/u.test(w))) return false;
  const prev = /([\p{L}@]+)[\s,]*$/u.exec(text.slice(0, start));
  return Boolean(prev && PERSON_CUES.has(prev[1].toLowerCase()));
}

/** Expand a span so it never starts or ends in the middle of a word. */
export function toWordBoundaries(text, start, end) {
  while (start > 0 && WORD_CHAR.test(text[start - 1]) && WORD_CHAR.test(text[start])) start--;
  while (end < text.length && WORD_CHAR.test(text[end]) && WORD_CHAR.test(text[end - 1])) end++;
  return { start, end };
}

/** Drop lowercase words at the edges of a person span; names are capitalised in screenshots. */
export function trimToNameWords(text, start, end) {
  const words = [...text.slice(start, end).matchAll(/\S+/g)];
  const isName = (w) => /^\p{Lu}/u.test(w[0]) || /^\p{Lo}/u.test(w[0]);
  let i = 0, j = words.length - 1;
  while (i <= j && !isName(words[i])) i++;
  while (j >= i && !isName(words[j])) j--;
  if (i > j) return { start, end }; // all lowercase (e.g. OCR'd handle): keep the model's span
  return { start: start + words[i].index, end: start + words[j].index + words[j][0].length };
}

/** Grow an address span over partially-tagged numbers and a trailing "ST 12345" / ZIP code. */
export function extendAddress(text, start, end) {
  while (start > 0 && /\d/.test(text[start - 1])) start--;
  while (end < text.length && /[\dA-Za-z]/.test(text[end]) && /[\dA-Za-z]/.test(text[end - 1])) end++;
  const tail = /^,?\s*(?:[A-Z]{2}\s+)?\d{5}(?:-\d{4})?\b/.exec(text.slice(end));
  if (tail) end += tail[0].length;
  return { start, end };
}
