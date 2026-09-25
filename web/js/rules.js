// Rule-based detection of secrets and PII in plain text (port of python/redactor/rules.py).
// Every rule yields character spans so they can be mapped back to pixels.

export const CATEGORIES = {
  secrets: "API keys, tokens, passwords, private keys",
  contact: "Emails and phone numbers",
  financial: "Credit cards, IBANs, bank accounts, crypto wallets",
  government_id: "SSNs, passports, driver licenses",
  network: "IP and MAC addresses",
  person: "People's names",
  location: "Street addresses",
  dates: "Dates of birth",
  faces: "Human faces",
  codes: "QR codes and barcodes",
};
export const DEFAULT_CATEGORIES = Object.keys(CATEGORIES);

// ---------------------------------------------------------------- validators

export function luhnOk(value) {
  const digits = [...value].filter((c) => c >= "0" && c <= "9").map(Number);
  if (digits.length < 13 || digits.length > 19 || new Set(digits).size === 1) return false;
  let total = 0;
  digits.reverse().forEach((d, i) => {
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    total += d;
  });
  return total % 10 === 0;
}

export function ibanOk(value) {
  const s = value.replace(/\s/g, "").toUpperCase();
  if (s.length < 15 || s.length > 34 || !/^[A-Z0-9]+$/.test(s)) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const c of rearranged) {
    const n = parseInt(c, 36);
    for (const d of String(n)) rem = (rem * 10 + Number(d)) % 97;
  }
  return rem === 1;
}

const phoneOk = (v) => {
  const n = (v.match(/\d/g) || []).length;
  return n >= 10 && n <= 15;
};

export function ipv4Ok(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p) || (p.length > 1 && p[0] === "0") || Number(p) > 255) return false;
  }
  return value !== "0.0.0.0";
}

export function ipv6Ok(value) {
  if ((value.match(/:/g) || []).length < 2) return false;
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const groups = (h) => (h === "" ? [] : h.split(":"));
  const head = groups(halves[0]);
  const tail = halves.length === 2 ? groups(halves[1]) : [];
  const all = [...head, ...tail];
  if (!all.every((g) => /^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  if (halves.length === 2) return all.length <= 7;
  return all.length === 8;
}

export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const c of value) counts.set(c, (counts.get(c) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function looksRandom(value) {
  const v = value.replace(/^=+|=+$/g, "");
  if (v.length < 20) return false;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((r) => r.test(v)).length;
  if (classes < 3) return false;
  if (/[A-Za-z]{12,}/.test(v)) return false; // CamelCaseIdentifiers, not secrets
  return shannonEntropy(v) >= 3.7;
}

const notMasked = (v) => Boolean(v) && !/^[*•●·xX.\-_]+$/.test(v);

function secretValueOk(value) {
  const v = value.toLowerCase();
  if (["http://", "https://", "${", "$(", "<", "{{", "%"].some((p) => v.startsWith(p))) return false;
  return notMasked(value) && !["none", "null", "true", "false", "undefined", "required"].includes(v);
}

// --------------------------------------------------------------------- rules

const ID_LABEL = String.raw`\s*(?:no\.?|num(?:ber)?|#)?\s*[:#]?\s*`;

function rule(label, category, pattern, group = 0, validator = null, flags = "", extra = {}) {
  return { label, category, re: new RegExp(pattern, `gd${flags}`), group, validator, ...extra };
}

// A capitalised name word (any script), excluding timestamp words and common UI/calendar words.
const NOT_TIME_WORD = String.raw`(?!(?:Yesterday|Today|Tomorrow|Now|Just|Edited|Sent|Seen|Read|Delivered|` +
  String.raw`Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|` +
  String.raw`Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|June|July|August|September|October|November|December|` +
  String.raw`Meeting|Standup|Sync|Call|Review|Lunch|Updated|Posted|Created|Modified|Last|Due|Starts?|Ends?|Daily|Weekly|Monthly|Team|Project|Sprint|Reminder|Event|Deadline|Break|Demo|Office|Hours|Planning|Retro|All)\b)`;
// Time words OCR sometimes glues onto a name ("KulkarniYesterday"); a name word stops before them.
const GLUE = String.raw`(?:Yesterday|Today|Tomorrow|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b`;
const NAME_WORD = NOT_TIME_WORD + String.raw`\p{Lu}(?:(?!${GLUE})[\p{L}\p{M}'’.\-])*`;
const PARTICLE = String.raw`(?:(?:de|da|di|du|van|von|der|den|del|la|le|bin|binti|al|el|ibn)\s+){0,2}`;
const NAME = `${NAME_WORD}(?:\\s+${PARTICLE}${NAME_WORD}){0,3}`;
const FULL_NAME = `${NAME_WORD}(?:\\s+${PARTICLE}${NAME_WORD}){1,3}`;
// "Yesterday 12:02 PM", "11:20 AM", "Mon 9:05", "9/24 3:41 PM", "Sep 24, 2026, 3:41 PM", "14:05"
export const TIMESTAMP = String.raw`(?:(?:Yesterday|Today|Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|Sat(?:urday)?|Sun(?:day)?|\d{1,2}\/\d{1,2}(?:\/\d{2,4})?|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2}(?:,? \d{4})?),?\s+)?\d{1,2}:\d{2}(?:\s?[AaPp]\.?[Mm]\.?)?`;
const NOT_GENERIC = String.raw`(?!(?:Team|All|Everyone|There|Folks|Guys|Friends|Sir|Madam|Support|Admin|Hi|Hello)\b)`;
/** A label whose value (the secret) is in the next OCR box, e.g. a form field. */
export const SECRET_LABEL_ONLY = /(?:^|\s)(?:pass(?:word|wd|code|phrase)?|pwd|secret|token|api[ _-]?key|access[ _-]?key|private[ _-]?key|client[ _-]?secret|pin|otp)\s*[:=]?\s*$/i;
export const NAME_ONLY = new RegExp(`^\\s*${NAME}\\s*$`, "u");
export const TIMESTAMP_ONLY = new RegExp(`^\\s*${TIMESTAMP}\\s*$`, "i");

// Order matters: earlier rules win when spans overlap.
export const RULES = [
  // secrets
  rule("PRIVATE_KEY", "secrets", String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
  rule("AWS_ACCESS_KEY", "secrets", String.raw`\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b`),
  rule("GITHUB_TOKEN", "secrets", String.raw`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b`),
  rule("AI_API_KEY", "secrets", String.raw`\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{20,}`),
  rule("HUGGINGFACE_TOKEN", "secrets", String.raw`\bhf_[A-Za-z0-9]{30,}\b`),
  rule("SLACK_TOKEN", "secrets", String.raw`\bxox[abposr]-[A-Za-z0-9-]{10,}`),
  rule("GOOGLE_API_KEY", "secrets", String.raw`\bAIza[0-9A-Za-z_\-]{35}\b`),
  rule("STRIPE_KEY", "secrets", String.raw`\b(?:sk|rk)_(?:[l1I]ive|test)_[0-9a-zA-Z]{16,}\b`), // OCR reads l as 1
  rule("JWT", "secrets", String.raw`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
  rule("CONNECTION_STRING_KEY", "secrets",
    String.raw`\b(?:AccountKey|SharedAccessKey|SharedAccessSignature|sig)=([A-Za-z0-9+/%=]{16,})`, 1),
  rule("BEARER_TOKEN", "secrets", String.raw`\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)`, 1, null, "i"),
  rule("URL_PASSWORD", "secrets", String.raw`\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@`, 1),
  rule("URL_TOKEN", "secrets",
    String.raw`[?&](?:token|key|api_?key|sig|signature|access_token|auth|code|secret|password)=([^&\s]{8,})`,
    1, null, "i"),
  // Matches `password: x`, `API_KEY=x`, `AWS_SECRET_ACCESS_KEY=x`, `"client_secret": "x"`...
  rule("PASSWORD_OR_SECRET", "secrets",
    String.raw`(?<![A-Za-z])(?:pass(?:word|wd|code|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|` +
    String.raw`private[_-]?key|client[_-]?secret|credentials?)(?:[_-][A-Za-z0-9]+)*` +
    String.raw`\s*["']?\s*[:=]\s*["']?([^\s"',;]{4,})`,
    1, secretValueOk, "i", { extend: true }),
  // financial
  rule("CREDIT_CARD", "financial", String.raw`\b(?:\d[ -]?){12,18}\d\b`, 0, luhnOk),
  rule("IBAN", "financial", String.raw`\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b`, 0, ibanOk),
  rule("BANK_ACCOUNT", "financial", String.raw`\b(?:account|acct|a\/c)` + ID_LABEL + String.raw`(\d[\d -]{5,20}\d)\b`,
    1, null, "i"),
  rule("ROUTING_NUMBER", "financial", String.raw`\b(?:routing|aba)` + ID_LABEL + String.raw`(\d{9})\b`, 1, null, "i"),
  rule("CRYPTO_WALLET", "financial",
    String.raw`\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b`),
  // government ids
  rule("US_SSN", "government_id", String.raw`\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b`),
  rule("PASSPORT", "government_id", String.raw`\bpassport` + ID_LABEL + String.raw`([A-Z0-9]{6,9})\b`, 1, null, "i"),
  rule("DRIVER_LICENSE", "government_id",
    String.raw`\b(?:driver'?s?\s*licen[sc]e|DL)` + ID_LABEL + String.raw`([A-Z0-9-]{5,15})\b`, 1, null, "i"),
  // contact
  rule("EMAIL", "contact", String.raw`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
  rule("PHONE", "contact", String.raw`\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b`, 0, phoneOk),
  rule("PHONE", "contact", String.raw`(?:\(\d{3}\)\s?|\b\d{3}[\s.-])\d{3}[\s.-]\d{4}\b`, 0, phoneOk),
  // people: chat headers ("Parag Sawant  Yesterday 12:02 PM"), @mentions, greetings, "From: …" labels
  rule("PERSON", "person", String.raw`^\s*(${FULL_NAME})(?:\s*\([^)]{1,40}\))?(?:\s+|(?=${GLUE}))${TIMESTAMP}\s*$`, 1, null, "u"),
  rule("PERSON", "person", String.raw`(?<![\w.])@(${NAME})`, 1, null, "u"),
  rule("PERSON", "person",
    String.raw`\b(?:Hi|Hello|Hey|Dear|Thanks|Thank you|Cheers|Regards|Best),?\s+${NOT_GENERIC}(${NAME_WORD}(?:\s+${NAME_WORD})?)`,
    1, null, "u"),
  rule("PERSON", "person",
    String.raw`\b(?:From|To|Cc|Bcc|Sender|Recipient|Name|Full name|Owner|Assignee|Author|Contact|Signed by)\s*:\s*${NOT_GENERIC}(${NAME})`,
    1, null, "u"),
  // dates
  rule("DATE_OF_BIRTH", "dates",
    String.raw`\b(?:dob|d\.o\.b\.?|date of birth|birth\s*date|born)\s*[:#-]?\s*` +
    String.raw`(\d{4}-\d{2}-\d{2}|[0-3]?\d[/.-][0-3]?\d[/.-](?:19|20)?\d{2}|[A-Za-z]{3,9}\.? \d{1,2},? \d{4})`,
    1, null, "i"),
  // network
  rule("MAC_ADDRESS", "network", String.raw`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`),
  rule("IP_ADDRESS", "network", String.raw`\b(?:\d{1,3}\.){3}\d{1,3}\b`, 0, ipv4Ok),
  rule("IP_ADDRESS", "network", String.raw`(?<![\w:])[0-9A-Fa-f:]{6,39}(?![\w:])`, 0, ipv6Ok),
];

const TOKEN = /[A-Za-z0-9+/_\-]{20,}={0,2}/g;
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Does a space-separated chunk look like more of a secret rather than an ordinary word? */
export function secretLikeChunk(chunk) {
  if (chunk.length < 3) return false;
  if (/\d/.test(chunk) || /[^\p{L}\p{M}]/u.test(chunk)) return true; // digits or symbols
  return /\p{Ll}/u.test(chunk) && /\p{Lu}/u.test(chunk) && !/^\p{Lu}\p{Ll}+$/u.test(chunk); // xQrTz, not "Thanks"
}

/**
 * Passwords can contain spaces, and OCR sometimes inserts one into long values, so keep
 * covering following chunks that look secret-like ("password: hK3#9vLp jfn2n2mcnkc2").
 */
export function extendSecret(text, end, maxChunks = 4) {
  for (let i = 0; i < maxChunks; i++) {
    const m = /^ {1,2}([^\s"',;]+)/.exec(text.slice(end));
    if (!m || !secretLikeChunk(m[1])) break;
    end += m[0].length;
  }
  return end;
}

/**
 * Return non-overlapping sensitive spans {start, end, label, category, score, source} in `text`.
 */
export function findSpans(text, categories = null, customTerms = []) {
  const wanted = categories ? new Set(categories) : null;
  const candidates = [];
  const add = (span, prio) => {
    if (span.end > span.start && (!wanted || wanted.has(span.category) || span.category === "custom")) {
      candidates.push({ ...span, prio });
    }
  };

  customTerms.map((t) => t.trim()).filter(Boolean).forEach((term, i) => {
    for (const m of text.matchAll(new RegExp(escapeRe(term), "gi"))) {
      add({ start: m.index, end: m.index + m[0].length, label: "CUSTOM", category: "custom", score: 1, source: "rule" },
        -1000 + i);
    }
  });

  RULES.forEach((r, prio) => {
    if (wanted && !wanted.has(r.category)) return;
    r.re.lastIndex = 0;
    for (const m of text.matchAll(r.re)) {
      const value = m[r.group];
      if (!value || (r.validator && !r.validator(value))) continue;
      let [start, end] = m.indices[r.group];
      if (r.extend) end = extendSecret(text, end);
      add({ start, end, label: r.label, category: r.category, score: 1, source: "rule" }, prio);
    }
  });

  if (!wanted || wanted.has("secrets")) {
    for (const m of text.matchAll(TOKEN)) {
      if (looksRandom(m[0])) {
        add({ start: m.index, end: m.index + m[0].length, label: "POSSIBLE_SECRET", category: "secrets",
          score: 0.7, source: "rule" }, RULES.length);
      }
    }
  }
  return resolveOverlaps(candidates);
}

export function resolveOverlaps(spans) {
  const ordered = [...spans].sort((a, b) => a.prio - b.prio || (b.end - b.start) - (a.end - a.start) || a.start - b.start);
  const kept = [];
  for (const s of ordered) {
    if (kept.every((k) => s.end <= k.start || s.start >= k.end)) kept.push(s);
  }
  return kept.sort((a, b) => a.start - b.start).map(({ prio, ...s }) => s);
}

/** Add NER spans that don't overlap rule spans (rules are more precise). */
export function mergeSpans(ruleSpans, nerSpans) {
  const kept = [...ruleSpans];
  for (const s of nerSpans) {
    if (kept.every((k) => s.end <= k.start || s.start >= k.end)) kept.push(s);
  }
  return kept.sort((a, b) => a.start - b.start);
}

// ------------------------------------------------------------------ display

const ACRONYMS = new Set(["IP", "AWS", "URL", "SSN", "US", "IBAN", "JWT", "MAC", "QR", "AI", "API"]);
const SPECIAL = { GITHUB: "GitHub", HUGGINGFACE: "Hugging Face" };

export const prettyLabel = (label) =>
  label.split("_").map((w) => (ACRONYMS.has(w) ? w : SPECIAL[w] ?? w[0] + w.slice(1).toLowerCase())).join(" ");

/** Show just enough of a value to recognise it, never the whole thing. */
export function maskPreview(text) {
  const t = (text || "").trim();
  if (t.length < 8) return "•".repeat(t.length);
  const keep = t.length < 20 ? 2 : 4;
  return t.slice(0, keep) + "•".repeat(Math.min(8, t.length - keep));
}
