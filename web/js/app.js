import { detectCodes } from "./codes.js";
import { CATEGORY_COLORS, renderRedacted, renderReview } from "./redact.js";
import { CATEGORIES, DEFAULT_CATEGORIES, maskPreview, prettyLabel } from "./rules.js";

const $ = (sel) => document.querySelector(sel);

const els = {
  drop: $("#drop"), file: $("#file"), workspace: $("#workspace"), status: $("#status"), engine: $("#engine"),
  list: $("#detections"), listEmpty: $("#detections-empty"), redacted: $("#redacted"), review: $("#review"),
  cats: $("#categories"), terms: $("#terms"), useNer: $("#use-ner"), styleNote: $("#style-note"),
  download: $("#download"), copy: $("#copy"), rescan: $("#rescan"), reset: $("#reset"),
  selectAll: $("#select-all"), selectNone: $("#select-none"), tabs: document.querySelectorAll("[role=tab]"),
};

const state = { source: null, detections: [], selected: new Set(), style: "black box", nextId: 1, scanId: 0,
  busy: false, fileName: "screenshot" };

// ------------------------------------------------------------------ worker

const worker = new Worker(new URL("./worker.js", import.meta.url), { type: "module" });
const pending = new Map();
const downloads = new Map();

worker.onmessage = ({ data: m }) => {
  if (m.type === "download") {
    downloads.set(m.label, m);
    const loaded = [...downloads.values()].reduce((a, d) => a + d.loaded, 0);
    const total = [...downloads.values()].reduce((a, d) => a + d.total, 0);
    if (loaded < total) setEngine(`Downloading on-device models… ${mb(loaded)} / ${mb(total)} MB (one time)`);
  } else if (m.type === "ready") {
    setEngine(m.part === "core" ? "✓ Engine ready — works offline" : "✓ Engine + name/address model ready", "ok");
  } else if (m.type === "progress") {
    setStatus(m.text, "busy");
  } else if (m.type === "warning") {
    setStatus(m.text, "warn");
  } else if (m.type === "error" && !m.id) {
    downloads.clear();
    setEngine(`Engine failed to start: ${m.text || "unknown error"}`, "error", true);
  } else if (m.type === "result" || m.type === "error") {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    m.type === "result" ? p.resolve(m) : p.reject(new Error(m.text));
  }
};
worker.onerror = (e) => setEngine(`Engine failed to start: ${e.message || "unknown error"}`, "error", true);
warmup();

function warmup() {
  downloads.clear();
  setEngine("Starting engine…");
  worker.postMessage({ type: "warmup", ner: false });
}

function scanInWorker(image, options) {
  const id = ++state.scanId;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    worker.postMessage({ type: "scan", id, image, options }, [image.data.buffer]);
  });
}

// ------------------------------------------------------------------- input

els.file.addEventListener("change", () => els.file.files[0] && loadFile(els.file.files[0]));
els.drop.addEventListener("click", (e) => e.target.closest("button, a") || els.file.click());
els.drop.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), els.file.click()));
for (const t of [document.body]) {
  t.addEventListener("dragover", (e) => { e.preventDefault(); els.drop.classList.add("over"); });
  t.addEventListener("dragleave", (e) => e.relatedTarget || els.drop.classList.remove("over"));
  t.addEventListener("drop", (e) => {
    e.preventDefault();
    els.drop.classList.remove("over");
    const f = [...(e.dataTransfer?.files || [])].find((x) => x.type.startsWith("image/"));
    if (f) loadFile(f);
  });
}
document.addEventListener("paste", (e) => {
  const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
  if (item) {
    e.preventDefault();
    loadFile(item.getAsFile(), "pasted-screenshot");
  }
});
document.querySelectorAll("[data-example]").forEach((b) => b.addEventListener("click", async (e) => {
  e.stopPropagation();
  const res = await fetch(b.dataset.example);
  loadFile(await res.blob(), b.dataset.name);
}));

async function loadFile(blob, name) {
  if (!blob || state.busy) return;
  state.fileName = (name || blob.name || "screenshot").replace(/\.[^.]+$/, "");
  let bmp;
  try {
    bmp = await createImageBitmap(blob);
  } catch {
    setStatus("That file isn't an image this browser can read.", "warn");
    return;
  }
  const c = document.createElement("canvas");
  c.width = bmp.width;
  c.height = bmp.height;
  const ctx = c.getContext("2d", { willReadFrequently: true });
  ctx.fillStyle = "#fff"; // flatten transparency like the Python app
  ctx.fillRect(0, 0, c.width, c.height);
  ctx.drawImage(bmp, 0, 0, c.width, c.height);
  bmp.close?.();
  state.source = c;
  state.detections = [];
  state.selected = new Set();
  els.drop.hidden = true;
  els.workspace.hidden = false;
  render();
  await runScan();
}

// -------------------------------------------------------------------- scan

async function runScan() {
  if (!state.source || state.busy) return;
  state.busy = true;
  els.rescan.disabled = true;
  const categories = [...els.cats.querySelectorAll("input:checked")].map((i) => i.value);
  const customTerms = els.terms.value.split(/[,\n]/).map((t) => t.trim()).filter(Boolean);
  const manual = state.detections.filter((d) => d.source === "you");
  const t0 = performance.now();
  setStatus("Scanning…", "busy");
  try {
    const { width, height } = state.source;
    const image = state.source.getContext("2d", { willReadFrequently: true }).getImageData(0, 0, width, height);
    const [res, codes] = await Promise.all([
      scanInWorker({ data: image.data, width, height }, { categories, customTerms, useNer: els.useNer.checked }),
      categories.includes("codes") ? detectCodes(state.source).catch(() => []) : [],
    ]);
    const found = [
      ...res.detections,
      ...codes.map((c) => ({ category: "codes", label: c.kind, box: c, score: 1, source: "barcode", text: c.text })),
    ];
    state.nextId = 1;
    state.detections = [...found, ...manual].map((d) => ({ ...d, id: state.nextId++ }));
    state.selected = new Set(state.detections.map((d) => d.id));
    const secs = ((performance.now() - t0) / 1000).toFixed(1);
    setStatus(summary(found.length, secs), "ok");
  } catch (err) {
    setStatus(`Scan failed: ${err.message}. You can still draw boxes by hand in “Review & edit”.`, "warn");
  } finally {
    state.busy = false;
    els.rescan.disabled = false;
    render();
  }
}

function summary(n, secs) {
  if (!n) return `Nothing sensitive found (${secs}s). Draw boxes in “Review & edit” to hide anything by hand.`;
  const counts = {};
  for (const d of state.detections) if (d.source !== "you") counts[d.category] = (counts[d.category] || 0) + 1;
  const parts = Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([c, k]) => `${k} ${c.replace("_", " ")}`);
  return `Found ${n} item${n === 1 ? "" : "s"} in ${secs}s — ${parts.join(", ")}. Untick anything you want to keep.`;
}

// ------------------------------------------------------------------ render

function render() {
  if (!state.source) return;
  renderRedacted(els.redacted, state.source, state.detections, state.selected, state.style);
  renderReview(els.review, state.source, state.detections, state.selected, drag.box);
  renderList();
  els.download.disabled = els.copy.disabled = !state.source;
}

function renderList() {
  els.list.replaceChildren(...state.detections.map((d) => {
    const li = document.createElement("li");
    const label = document.createElement("label");
    const cb = Object.assign(document.createElement("input"), { type: "checkbox", checked: state.selected.has(d.id) });
    cb.addEventListener("change", () => {
      cb.checked ? state.selected.add(d.id) : state.selected.delete(d.id);
      render();
    });
    const dot = Object.assign(document.createElement("span"), { className: "dot" });
    dot.style.background = CATEGORY_COLORS[d.category];
    const name = Object.assign(document.createElement("span"), { className: "name",
      textContent: `#${d.id} ${d.source === "you" ? "Your box" : prettyLabel(d.label)}` });
    const prev = Object.assign(document.createElement("span"), { className: "preview", textContent: maskPreview(d.text) });
    label.append(cb, dot, name, prev);
    li.append(label);
    if (d.source === "you") {
      const del = Object.assign(document.createElement("button"), { className: "icon", textContent: "✕",
        title: "Remove this box", ariaLabel: `Remove box ${d.id}` });
      del.addEventListener("click", () => {
        state.detections = state.detections.filter((x) => x.id !== d.id);
        state.selected.delete(d.id);
        render();
      });
      li.append(del);
    }
    return li;
  }));
  els.listEmpty.hidden = state.detections.length > 0;
}

// --------------------------------------------------------- manual boxes

const drag = { start: null, box: null };

function toImage(e) {
  const r = els.review.getBoundingClientRect();
  return { x: ((e.clientX - r.left) / r.width) * els.review.width, y: ((e.clientY - r.top) / r.height) * els.review.height };
}

els.review.addEventListener("pointerdown", (e) => {
  if (!state.source) return;
  els.review.setPointerCapture(e.pointerId);
  drag.start = toImage(e);
});
els.review.addEventListener("pointermove", (e) => {
  if (!drag.start) return;
  const p = toImage(e);
  drag.box = { x0: Math.min(p.x, drag.start.x), y0: Math.min(p.y, drag.start.y),
    x1: Math.max(p.x, drag.start.x), y1: Math.max(p.y, drag.start.y) };
  renderReview(els.review, state.source, state.detections, state.selected, drag.box);
});
els.review.addEventListener("pointerup", () => {
  const b = drag.box;
  drag.start = drag.box = null;
  if (b && b.x1 - b.x0 > 4 && b.y1 - b.y0 > 4) {
    const d = { id: state.nextId++, category: "custom", label: "MANUAL", box: b, score: 1, source: "you", text: "" };
    state.detections.push(d);
    state.selected.add(d.id);
  }
  render();
});

// ---------------------------------------------------------------- controls

document.querySelectorAll("input[name=style]").forEach((r) => r.addEventListener("change", () => {
  state.style = r.value;
  els.styleNote.hidden = state.style === "black box";
  render();
}));
els.tabs.forEach((tab) => tab.addEventListener("click", () => {
  els.tabs.forEach((t) => {
    const on = t === tab;
    t.setAttribute("aria-selected", on);
    document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
  });
}));
els.selectAll.addEventListener("click", () => { state.selected = new Set(state.detections.map((d) => d.id)); render(); });
els.selectNone.addEventListener("click", () => { state.selected = new Set(); render(); });
els.rescan.addEventListener("click", runScan);
els.reset.addEventListener("click", () => {
  state.source = null;
  state.detections = [];
  els.file.value = "";
  els.workspace.hidden = true;
  els.drop.hidden = false;
  setStatus("");
});

const toBlob = () => new Promise((res) => els.redacted.toBlob(res, "image/png"));
els.download.addEventListener("click", async () => {
  // Re-encoding from canvas pixels drops EXIF/GPS and any other metadata.
  const url = URL.createObjectURL(await toBlob());
  const a = Object.assign(document.createElement("a"), { href: url, download: `${state.fileName}-redacted.png` });
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
});
els.copy.addEventListener("click", async () => {
  try {
    await navigator.clipboard.write([new ClipboardItem({ "image/png": toBlob() })]);
    flash(els.copy, "✓ Copied");
  } catch {
    flash(els.copy, "Copy not allowed here");
  }
});

// -------------------------------------------------------------- category UI

for (const [key, desc] of Object.entries(CATEGORIES)) {
  const label = document.createElement("label");
  const cb = Object.assign(document.createElement("input"), { type: "checkbox", value: key,
    checked: DEFAULT_CATEGORIES.includes(key) });
  const dot = Object.assign(document.createElement("span"), { className: "dot" });
  dot.style.background = CATEGORY_COLORS[key];
  label.append(cb, dot, Object.assign(document.createElement("span"), { textContent: desc }));
  els.cats.append(label);
}

// ------------------------------------------------------------------ helpers

function setStatus(text, kind = "") {
  els.status.textContent = text;
  els.status.dataset.kind = kind;
}
function setEngine(text, kind = "", retry = false) {
  els.engine.textContent = text;
  els.engine.dataset.kind = kind;
  if (retry) {
    els.engine.append(" ");
    const btn = Object.assign(document.createElement("button"), { type: "button", textContent: "Retry" });
    btn.addEventListener("click", warmup);
    els.engine.append(btn);
  }
}
function flash(btn, text) {
  const old = btn.textContent;
  btn.textContent = text;
  setTimeout(() => (btn.textContent = old), 1600);
}
const mb = (b) => (b / 1048576).toFixed(1);
