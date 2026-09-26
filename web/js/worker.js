// Runs all model inference off the main thread. Every file is loaded from this app's own origin.
import * as ort from "../vendor/ort/ort.wasm.min.mjs";

import { FaceDetector } from "./faces.js";
import { createNer } from "./ner.js";
import { OCR } from "./ocr.js";
import { scan } from "./pipeline.js";

const BASE = new URL("../", import.meta.url);
const WASM_PATH = new URL("vendor/ort/", BASE).href;
ort.env.wasm.wasmPaths = WASM_PATH;
// Single-threaded WASM: the threaded build intermittently deadlocked with several sessions
// sharing its pool, and the models here are small enough that one thread is fast.
ort.env.wasm.numThreads = 1;

const post = (msg) => self.postMessage(msg);
const MODEL_CACHE = "screenshot-redactor-models-v1";

async function fetchBytes(path, label) {
  const url = new URL(path, BASE);
  const res = await cachedFetch(url);
  if (!res.ok) throw new Error(`Could not load ${path} (${res.status})`);
  const total = Number(res.headers.get("content-length")) || 0;
  if (!res.body || !total) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const buf = new Uint8Array(total);
  let got = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buf.set(value, got);
    got += value.length;
    post({ type: "download", label, loaded: got, total });
  }
  return buf.subarray(0, got);
}

const loadBytes = (f) => fetchBytes(`models/${f}`, f);
const loadJson = async (f) => JSON.parse(new TextDecoder().decode(await fetchBytes(`models/${f}`, f)));

let core = null;
let ner = null;

function loadCore() {
  core ??= Promise.all([OCR.create(ort, loadBytes, loadJson), FaceDetector.create(ort, loadBytes)])
    .then(([ocr, faces]) => ({ ocr, faces }))
    .catch((err) => {
      core = null;
      throw err;
    });
  return core;
}

function loadNer() {
  ner ??= import("../vendor/transformers.web.min.js").then((transformers) => {
    transformers.env.useBrowserCache = true;
    return createNer(transformers, {
      // A path, not a full URL: transformers.js only checks local files for non-http(s) paths.
      localModelPath: new URL("models/", BASE).pathname, wasmPaths: WASM_PATH, device: "wasm",
    });
  }).catch((err) => {
    ner = null;
    throw err;
  });
  return ner;
}

async function cachedFetch(url) {
  if (!self.caches) return fetch(url);
  const cache = await caches.open(MODEL_CACHE);
  const cached = await cache.match(url.href);
  if (cached) return cached;
  const res = await fetch(url);
  if (res.ok) await cache.put(url.href, res.clone()).catch(() => {});
  return res;
}

self.onmessage = async ({ data: msg }) => {
  try {
    if (msg.type === "warmup") {
      await loadCore();
      post({ type: "ready", part: "core" });
      if (msg.ner) {
        await loadNer();
        post({ type: "ready", part: "ner" });
      }
    } else if (msg.type === "scan") {
      const engines = { ...(await loadCore()) };
      if (msg.options.useNer) {
        post({ type: "progress", text: "Loading the name & address model…" });
        engines.ner = await loadNer().catch((e) => {
          post({ type: "warning", text: `Name/address model unavailable (${e.message}); using rules only.` });
          return null;
        });
      }
      const result = await scan(msg.image, engines, {
        ...msg.options, onProgress: (text) => post({ type: "progress", text }),
      });
      post({ type: "result", id: msg.id, detections: result.detections, timings: result.timings,
        lines: result.lines.length });
    }
  } catch (err) {
    post({ type: "error", id: msg.id, phase: msg.type, text: err?.message || String(err) });
  }
};
