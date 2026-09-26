// End-to-end scan on the example screenshots with the real bundled models (onnxruntime-node).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

import * as ort from "onnxruntime-node";
import * as transformers from "@huggingface/transformers";

import { DEFAULT_CATEGORIES, SECRET_LABEL_ONLY } from "../js/rules.js";
import { FaceDetector, tileStarts } from "../js/faces.js";
import { alignTokens, coordinatedNames, createNer, extendAddress, groupEntities, looksLikePersonInContext, toWordBoundaries, trimToNameWords } from "../js/ner.js";
import { OCR } from "../js/ocr.js";
import { groupRows, labelledValues, rowSpanBox, scan, spanBox } from "../js/pipeline.js";
import { readPng } from "./png.mjs";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const models = join(web, "models");
const loadBytes = async (f) => readFileSync(join(models, f));
const loadJson = async (f) => JSON.parse(readFileSync(join(models, f), "utf8"));
const cpu = { executionProviders: ["cpu"] };

let engines;
before(async () => {
  engines = {
    ocr: await OCR.create(ort, loadBytes, loadJson, cpu),
    faces: await FaceDetector.create(ort, loadBytes, cpu),
    ner: await createNer(transformers, { localModelPath: models + "/" }),
  };
});

const run = (file, opts = {}) =>
  scan(readPng(join(web, "examples", file)), engines, { categories: DEFAULT_CATEGORIES, ...opts });

test("fake profile: every planted item is found, harmless line untouched", async () => {
  const { detections, lines } = await run("fake_profile.png");
  const labels = new Set(detections.map((d) => d.label));
  for (const l of ["PERSON", "EMAIL", "PHONE", "ADDRESS", "CREDIT_CARD", "US_SSN", "AI_API_KEY", "IP_ADDRESS"]) {
    assert.ok(labels.has(l), `missing ${l}; got ${[...labels]}`);
  }
  const theme = lines.find((l) => l.text.startsWith("Theme"));
  assert.ok(theme);
  assert.ok(detections.every((d) => d.box.y1 < theme.box.y0 || d.box.y0 > theme.box.y1));
  const key = detections.find((d) => d.label === "AI_API_KEY");
  const keyLine = lines.find((l) => l.text.startsWith("OPENAI_API_KEY"));
  // The label stays readable; only the value is covered.
  assert.ok(key.box.x0 > keyLine.box.x0 + (keyLine.box.x1 - keyLine.box.x0) * 0.25);
});

test("developer screenshot: secrets, contact details and address", async () => {
  const { detections } = await run("dev_leak.png");
  const labels = detections.map((d) => d.label);
  for (const l of ["URL_PASSWORD", "IP_ADDRESS", "AWS_ACCESS_KEY", "GITHUB_TOKEN", "EMAIL", "PHONE", "PERSON", "ADDRESS"]) {
    assert.ok(labels.includes(l), `missing ${l}; got ${labels}`);
  }
  assert.ok(labels.filter((l) => ["STRIPE_KEY", "PASSWORD_OR_SECRET", "POSSIBLE_SECRET"].includes(l)).length >= 2);
  assert.ok(!detections.some((d) => /Meeting|Senior|listening|retrying/.test(d.text)));
});

test("category filter and custom terms", async () => {
  const { detections } = await run("fake_profile.png", { categories: ["secrets"], customTerms: ["Walsh"] });
  assert.deepEqual([...new Set(detections.map((d) => d.label))].sort(), ["AI_API_KEY", "CUSTOM"]);
});

test("NER token alignment handles accents, punctuation and subwords", () => {
  const text = "Zoë O'Neill, 742 Evergreen";
  const offsets = alignTokens(text, ["zoe", "o", "'", "neill", ",", "74", "##2", "evergreen"]);
  assert.deepEqual(offsets.map(([s, e]) => text.slice(s, e)), ["Zoë", "O", "'", "Neill", ",", "74", "2", "Evergreen"]);
});

test("addresses are extended over the state and ZIP code", () => {
  for (const [text, start, end] of [
    ["Ship it to 742 Evergreen Terrace, Springfield, OR 97403", 11, 44],
    ["Address: 1600 Amphitheatre Parkway, Mountain View, CA 94043", 9, 51],
  ]) {
    const r = extendAddress(text, start, end);
    assert.ok(text.slice(r.start, r.end).endsWith(text.slice(-5)), text.slice(r.start, r.end));
  }
  const groups = groupEntities([
    { entity: "B-LOCATION", index: 1, word: "1600", score: 0.9 },
    { entity: "I-LOCATION", index: 2, word: "ca", score: 0.9 },
    { entity: "I-LOCATION", index: 4, word: "##043", score: 0.9 },
  ], [[0, 4], [5, 7], [8, 10], [10, 13]], "1600 CA 94043");
  assert.equal(groups.length, 1);
  assert.deepEqual([groups[0].start, groups[0].end], [0, 13]);
});

test("every planted address is fully covered, ZIP included", async () => {
  for (const [file, zip] of [["fake_profile.png", "94043"], ["dev_leak.png", "97403"]]) {
    const { detections, lines } = await run(file);
    const line = lines.find((l) => l.text.includes(zip));
    const zipBox = spanBox(line, line.text.indexOf(zip), line.text.indexOf(zip) + zip.length, 0, 0);
    const covered = detections.some((d) => d.box.x0 <= zipBox.x0 + 1 && d.box.x1 >= zipBox.x1 - 1 &&
      d.box.y0 <= zipBox.y0 + 1 && d.box.y1 >= zipBox.y1 - 1);
    assert.ok(covered, `${file}: ZIP ${zip} not fully covered`);
  }
});

test("spanBox pads inside the line and reaches the edges at line ends", () => {
  const line = { text: "abcd", box: { x0: 0, y0: 0, x1: 100, y1: 10 }, bounds: [[0, .25], [.25, .5], [.5, .75], [.75, 1]] };
  const mid = spanBox(line, 1, 3);
  assert.ok(mid.x0 > 15 && mid.x0 < 25 && mid.x1 > 75 && mid.x1 < 85);
  const all = spanBox(line, 0, 4);
  assert.ok(all.x0 <= 0 && all.x1 >= 100);
});

test("spanBox maps rotated OCR character bounds along the vertical axis", () => {
  const line = { text: "abcdef", orientation: "cw", box: { x0: 40, y0: 100, x1: 70, y1: 220 },
    bounds: [[0, 1 / 6], [1 / 6, 2 / 6], [2 / 6, 3 / 6], [3 / 6, 4 / 6], [4 / 6, 5 / 6], [5 / 6, 1]] };
  const box = spanBox(line, 0, 3, 0, 0);
  assert.deepEqual(box, { x0: 40, x1: 70, y0: 160, y1: 220 });
});

// ---- regressions from a real chat screenshot (synthetic fixture: tests/fixtures/chat.png) ----

test("chat screenshot: sender headers, inline names and full passwords are covered", async () => {
  const { detections } = await scan(readPng(join(web, "tests", "fixtures", "chat.png")), engines, { categories: DEFAULT_CATEGORIES });
  const texts = detections.map((d) => d.text);
  for (const t of ["Nikhil Kulkarni", "Aarav", "Priya Raman", "Mei-Ling", "Kwame", "hK3#9vLp jfn2n2mcnkc2", "hunter2"]) {
    assert.ok(texts.includes(t), `missing ${t}; got ${JSON.stringify(texts)}`);
  }
  assert.equal(texts.filter((t) => t === "Nikhil Kulkarni").length, 2);
  for (const t of ["Daily Standup", "Contoso Ltd", "please", "Meeting"]) {
    assert.ok(!texts.some((x) => x.includes(t)), `false positive on ${t}`);
  }
});

const L = (text, x0, x1, y0 = 100, y1 = 124) => ({ text, box: { x0, y0, x1, y1 }, bounds: [] });

test("groupRows joins nearby boxes on the same row, keeps distant ones apart", () => {
  const rows = groupRows([L("ant Yesterday 12:02 PM", 352, 534), L("Parag", 270, 321), L("far away", 1200, 1300)]);
  assert.deepEqual(rows.map((r) => r.text), ["Parag ant Yesterday 12:02 PM", "far away"]);
  const box = rowSpanBox(rows[0], 0, 9); // "Parag ant" spans two OCR boxes
  assert.ok(box.x0 <= 270 && box.x1 >= 352);
});

test("a label-only box takes the next box on the row as its secret value", () => {
  const lines = [L("password:", 287, 386), L("jfn2n2mcnkc2", 501, 630), L("Shift+Enter starts a new line.", 1336, 1553, 150, 170)];
  assert.deepEqual(labelledValues(lines, SECRET_LABEL_ONLY).map((v) => v.line.text), ["jfn2n2mcnkc2"]);
  assert.deepEqual(labelledValues([L("Passwords are hashed", 0, 300), L("abc", 320, 360)], SECRET_LABEL_ONLY), []);
});

test("NER span cleanup: subwords widen to words, lowercase edges trimmed, uncommon names kept", () => {
  const t = "Parag Sawant Yesterday";
  assert.deepEqual(toWordBoundaries(t, 6, 9), { start: 6, end: 12 }); // "Saw" -> "Sawant"
  const u = "ping Priya Raman or";
  const r = trimToNameWords(u, 0, 16);
  assert.equal(u.slice(r.start, r.end), "Priya Raman");
  assert.ok(looksLikePersonInContext("dentist with Aarav and", 13, 18));
  assert.ok(!looksLikePersonInContext("works at Contoso Ltd", 9, 20));
  const v = "ask Mei-Ling or Kwame at Contoso Ltd";
  assert.deepEqual(coordinatedNames(v, [{ start: 4, end: 12, score: 0.9 }]).map((p) => v.slice(p.start, p.end)), ["Kwame"]);
});

test("face tiles cover the whole image", () => {
  assert.deepEqual(tileStarts(500, 640, 512), [0]);
  const starts = tileStarts(1604, 640, 512);
  assert.equal(starts[0], 0);
  assert.equal(starts.at(-1) + 640, 1604);
});
