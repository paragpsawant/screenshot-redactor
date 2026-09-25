// End-to-end scan on the example screenshots with the real bundled models (onnxruntime-node).
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { before, test } from "node:test";
import { fileURLToPath } from "node:url";

import * as ort from "onnxruntime-node";
import * as transformers from "@huggingface/transformers";

import { DEFAULT_CATEGORIES } from "../js/rules.js";
import { FaceDetector } from "../js/faces.js";
import { alignTokens, createNer, extendAddress, groupEntities } from "../js/ner.js";
import { OCR } from "../js/ocr.js";
import { scan, spanBox } from "../js/pipeline.js";
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
