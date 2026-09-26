// Browser end-to-end check: loads the app from a local server, scans both examples,
// and asserts that the page never contacts another host. Usage: node tests/e2e.browser.mjs [baseUrl]
import assert from "node:assert/strict";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const base = process.argv[2] || "http://127.0.0.1:8090/";
const shotsDir = fileURLToPath(new URL("../.cache/e2e/", import.meta.url));
mkdirSync(shotsDir, { recursive: true });
const shot = (name) => `${shotsDir}${name}.png`;
// E2E_BROWSER: "msedge" / "chrome" (installed browser) or "chromium" (Playwright's own build, used in CI).
const channel = process.env.E2E_BROWSER || "msedge";

const browser = await chromium.launch({
  ...(channel === "chromium" ? {} : { channel }), headless: process.env.HEADED ? false : true,
});
await testEngineRetry(browser);
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const external = [];
const problems = [];
const nonGet = [];
const baseHost = new URL(base).host;
// Hugging Face serves a Space's large (LFS/Xet) files by redirecting to its own CDN (*.hf.co);
// those are still this Space's files.
const allowedHost = (h) => h === baseHost || /(^|\.)hf\.co$/.test(h);
page.on("request", (r) => {
  const u = new URL(r.url());
  if (["blob:", "data:"].includes(u.protocol)) return;
  if (r.method() !== "GET" || r.postData()) nonGet.push(`${r.method()} ${r.url()}`);
  if (!allowedHost(u.host)) external.push(r.url());
});
page.on("console", (m) => ["error", "warning"].includes(m.type()) && problems.push(`${m.type()}: ${m.text().slice(0, 200)}`));
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));

const t0 = Date.now();
await page.goto(base);
await page.locator("#engine[data-kind=ok]").waitFor({ timeout: 180_000 });
assert.ok((await page.evaluate(async () => {
  const keys = await caches.keys();
  const cache = await caches.open("screenshot-redactor-models-v1");
  const reqs = await cache.keys();
  return keys.includes("screenshot-redactor-models-v1") && reqs.some((r) => r.url.includes("/models/ocr_det.onnx"));
})), "model files should be saved in Cache Storage for warm navigations");
assert.ok(await page.locator("img.logo").evaluate((i) => i.complete && i.naturalWidth > 0), "header logo should load");
console.log(`engine ready in ${((Date.now() - t0) / 1000).toFixed(1)}s | crossOriginIsolated=${await page.evaluate(() => crossOriginIsolated)}`);

async function scanExample(name, expected) {
  if (await page.locator("#reset").isVisible()) await page.locator("#reset").click();
  await page.getByRole("button", { name }).click();
  await page.locator("#status[data-kind=ok], #status[data-kind=warn]").waitFor({ timeout: 60_000 }).catch(async (e) => {
    throw new Error(`${name}: scan did not finish; status="${await page.locator("#status").innerText()}" engine="${
      await page.locator("#engine").innerText()}"\n${problems.join("\n")}`);
  });
  const status = await page.locator("#status").innerText();
  const items = await page.locator("#detections li .name").allInnerTexts();
  console.log(`\n${name}: ${status}`);
  console.log("  " + items.join(" | "));
  for (const label of expected) assert.ok(items.some((i) => i.includes(label)), `${name}: missing ${label}`);
  await page.screenshot({ path: shot(name.replace(/\W+/g, "_")), fullPage: true });
  return items;
}

await scanExample("Developer terminal", ["URL Password", "IP Address", "AWS Access Key", "GitHub Token", "Email",
  "Phone", "Person", "Address"]);
await scanExample("Profile page", ["Person", "Email", "Phone", "Address", "Credit Card", "US SSN", "AI API Key",
  "IP Address", "QR Code"]);

async function generatedPng(name, draw) {
  const base64 = await page.evaluate(draw);
  const file = `${shotsDir}${name}.png`;
  writeFileSync(file, Buffer.from(base64, "base64"));
  return file;
}

async function scanFile(file, expected) {
  if (await page.locator("#reset").isVisible()) await page.locator("#reset").click();
  await page.locator("#use-ner").evaluate((el) => { el.checked = false; el.dispatchEvent(new Event("change", { bubbles: true })); });
  await page.locator("#file").setInputFiles(file);
  await page.locator("#status[data-kind=ok], #status[data-kind=warn]").waitFor({ timeout: 180_000 });
  const items = await page.locator("#detections li .name").allInnerTexts();
  for (const label of expected) assert.ok(items.some((i) => i.includes(label)), `${file}: missing ${label}; got ${items}`);
  return items;
}

const rotatedFile = await generatedPng("rotated_token", () => {
  const token = "gh" + "p_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
  const c = document.createElement("canvas");
  c.width = c.height = 900;
  const ctx = c.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, c.width, c.height);
  ctx.fillStyle = "#111"; ctx.font = "36px Arial, sans-serif";
  ctx.fillText("support@example.com", 60, 80);
  ctx.save();
  ctx.translate(260, 780);
  ctx.rotate(-Math.PI / 2);
  ctx.fillText(`Deploy token: ${token}`, 0, 0);
  ctx.restore();
  return c.toDataURL("image/png").split(",")[1];
});
await scanFile(rotatedFile, ["GitHub Token"]);

const tallFile = await generatedPng("tall_secret", () => {
  const key = "sk-" + "proj-" + "A".repeat(28);
  const c = document.createElement("canvas");
  c.width = 400; c.height = 20000;
  const ctx = c.getContext("2d");
  ctx.fillStyle = "#fff"; ctx.fillRect(0, 0, c.width, c.height);
  ctx.fillStyle = "#334155"; ctx.font = "20px Arial, sans-serif";
  for (let y = 120; y < c.height - 400; y += 800) ctx.fillText(`Chat message at ${y}`, 20, y);
  ctx.fillStyle = "#111"; ctx.font = "22px Arial, sans-serif";
  ctx.fillText(`OPENAI_API_KEY=${key}`, 20, 19880);
  return c.toDataURL("image/png").split(",")[1];
});
await scanFile(tallFile, ["Password Or Secret"]);
const tallCanvas = await page.locator("#redacted").evaluate((c) => ({ width: c.width, height: c.height }));
assert.deepEqual(tallCanvas, { width: 400, height: 20000 });
const [tallDownload] = await Promise.all([page.waitForEvent("download"), page.locator("#download").click()]);
const tallPng = readFileSync(await tallDownload.path());
assert.deepEqual(pngSize(tallPng), { width: 400, height: 20000 });
await tallDownload.delete();

await scanExample("Profile page", ["Person", "Email", "Phone", "Address", "Credit Card", "US SSN", "AI API Key",
  "IP Address", "QR Code"]);

// Untick one item, switch styles, draw a manual box, and check the redacted canvas changes accordingly.
const pixel = () => page.evaluate(() => {
  const c = document.querySelector("#redacted");
  return Array.from(c.getContext("2d").getImageData(0, 0, c.width, c.height).data.filter((_, i) => i % 17 === 0))
    .reduce((a, b) => a + b, 0);
});
const T = Date.now(); const step = (n) => console.log(`  step ${n} +${((Date.now() - T) / 1000).toFixed(1)}s`);
const before = await pixel(); step("pixel");
await page.locator("#select-none").click(); step("uncheck");
const afterUntick = await pixel();
assert.notEqual(before, afterUntick, "unticking should change the output");
await page.getByLabel("Pixelate").check(); step("pixelate");
assert.ok(await page.locator("#style-note").isVisible(), "pixelate warning should show");
await page.getByLabel("Black box").check(); step("blackbox");
await page.getByRole("tab", { name: "Review & edit" }).click();
const box = await page.locator("#review").boundingBox();
await page.mouse.move(box.x + box.width * 0.6, box.y + box.height * 0.8);
await page.mouse.down();
await page.mouse.move(box.x + box.width * 0.75, box.y + box.height * 0.9, { steps: 5 });
await page.mouse.up(); step("drawn");
assert.ok((await page.locator("#detections li .name").allInnerTexts()).some((t) => t.includes("Your box")), "manual box");
await page.screenshot({ path: shot("review"), fullPage: true });

const [download] = await Promise.all([page.waitForEvent("download"), page.locator("#download").click()]);
console.log(`\ndownload: ${download.suggestedFilename()}`);
assert.match(download.suggestedFilename(), /-redacted\.png$/);
const png = readFileSync(await download.path());
assert.equal(png.subarray(1, 4).toString(), "PNG", "download is a PNG");
assert.ok(!png.includes(Buffer.from("eXIf")) && !png.includes(Buffer.from("tEXt")), "no metadata chunks");
await download.delete();

console.log(`\nexternal requests: ${external.length ? external.join(", ") : "none"}`);
console.log(`uploads / non-GET requests: ${nonGet.length ? nonGet.join(", ") : "none"}`);
if (problems.length) console.log("console:\n  " + problems.slice(0, 20).join("\n  "));
assert.deepEqual(external, [], "the page must not contact other hosts");
assert.deepEqual(nonGet, [], "the page must never send data anywhere");
await Promise.race([browser.close(), new Promise((r) => setTimeout(r, 5000))]);
console.log("\nE2E OK");
process.exit(0);

async function testEngineRetry(browser) {
  const ctx = await browser.newContext({ viewport: { width: 1200, height: 800 } });
  const blocker = (route) => route.abort("failed");
  await ctx.route(/\/models\/.*\.onnx(?:\?|$)/, blocker);
  const p = await ctx.newPage();
  await p.goto(base);
  await p.locator("#engine[data-kind=error]").waitFor({ timeout: 60_000 });
  assert.match(await p.locator("#engine").innerText(), /Engine failed.*Retry/s);
  await ctx.unroute(/\/models\/.*\.onnx(?:\?|$)/, blocker);
  await p.getByRole("button", { name: "Retry" }).click();
  await p.locator("#engine[data-kind=ok]").waitFor({ timeout: 180_000 });
  await ctx.close();
}

function pngSize(buf) {
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}
