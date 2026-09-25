// Browser end-to-end check: loads the app from a local server, scans both examples,
// and asserts that the page never contacts another host. Usage: node tests/e2e.browser.mjs [baseUrl]
import assert from "node:assert/strict";
import { mkdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright-core";

const base = process.argv[2] || "http://127.0.0.1:8090/";
const shotsDir = fileURLToPath(new URL("../.cache/e2e/", import.meta.url));
mkdirSync(shotsDir, { recursive: true });
const shot = (name) => `${shotsDir}${name}.png`;
const channel = process.env.E2E_BROWSER || "msedge";

const browser = await chromium.launch({ channel, headless: process.env.HEADED ? false : true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const external = [];
const problems = [];
const baseHost = new URL(base).host;
page.on("request", (r) => {
  const u = new URL(r.url());
  if (!["blob:", "data:"].includes(u.protocol) && u.host !== baseHost) external.push(r.url());
});
page.on("console", (m) => ["error", "warning"].includes(m.type()) && problems.push(`${m.type()}: ${m.text().slice(0, 200)}`));
page.on("pageerror", (e) => problems.push(`pageerror: ${e.message}`));

const t0 = Date.now();
await page.goto(base);
await page.locator("#engine[data-kind=ok]").waitFor({ timeout: 180_000 });
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

// Untick one item, switch styles, draw a manual box, and check the redacted canvas changes accordingly.
const pixel = () => page.evaluate(() => {
  const c = document.querySelector("#redacted");
  return Array.from(c.getContext("2d").getImageData(0, 0, c.width, c.height).data.filter((_, i) => i % 97 === 0))
    .reduce((a, b) => a + b, 0);
});
const T = Date.now(); const step = (n) => console.log(`  step ${n} +${((Date.now() - T) / 1000).toFixed(1)}s`);
const before = await pixel(); step("pixel");
await page.locator("#detections li input").first().uncheck(); step("uncheck");
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
if (problems.length) console.log("console:\n  " + problems.slice(0, 20).join("\n  "));
assert.deepEqual(external, [], "the page must not contact other hosts");
await Promise.race([browser.close(), new Promise((r) => setTimeout(r, 5000))]);
console.log("\nE2E OK");
process.exit(0);

