// Copies the runtime JS libraries (and the PII model, if missing) into the app so the deployed
// page never requests anything from a CDN or third-party host. OCR and face models live in
// models/ and are committed (see models/README.md for sources and checksums).
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const web = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const nm = join(web, "node_modules");
const tf = join(nm, "@huggingface", "transformers");
// Use the ONNX Runtime build that transformers.js was released against.
const ortPkg = [join(tf, "node_modules", "onnxruntime-web"), join(nm, "onnxruntime-web")].find(existsSync);

function copy(src, dst) {
  if (!existsSync(src)) throw new Error(`missing ${src}`);
  mkdirSync(dirname(dst), { recursive: true });
  cpSync(src, dst, { recursive: true });
  console.log("  ", dst.replace(web, "."));
}

console.log("vendor/");
for (const f of ["ort.wasm.min.mjs", "ort-wasm-simd-threaded.mjs", "ort-wasm-simd-threaded.wasm"]) {
  copy(join(ortPkg, "dist", f), join(web, "vendor", "ort", f));
}

// transformers.js imports ONNX Runtime by bare name; workers can't use import maps,
// so point those imports at the single vendored runtime.
const tfSrc = readFileSync(join(tf, "dist", "transformers.web.min.js"), "utf8")
  .replaceAll(/from\s*["']onnxruntime-web\/webgpu["']/g, 'from"./ort/ort.wasm.min.mjs"')
  .replaceAll(/from\s*["']onnxruntime-web["']/g, 'from"./ort/ort.wasm.min.mjs"')
  .replaceAll(/from\s*["']onnxruntime-common["']/g, 'from"./ort/ort.wasm.min.mjs"');
if (/from\s*["']onnxruntime-/.test(tfSrc)) throw new Error("transformers bundle still imports onnxruntime by bare name");
writeFileSync(join(web, "vendor", "transformers.web.min.js"), tfSrc);
console.log("   ./vendor/transformers.web.min.js");

copy(join(nm, "jsqr", "dist", "jsQR.js"), join(web, "vendor", "jsQR.js"));

const licDir = join(web, "licenses"); // committed; vendor/ itself is a build output
mkdirSync(licDir, { recursive: true });
copy(join(tf, "LICENSE"), join(licDir, "transformers.js.txt"));
copy(join(nm, "jsqr", "LICENSE"), join(licDir, "jsQR.txt"));
const ortVersion = JSON.parse(readFileSync(join(ortPkg, "package.json"), "utf8")).version;
writeFileSync(join(licDir, "onnxruntime-web.txt"), `onnxruntime-web ${ortVersion} — MIT License

Copyright (c) Microsoft Corporation

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
`);
console.log("   ./licenses/onnxruntime-web.txt");

// The PII model is fetched once at dev time (e.g. by the Node tests' first run) into .cache.
const piiDst = join(web, "models", "pii");
if (!existsSync(join(piiDst, "onnx", "model_quantized.onnx"))) {
  const pii = join(web, ".cache", "onnx-community", "bert-small-pii-detection-ONNX");
  for (const f of ["config.json", "tokenizer.json", "tokenizer_config.json", join("onnx", "model_quantized.onnx")]) {
    copy(join(pii, f), join(piiDst, f));
  }
}
for (const f of ["ocr_det.onnx", "ocr_rec.onnx", "ocr_keys.json", "yunet.onnx"]) {
  if (!existsSync(join(web, "models", f))) throw new Error(`models/${f} is missing (see models/README.md)`);
}
console.log("done");

