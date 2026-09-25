// QR codes and barcodes: the browser's built-in BarcodeDetector when available, else bundled jsQR.

let jsQRPromise = null;

function loadJsQR() {
  jsQRPromise ??= new Promise((resolve, reject) => {
    if (globalThis.jsQR) return resolve(globalThis.jsQR);
    const s = document.createElement("script");
    s.src = new URL("../vendor/jsQR.js", import.meta.url).href;
    s.onload = () => resolve(globalThis.jsQR);
    s.onerror = () => reject(new Error("jsQR failed to load"));
    document.head.appendChild(s);
  });
  return jsQRPromise;
}

/** Returns [{x0, y0, x1, y1, kind, text}] for `canvas`. */
export async function detectCodes(canvas, pad = 6) {
  const w = canvas.width, h = canvas.height;
  const box = (x0, y0, x1, y1) => ({
    x0: Math.max(0, x0 - pad), y0: Math.max(0, y0 - pad), x1: Math.min(w, x1 + pad), y1: Math.min(h, y1 + pad),
  });

  if ("BarcodeDetector" in globalThis) {
    try {
      const formats = await globalThis.BarcodeDetector.getSupportedFormats();
      if (formats.length) {
        const found = await new globalThis.BarcodeDetector({ formats }).detect(canvas);
        return found.map((f) => {
          const b = f.boundingBox;
          return { ...box(b.x, b.y, b.x + b.width, b.y + b.height),
            kind: f.format === "qr_code" ? "QR_CODE" : "BARCODE", text: f.rawValue || "" };
        });
      }
    } catch {
      // fall through to jsQR
    }
  }

  const jsQR = await loadJsQR();
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const img = ctx.getImageData(0, 0, w, h);
  const results = [];
  for (let i = 0; i < 6; i++) {
    const code = jsQR(img.data, w, h, { inversionAttempts: "attemptBoth" });
    if (!code) break;
    const pts = Object.values(code.location).filter((p) => p && typeof p.x === "number");
    const xs = pts.map((p) => p.x), ys = pts.map((p) => p.y);
    const b = box(Math.min(...xs), Math.min(...ys), Math.max(...xs), Math.max(...ys));
    results.push({ ...b, kind: "QR_CODE", text: code.data || "" });
    // Blank out this code and look again for more.
    for (let y = Math.floor(b.y0); y < Math.ceil(b.y1); y++) {
      for (let x = Math.floor(b.x0); x < Math.ceil(b.x1); x++) img.data.fill(255, (y * w + x) * 4, (y * w + x) * 4 + 3);
    }
  }
  return results;
}
