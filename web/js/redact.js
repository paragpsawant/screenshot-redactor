// Canvas rendering: the redacted output and the numbered review overlay.

export const STYLES = ["black box", "pixelate", "blur"];

export const CATEGORY_COLORS = {
  secrets: "#dc2626", contact: "#2563eb", financial: "#16a34a", government_id: "#9333ea", network: "#0891b2",
  person: "#ea580c", location: "#ca8a04", dates: "#db2777", faces: "#4f46e5", codes: "#475569", custom: "#059669",
};

const rect = (d) => {
  const x = Math.floor(d.box.x0), y = Math.floor(d.box.y0);
  return [x, y, Math.ceil(d.box.x1) - x, Math.ceil(d.box.y1) - y];
};

/** Draw `source` with every selected detection hidden. */
export function renderRedacted(canvas, source, detections, selected, style = "black box") {
  canvas.width = source.width;
  canvas.height = source.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(source, 0, 0);
  const chosen = detections.filter((d) => selected.has(d.id));
  if (!chosen.length) return canvas;

  if (style === "black box") {
    ctx.fillStyle = "#000";
    for (const d of chosen) ctx.fillRect(...rect(d));
    return canvas;
  }

  const minSide = Math.min(canvas.width, canvas.height);
  if (style === "blur" && "filter" in ctx) {
    const radius = Math.max(12, minSide / 40);
    for (const d of chosen) {
      const [x, y, w, h] = rect(d);
      ctx.save();
      ctx.beginPath();
      ctx.rect(x, y, w, h);
      ctx.clip();
      ctx.filter = `blur(${radius}px)`;
      // Blur twice so no glyph shapes survive, then fill the clipped area.
      ctx.drawImage(source, 0, 0);
      ctx.drawImage(canvas, 0, 0);
      ctx.restore();
    }
    return canvas;
  }

  // Pixelate (also the fallback for browsers without canvas filters).
  const block = Math.max(8, Math.round(minSide / 60));
  const tmp = document.createElement("canvas");
  const tctx = tmp.getContext("2d");
  ctx.imageSmoothingEnabled = false;
  for (const d of chosen) {
    const [x, y, w, h] = rect(d);
    tmp.width = Math.max(1, Math.ceil(w / block));
    tmp.height = Math.max(1, Math.ceil(h / block));
    tctx.imageSmoothingEnabled = true;
    tctx.drawImage(source, x, y, w, h, 0, 0, tmp.width, tmp.height);
    ctx.drawImage(tmp, 0, 0, tmp.width, tmp.height, x, y, w, h);
  }
  ctx.imageSmoothingEnabled = true;
  return canvas;
}

/** Draw numbered, colour-coded boxes over `source` for review. */
export function renderReview(canvas, source, detections, selected, draft = null) {
  canvas.width = source.width;
  canvas.height = source.height;
  const ctx = canvas.getContext("2d");
  ctx.drawImage(source, 0, 0);
  const lw = Math.max(2, Math.round(Math.min(canvas.width, canvas.height) / 400));
  const font = Math.max(11, Math.round(Math.min(canvas.width, canvas.height) / 55));
  ctx.font = `600 ${font}px system-ui, sans-serif`;
  ctx.textBaseline = "top";
  for (const d of detections) {
    const on = selected.has(d.id);
    const color = CATEGORY_COLORS[d.category] || "#000";
    const [x, y, w, h] = rect(d);
    if (on) {
      ctx.globalAlpha = 0.28;
      ctx.fillStyle = color;
      ctx.fillRect(x, y, w, h);
      ctx.globalAlpha = 1;
    }
    ctx.setLineDash(on ? [] : [lw * 3, lw * 2]);
    ctx.lineWidth = lw;
    ctx.strokeStyle = color;
    ctx.strokeRect(x, y, w, h);
    ctx.setLineDash([]);
    const label = String(d.id);
    const tw = ctx.measureText(label).width + 8;
    const ty = Math.max(0, y - font - 4);
    ctx.fillStyle = color;
    ctx.fillRect(x, ty, tw, font + 4);
    ctx.fillStyle = "#fff";
    ctx.fillText(label, x + 4, ty + 2);
  }
  if (draft) {
    ctx.setLineDash([6, 4]);
    ctx.lineWidth = lw;
    ctx.strokeStyle = CATEGORY_COLORS.custom;
    ctx.strokeRect(draft.x0, draft.y0, draft.x1 - draft.x0, draft.y1 - draft.y0);
    ctx.setLineDash([]);
  }
  return canvas;
}
