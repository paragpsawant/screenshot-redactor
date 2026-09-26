// Minimal image helpers on RGBA buffers ({data, width, height}); no DOM needed.

/** Bilinear-resample the region (sx, sy, sw, sh) of `img` to dw×dh. Returns RGBA Uint8ClampedArray. */
export function resizeRegion(img, sx, sy, sw, sh, dw, dh) {
  const { data, width, height } = img;
  const out = new Uint8ClampedArray(dw * dh * 4);
  const scaleX = sw / dw;
  const scaleY = sh / dh;
  for (let y = 0; y < dh; y++) {
    const fy = Math.min(height - 1, Math.max(0, sy + (y + 0.5) * scaleY - 0.5));
    const y0 = Math.floor(fy);
    const y1 = Math.min(height - 1, y0 + 1);
    const wy = fy - y0;
    for (let x = 0; x < dw; x++) {
      const fx = Math.min(width - 1, Math.max(0, sx + (x + 0.5) * scaleX - 0.5));
      const x0 = Math.floor(fx);
      const x1 = Math.min(width - 1, x0 + 1);
      const wx = fx - x0;
      const i00 = (y0 * width + x0) * 4;
      const i01 = (y0 * width + x1) * 4;
      const i10 = (y1 * width + x0) * 4;
      const i11 = (y1 * width + x1) * 4;
      const o = (y * dw + x) * 4;
      for (let c = 0; c < 4; c++) {
        const top = data[i00 + c] * (1 - wx) + data[i01 + c] * wx;
        const bot = data[i10 + c] * (1 - wx) + data[i11 + c] * wx;
        out[o + c] = top * (1 - wy) + bot * wy;
      }
    }
  }
  return out;
}

/**
 * Write an RGBA buffer into a CHW float tensor as BGR (PaddleOCR / OpenCV channel order),
 * applying (v * scale - mean) / std. The destination may be larger (right/bottom padding).
 */
export function writeBGR(dst, offset, rgba, w, h, dstW, { scale = 1 / 255, mean = 0.5, std = 0.5, dstH = h } = {}) {
  const plane = dstH * dstW;
  for (let y = 0; y < h; y++) {
    for (let x = 0; x < w; x++) {
      const i = (y * w + x) * 4;
      const o = offset + y * dstW + x;
      dst[o] = (rgba[i + 2] * scale - mean) / std;
      dst[o + plane] = (rgba[i + 1] * scale - mean) / std;
      dst[o + 2 * plane] = (rgba[i] * scale - mean) / std;
    }
  }
}

export function cropImage(img, sx, sy, sw, sh) {
  const out = new Uint8ClampedArray(sw * sh * 4);
  for (let y = 0; y < sh; y++) {
    const src = ((sy + y) * img.width + sx) * 4;
    out.set(img.data.subarray(src, src + sw * 4), y * sw * 4);
  }
  return { data: out, width: sw, height: sh, offsetX: sx, offsetY: sy };
}

export function rotateImage90(img, clockwise = true) {
  const out = new Uint8ClampedArray(img.width * img.height * 4);
  const dw = img.height;
  for (let y = 0; y < img.height; y++) {
    for (let x = 0; x < img.width; x++) {
      const dx = clockwise ? img.height - 1 - y : y;
      const dy = clockwise ? x : img.width - 1 - x;
      out.set(img.data.subarray((y * img.width + x) * 4, (y * img.width + x) * 4 + 4), (dy * dw + dx) * 4);
    }
  }
  return { data: out, width: img.height, height: img.width };
}
