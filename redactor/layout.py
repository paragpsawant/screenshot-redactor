"""Geometry: map character spans inside an OCR line to image polygons.

OCR engines give a (possibly rotated) quadrilateral per line and, optionally,
per word. We project every character onto the line's reading axis so a span
can be cut out of the line precisely, then pad it so no glyph edge leaks.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from .types import Polygon


@dataclass
class OCRWord:
    text: str
    polygon: Polygon


@dataclass
class OCRLine:
    text: str
    polygon: Polygon  # tl, tr, br, bl
    score: float = 1.0
    words: list[OCRWord] = field(default_factory=list)


def _axis_t(line: OCRLine, points: Polygon) -> tuple[float, float]:
    tl, tr = np.asarray(line.polygon[0], float), np.asarray(line.polygon[1], float)
    axis = tr - tl
    denom = float(axis @ axis) or 1.0
    ts = [float((np.asarray(p, float) - tl) @ axis) / denom for p in points]
    return min(ts), max(ts)


def char_bounds(line: OCRLine) -> list[tuple[float, float]]:
    """Fractional [t0, t1] along the line axis for every character in ``line.text``."""
    n = len(line.text)
    if n == 0:
        return []
    uniform = [(i / n, (i + 1) / n) for i in range(n)]
    if not line.words:
        return uniform

    bounds: list[tuple[float, float] | None] = [None] * n
    cursor = 0
    for word in line.words:
        w = word.text.strip()
        if not w:
            continue
        start = line.text.find(w, cursor)
        if start < 0:
            return uniform  # word boxes don't line up with the text; fall back
        t0, t1 = _axis_t(line, word.polygon)
        step = (t1 - t0) / len(w)
        for k in range(len(w)):
            bounds[start + k] = (t0 + k * step, t0 + (k + 1) * step)
        cursor = start + len(w)

    # Fill gaps (spaces, unmatched chars) by interpolating between neighbours.
    for i in range(n):
        if bounds[i] is None:
            left = next((bounds[j][1] for j in range(i - 1, -1, -1) if bounds[j]), 0.0)
            right = next((bounds[j][0] for j in range(i + 1, n) if bounds[j]), 1.0)
            run_end = next((j for j in range(i, n) if bounds[j]), n)
            run = run_end - i
            k = 0
            while i + k < run_end:
                a = left + (right - left) * k / run
                b = left + (right - left) * (k + 1) / run
                bounds[i + k] = (a, b)
                k += 1
    return bounds  # type: ignore[return-value]


def span_polygon(line: OCRLine, start: int, end: int, pad_chars: float = 0.35,
                 pad_y: float = 0.08) -> Polygon:
    """Polygon covering ``line.text[start:end]`` with a small safety margin."""
    bounds = char_bounds(line)
    start = max(0, min(start, len(bounds) - 1))
    end = max(start + 1, min(end, len(bounds)))
    t0, t1 = bounds[start][0], bounds[end - 1][1]
    char_w = (t1 - t0) / max(1, end - start)
    t0 = max(0.0, t0 - pad_chars * char_w) if start > 0 else min(0.0, t0 - pad_chars * char_w)
    t1 = min(1.0, t1 + pad_chars * char_w) if end < len(bounds) else max(1.0, t1 + pad_chars * char_w)

    tl, tr, br, bl = (np.asarray(p, float) for p in line.polygon)
    up = tl - bl
    tl2, bl2 = tl + pad_y * up, bl - pad_y * up
    tr2, br2 = tr + pad_y * (tr - br), br - pad_y * (tr - br)

    def lerp(a: np.ndarray, b: np.ndarray, t: float) -> np.ndarray:
        return a + (b - a) * t

    pts = [lerp(tl2, tr2, t0), lerp(tl2, tr2, t1), lerp(bl2, br2, t1), lerp(bl2, br2, t0)]
    return [(float(p[0]), float(p[1])) for p in pts]


def rect_polygon(x0: float, y0: float, x1: float, y1: float) -> Polygon:
    return [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
