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


def _bbox(poly: Polygon) -> tuple[float, float, float, float]:
    xs, ys = zip(*poly)
    return min(xs), min(ys), max(xs), max(ys)


@dataclass
class Row:
    """OCR boxes on the same text row, read as one logical line."""

    text: str
    parts: list[tuple[OCRLine, int]]  # (line, character offset of that line in `text`)


def group_rows(lines: list[OCRLine], max_gap_in_heights: float = 2.5) -> list[Row]:
    """Join nearby boxes on the same row so a value split from its label, or a name split
    from its timestamp, is still read as one phrase."""
    rows: list[Row] = []
    for line in sorted(lines, key=lambda l: _bbox(l.polygon)[0]):
        x0, y0, x1, y1 = _bbox(line.polygon)
        h = y1 - y0
        target = None
        for row in rows:
            lx0, ly0, lx1, ly1 = _bbox(row.parts[-1][0].polygon)
            lh = ly1 - ly0
            overlap = min(ly1, y1) - max(ly0, y0)
            gap = x0 - lx1
            if (overlap >= 0.6 * min(h, lh) and abs(h - lh) <= 0.4 * max(h, lh)
                    and -0.5 * h <= gap <= max_gap_in_heights * max(h, lh)):
                target = row
                break
        if target:
            target.parts.append((line, len(target.text) + 1))
            target.text += " " + line.text
        else:
            rows.append(Row(line.text, [(line, 0)]))
    return sorted(rows, key=lambda r: (_bbox(r.parts[0][0].polygon)[1], _bbox(r.parts[0][0].polygon)[0]))


def row_span_polygon(row: Row, start: int, end: int) -> Polygon:
    """Polygon covering ``row.text[start:end]``, which may span several OCR boxes."""
    boxes = []
    for line, offset in row.parts:
        s, e = max(start, offset) - offset, min(end, offset + len(line.text)) - offset
        if e > s:
            boxes.append(_bbox(span_polygon(line, s, e)))
    if not boxes:
        return span_polygon(row.parts[0][0], 0, 1)
    if len(boxes) == 1:
        line, offset = next((l, o) for l, o in row.parts if max(start, o) < min(end, o + len(l.text)))
        return span_polygon(line, max(start, offset) - offset, min(end, offset + len(line.text)) - offset)
    return rect_polygon(min(b[0] for b in boxes), min(b[1] for b in boxes),
                        max(b[2] for b in boxes), max(b[3] for b in boxes))


def labelled_values(lines: list[OCRLine], label_re, max_gap_in_heights: float = 20) -> list[OCRLine]:
    """For boxes that are only a label (e.g. "Password:"), the value box: the nearest box to the
    right on the same row. Handles form layouts where label and field are far apart."""
    out = []
    for label in lines:
        if not label_re.search(label.text):
            continue
        lx0, ly0, lx1, ly1 = _bbox(label.polygon)
        h = ly1 - ly0
        candidates = []
        for other in lines:
            if other is label:
                continue
            x0, y0, x1, y1 = _bbox(other.polygon)
            if (x0 >= lx1 - 0.5 * h and x0 - lx1 <= max_gap_in_heights * h
                    and min(y1, ly1) - max(y0, ly0) >= 0.5 * min(h, y1 - y0)):
                candidates.append((x0, other))
        if candidates:
            best = min(candidates, key=lambda c: c[0])[1]
            if len(best.text.strip()) >= 3:
                out.append(best)
    return out
