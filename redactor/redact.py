"""Pixel operations: draw redactions and review annotations."""

from __future__ import annotations

from typing import Iterable

import cv2
import numpy as np

from .types import Detection, Polygon

STYLES = ("black box", "pixelate", "blur")

CATEGORY_COLORS: dict[str, tuple[int, int, int]] = {
    "secrets": (220, 38, 38),
    "contact": (37, 99, 235),
    "financial": (22, 163, 74),
    "government_id": (147, 51, 234),
    "network": (8, 145, 178),
    "person": (234, 88, 12),
    "location": (202, 138, 4),
    "dates": (219, 39, 119),
    "faces": (79, 70, 229),
    "codes": (71, 85, 105),
    "custom": (5, 150, 105),
}


def _mask(shape: tuple[int, ...], polygons: Iterable[Polygon]) -> np.ndarray:
    mask = np.zeros(shape[:2], np.uint8)
    for poly in polygons:
        pts = np.round(np.asarray(poly, np.float32)).astype(np.int32)
        cv2.fillPoly(mask, [pts], 255)
    return mask


def apply_redactions(image: np.ndarray, polygons: list[Polygon], style: str = "black box") -> np.ndarray:
    """Return a copy of ``image`` (H×W×3 RGB uint8) with every polygon hidden."""
    if style not in STYLES:
        raise ValueError(f"style must be one of {STYLES}")
    out = image.copy()
    if not polygons:
        return out
    mask = _mask(out.shape, polygons)
    if style == "black box":
        out[mask > 0] = 0
        return out

    h, w = out.shape[:2]
    if style == "pixelate":
        block = max(8, min(h, w) // 60)
        small = cv2.resize(out, (max(1, w // block), max(1, h // block)), interpolation=cv2.INTER_AREA)
        effect = cv2.resize(small, (w, h), interpolation=cv2.INTER_NEAREST)
    else:
        k = max(31, (min(h, w) // 20) | 1)
        effect = cv2.GaussianBlur(out, (k, k), 0)
        effect = cv2.GaussianBlur(effect, (k, k), 0)
    out[mask > 0] = effect[mask > 0]
    return out


def annotate(image: np.ndarray, detections: list[Detection], selected: set[int] | None = None) -> np.ndarray:
    """Draw numbered, colour-coded outlines; selected detections are also tinted."""
    overlay = image.copy()
    for det in detections:
        if selected is None or det.id in selected:
            pts = np.round(np.asarray(det.polygon, np.float32)).astype(np.int32)
            cv2.fillPoly(overlay, [pts], CATEGORY_COLORS.get(det.category, (0, 0, 0)))
    out = cv2.addWeighted(overlay, 0.3, image, 0.7, 0)
    scale = max(0.4, min(out.shape[:2]) / 1400)
    for det in detections:
        on = selected is None or det.id in selected
        color = CATEGORY_COLORS.get(det.category, (0, 0, 0))
        pts = np.round(np.asarray(det.polygon, np.float32)).astype(np.int32)
        cv2.polylines(out, [pts], True, color, 2 if on else 1, cv2.LINE_AA)
        x, y = int(pts[:, 0].min()), int(pts[:, 1].min())
        label = str(det.id)
        (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_SIMPLEX, scale, 1)
        y_text = max(th + 4, y)
        cv2.rectangle(out, (x, y_text - th - 4), (x + tw + 4, y_text), color, -1)
        cv2.putText(out, label, (x + 2, y_text - 2), cv2.FONT_HERSHEY_SIMPLEX, scale,
                    (255, 255, 255), 1, cv2.LINE_AA)
    return out
