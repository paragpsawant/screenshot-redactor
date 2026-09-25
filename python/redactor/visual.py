"""Non-text detectors: faces (YuNet) and QR codes / barcodes (OpenCV)."""

from __future__ import annotations

import logging
from pathlib import Path

import cv2
import numpy as np

from .layout import rect_polygon
from .types import Polygon

log = logging.getLogger(__name__)

# Bundled with the app (MIT licence, see models/YUNET_LICENSE); never downloaded at runtime.
YUNET_PATH = Path(__file__).parent / "models" / "face_detection_yunet_2023mar.onnx"


def _yunet_model() -> Path | None:
    if YUNET_PATH.exists():
        return YUNET_PATH
    log.warning("Face detection disabled: %s is missing", YUNET_PATH.name)
    return None


def _yunet_pass(model, bgr: np.ndarray, score_threshold: float) -> list[tuple[float, float, float, float, float]]:
    h, w = bgr.shape[:2]
    det = cv2.FaceDetectorYN.create(str(model), "", (w, h), score_threshold, 0.3, 5000)
    _, faces = det.detect(np.ascontiguousarray(bgr))
    return [(float(f[0]), float(f[1]), float(f[2]), float(f[3]), float(f[-1])) for f in (faces if faces is not None else [])]


def tile_starts(length: int, tile: int, step: int) -> list[int]:
    """Start offsets covering [0, length) with windows of ``tile`` advancing by ``step``."""
    if length <= tile:
        return [0]
    starts = list(range(0, length - tile, step))
    return starts + [length - tile]


def detect_faces(image: np.ndarray, score_threshold: float = 0.7, pad: float = 0.35) -> list[tuple[Polygon, float]]:
    model = _yunet_model()
    if model is None:
        return []
    h, w = image.shape[:2]
    bgr = np.ascontiguousarray(image[:, :, ::-1])
    # Whole image (scaled for speed) finds large faces; full-resolution tiles find small
    # ones such as 40px chat avatars that would vanish when the screenshot is scaled down.
    scale = min(1.0, 1280 / max(h, w))
    small = cv2.resize(bgr, (int(w * scale), int(h * scale))) if scale < 1 else bgr
    found = [(x / scale, y / scale, fw / scale, fh / scale, s) for x, y, fw, fh, s in _yunet_pass(model, small, score_threshold)]
    if max(h, w) > 640:
        tile, step = 640, 512
        for ty in tile_starts(h, tile, step):
            for tx in tile_starts(w, tile, step):
                crop = bgr[ty:ty + tile, tx:tx + tile]
                found += [(x + tx, y + ty, fw, fh, s) for x, y, fw, fh, s in _yunet_pass(model, crop, score_threshold)]
    if not found:
        return []
    keep = cv2.dnn.NMSBoxes([[x, y, fw, fh] for x, y, fw, fh, _ in found], [s for *_, s in found], score_threshold, 0.3)
    results = []
    for i in np.array(keep).flatten():
        x, y, fw, fh, s = found[int(i)]
        p = max(pad, 0.55) if fw < 64 else pad  # small faces are usually avatars: cover the whole circle
        results.append((rect_polygon(max(0, x - fw * p), max(0, y - fh * p * 1.3),
                                     min(w, x + fw * (1 + p)), min(h, y + fh * (1 + p))), s))
    return results


def detect_codes(image: np.ndarray, pad: int = 6) -> list[tuple[Polygon, str, str]]:
    """Return (polygon, kind, decoded_text) for QR codes and 1-D barcodes."""
    bgr = np.ascontiguousarray(image[:, :, ::-1])
    h, w = bgr.shape[:2]
    found: list[tuple[Polygon, str, str]] = []

    def add(points, kind: str, text: str) -> None:
        pts = np.asarray(points, float).reshape(-1, 2)
        x0, y0 = pts.min(axis=0) - pad
        x1, y1 = pts.max(axis=0) + pad
        found.append((rect_polygon(max(0, x0), max(0, y0), min(w, x1), min(h, y1)), kind, text or ""))

    try:
        ok, texts, points, _ = cv2.QRCodeDetector().detectAndDecodeMulti(bgr)
        if ok and points is not None:
            for t, p in zip(texts, points):
                add(p, "QR_CODE", t)
        else:
            ok, points = cv2.QRCodeDetector().detectMulti(bgr)
            if ok and points is not None:
                for p in points:
                    add(p, "QR_CODE", "")
    except cv2.error as exc:
        log.debug("QR detection failed: %s", exc)

    try:
        ok, texts, _types, points = cv2.barcode.BarcodeDetector().detectAndDecodeWithType(bgr)
        if ok and points is not None:
            for t, p in zip(texts, points):
                add(p, "BARCODE", t)
    except (cv2.error, AttributeError, ValueError) as exc:
        log.debug("Barcode detection failed: %s", exc)
    return found
