"""Non-text detectors: faces (YuNet) and QR codes / barcodes (OpenCV)."""

from __future__ import annotations

import logging
import threading
import urllib.request
from pathlib import Path

import cv2
import numpy as np

from .layout import rect_polygon
from .types import Polygon

log = logging.getLogger(__name__)

YUNET_FILE = "face_detection_yunet_2023mar.onnx"
YUNET_URL = f"https://github.com/opencv/opencv_zoo/raw/main/models/face_detection_yunet/{YUNET_FILE}"
_CACHE = Path.home() / ".cache" / "screenshot-redactor"

_lock = threading.Lock()
_yunet_path: Path | None = None
_yunet_failed = False


def _yunet_model() -> Path | None:
    global _yunet_path, _yunet_failed
    with _lock:
        if _yunet_path or _yunet_failed:
            return _yunet_path
        bundled = Path(__file__).parent / "models" / YUNET_FILE
        cached = _CACHE / YUNET_FILE
        for p in (bundled, cached):
            if p.exists() and p.stat().st_size > 100_000:
                _yunet_path = p
                return p
        try:
            _CACHE.mkdir(parents=True, exist_ok=True)
            urllib.request.urlretrieve(YUNET_URL, cached)
            _yunet_path = cached
        except Exception as exc:
            log.warning("Face detection disabled: %s", exc)
            _yunet_failed = True
        return _yunet_path


def detect_faces(image: np.ndarray, score_threshold: float = 0.7, pad: float = 0.35) -> list[tuple[Polygon, float]]:
    model = _yunet_model()
    if model is None:
        return []
    h, w = image.shape[:2]
    # YuNet works best around 640px; scale big screenshots down for speed.
    scale = min(1.0, 1280 / max(h, w))
    small = cv2.resize(image, (int(w * scale), int(h * scale))) if scale < 1 else image
    bgr = np.ascontiguousarray(small[:, :, ::-1])
    det = cv2.FaceDetectorYN.create(str(model), "", (bgr.shape[1], bgr.shape[0]), score_threshold, 0.3, 5000)
    _, faces = det.detect(bgr)
    results = []
    for f in faces if faces is not None else []:
        x, y, fw, fh = (float(v) / scale for v in f[:4])
        px, py = fw * pad, fh * pad
        results.append((rect_polygon(max(0, x - px), max(0, y - py * 1.5),
                                     min(w, x + fw + px), min(h, y + fh + py)), float(f[-1])))
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
