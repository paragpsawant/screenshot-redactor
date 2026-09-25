"""OCR wrapper (RapidOCR / PP-OCR on ONNX Runtime, CPU-friendly)."""

from __future__ import annotations

import threading

import numpy as np

from .layout import OCRLine, OCRWord

_engine = None
_lock = threading.Lock()


def _get_engine():
    global _engine
    with _lock:
        if _engine is None:
            from rapidocr import RapidOCR

            _engine = RapidOCR(params={
                "Global.log_level": "error",
                "Global.max_side_len": 2600,
                "Global.use_cls": False,  # screenshots are upright; skip the angle classifier
            })
        return _engine


def _poly(box) -> list[tuple[float, float]]:
    return [(float(x), float(y)) for x, y in box]


def run_ocr(image: np.ndarray, min_score: float = 0.5) -> list[OCRLine]:
    """Detect and read text lines (with word boxes) from an RGB image."""
    bgr = np.ascontiguousarray(image[:, :, ::-1])
    result = _get_engine()(bgr, return_word_box=True)
    if result is None or result.boxes is None or result.txts is None:
        return []
    words_per_line = result.word_results or ()
    lines: list[OCRLine] = []
    for i, (box, text, score) in enumerate(zip(result.boxes, result.txts, result.scores)):
        if not text or float(score) < min_score:
            continue
        words = []
        if i < len(words_per_line):
            for item in words_per_line[i] or ():
                if len(item) >= 3 and item[0]:
                    words.append(OCRWord(str(item[0]), _poly(item[2])))
        lines.append(OCRLine(str(text), _poly(box), float(score), words))
    return lines
