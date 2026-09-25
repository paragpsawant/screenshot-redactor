"""Zero-shot PII entity recognition with GLiNER (names, addresses, birth dates...).

Loaded lazily and optional: if the model can't be loaded the app still works
with rule-based detection only.
"""

from __future__ import annotations

import logging
import os
import threading

from .layout import OCRLine
from .types import TextSpan

log = logging.getLogger(__name__)

MODEL_ID = os.environ.get("REDACTOR_NER_MODEL", "urchade/gliner_multi_pii-v1")

LABELS: dict[str, tuple[str, str]] = {
    "person": ("PERSON", "person"),
    "street address": ("ADDRESS", "location"),
    "date of birth": ("DATE_OF_BIRTH", "dates"),
    "passport number": ("PASSPORT", "government_id"),
    "driver's license number": ("DRIVER_LICENSE", "government_id"),
    "social security number": ("US_SSN", "government_id"),
    "bank account number": ("BANK_ACCOUNT", "financial"),
    "username": ("USERNAME", "contact"),
}

_model = None
_failed = False
_lock = threading.Lock()


def _get_model():
    global _model, _failed
    with _lock:
        if _model is None and not _failed:
            try:
                from gliner import GLiNER

                _model = GLiNER.from_pretrained(MODEL_ID)
            except Exception as exc:  # network, disk, or dependency issues
                log.warning("NER disabled: could not load %s (%s)", MODEL_ID, exc)
                _failed = True
        return _model


def available() -> bool:
    return _get_model() is not None


def find_entities(lines: list[OCRLine], categories: set[str], threshold: float = 0.5,
                  max_chars: int = 900) -> dict[int, list[TextSpan]]:
    """Return spans per line index for the requested categories."""
    labels = [k for k, (_, cat) in LABELS.items() if cat in categories]
    if not labels or not lines:
        return {}
    model = _get_model()
    if model is None:
        return {}

    out: dict[int, list[TextSpan]] = {}
    for chunk in _chunks(lines, max_chars):
        text = "\n".join(lines[i].text for i in chunk)
        starts, pos = [], 0
        for i in chunk:
            starts.append(pos)
            pos += len(lines[i].text) + 1
        for ent in model.predict_entities(text, labels, threshold=threshold):
            label, cat = LABELS.get(ent["label"], ("PII", "person"))
            for idx, line_start in zip(chunk, starts):
                line_end = line_start + len(lines[idx].text)
                s, e = max(ent["start"], line_start), min(ent["end"], line_end)
                if e > s and lines[idx].text[s - line_start:e - line_start].strip():
                    out.setdefault(idx, []).append(
                        TextSpan(s - line_start, e - line_start, label, cat, float(ent["score"]), "ner"))
    return out


def _chunks(lines: list[OCRLine], max_chars: int) -> list[list[int]]:
    chunks: list[list[int]] = [[]]
    size = 0
    for i, line in enumerate(lines):
        if chunks[-1] and size + len(line.text) > max_chars:
            chunks.append([])
            size = 0
        chunks[-1].append(i)
        size += len(line.text) + 1
    return [c for c in chunks if c]
