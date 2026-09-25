"""End-to-end scan → review → redact pipeline."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

import numpy as np

from . import ner, rules
from .layout import OCRLine, span_polygon
from .redact import apply_redactions
from .types import DEFAULT_CATEGORIES, Detection, TextSpan

TEXT_CATEGORIES = {"secrets", "contact", "financial", "government_id", "network",
                   "person", "location", "dates", "custom"}
NER_CATEGORIES = {"person", "location", "dates", "government_id", "financial", "contact"}


@dataclass
class ScanResult:
    detections: list[Detection]
    lines: list[OCRLine] = field(default_factory=list)
    timings: dict[str, float] = field(default_factory=dict)
    ner_used: bool = False

    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.detections:
            counts[d.category] = counts.get(d.category, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def _merge_line_spans(rule_spans: list[TextSpan], ner_spans: list[TextSpan]) -> list[TextSpan]:
    kept = list(rule_spans)
    for s in ner_spans:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)


def scan(image: np.ndarray, categories: Iterable[str] = DEFAULT_CATEGORIES,
         custom_terms: Iterable[str] = (), use_ner: bool = True,
         ner_threshold: float = 0.5, lines: list[OCRLine] | None = None) -> ScanResult:
    """Find every sensitive region in an RGB uint8 image."""
    cats = set(categories)
    terms = [t for t in custom_terms if t and t.strip()]
    if terms:
        cats.add("custom")
    timings: dict[str, float] = {}
    detections: list[Detection] = []

    def add(**kw) -> None:
        detections.append(Detection(id=len(detections) + 1, **kw))

    if cats & TEXT_CATEGORIES:
        t = time.perf_counter()
        if lines is None:
            from .ocr import run_ocr

            lines = run_ocr(image)
        timings["ocr"] = time.perf_counter() - t

        t = time.perf_counter()
        ner_spans: dict[int, list[TextSpan]] = {}
        ner_used = False
        if use_ner and cats & NER_CATEGORIES:
            ner_spans = ner.find_entities(lines, cats & NER_CATEGORIES, threshold=ner_threshold)
            ner_used = ner.available()
        timings["ner"] = time.perf_counter() - t

        for idx, line in enumerate(lines):
            spans = _merge_line_spans(rules.find_spans(line.text, cats, terms), ner_spans.get(idx, []))
            for s in spans:
                add(category=s.category, label=s.label, polygon=span_polygon(line, s.start, s.end),
                    score=s.score, source=s.source, text=line.text[s.start:s.end])
    else:
        lines, ner_used = [], False

    if "faces" in cats:
        from .visual import detect_faces

        t = time.perf_counter()
        for poly, score in detect_faces(image):
            add(category="faces", label="FACE", polygon=poly, score=score, source="yunet")
        timings["faces"] = time.perf_counter() - t

    if "codes" in cats:
        from .visual import detect_codes

        t = time.perf_counter()
        for poly, kind, text in detect_codes(image):
            add(category="codes", label=kind, polygon=poly, source="opencv", text=text)
        timings["codes"] = time.perf_counter() - t

    return ScanResult(detections, lines or [], timings, ner_used)


def redact(image: np.ndarray, detections: list[Detection], selected_ids: Iterable[int] | None = None,
           style: str = "black box") -> np.ndarray:
    ids = None if selected_ids is None else set(selected_ids)
    polys = [d.polygon for d in detections if ids is None or d.id in ids]
    return apply_redactions(image, polys, style)


def to_rgb_array(image) -> np.ndarray:
    """Accept PIL images or numpy arrays (gray, RGB, RGBA) and return RGB uint8."""
    from PIL import Image

    if isinstance(image, Image.Image):
        image = np.asarray(image.convert("RGB"))
    arr = np.asarray(image)
    if arr.ndim == 2:
        arr = np.stack([arr] * 3, axis=-1)
    elif arr.shape[2] == 4:
        rgb, alpha = arr[:, :, :3].astype(np.float32), arr[:, :, 3:4].astype(np.float32) / 255
        arr = (rgb * alpha + 255 * (1 - alpha)).astype(np.uint8)
    return np.ascontiguousarray(arr[:, :, :3].astype(np.uint8))
