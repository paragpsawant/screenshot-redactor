"""Full pipeline on a generated screenshot (runs real OCR; NER optional)."""

import os
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("rapidocr")

from examples.make_example import make_screenshot  # noqa: E402
from redactor.pipeline import redact, scan, to_rgb_array  # noqa: E402

USE_NER = os.environ.get("REDACTOR_TEST_NER", "0") == "1"


@pytest.fixture(scope="module")
def image():
    return to_rgb_array(make_screenshot())


@pytest.fixture(scope="module")
def result(image):
    return scan(image, use_ner=USE_NER)


def test_finds_planted_secrets(result):
    found = {d.label for d in result.detections}
    for label in ["EMAIL", "PHONE", "CREDIT_CARD", "US_SSN", "AI_API_KEY", "IP_ADDRESS", "QR_CODE"]:
        assert label in found, f"missing {label}; got {sorted(found)}"
    if USE_NER:
        assert {"PERSON", "ADDRESS"} <= found


def test_no_false_positive_on_harmless_line(result):
    harmless = [l for l in result.lines if l.text.startswith("Theme")]
    assert harmless
    y = np.mean([p[1] for p in harmless[0].polygon])
    for d in result.detections:
        if d.category == "codes":
            continue  # the QR code shares the same rows but sits far to the right
        ys = [p[1] for p in d.polygon]
        assert not (min(ys) < y < max(ys)), f"unexpected detection on harmless line: {d.label}"


def test_redacted_pixels_are_black_and_rest_untouched(image, result):
    out = redact(image, result.detections)
    email = next(d for d in result.detections if d.label == "EMAIL")
    xs, ys = zip(*email.polygon)
    cx, cy = int(np.mean(xs)), int(np.mean(ys))
    assert out[cy, cx].sum() == 0
    assert np.array_equal(out[:40], image[:40])  # title bar has nothing sensitive


def test_rgba_and_gray_inputs():
    rgba = np.zeros((10, 10, 4), np.uint8)
    rgba[..., 3] = 0
    assert to_rgb_array(rgba).shape == (10, 10, 3) and to_rgb_array(rgba).min() == 255
    assert to_rgb_array(np.zeros((10, 10), np.uint8)).shape == (10, 10, 3)
