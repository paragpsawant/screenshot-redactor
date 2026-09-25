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


# ---- regressions from a real chat screenshot (synthetic fixture shared with the web app) ----

from redactor.layout import OCRLine as _Line, group_rows, labelled_values, rect_polygon, row_span_polygon  # noqa: E402
from redactor.ner import clean_span  # noqa: E402
from redactor.rules import SECRET_LABEL_ONLY  # noqa: E402
from redactor.visual import tile_starts  # noqa: E402

CHAT = Path(__file__).resolve().parents[2] / "web" / "tests" / "fixtures" / "chat.png"


def _l(text, x0, x1, y0=100, y1=124):
    return _Line(text, rect_polygon(x0, y0, x1, y1))


@pytest.mark.skipif(not CHAT.exists(), reason="web fixture not available")
def test_chat_screenshot_headers_and_full_passwords():
    from PIL import Image

    result = scan(to_rgb_array(Image.open(CHAT)), use_ner=USE_NER)
    texts = [d.text for d in result.detections]
    for t in ["hK3#9vLp jfn2n2mcnkc2", "hunter2"]:
        assert t in texts, texts
    assert texts.count("Nikhil Kulkarni") == 2, texts
    for t in ["Daily Standup", "Contoso Ltd", "please"]:
        assert not any(t in x for x in texts), texts


def test_group_rows_and_split_label_value():
    rows = group_rows([_l("ant Yesterday 12:02 PM", 352, 534), _l("Parag", 270, 321), _l("far away", 1200, 1300)])
    assert [r.text for r in rows] == ["Parag ant Yesterday 12:02 PM", "far away"]
    xs = [p[0] for p in row_span_polygon(rows[0], 0, 9)]
    assert min(xs) <= 270 and max(xs) >= 352
    lines = [_l("password:", 287, 386), _l("jfn2n2mcnkc2", 501, 630), _l("Shift+Enter starts a new line.", 1336, 1553, 150, 170)]
    assert [v.text for v in labelled_values(lines, SECRET_LABEL_ONLY)] == ["jfn2n2mcnkc2"]


def test_ner_span_cleanup():
    t = "Parag Sawant Yesterday"
    assert clean_span(t, 6, 9, "person") == (6, 12)
    u = "ping Priya Raman or"
    s, e = clean_span(u, 0, 16, "person")
    assert u[s:e] == "Priya Raman"


def test_face_tiles_cover_image():
    assert tile_starts(500, 640, 512) == [0]
    starts = tile_starts(1604, 640, 512)
    assert starts[0] == 0 and starts[-1] + 640 == 1604
