import numpy as np
import pytest

from redactor.layout import OCRLine, OCRWord, char_bounds, rect_polygon, span_polygon
from redactor.redact import annotate, apply_redactions
from redactor.types import Detection, mask_preview


def line(text="Email: a@b.com", words=True):
    poly = rect_polygon(0, 0, 140, 20)
    ws = [OCRWord("Email:", rect_polygon(0, 0, 60, 20)), OCRWord("a@b.com", rect_polygon(70, 0, 140, 20))]
    return OCRLine(text, poly, 1.0, ws if words else [])


def test_char_bounds_uses_word_boxes():
    b = char_bounds(line())
    assert b[7][0] == pytest.approx(0.5)      # 'a' starts at x=70 of 140
    assert b[-1][1] == pytest.approx(1.0)


def test_char_bounds_fallback_uniform_when_words_mismatch():
    ln = line()
    ln.words = [OCRWord("zzz", rect_polygon(0, 0, 10, 20))]
    assert char_bounds(ln)[0] == pytest.approx((0, 1 / len(ln.text)))


def test_span_polygon_covers_value_not_label():
    poly = span_polygon(line(), 7, 14)
    xs = [p[0] for p in poly]
    assert min(xs) > 60 and max(xs) >= 140


def test_rotated_line_polygon_follows_rotation():
    ln = OCRLine("abcd", [(0, 0), (100, 100), (90, 110), (-10, 10)])
    poly = span_polygon(ln, 2, 4, pad_chars=0, pad_y=0)
    assert poly[0] == pytest.approx((50, 50))
    assert poly[1] == pytest.approx((100, 100))


@pytest.mark.parametrize("style", ["black box", "pixelate", "blur"])
def test_apply_redactions_only_touches_region(style):
    rng = np.random.default_rng(0)
    img = rng.integers(0, 255, (100, 200, 3), dtype=np.uint8)
    out = apply_redactions(img, [rect_polygon(10, 10, 60, 40)], style)
    assert out.shape == img.shape
    assert np.array_equal(out[60:, :], img[60:, :])
    assert not np.array_equal(out[15:35, 15:55], img[15:35, 15:55])
    if style == "black box":
        assert out[15:35, 15:55].max() == 0


def test_apply_redactions_rejects_unknown_style():
    with pytest.raises(ValueError):
        apply_redactions(np.zeros((10, 10, 3), np.uint8), [], "sparkles")


def test_annotate_returns_same_shape():
    img = np.full((50, 80, 3), 255, np.uint8)
    det = Detection(1, "secrets", "API", rect_polygon(5, 5, 40, 20))
    assert annotate(img, [det]).shape == img.shape


def test_mask_preview_never_reveals_full_value():
    secret = "sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1"
    p = mask_preview(secret)
    assert p.startswith("sk-p") and "9fQ2" not in p and len(p) < len(secret)
    assert mask_preview("abc") == "•••"
    assert mask_preview("hunter2") == "•••••••"
    assert mask_preview("Pr0dP4ss!2026").startswith("Pr•")


def test_pretty_label_keeps_acronyms():
    from redactor.types import pretty_label

    assert pretty_label("AWS_ACCESS_KEY") == "AWS Access Key"
    assert pretty_label("IP_ADDRESS") == "IP Address"
