"""Screenshot Auto-Redactor — Gradio app / Hugging Face Space / MCP server."""

from __future__ import annotations

import os

# No usage telemetry to outside services; the app needs no network access except the model download.
os.environ.setdefault("GRADIO_ANALYTICS_ENABLED", "False")
os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")

import tempfile
import threading
import time
from pathlib import Path

import gradio as gr
import numpy as np
from PIL import Image

from redactor import CATEGORIES, DEFAULT_CATEGORIES, Detection
from redactor.pipeline import redact, scan, to_rgb_array
from redactor.redact import STYLES, annotate
from redactor.types import pretty_label

ROOT = Path(__file__).parent
EXAMPLE = ROOT / "examples" / "fake_profile.png"
if not EXAMPLE.exists():
    from examples.make_example import make_screenshot

    make_screenshot(EXAMPLE)
EXAMPLES = [[str(p)] for p in (EXAMPLE, ROOT / "examples" / "dev_leak.png") if p.exists()]

CATEGORY_CHOICES = [(f"{k.replace('_', ' ').title()} — {v}", k) for k, v in CATEGORIES.items() if k != "custom"]
MAX_SIDE = 4096


def _prep(image) -> np.ndarray:
    if image is None:
        raise gr.Error("Upload or paste a screenshot first.")
    arr = to_rgb_array(image)
    h, w = arr.shape[:2]
    if max(h, w) > MAX_SIDE:
        s = MAX_SIDE / max(h, w)
        arr = np.asarray(Image.fromarray(arr).resize((int(w * s), int(h * s)), Image.LANCZOS))
    return arr


def _terms(text: str | None) -> list[str]:
    return [t.strip() for t in (text or "").replace("\n", ",").split(",") if t.strip()]


def _save_png(arr: np.ndarray) -> str:
    # Re-encoding from raw pixels drops EXIF/GPS and any other embedded metadata.
    path = Path(tempfile.mkdtemp(prefix="redacted_")) / "redacted.png"
    Image.fromarray(arr).save(path, format="PNG", optimize=True)
    return str(path)


def _choice_label(d: Detection) -> str:
    text = f" · {d.preview}" if d.preview else ""
    return f"#{d.id} {pretty_label(d.label)}{text}"


# --- UI handlers -----------------------------------------------------------------

def on_scan(image, categories, custom, style, use_ner):
    arr = _prep(image)
    t = time.perf_counter()
    result = scan(arr, categories or [], _terms(custom), use_ner=use_ner)
    elapsed = time.perf_counter() - t
    dets = result.detections
    ids = [d.id for d in dets]
    counts = ", ".join(f"{n} {c.replace('_', ' ')}" for c, n in result.summary().items()) or "nothing sensitive"
    status = f"**Found {len(dets)} item(s)** in {elapsed:.1f}s — {counts}. Untick anything you want to keep visible."
    if use_ner and not result.ner_used and set(categories or []) & {"person", "location", "dates"}:
        status += "\n\n⚠️ AI name/address model unavailable — using rules only."
    state = {"image": arr, "detections": dets}
    choices = gr.CheckboxGroup(choices=[(_choice_label(d), d.id) for d in dets], value=ids,
                               visible=bool(dets))
    return (state, status, choices, *_render(state, ids, style))


def _render(state, selected, style):
    arr, dets = state["image"], state["detections"]
    sel = set(selected or [])
    out = redact(arr, dets, sel, style)
    report = {
        "redacted": [d.to_dict() for d in dets if d.id in sel],
        "kept_visible": [d.to_dict() for d in dets if d.id not in sel],
        "style": style,
    }
    return annotate(arr, dets, sel), out, _save_png(out), report


def on_change(state, selected, style):
    if not state:
        return gr.skip(), gr.skip(), gr.skip(), gr.skip()
    return _render(state, selected, style)


def style_note(style):
    if style == "black box":
        return ""
    return ("⚠️ **Blur and pixelation are not secure for text.** Tools can sometimes recover "
            "pixelated or blurred words. Use *black box* for passwords, keys and numbers.")


# --- API / MCP tool ----------------------------------------------------------------

def redact_screenshot(image: Image.Image, categories: list[str] | None = None,
                      style: str = "black box", custom_terms: str = "",
                      detect_names: bool = True) -> tuple[Image.Image, dict]:
    """Automatically find and hide sensitive information in a screenshot before sharing it.

    Detects API keys, tokens, passwords, private keys, emails, phone numbers, credit cards,
    IBANs, SSNs, passports, IP/MAC addresses, people's names, street addresses, dates of
    birth, faces, QR codes and barcodes, then covers them. Output has all metadata removed.

    Args:
        image: The screenshot or photo to redact.
        categories: Which kinds of data to hide. Any of: secrets, contact, financial,
            government_id, network, person, location, dates, faces, codes. Defaults to all.
        style: How to hide regions: "black box" (secure, default), "pixelate" or "blur".
        custom_terms: Extra comma-separated words or phrases to hide, e.g. a company name.
        detect_names: Use the AI model to find names, addresses and birth dates.

    Returns:
        The redacted image and a JSON report listing each hidden region (values are masked).
    """
    arr = _prep(image)
    style = style if style in STYLES else "black box"
    result = scan(arr, categories or DEFAULT_CATEGORIES, _terms(custom_terms), use_ner=detect_names)
    out = redact(arr, result.detections, None, style)
    report = {"count": len(result.detections), "by_category": result.summary(),
              "regions": [d.to_dict() for d in result.detections]}
    return Image.fromarray(out), report


# --- Layout ------------------------------------------------------------------------

INTRO = """
# 🕶️ Screenshot Auto-Redactor
**Share screenshots without leaking secrets.** Drop in a screenshot (or paste with Ctrl+V) and it
finds and covers API keys, passwords, emails, phone numbers, card numbers, SSNs, IPs, names,
addresses, faces and QR codes. Review every box, untick false positives, download a clean PNG
with metadata stripped. Nothing is stored.
"""

with gr.Blocks(title="Screenshot Auto-Redactor", delete_cache=(1800, 1800), analytics_enabled=False) as demo:
    gr.Markdown(INTRO)
    state = gr.State(None)
    with gr.Row():
        with gr.Column(scale=5):
            image_in = gr.Image(label="Screenshot", type="numpy", sources=["upload", "clipboard"],
                                image_mode="RGB", height=380)
            with gr.Accordion("What to hide", open=False):
                cats = gr.CheckboxGroup(CATEGORY_CHOICES, value=DEFAULT_CATEGORIES, label="Categories")
                custom = gr.Textbox(label="Also hide these words (comma-separated)",
                                    placeholder="e.g. Contoso, Project Falcon, my-server-01")
                use_ner = gr.Checkbox(True, label="Use AI to find names, addresses and birth dates")
            style = gr.Radio(list(STYLES), value="black box", label="Redaction style")
            note = gr.Markdown()
            scan_btn = gr.Button("🔍 Find & redact", variant="primary", size="lg")
            gr.Examples(EXAMPLES, inputs=[image_in], label="Try an example (all data is fake)")
        with gr.Column(scale=7):
            status = gr.Markdown("Upload a screenshot and press **Find & redact**.")
            with gr.Tabs():
                with gr.Tab("✅ Redacted"):
                    image_out = gr.Image(label="Redacted", type="numpy", interactive=False, height=460,
                                         format="png")
                    download = gr.DownloadButton("⬇️ Download PNG", variant="primary")
                with gr.Tab("🔎 Review detections"):
                    review = gr.Image(label="Numbered detections", type="numpy", interactive=False, height=460)
                with gr.Tab("🧾 Report"):
                    report = gr.JSON(label="What was hidden (values masked)")
            picks = gr.CheckboxGroup(label="Redact these (untick to keep visible)", visible=False)

    # Hidden components that expose a clean one-call API / MCP tool.
    with gr.Row(visible=False):
        api_in = gr.Image(type="pil")
        api_cats = gr.CheckboxGroup([c for _, c in CATEGORY_CHOICES], value=DEFAULT_CATEGORIES)
        api_style = gr.Textbox("black box")
        api_terms = gr.Textbox("")
        api_ner = gr.Checkbox(True)
        api_out = gr.Image(type="pil", format="png")
        api_report = gr.JSON()
        api_btn = gr.Button()

    outs = [review, image_out, download, report]
    scan_btn.click(on_scan, [image_in, cats, custom, style, use_ner], [state, status, picks, *outs],
                   api_visibility="private")
    picks.change(on_change, [state, picks, style], outs, api_visibility="private", show_progress="hidden")
    style.change(on_change, [state, picks, style], outs, api_visibility="private", show_progress="hidden")
    style.change(style_note, style, note, api_visibility="private", show_progress="hidden")
    api_btn.click(redact_screenshot, [api_in, api_cats, api_style, api_terms, api_ner],
                  [api_out, api_report], api_name="redact_screenshot")


def _warm_up() -> None:
    try:
        scan(to_rgb_array(Image.open(EXAMPLE)))
    except Exception as exc:  # warm-up is best effort
        print(f"warm-up skipped: {exc}")


if __name__ == "__main__":
    threading.Thread(target=_warm_up, daemon=True).start()
    demo.queue(default_concurrency_limit=2).launch(
        mcp_server=True,
        theme=gr.themes.Soft(primary_hue="slate"),
        footer_links=["api"],
        favicon_path=str(ROOT / "assets" / "favicon.png"),
    )
