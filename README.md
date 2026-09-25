# 🕶️ Screenshot Redactor

[![CI](https://github.com/paragpsawant/screenshot-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/paragpsawant/screenshot-redactor/actions/workflows/ci.yml)
[![Live demo on Hugging Face](https://img.shields.io/badge/%F0%9F%A4%97%20Live%20demo-Hugging%20Face%20Space-yellow)](https://huggingface.co/spaces/screenshot-redactor/app)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
![Runs in your browser](https://img.shields.io/badge/runs-100%25%20in%20your%20browser-111827)

**Hide API keys, passwords, emails, phone numbers, card numbers, SSNs, IPs, names, addresses, faces
and QR codes in a screenshot before you share it. Everything runs on your device; the image is never uploaded.**

👉 **Try it: [huggingface.co/spaces/screenshot-redactor/app](https://huggingface.co/spaces/screenshot-redactor/app)**

| Before | After (one click) |
|---|---|
| ![Before: a terminal leaking .env secrets and a chat with a phone number and address](web/examples/dev_leak.png) | ![After: every secret, contact detail and address covered; harmless text untouched](web/examples/dev_leak_redacted.png) |

*All data in these images is fake.*

## Why

Screenshots end up in bug reports, Slack threads, docs and social posts, and they routinely leak
`.env` secrets, customer emails and home addresses. Hiding them by hand is slow and easy to get
wrong, and most "AI redaction" tools ask you to upload the very image you're trying to protect.
This one runs the AI models in the browser tab instead.

## Features

- **Finds** secrets (OpenAI/Anthropic, AWS, GitHub, Stripe, Slack, Google, Hugging Face keys, JWTs,
  bearer tokens, `PASSWORD=…`, passwords inside DB URLs, private keys, unlabeled high-entropy tokens),
  emails and phone numbers, credit cards (Luhn), IBANs (mod-97), SSNs, passports, IPv4/IPv6/MAC,
  names, street addresses, faces, QR codes and barcodes, plus any custom words you add.
- **Covers only the value**: `OPENAI_API_KEY=` stays readable and the key doesn't, because each
  character's position comes from the OCR model's CTC timesteps.
- **Review and edit**: untick false positives, or drag a box over anything that was missed.
- **Black box, pixelate or blur.** It warns that blur and pixelation aren't safe for text.
- **Clean output**: download or copy a PNG re-encoded from pixels, so EXIF/GPS metadata is dropped.
- **Private and offline**: after the first load (~50 MB of models, cached) it works with no network.

## How it works

```
screenshot ─► PP-OCRv6 text detection + recognition (ONNX Runtime Web, in a Web Worker)
           ├─► secret/PII rules + checksums ─┐
           ├─► on-device PII token classifier ┼─► character spans → pixel boxes ─► review / edit ─► PNG
           ├─► YuNet face detector ───────────┤
           └─► QR / barcode detector ─────────┘
```

| Folder | What | Runs on |
|---|---|---|
| [`web/`](web/) | **The app.** Static site: vanilla JS + ONNX Runtime Web (WebAssembly). Deployed as a free static Hugging Face Space. | Any modern browser |
| [`python/`](python/) | Gradio version with an HTTP API and an **MCP tool** (`redact_screenshot`) for scripts and AI agents. | Local, or a Gradio Space |

Every library and model ships with the app: models are committed in [`web/models/`](web/models/), and
`npm run vendor` copies the pinned npm libraries into `web/vendor/` at build time. So it never calls a CDN
or a third-party API. The CI browser test **fails if the page makes an upload or contacts any other host**.

## Run it locally

```bash
# Web app
cd web
npm ci
npm run vendor       # copy the pinned runtime libraries into web/vendor (build output, not committed)
npm run serve        # http://127.0.0.1:8080
npm test             # 50 tests: rules + full pipeline on the real bundled models (Node)
node tests/e2e.browser.mjs http://127.0.0.1:8080/   # real browser (Edge/Chrome); set E2E_BROWSER=chromium for Playwright's build

# Python app (API + MCP)
cd python
pip install -r requirements.txt
python app.py        # http://127.0.0.1:7860   MCP endpoint: /gradio_api/mcp/
pytest -q
```

## CI/CD

- **[CI](.github/workflows/ci.yml)**, on every push and PR:
  - web unit and end-to-end model tests;
  - a check that the vendored libraries match `package.json`;
  - a real-browser test in Chromium that asserts no uploads and no third-party requests;
  - the Python test suite.
- **[Deploy](.github/workflows/deploy-space.yml)**: on pushes to `main` that touch `web/`, uploads
  the app to the Hugging Face Space (requires an `HF_TOKEN` repository secret).

## Limitations

- Only text the OCR can read is found automatically. Tiny, blurry or stylised text can be missed, so review before sharing and drag boxes over anything left.
- Name and address detection is an AI model tuned for English, so untick any false positives.

## Author

Built by **Parag Sawant**: [@paragpsawant](https://github.com/paragpsawant) ·
[parags.dev](https://parags.dev) · [LinkedIn](https://www.linkedin.com/in/paragsawant/) ·
[Hugging Face](https://huggingface.co/paragpsawant)

If this saved you from leaking a key, a ⭐ helps others find it.

## Credits & licenses

Apache-2.0. Bundled third-party work: PP-OCRv6 via RapidOCR (Apache-2.0), YuNet (MIT),
bert-small-pii-detection (Apache-2.0), ONNX Runtime Web (MIT), transformers.js (Apache-2.0),
jsQR (Apache-2.0). Sources and checksums are in [`web/models/README.md`](web/models/README.md); license texts are in
[`web/licenses/`](web/licenses/) and [`web/models/LICENSES/`](web/models/LICENSES/).

