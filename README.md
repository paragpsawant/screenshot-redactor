# 🕶️ Screenshot Redactor

Hide API keys, passwords, emails, phone numbers, card numbers, SSNs, IPs, names, addresses, faces and
QR codes in screenshots before you share them.

| Folder | What | Where it runs |
|---|---|---|
| [`web/`](web/) | **Main app.** Fully in-browser (ONNX Runtime Web + WebAssembly); nothing is uploaded. Deployed as a static Hugging Face Space. | Any modern browser |
| [`python/`](python/) | Gradio app + API + MCP tool (`redact_screenshot`) for scripts and AI agents. | Local, or a Gradio Space |

## Web app

```bash
cd web
npm install          # dev tooling + libraries to vendor
npm run vendor       # copy runtime libraries into web/vendor (no CDN at runtime)
npm run serve        # http://127.0.0.1:8080
npm test             # rules + end-to-end pipeline on the bundled models (Node)
node tests/e2e.browser.mjs http://127.0.0.1:8080/   # real-browser check (Edge/Chrome), asserts zero external requests
```

## Python app

```bash
cd python
pip install -r requirements.txt
python app.py        # http://127.0.0.1:7860  (MCP: /gradio_api/mcp/)
pytest -q
```

Licensed under Apache-2.0. Third-party model and library licenses are listed in `web/models/README.md`
and `web/vendor/LICENSES/`.
