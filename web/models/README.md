# Bundled models

All models are served from this Space; the page never downloads them from anywhere else.

| File | Model | Source | License | SHA-256 |
|---|---|---|---|---|
| `ocr_det.onnx` | PP-OCRv6 text detection (tiny) | RapidOCR v3.9.2 model zoo (`onnx/PP-OCRv6/det/PP-OCRv6_det_tiny.onnx`) | Apache-2.0 | `f42c0fbd294d95eac1a550e131b277dac97462c8025fa4b6c3cec1b7894bd3d5` |
| `ocr_rec.onnx` | PP-OCRv6 text recognition (tiny) | RapidOCR v3.9.2 model zoo (`onnx/PP-OCRv6/rec/PP-OCRv6_rec_tiny.onnx`) | Apache-2.0 | `e16e242de5937ad92609223f19bc2aff3727ee40b095f996907c24749bad251b` |
| `ocr_keys.json` | Character list for `ocr_rec.onnx` | Extracted from the model's `character` metadata (`splitlines()`) | Apache-2.0 | `b9bf03b8b02c9c22f6af847769269d5c1f877cfc8914bbaecac6a44d7a6061de` |
| `yunet.onnx` | YuNet face detection (2023mar) | OpenCV Zoo | MIT (`LICENSES/yunet.txt`) | `8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4` |
| `pii/` | bert-small-pii-detection (int8) | `onnx-community/bert-small-pii-detection-ONNX` (from `gravitee-io/bert-small-pii-detection`) | Apache-2.0 | `40e94266f077c088d3dda3e12fe7be8faa1cae862c3e3fe84b799439c509095a` (model_quantized.onnx) |

The tiny OCR models were chosen over PP-OCRv6 *small* after an A/B on the example screenshots:
same sensitive items found, ~3× faster, 6 MB instead of 31 MB.
