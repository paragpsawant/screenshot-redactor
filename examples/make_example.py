"""Generate a realistic fake screenshot full of (fake) sensitive data for demos and tests."""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

LINES = [
    ("Account settings", 30, (17, 24, 39)),
    ("Name: Jennifer Walsh", 22, (55, 65, 81)),
    ("Email: jennifer.walsh@contoso.com", 22, (55, 65, 81)),
    ("Phone: (415) 555-0132", 22, (55, 65, 81)),
    ("Address: 1600 Amphitheatre Parkway, Mountain View, CA 94043", 22, (55, 65, 81)),
    ("Card: 4111 1111 1111 1111   SSN: 219-09-9999", 22, (55, 65, 81)),
    ("OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1", 22, (190, 18, 60)),
    ("Server: 192.168.14.201   Last login: Tuesday", 22, (55, 65, 81)),
    ("Theme: Light    Language: English    Notifications: On", 22, (55, 65, 81)),
]


def _font(size: int) -> ImageFont.ImageFont:
    for name in ("arial.ttf", "DejaVuSans.ttf", "LiberationSans-Regular.ttf"):
        try:
            return ImageFont.truetype(name, size)
        except OSError:
            continue
    return ImageFont.load_default(size=size)


def make_screenshot(path: str | Path | None = None, with_qr: bool = True) -> Image.Image:
    img = Image.new("RGB", (1100, 620), (249, 250, 251))
    draw = ImageDraw.Draw(img)
    draw.rectangle([0, 0, 1100, 44], fill=(31, 41, 55))
    draw.text((20, 11), "My App  -  Profile", font=_font(18), fill=(243, 244, 246))
    y = 70
    for text, size, color in LINES:
        draw.text((40, y), text, font=_font(size), fill=color)
        y += size + 30
    if with_qr:
        try:
            import cv2
            import numpy as np

            qr = cv2.QRCodeEncoder.create().encode("https://example.com/invite?token=abc123XYZ")
            qr = cv2.resize(qr, (qr.shape[1] * 5, qr.shape[0] * 5), interpolation=cv2.INTER_NEAREST)
            qr = np.pad(qr, 12, constant_values=255)
            img.paste(Image.fromarray(qr).convert("RGB"), (900, 430))
        except Exception:
            pass
    if path:
        img.save(path)
    return img


if __name__ == "__main__":
    out = Path(__file__).parent / "fake_profile.png"
    make_screenshot(out)
    print(out)
