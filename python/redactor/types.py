from __future__ import annotations

from dataclasses import asdict, dataclass, field

Point = tuple[float, float]
Polygon = list[Point]

CATEGORIES: dict[str, str] = {
    "secrets": "API keys, tokens, passwords, private keys",
    "contact": "Emails and phone numbers",
    "financial": "Credit cards, IBANs, bank accounts, crypto wallets",
    "government_id": "SSNs, passports, driver licenses",
    "network": "IP and MAC addresses",
    "person": "People's names",
    "location": "Street addresses",
    "dates": "Dates of birth",
    "faces": "Human faces",
    "codes": "QR codes and barcodes",
    "custom": "Your own words or phrases",
}

DEFAULT_CATEGORIES = [c for c in CATEGORIES if c != "custom"]


@dataclass
class TextSpan:
    """A sensitive span found in a string (character offsets)."""

    start: int
    end: int
    label: str
    category: str
    score: float = 1.0
    source: str = "rule"


@dataclass
class Detection:
    """A sensitive region found in the image."""

    id: int
    category: str
    label: str
    polygon: Polygon
    score: float = 1.0
    source: str = "rule"
    text: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def preview(self) -> str:
        return mask_preview(self.text) if self.text else ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["text"] = self.preview
        d["polygon"] = [[round(x, 1), round(y, 1)] for x, y in self.polygon]
        d["score"] = round(self.score, 3)
        return d


_ACRONYMS = {"IP", "AWS", "URL", "SSN", "US", "IBAN", "JWT", "MAC", "QR", "AI", "API"}
_SPECIAL = {"GITHUB": "GitHub", "HUGGINGFACE": "Hugging Face"}


def pretty_label(label: str) -> str:
    return " ".join(w if w in _ACRONYMS else _SPECIAL.get(w, w.capitalize()) for w in label.split("_"))


def mask_preview(text: str) -> str:
    """Show just enough of a value to recognise it, never the whole thing."""
    t = text.strip()
    if len(t) < 8:
        return "•" * len(t)
    keep = 2 if len(t) < 20 else 4
    return f"{t[:keep]}{'•' * min(8, len(t) - keep)}"
