import pytest

from redactor.rules import find_spans, iban_ok, looks_random, luhn_ok


def labels(text, **kw):
    return [(s.label, text[s.start:s.end]) for s in find_spans(text, **kw)]


@pytest.mark.parametrize("text,label,value", [
    ("contact me at jane.doe+work@example.co.uk today", "EMAIL", "jane.doe+work@example.co.uk"),
    ("Phone: (415) 555-0132", "PHONE", "(415) 555-0132"),
    ("call +44 20 7946 0958 now", "PHONE", "+44 20 7946 0958"),
    ("Card 4111 1111 1111 1111 exp 12/29", "CREDIT_CARD", "4111 1111 1111 1111"),
    ("SSN: 219-09-9999", "US_SSN", "219-09-9999"),
    ("IBAN GB82 WEST 1234 5698 7654 32", "IBAN", "GB82 WEST 1234 5698 7654 32"),
    ("host 10.0.12.254 is down", "IP_ADDRESS", "10.0.12.254"),
    ("addr 2001:db8::8a2e:370:7334", "IP_ADDRESS", "2001:db8::8a2e:370:7334"),
    ("mac 00:1A:2B:3C:4D:5E", "MAC_ADDRESS", "00:1A:2B:3C:4D:5E"),
    ("key AKIAIOSFODNN7EXAMPLE here", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
    ("token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GITHUB_TOKEN",
     "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
    ("OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1", "AI_API_KEY", "sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1"),
    ("HF_TOKEN=hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567", "HUGGINGFACE_TOKEN",
     "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567"),
    ("Authorization: Bearer abcDEF123456ghiJKL789", "BEARER_TOKEN", "abcDEF123456ghiJKL789"),
    ("password: hunter2!", "PASSWORD_OR_SECRET", "hunter2!"),
    ("https://x.io/cb?code=Zx81kLpQ02mN&state=1", "URL_TOKEN", "Zx81kLpQ02mN"),
    ("-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----"),
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "JWT",
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"),
    ("DOB: 04/12/1987", "DATE_OF_BIRTH", "04/12/1987"),
    ("Passport No: X1234567", "PASSPORT", "X1234567"),
    ("wallet 0x52908400098527886E0F7030069857D2E4169EE7", "CRYPTO_WALLET",
     "0x52908400098527886E0F7030069857D2E4169EE7"),
    ("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7K7MDENGbPxRfiCYz3kL9mQ", "PASSWORD_OR_SECRET",
     "wJalrXUtnFEMI7K7MDENGbPxRfiCYz3kL9mQ"),
    ('"client_secret": "a1b2c3d4e5"', "PASSWORD_OR_SECRET", "a1b2c3d4e5"),
    ("DB_PASSWORD=Pr0dP4ss!2026", "PASSWORD_OR_SECRET", "Pr0dP4ss!2026"),
    ("postgres://admin:Pr0dP4ss!2026@10.20.30.40:5432/db", "URL_PASSWORD", "Pr0dP4ss!2026"),
    ("STRIPE_SECRET_KEY=sk_1ive_51HxQ2eKz8LmN4pRtY7uVwXa9", "STRIPE_KEY", "sk_1ive_51HxQ2eKz8LmN4pRtY7uVwXa9"),
])
def test_detects(text, label, value):
    assert (label, value) in labels(text)


@pytest.mark.parametrize("text", [
    "Theme: Light    Language: English    Notifications: On",
    "Order #123456 shipped on 2026-09-24",
    "Card 4111 1111 1111 1112",           # fails Luhn
    "SSN: 000-12-3456",                   # invalid area number
    "password: ********",                 # already masked
    "Version 12:30:45 build",
    "useSomeVeryLongCamelCaseIdentifierName",
    "The secretary: Dana will join",       # 'secret' prefix of another word
    "TOKEN_URL=https://login.example.com/oauth2/token",
    "password: required",
])
def test_no_false_positives(text):
    assert labels(text) == []


def test_category_filter():
    text = "mail a@b.com key AKIAIOSFODNN7EXAMPLE"
    assert [l for l, _ in labels(text, categories=["secrets"])] == ["AWS_ACCESS_KEY"]
    assert [l for l, _ in labels(text, categories=["contact"])] == ["EMAIL"]


def test_custom_terms_case_insensitive():
    assert labels("Project FALCON launch", custom_terms=["project falcon"]) == [("CUSTOM", "Project FALCON")]


def test_overlaps_resolved():
    spans = find_spans("OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1")
    assert len(spans) == 1


def test_validators():
    assert luhn_ok("4111111111111111") and not luhn_ok("4111111111111112")
    assert iban_ok("DE89 3704 0044 0532 0130 00") and not iban_ok("DE89 3704 0044 0532 0130 01")
    assert looks_random("x9Kq2LmZ7vB4nR8tW1yP3sD6") and not looks_random("aaaaaaaaaaaaaaaaaaaaaaaa")
