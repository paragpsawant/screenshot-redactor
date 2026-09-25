"""Rule-based detection of secrets and PII in plain text.

Every rule returns character spans so the caller can map them back to pixels.
Rules favour recall for secrets (a missed API key is worse than an extra box)
and use checksums (Luhn, IBAN mod-97, IP parsing) to keep numeric PII precise.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass
from typing import Callable, Iterable

import regex as uregex

from .types import TextSpan

Validator = Callable[[str], bool]


def luhn_ok(value: str) -> bool:
    digits = [int(c) for c in value if c.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    s = re.sub(r"\s", "", value).upper()
    if not 15 <= len(s) <= 34:
        return False
    rearranged = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1
    except ValueError:
        return False


def phone_ok(value: str) -> bool:
    return 10 <= sum(c.isdigit() for c in value) <= 15


def ipv4_ok(value: str) -> bool:
    try:
        return not ipaddress.IPv4Address(value).is_unspecified
    except ValueError:
        return False


def ipv6_ok(value: str) -> bool:
    if value.count(":") < 2:
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return "::" in value or value.count(":") == 7


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_random(value: str) -> bool:
    """Heuristic for unlabeled secrets: long, mixed character classes, high entropy."""
    v = value.strip("=")
    if len(v) < 20:
        return False
    classes = sum(
        [any(c.islower() for c in v), any(c.isupper() for c in v), any(c.isdigit() for c in v)]
    )
    if classes < 3:
        return False
    # Words glued together (CamelCaseIdentifiers) have long letter runs; secrets don't.
    if re.search(r"[A-Za-z]{12,}", v):
        return False
    return shannon_entropy(v) >= 3.7


def not_masked(value: str) -> bool:
    """Ignore values that are already hidden, e.g. `password: ********`."""
    return bool(value) and not re.fullmatch(r"[*•●·xX.\-_]+", value)


def secret_value_ok(value: str) -> bool:
    """A labeled secret's value: not masked, not a URL/placeholder like `TOKEN_URL=https://…`."""
    v = value.lower()
    if v.startswith(("http://", "https://", "${", "$(", "<", "{{", "%")):
        return False
    return not_masked(value) and v not in {"none", "null", "true", "false", "undefined", "required"}


@dataclass(frozen=True)
class Rule:
    label: str
    category: str
    pattern: re.Pattern[str]
    group: int = 0
    validator: Validator | None = None


def _r(label: str, category: str, pattern: str, group: int = 0,
       validator: Validator | None = None, flags: int = 0) -> Rule:
    return Rule(label, category, re.compile(pattern, flags), group, validator)


_I = re.IGNORECASE
_ID_LABEL = r"\s*(?:no\.?|num(?:ber)?|#)?\s*[:#]?\s*"

# Order matters: earlier rules win when spans overlap.
RULES: list[Rule] = [
    # --- secrets -------------------------------------------------------------
    _r("PRIVATE_KEY", "secrets", r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    _r("AWS_ACCESS_KEY", "secrets", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _r("GITHUB_TOKEN", "secrets", r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b"),
    _r("AI_API_KEY", "secrets", r"\bsk-(?:ant-|proj-|or-)?[A-Za-z0-9_\-]{20,}"),
    _r("HUGGINGFACE_TOKEN", "secrets", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _r("SLACK_TOKEN", "secrets", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
    _r("GOOGLE_API_KEY", "secrets", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    _r("STRIPE_KEY", "secrets", r"\b(?:sk|rk)_(?:[l1I]ive|test)_[0-9a-zA-Z]{16,}\b"),  # OCR reads l as 1
    _r("JWT", "secrets", r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _r("CONNECTION_STRING_KEY", "secrets",
       r"\b(?:AccountKey|SharedAccessKey|SharedAccessSignature|sig)=([A-Za-z0-9+/%=]{16,})", 1),
    _r("BEARER_TOKEN", "secrets", r"\bbearer\s+([A-Za-z0-9._~+/-]{16,}=*)", 1, flags=_I),
    _r("URL_PASSWORD", "secrets", r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+:([^\s@/]{3,})@", 1),
    _r("URL_TOKEN", "secrets",
       r"[?&](?:token|key|api_?key|sig|signature|access_token|auth|code|secret|password)=([^&\s]{8,})",
       1, flags=_I),
    # Matches `password: x`, `API_KEY=x`, `AWS_SECRET_ACCESS_KEY=x`, `"client_secret": "x"`...
    _r("PASSWORD_OR_SECRET", "secrets",
       r"(?<![A-Za-z])(?:pass(?:word|wd|code|phrase)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
       r"private[_-]?key|client[_-]?secret|credentials?)(?:[_-][A-Za-z0-9]+)*"
       r"\s*[\"']?\s*[:=]\s*[\"']?([^\s\"',;]{4,})",
       1, secret_value_ok, flags=_I),
    # --- financial -----------------------------------------------------------
    _r("CREDIT_CARD", "financial", r"\b(?:\d[ -]?){12,18}\d\b", 0, luhn_ok),
    _r("IBAN", "financial", r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", 0, iban_ok),
    _r("BANK_ACCOUNT", "financial",
       r"\b(?:account|acct|a/c)" + _ID_LABEL + r"(\d[\d -]{5,20}\d)\b", 1, flags=_I),
    _r("ROUTING_NUMBER", "financial", r"\b(?:routing|aba)" + _ID_LABEL + r"(\d{9})\b", 1, flags=_I),
    _r("CRYPTO_WALLET", "financial",
       r"\b(?:0x[a-fA-F0-9]{40}|bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    # --- government ids ------------------------------------------------------
    _r("US_SSN", "government_id", r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    _r("PASSPORT", "government_id", r"\bpassport" + _ID_LABEL + r"([A-Z0-9]{6,9})\b", 1, flags=_I),
    _r("DRIVER_LICENSE", "government_id",
       r"\b(?:driver'?s?\s*licen[sc]e|DL)" + _ID_LABEL + r"([A-Z0-9-]{5,15})\b", 1, flags=_I),
    # --- contact -------------------------------------------------------------
    _r("EMAIL", "contact", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    _r("PHONE", "contact", r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}\b", 0, phone_ok),
    _r("PHONE", "contact", r"(?:\(\d{3}\)\s?|\b\d{3}[\s.-])\d{3}[\s.-]\d{4}\b", 0, phone_ok),
    # --- dates ---------------------------------------------------------------
    _r("DATE_OF_BIRTH", "dates",
       r"\b(?:dob|d\.o\.b\.?|date of birth|birth\s*date|born)\s*[:#-]?\s*"
       r"(\d{4}-\d{2}-\d{2}|[0-3]?\d[/.-][0-3]?\d[/.-](?:19|20)?\d{2}|[A-Za-z]{3,9}\.? \d{1,2},? \d{4})",
       1, flags=_I),
    # --- network -------------------------------------------------------------
    _r("MAC_ADDRESS", "network", r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
    _r("IP_ADDRESS", "network", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0, ipv4_ok),
    _r("IP_ADDRESS", "network", r"(?<![\w:])[0-9A-Fa-f:]{6,39}(?![\w:])", 0, ipv6_ok),
]

_TOKEN = re.compile(r"[A-Za-z0-9+/_\-]{20,}={0,2}")

# ---------------------------------------------------------------- people (chat UIs)
# Unicode letter classes need the `regex` module (stdlib `re` has no \p{Lu}).
_NOT_TIME_WORD = (
    r"(?!(?:Yesterday|Today|Tomorrow|Now|Just|Edited|Sent|Seen|Read|Delivered|"
    r"Mon|Tue|Wed|Thu|Fri|Sat|Sun|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
    r"Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec|January|February|March|April|June|July|"
    r"August|September|October|November|December|"
    r"Meeting|Standup|Sync|Call|Review|Lunch|Updated|Posted|Created|Modified|Last|Due|Starts?|Ends?|"
    r"Daily|Weekly|Monthly|Team|Project|Sprint|Reminder|Event|Deadline|Break|Demo|Office|Hours|"
    r"Planning|Retro|All)\b)"
)
_GLUE = (r"(?:Yesterday|Today|Tomorrow|Monday|Tuesday|Wednesday|Thursday|Friday|Saturday|Sunday|"
         r"Mon|Tue|Wed|Thu|Fri|Sat|Sun)\b")  # time words OCR sometimes glues onto a name
_NAME_WORD = _NOT_TIME_WORD + rf"\p{{Lu}}(?:(?!{_GLUE})[\p{{L}}\p{{M}}'’.\-])*"
_PARTICLE = r"(?:(?:de|da|di|du|van|von|der|den|del|la|le|bin|binti|al|el|ibn)\s+){0,2}"
_NAME = rf"{_NAME_WORD}(?:\s+{_PARTICLE}{_NAME_WORD}){{0,3}}"
_FULL_NAME = rf"{_NAME_WORD}(?:\s+{_PARTICLE}{_NAME_WORD}){{1,3}}"
TIMESTAMP = (
    r"(?:(?:Yesterday|Today|Mon(?:day)?|Tue(?:sday)?|Wed(?:nesday)?|Thu(?:rsday)?|Fri(?:day)?|"
    r"Sat(?:urday)?|Sun(?:day)?|\d{1,2}/\d{1,2}(?:/\d{2,4})?|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\.? \d{1,2}(?:,? \d{4})?),?\s+)?"
    r"\d{1,2}:\d{2}(?:\s?[AaPp]\.?[Mm]\.?)?"
)
_NOT_GENERIC = r"(?!(?:Team|All|Everyone|There|Folks|Guys|Friends|Sir|Madam|Support|Admin|Hi|Hello)\b)"

# (label, pattern with the name in group 1); matched with `regex`, after the rules above.
PERSON_RULES = [
    uregex.compile(rf"^\s*({_FULL_NAME})(?:\s*\([^)]{{1,40}}\))?(?:\s+|(?={_GLUE})){TIMESTAMP}\s*$"),  # chat header
    uregex.compile(rf"(?<![\w.])@({_NAME})"),  # @mention
    uregex.compile(rf"\b(?:Hi|Hello|Hey|Dear|Thanks|Thank you|Cheers|Regards|Best),?\s+{_NOT_GENERIC}"
                   rf"({_NAME_WORD}(?:\s+{_NAME_WORD})?)"),
    uregex.compile(rf"\b(?:From|To|Cc|Bcc|Sender|Recipient|Name|Full name|Owner|Assignee|Author|Contact|"
                   rf"Signed by)\s*:\s*{_NOT_GENERIC}({_NAME})"),
]

#: An OCR box that is only a secret label; its value is in the next box on the row (form fields).
SECRET_LABEL_ONLY = re.compile(
    r"(?:^|\s)(?:pass(?:word|wd|code|phrase)?|pwd|secret|token|api[ _-]?key|access[ _-]?key|"
    r"private[ _-]?key|client[ _-]?secret|pin|otp)\s*[:=]?\s*$", _I)


def secret_like_chunk(chunk: str) -> bool:
    """Does a space-separated chunk look like more of a secret rather than an ordinary word?"""
    if len(chunk) < 3:
        return False
    if any(c.isdigit() for c in chunk) or not all(c.isalpha() for c in chunk):
        return True
    has_lower, has_upper = any(c.islower() for c in chunk), any(c.isupper() for c in chunk)
    return has_lower and has_upper and not (chunk[0].isupper() and chunk[1:].islower())


def extend_secret(text: str, end: int, max_chunks: int = 4) -> int:
    """Passwords can contain spaces (and OCR sometimes inserts one): keep covering secret-like chunks."""
    for _ in range(max_chunks):
        m = re.match(r" {1,2}([^\s\"',;]+)", text[end:])
        if not m or not secret_like_chunk(m.group(1)):
            break
        end += m.end()
    return end


def find_spans(text: str, categories: Iterable[str] | None = None,
               custom_terms: Iterable[str] = ()) -> list[TextSpan]:
    """Return non-overlapping sensitive spans in ``text``."""
    wanted = set(categories) if categories is not None else None
    candidates: list[TextSpan] = []
    priority: dict[int, int] = {}

    def add(span: TextSpan, prio: int) -> None:
        if span.end > span.start and (wanted is None or span.category in wanted):
            priority[id(span)] = prio
            candidates.append(span)

    for prio, term in enumerate(t.strip() for t in custom_terms):
        if not term:
            continue
        for m in re.finditer(re.escape(term), text, _I):
            add(TextSpan(m.start(), m.end(), "CUSTOM", "custom"), -1000 + prio)

    for prio, rule in enumerate(RULES):
        for m in rule.pattern.finditer(text):
            value = m.group(rule.group)
            if not value or (rule.validator and not rule.validator(value)):
                continue
            end = m.end(rule.group)
            if rule.label == "PASSWORD_OR_SECRET":
                end = extend_secret(text, end)
            add(TextSpan(m.start(rule.group), end, rule.label, rule.category), prio)

    for pattern in PERSON_RULES:
        for m in pattern.finditer(text):
            add(TextSpan(m.start(1), m.end(1), "PERSON", "person"), len(RULES))

    for m in _TOKEN.finditer(text):
        if looks_random(m.group()):
            add(TextSpan(m.start(), m.end(), "POSSIBLE_SECRET", "secrets", 0.7), len(RULES))

    return _resolve_overlaps(candidates, priority)


def _resolve_overlaps(spans: list[TextSpan], priority: dict[int, int]) -> list[TextSpan]:
    ordered = sorted(spans, key=lambda s: (priority[id(s)], -(s.end - s.start), s.start))
    kept: list[TextSpan] = []
    for s in ordered:
        if all(s.end <= k.start or s.start >= k.end for k in kept):
            kept.append(s)
    return sorted(kept, key=lambda s: s.start)
