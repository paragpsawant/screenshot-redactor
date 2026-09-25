import assert from "node:assert/strict";
import { test } from "node:test";

import { findSpans, ibanOk, ipv6Ok, looksRandom, luhnOk, maskPreview, prettyLabel } from "../js/rules.js";

const labels = (text, ...args) => findSpans(text, ...args).map((s) => [s.label, text.slice(s.start, s.end)]);

const DETECTS = [
  ["contact me at jane.doe+work@example.co.uk today", "EMAIL", "jane.doe+work@example.co.uk"],
  ["Phone: (415) 555-0132", "PHONE", "(415) 555-0132"],
  ["call +44 20 7946 0958 now", "PHONE", "+44 20 7946 0958"],
  ["Card 4111 1111 1111 1111 exp 12/29", "CREDIT_CARD", "4111 1111 1111 1111"],
  ["SSN: 219-09-9999", "US_SSN", "219-09-9999"],
  ["IBAN GB82 WEST 1234 5698 7654 32", "IBAN", "GB82 WEST 1234 5698 7654 32"],
  ["host 10.0.12.254 is down", "IP_ADDRESS", "10.0.12.254"],
  ["addr 2001:db8::8a2e:370:7334", "IP_ADDRESS", "2001:db8::8a2e:370:7334"],
  ["mac 00:1A:2B:3C:4D:5E", "MAC_ADDRESS", "00:1A:2B:3C:4D:5E"],
  ["key AKIAIOSFODNN7EXAMPLE here", "AWS_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"],
  ["token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "GITHUB_TOKEN", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"],
  ["OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1", "AI_API_KEY", "sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1"],
  ["HF_TOKEN=hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567", "HUGGINGFACE_TOKEN", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567"],
  ["Authorization: Bearer abcDEF123456ghiJKL789", "BEARER_TOKEN", "abcDEF123456ghiJKL789"],
  ["password: hunter2!", "PASSWORD_OR_SECRET", "hunter2!"],
  ["https://x.io/cb?code=Zx81kLpQ02mN&state=1", "URL_TOKEN", "Zx81kLpQ02mN"],
  ["-----BEGIN RSA PRIVATE KEY-----", "PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----"],
  ["eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", "JWT",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N"],
  ["DOB: 04/12/1987", "DATE_OF_BIRTH", "04/12/1987"],
  ["Passport No: X1234567", "PASSPORT", "X1234567"],
  ["wallet 0x52908400098527886E0F7030069857D2E4169EE7", "CRYPTO_WALLET", "0x52908400098527886E0F7030069857D2E4169EE7"],
  ["AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI7K7MDENGbPxRfiCYz3kL9mQ", "PASSWORD_OR_SECRET", "wJalrXUtnFEMI7K7MDENGbPxRfiCYz3kL9mQ"],
  ['"client_secret": "a1b2c3d4e5"', "PASSWORD_OR_SECRET", "a1b2c3d4e5"],
  ["DB_PASSWORD=Pr0dP4ss!2026", "PASSWORD_OR_SECRET", "Pr0dP4ss!2026"],
  ["postgres://admin:Pr0dP4ss!2026@10.20.30.40:5432/db", "URL_PASSWORD", "Pr0dP4ss!2026"],
  ["STRIPE_SECRET_KEY=sk_1ive_51HxQ2eKz8LmN4pRtY7uVwXa9", "STRIPE_KEY", "sk_1ive_51HxQ2eKz8LmN4pRtY7uVwXa9"],
];

for (const [text, label, value] of DETECTS) {
  test(`detects ${label}: ${text.slice(0, 40)}`, () => {
    assert.ok(labels(text).some(([l, v]) => l === label && v === value), JSON.stringify(labels(text)));
  });
}

const HARMLESS = [
  "Theme: Light    Language: English    Notifications: On",
  "Order #123456 shipped on 2026-09-24",
  "Card 4111 1111 1111 1112",
  "SSN: 000-12-3456",
  "password: ********",
  "Version 12:30:45 build",
  "useSomeVeryLongCamelCaseIdentifierName",
  "The secretary: Dana will join",
  "TOKEN_URL=https://login.example.com/oauth2/token",
  "password: required",
  "Server listening on http://0.0.0.0:8080 (pid 4312)",
  "warn: retrying 3 of 5 in 2000ms",
];

for (const text of HARMLESS) {
  test(`no false positive: ${text}`, () => assert.deepEqual(labels(text), []));
}

test("category filter", () => {
  const text = "mail a@b.com key AKIAIOSFODNN7EXAMPLE";
  assert.deepEqual(labels(text, ["secrets"]).map(([l]) => l), ["AWS_ACCESS_KEY"]);
  assert.deepEqual(labels(text, ["contact"]).map(([l]) => l), ["EMAIL"]);
});

test("custom terms are case-insensitive and always applied", () => {
  assert.deepEqual(labels("Project FALCON launch", ["secrets"], ["project falcon"]), [["CUSTOM", "Project FALCON"]]);
});

test("overlapping matches resolve to one span", () => {
  assert.equal(findSpans("OPENAI_API_KEY=sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1").length, 1);
});

test("validators", () => {
  assert.ok(luhnOk("4111111111111111") && !luhnOk("4111111111111112"));
  assert.ok(ibanOk("DE89 3704 0044 0532 0130 00") && !ibanOk("DE89 3704 0044 0532 0130 01"));
  assert.ok(looksRandom("x9Kq2LmZ7vB4nR8tW1yP3sD6") && !looksRandom("aaaaaaaaaaaaaaaaaaaaaaaa"));
  assert.ok(ipv6Ok("::1") && ipv6Ok("fe80::1ff:fe23:4567:890a") && !ipv6Ok("12:30:45"));
});

test("display helpers", () => {
  assert.equal(prettyLabel("AWS_ACCESS_KEY"), "AWS Access Key");
  assert.equal(prettyLabel("GITHUB_TOKEN"), "GitHub Token");
  assert.equal(maskPreview("hunter2"), "•••••••");
  const p = maskPreview("sk-proj-9fQ2xLr7TbWm4KpZ8vNs3HcYd1");
  assert.ok(p.startsWith("sk-p") && !p.includes("9fQ2"));
});

// ---- regressions from a real chat screenshot (Teams): passwords with spaces, chat headers ----

const SECRET_VALUES = [
  ["password: hK3#9vLp jfn2n2mcnkc2", "hK3#9vLp jfn2n2mcnkc2"],
  ["password: mypass jfn2n2mcnkc2", "mypass jfn2n2mcnkc2"],
  ["Password = Summer2026!xQ7jfn2n2mcnkc2", "Summer2026!xQ7jfn2n2mcnkc2"],
  ["password: hunter2 please", "hunter2"],            // stops at a plain word
  ["pwd: Tr0ub4dor&3 Thanks", "Tr0ub4dor&3"],
];
for (const [text, value] of SECRET_VALUES) {
  test(`secret value covers the whole value: ${text}`, () => {
    const s = findSpans(text).find((x) => x.label === "PASSWORD_OR_SECRET");
    assert.equal(text.slice(s.start, s.end), value);
  });
}

const PEOPLE = [
  ["Parag Sawant Yesterday 12:02 PM", "Parag Sawant"],
  ["Parag Sawant 11:20 AM", "Parag Sawant"],
  ["Nikhil KulkarniYesterday 12:02 PM", "Nikhil Kulkarni"], // OCR dropped the space
  ["Olumide Adeyemi (External) Mon 9:05", "Olumide Adeyemi"],
  ["Maria de la Cruz Sep 24, 2026, 3:41 PM", "Maria de la Cruz"],
  ["thanks @Wei Zhang for the fix", "Wei Zhang"],
  ["Hi Aarav, can you check this?", "Aarav"],
  ["From: Siddharth Rao", "Siddharth Rao"],
];
for (const [text, name] of PEOPLE) {
  test(`person rule: ${text}`, () => {
    const s = findSpans(text, ["person"]);
    assert.ok(s.some((x) => text.slice(x.start, x.end) === name), JSON.stringify(s.map((x) => text.slice(x.start, x.end))));
  });
}

const NOT_PEOPLE = ["Daily Standup 9:30 AM", "Updated 3:45 PM", "Yesterday 12:15 PM", "Last read", "Hi Team, quick update",
  "Sprint Planning Mon 10:00", "Shift+Enter starts a new line."];
for (const text of NOT_PEOPLE) {
  test(`no person false positive: ${text}`, () => assert.deepEqual(findSpans(text, ["person"]), []));
}

