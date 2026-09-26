import assert from "node:assert/strict";
import { test } from "node:test";

import { findSpans, ibanOk, ipv6Ok, looksRandom, luhnOk, maskPreview, mergeSpans, prettyLabel } from "../js/rules.js";

const labels = (text, ...args) => findSpans(text, ...args).map((s) => [s.label, text.slice(s.start, s.end)]);
const awsKey = "AKIA" + "IOSFODNN7EXAMPLE";
const aiKey = "sk-" + "proj-" + "9fQ2xLr7TbWm4KpZ8vNs3HcYd1";
const dashes = "-".repeat(5);
const pemBlock = `${dashes}BEGIN RSA PRIVATE KEY${dashes}\nMIIEpAIBAAKCAQEA\n${dashes}END RSA PRIVATE KEY${dashes}`;
const githubToken = "gh" + "p_" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345";
const vendorTokens = {
  gitlab: "gl" + "pat-" + "A1b2C3d4E5".repeat(2),
  npm: "np" + "m_" + "A".repeat(36),
  pypi: "py" + "pi-" + "A".repeat(20),
  sendgrid: "S" + "G." + "A".repeat(16) + "." + "B".repeat(16),
  basic: "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==",
  slack: "https://hooks.slack.com/services/" + "T" + "A".repeat(8) + "/" + "B" + "C".repeat(8) + "/" + "D".repeat(24),
};

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
  [`key ${awsKey} here`, "AWS_ACCESS_KEY", awsKey],
  [`token ${githubToken}`, "GITHUB_TOKEN", githubToken],
  [`OPENAI_API_KEY=${aiKey}`, "AI_API_KEY", aiKey],
  ["HF_TOKEN=hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567", "HUGGINGFACE_TOKEN", "hf_AbCdEfGhIjKlMnOpQrStUvWxYz01234567"],
  ["Authorization: Bearer abcDEF123456ghiJKL789", "BEARER_TOKEN", "abcDEF123456ghiJKL789"],
  ["password: hunter2!", "PASSWORD_OR_SECRET", "hunter2!"],
  ["https://x.io/cb?code=Zx81kLpQ02mN&state=1", "URL_TOKEN", "Zx81kLpQ02mN"],
  [pemBlock, "PRIVATE_KEY", pemBlock],
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
  [`token ${vendorTokens.gitlab}`, "GITLAB_TOKEN", vendorTokens.gitlab],
  [`token ${vendorTokens.npm}`, "NPM_TOKEN", vendorTokens.npm],
  [`token ${vendorTokens.pypi}`, "PYPI_TOKEN", vendorTokens.pypi],
  [`token ${vendorTokens.sendgrid}`, "SENDGRID_TOKEN", vendorTokens.sendgrid],
  [vendorTokens.basic, "BASIC_AUTH", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="],
  [vendorTokens.slack, "SLACK_WEBHOOK", vendorTokens.slack],
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
  const text = `mail a@b.com key ${awsKey}`;
  assert.deepEqual(labels(text, ["secrets"]).map(([l]) => l), ["AWS_ACCESS_KEY"]);
  assert.deepEqual(labels(text, ["contact"]).map(([l]) => l), ["EMAIL"]);
});

test("custom terms are case-insensitive and always applied", () => {
  assert.deepEqual(labels("Project FALCON launch", ["secrets"], ["project falcon"]), [["CUSTOM", "Project FALCON"]]);
});

test("overlapping matches resolve to one span", () => {
  assert.equal(findSpans(`OPENAI_API_KEY=${aiKey}`).length, 1);
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
  const p = maskPreview(aiKey);
  assert.ok(p.startsWith("sk-p") && !p.includes("9fQ2"));
});

test("phone match stops before OCR newline spillover", () => {
  assert.ok(labels("Call +1 (415) 555-0132\n14 now").some(([l, v]) => l === "PHONE" && v === "+1 (415) 555-0132"));
});

test("mergeSpans scales near-linearly for many spans", () => {
  const n = 12000;
  const rules = Array.from({ length: n }, (_, i) => ({ start: i * 4, end: i * 4 + 1, label: "R", category: "secrets" }));
  const ner = Array.from({ length: n }, (_, i) => ({ start: i * 4 + 2, end: i * 4 + 3, label: "N", category: "person" }));
  const t0 = performance.now();
  const merged = mergeSpans(rules, ner);
  const elapsed = performance.now() - t0;
  assert.equal(merged.length, n * 2);
  assert.ok(elapsed < 1000, `merge took ${elapsed.toFixed(1)}ms`);
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

// Same regression matrix as core v0.1.6: the linear email/IPv6 scanners must not drop quoted/JSON
// addresses or addresses followed by sentence punctuation.
test("emails, phones, cards, IPs and keys survive every common wrapping", () => {
  const vals = {
    EMAIL: ["tom.oneill@example.org", "a@b.co", "jane.doe+work@example.co.uk"],
    PHONE: ["(415) 555-0132", "+44 20 7946 0958"],
    CREDIT_CARD: ["4111 1111 1111 1111"],
    IP_ADDRESS: ["203.0.113.42", "2001:db8::1"],
    AWS_ACCESS_KEY: [awsKey],
  };
  const wraps = [(v) => v, (v) => `"${v}"`, (v) => `'${v}'`, (v) => `(${v})`, (v) => `${v}.`, (v) => `${v},`, (v) => `${v}...`,
    (v) => `{"k": "${v}"}`, (v) => `k="${v}"`, (v) => `<k>${v}</k>`, (v) => `line1\n${v}\nline3`];
  const misses = [];
  for (const [label, list] of Object.entries(vals)) for (const v of list) for (const w of wraps) {
    const t = "prefix " + w(v) + " suffix", at = t.indexOf(v);
    if (!findSpans(t).some((s) => s.label === label && s.start <= at && s.end >= at + v.length)) misses.push(`${label} ${JSON.stringify(w(v))}`);
  }
  assert.deepEqual(misses, []);
  for (const bad of ["not-an-email@", "a@b", "x@y.c", "foo@bar..com"]) assert.deepEqual(labels(bad).filter(([l]) => l === "EMAIL"), [], bad);
});
