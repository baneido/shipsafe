// Test cases for rules/sast/javascript.yml (semgrep --test format).
const express = require("express");
const cors = require("cors");
const app = express();

// --- ai-js-dangerously-set-inner-html ---

function Comment({ body }) {
  // ruleid: ai-js-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

function SafeComment({ body }) {
  // ok: ai-js-dangerously-set-inner-html
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
}

// --- ai-js-inner-html-assignment ---

function renderName(el, name) {
  // ruleid: ai-js-inner-html-assignment
  el.innerHTML = `<b>${name}</b>`;
  // ruleid: ai-js-inner-html-assignment
  el.innerHTML = "<b>" + name;
  // ok: ai-js-inner-html-assignment
  el.textContent = name;
  // ok: ai-js-inner-html-assignment
  el.innerHTML = "<b>static</b>";
}

// --- ai-js-document-write ---

function legacyRender(content) {
  // ruleid: ai-js-document-write
  document.write(content);
}

// --- ai-express-sensitive-route-no-middleware ---

// ruleid: ai-express-sensitive-route-no-middleware
app.post("/admin/users", (req, res) => {
  res.json({ ok: true });
});

// ruleid: ai-express-sensitive-route-no-middleware
app.delete("/user/:id", async (req, res) => {
  res.json({ deleted: req.params.id });
});

// ok: ai-express-sensitive-route-no-middleware
app.post("/admin/users", requireAuth, (req, res) => {
  res.json({ ok: true });
});

// ok: ai-express-sensitive-route-no-middleware
app.post("/echo", (req, res) => {
  res.json(req.body);
});

// --- ai-js-cors-wildcard-credentials ---

// ruleid: ai-js-cors-wildcard-credentials
app.use(cors({ origin: "*", credentials: true }));

// ok: ai-js-cors-wildcard-credentials
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

// --- ai-js-insecure-cookie-defaults ---

function setSession(res, token) {
  // ruleid: ai-js-insecure-cookie-defaults
  res.cookie("session", token, { httpOnly: false });
  // ruleid: ai-js-insecure-cookie-defaults
  res.cookie("session", token, { secure: false, httpOnly: true });
  // ok: ai-js-insecure-cookie-defaults
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "lax" });
}

// --- ai-js-eval-interpolation ---

function runUserCode(snippet) {
  // ruleid: ai-js-eval-interpolation
  eval(`console.log(${snippet})`);
  // ruleid: ai-js-eval-interpolation
  const fn = new Function("return " + snippet);
  // ok: ai-js-eval-interpolation
  const parsed = JSON.parse(snippet);
  return fn, parsed;
}
