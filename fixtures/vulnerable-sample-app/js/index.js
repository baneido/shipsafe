// Intentionally vulnerable JS sample used by ShipSafe integration tests.
// DO NOT copy any of this into real code.
const express = require("express");
const app = express();

function renderComment(el, comment) {
  // XSS: interpolated assignment to innerHTML
  el.innerHTML = `<p>${comment}</p>`;
}

function legacyBanner(text) {
  // XSS sink
  document.write(text);
}

// Sensitive state-changing route registered without middleware
app.delete("/admin/users/:id", (req, res) => {
  res.json({ deleted: req.params.id });
});

function runSnippet(snippet) {
  // Arbitrary code execution
  eval(`console.log(${snippet})`);
}

module.exports = { renderComment, legacyBanner, runSnippet, app };
