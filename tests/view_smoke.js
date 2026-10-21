// Smoke test for the page `auditforge view` writes: run its script against a stub DOM and render
// every view, every risk drawer and every finding filter, so a runtime error fails the test.
// Usage: node view_smoke.js <page.html>   Prints {"risks": n, "runs": n} on success.
const fs = require("fs");

const html = fs.readFileSync(process.argv[2], "utf8");
const js = html.match(/<script>([\s\S]*)<\/script>/)[1];
const els = {};
const mk = () => ({
  innerHTML: "", textContent: "", dataset: {},
  classList: { toggle() {} }, setAttribute() {}, focus() {},
});
global.document = {
  getElementById: (id) => (els[id] ??= mk()),
  querySelectorAll: () => [], querySelector: () => mk(), addEventListener() {},
};
global.location = { hash: "" };
global.history = { replaceState() {} };
global.navigator = {};

eval(js + `
for (const v of ["dashboard", "risks", "evidence"]) {
  show(v);
  if (!els.view.innerHTML) throw new Error("empty view " + v);
}
state.heat = "inherent";
renderRisks();
for (const r of REG.risks) {
  openRisk(r.risk_id);
  if (!els["drawer-root"].innerHTML.includes("dr-title")) throw new Error("drawer " + r.risk_id);
}
REPORTS.forEach((rep, i) => {
  state.run = i;
  for (const f of rep.findings) {
    state.finding = f.check_id;
    for (const flt of ["all", "exception", "review", "ok"]) { state.filter = flt; renderEvidence(); }
  }
});
console.log(JSON.stringify({ risks: REG.risks.length, runs: REPORTS.length }));
`);
