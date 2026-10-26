/* DOM interaction checks against a real Python server; no browser renderer.
   Dev setup: npm install --prefix tmp/ui-dom --no-save linkedom
   Run: node tools/check_dashboard_ui.cjs
   The dashboard itself does not require Node or this development dependency. */
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const crypto = require("node:crypto");
const {spawn} = require("node:child_process");
const {parseHTML} = require("../tmp/ui-dom/node_modules/linkedom");
const root = path.resolve(__dirname, "..");
const checks = [];
let server;
const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
async function until(condition, label) {
  for (let i = 0; i < 150; i++) {
    if (condition()) return;
    await pause(20);
  }
  throw new Error("Timed out: " + label);
}
async function main() {
  server = spawn("python", ["app.py", "--port", "0", "--no-browser"], {cwd: root, env: {...process.env, PYTHONUNBUFFERED: "1"}, stdio: ["ignore", "pipe", "pipe"]});
  let output = "", serverErrors = "";
  server.stdout.setEncoding("utf8").on("data", (chunk) => {output += chunk;});
  server.stderr.setEncoding("utf8").on("data", (chunk) => {serverErrors += chunk;});
  await until(() => /http:\/\/127\.0\.0\.1:\d+/.test(output), "server ready: " + serverErrors);
  const url = output.match(/http:\/\/127\.0\.0\.1:\d+/)[0];
  const {window, document} = parseHTML(fs.readFileSync(path.join(root, "web/index.html"), "utf8"));
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const location = {hash: ""};
  const requests = [];
  window.scrollTo = () => {};
  // LinkeDOM exposes select.value as getter-only; supply normal selection semantics.
  const select = $("#event-filter");
  Object.defineProperty(select, "value", {get() {return [...this.querySelectorAll("option")].find((o) => o.selected)?.value || "all";}, set(value) {this.querySelectorAll("option").forEach((o) => {o.selected = o.value === value;});}});
  const context = vm.createContext({document, window, location,
    history: {replaceState(_a, _b, hash) {location.hash = hash;}},
    fetch: (route, options) => {requests.push({route, body: options?.body ? JSON.parse(options.body) : null}); return fetch(url + route, options);},
    URL, Blob, Uint8Array, btoa, setTimeout, clearTimeout, console});
  vm.runInContext(fs.readFileSync(path.join(root, "web/app.js"), "utf8"), context, {filename: "app.js"});
  await until(() => $("#stat-total").textContent === "15", "initial dataset");
  assert.equal($("#error-banner").hidden, true, $("#error-banner").textContent);
  assert.equal($$(".case-card").length, 2);
  assert.equal($$("#log-rows tr").length, 15);
  assert.ok($("#hash-result").textContent.includes("Kết quả sẽ xuất hiện"));
  checks.push("Initial load: two cases, 15 rows, hash awaits an explicit action");

  $('[data-page="logs"]').click();
  $('[data-scenario="spray"]').click();
  assert.equal($$("#log-rows tr").length, 3);
  assert.deepEqual($$("#log-rows tr").map((tr) => tr.children[1].textContent).sort(), ["binh", "chi", "mai"]);
  assert.ok($("#log-context").textContent.includes("3 tài khoản"));
  assert.equal($("#log-search").value, "");
  checks.push("Many accounts: one click selects the correct three users without typing an IP");

  $('[data-scenario="sequence"]').click();
  assert.equal($$("#log-rows tr").length, 6);
  assert.equal($$("#log-rows tr.success-evidence").length, 1);
  assert.ok($("#log-rows tr.success-evidence").textContent.includes("MFA chưa rõ"));
  $("#raw-log").checked = true;
  $("#raw-log").dispatchEvent(new window.Event("change"));
  assert.ok($("#log-rows").textContent.includes("login_success"));
  assert.ok($("#log-rows").textContent.includes("session_created=true"));
  $("#raw-log").checked = false;
  $("#clear-log-filters").click();
  assert.equal($$("#log-rows tr").length, 15);
  checks.push("Fail then success: six rows, green success, raw-log toggle and clear filter");

  $('[data-finding="198.51.100.24"]').click();
  assert.equal($$("#log-rows tr").length, 3);
  assert.equal($("#page-logs").classList.contains("active"), true);
  checks.push("Overview case opens its evidence directly");

  $('[data-go="integrity"]').click();
  assert.equal($("#data-actions").hidden, true);
  $("#check-hash").click();
  await until(() => $("#hash-result").textContent.includes("MISMATCH"), "sample hash");
  assert.equal(requests.filter((r) => r.route === "/api/sample-hash").length, 1);
  assert.ok($("#hash-heading").textContent.includes("khác baseline"));
  checks.push("Sample hash: one action computes and displays MISMATCH");

  $('[data-hash-mode="custom"]').click();
  assert.equal($("#hash-heading").textContent, "Chưa kiểm tra");
  assert.equal($("#hash-export-row").hidden, true);
  $("#check-hash").click();
  await until(() => !$("#error-banner").hidden, "missing file error");
  assert.ok($("#error-banner").textContent.includes("Chọn tệp"));
  const payload = Buffer.from([0, 1, 255]);
  $("#artifact-upload").files = [{name: "binary.dat", size: payload.length, arrayBuffer: async () => payload}];
  $("#artifact-upload").dispatchEvent(new window.Event("change"));
  $("#baseline-input").value = `SHA256 binary.dat ${crypto.createHash("sha256").update(payload).digest("hex")}`;
  $("#baseline-input").dispatchEvent(new window.Event("input"));
  $("#check-hash").click();
  await until(() => $("#hash-result").textContent.includes("MATCH"), "uploaded hash");
  assert.equal($("#hash-heading").textContent, "Tệp khớp baseline");
  $("#baseline-input").value = "changed";
  $("#baseline-input").dispatchEvent(new window.Event("input"));
  assert.equal($("#hash-export-row").hidden, true);
  checks.push("Custom hash: validation, binary MATCH and clearing stale results on input changes");

  $('[data-go="traceback"]').click();
  assert.equal($("#run-fixed").disabled, true);
  $("#run-original").click();
  await until(() => !$("#original-result").hidden, "original result");
  assert.equal($("#run-fixed").disabled, false);
  assert.ok($("#original-result").textContent.includes("TypeError"));
  assert.equal($("#fixed-result").hidden, true);
  const before = requests.filter((r) => r.route === "/api/traceback");
  assert.deepEqual(before.map((r) => r.body.version), ["before"]);
  $("#run-fixed").click();
  await until(() => !$("#fixed-result").hidden, "fixed result");
  assert.ok($("#fixed-result").textContent.includes("ALERT 203.0.113.77 5"));
  assert.equal($("#repair-conclusion").hidden, false);
  assert.deepEqual(requests.filter((r) => r.route === "/api/traceback").map((r) => r.body.version), ["before", "after"]);
  checks.push("Python repair: original runs first, unlocks fixed version, then shows real output");

  $('[data-go="documents"]').click();
  await until(() => $("#document-body").querySelector("h1"), "report");
  assert.equal($$("#document-body .incident-section").length, 5);
  const technical = $("#document-body details.document-details");
  assert.ok(technical);
  assert.equal(technical.hasAttribute("open"), false);
  assert.ok(technical.textContent.includes("adf82e65e0c245e5"));
  assert.ok(!$("#document-body .incident-sections").textContent.includes("adf82e65e0c245e5"));
  assert.ok($("#document-body .incident-sections").textContent.includes("MISMATCH"));
  for (const key of ["research", "assignment", "guide"]) {
    $(`[data-doc="${key}"]`).click();
    await until(() => vm.runInContext("state.document", context) === key, "document " + key);
    assert.ok($("#document-body").textContent.length > 300);
  }
  checks.push("Reports: five compact sections, technical details collapsed, all document tabs render");

  const oldCount = $("#stat-total").textContent;
  $("#csv-upload").files = [{name: "bad.csv", size: 8, text: async () => "bad,csv\n"}];
  $("#csv-upload").dispatchEvent(new window.Event("change"));
  await until(() => !$("#error-banner").hidden && !$("#upload-button").disabled, "invalid CSV");
  assert.equal($("#stat-total").textContent, oldCount);
  checks.push("Invalid CSV retains the last valid analysis");

  const emptyCsv = "timestamp,user,src_ip,event,asset,details\n";
  $("#csv-upload").files = [{name: "empty.csv", size: emptyCsv.length, text: async () => emptyCsv}];
  $("#csv-upload").dispatchEvent(new window.Event("change"));
  await until(() => $("#stat-total").textContent === "0", "empty CSV");
  assert.equal($('[data-scenario="spray"]').disabled, true);
  assert.equal($('[data-scenario="sequence"]').disabled, true);
  $("#restore-button").click();
  await until(() => $("#stat-total").textContent === "15", "restore dataset");
  assert.equal($('[data-scenario="spray"]').disabled, false);
  checks.push("Empty dataset has no misleading case buttons; restoring sample rebuilds cases");

  const report = `DOM/API interaction checks: ${checks.length} PASS\n` + checks.map((check, i) => `${i + 1}. ${check}`).join("\n") + "\n\nNo browser renderer was connected; visual layout remains unverified.\n";
  fs.writeFileSync(path.join(root, "evidence/ui_flow_results.txt"), report, "utf8");
  console.log(report);
}
main().catch((err) => { console.error(err); process.exitCode = 1; }).finally(() => {server?.kill();});
