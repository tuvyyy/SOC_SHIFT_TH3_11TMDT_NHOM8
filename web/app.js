"use strict";
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]));
const state = {analysis: null, hash: null, selected: null, chart: "time", page: "overview", document: "report", documentData: null, customCsv: null, sort: "timestamp", sortDirection: 1, artifact: null, scenario: "all", hashMode: "sample", hashInputVersion: 0, analysisRequest: 0};
const pageMeta = {
  overview: ["Ca trực SOC", "Bắt đầu từ các dấu hiệu đáng chú ý trong log.", "SOC-0815"],
  logs: ["Log đăng nhập", "Chọn một nhóm bên dưới để xem bằng chứng.", "01 / 04"],
  integrity: ["Kiểm tra tệp", "Đối chiếu file cấu hình với hash chuẩn từ ticket.", "02 / 04"],
  traceback: ["Sửa lỗi Python", "Chạy bản gốc trước, sau đó kiểm tra bản sửa.", "03 / 04"],
  documents: ["Báo cáo", "Tổng hợp phát hiện và các bước xác minh tiếp theo.", "04 / 04"],
};
async function api(path, body) {
  const response = await fetch(path, body === undefined ? {} : {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `Yêu cầu thất bại (${response.status})`);
  return result;
}
function error(message) { $("#error-banner").textContent = message; $("#error-banner").hidden = false; }
function clearError() { $("#error-banner").hidden = true; }
let toastTimer;
function toast(message) { clearTimeout(toastTimer); $("#toast").textContent = message; $("#toast").hidden = false; toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 3300); }
async function busy(button, action) {
  if (button.disabled) return;
  clearError();
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  try { await action(); } catch (err) { error(err.message); }
  finally { button.disabled = false; button.removeAttribute("aria-busy"); }
}
function download(filename, content, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], {type: `${type};charset=utf-8`}));
  const anchor = document.createElement("a"); anchor.href = url; anchor.download = filename; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(`Đã xuất ${filename}`);
}


function showPage(page, scroll = true) {
  if (!(page in pageMeta)) page = "overview";
  state.page = page;
  $$(".page").forEach((element) => element.classList.toggle("active", element.id === `page-${page}`));
  $$(".nav-item").forEach((element) => {
    const active = element.dataset.page === page;
    element.classList.toggle("active", active);
    if (active) element.setAttribute("aria-current", "page"); else element.removeAttribute("aria-current");
  });
  $("#page-title").textContent = pageMeta[page][0];
  $("#page-description").textContent = pageMeta[page][1];
  $("#page-step").textContent = pageMeta[page][2];
  $("#data-actions").hidden = !["overview", "logs"].includes(page);
  $("#source-strip").hidden = !["overview", "logs"].includes(page);
  history.replaceState(null, "", `#${page}`);
  clearError();
  if (scroll) window.scrollTo({top: 0, behavior: "instant"});
  if (page === "documents" && !state.documentData) loadDocument(state.document).catch((err) => error(err.message));
}
$$("[data-page], [data-go]").forEach((button) => button.addEventListener("click", () => showPage(button.dataset.page || button.dataset.go)));
$(".brand").addEventListener("click", (event) => { event.preventDefault(); showPage("overview"); });
window.addEventListener("hashchange", () => showPage(location.hash.slice(1)));
function timeLabel(timestamp) { return timestamp ? timestamp.split("T")[1]?.slice(0, 8) || timestamp : "—"; }

function setAnalysis(analysis) {
  state.analysis = analysis;
  const stats = analysis.stats;
  $("#source-name").textContent = analysis.source;
  $("#source-range").textContent = stats.first ? `${stats.first.slice(0, 10)} · ${timeLabel(stats.first)}–${timeLabel(stats.last)}` : "Không có sự kiện";
  $("#restore-button").hidden = state.customCsv === null;
  $("#stat-total").textContent = stats.total;
  $("#stat-failed").textContent = stats.failed;
  $("#stat-alerts").textContent = analysis.findings.length;
  $("#stat-summary").textContent = `${stats.success} lần thành công · ${stats.unique_ips} IP nguồn`;
  $("#rules-note").textContent = `Đếm trên toàn bộ file: ít nhất ${analysis.failure_threshold} lần thất bại hoặc ${analysis.spray_unique_users_threshold} tài khoản khác nhau từ cùng IP.`;
  // A new analysis starts with an unfiltered table; case buttons always set an exact IP.
  resetLogFilters();
  renderFindings(); renderChart();
}
function scenarioFinding(kind) {
  if (!state.analysis) return null;
  return state.analysis.findings.find((item) => kind === "sequence" ? item.success_after_failures.length > 0 : item.rules.includes("POSSIBLE_PASSWORD_SPRAY"));
}
function renderFindings() {
  const findings = state.analysis.findings;
  $("#finding-list").innerHTML = findings.map((item, index) => {
    const sequence = item.success_after_failures.length > 0;
    const spray = item.rules.includes("POSSIBLE_PASSWORD_SPRAY");
    const title = sequence ? "Thất bại rồi đăng nhập được" : spray ? "Thử nhiều tài khoản" : "Đăng nhập thất bại lặp lại";
    const count = item.evidence.length;
    return `<article class="case-card ${item.priority === "HIGH" ? "priority-high" : ""}"><div class="case-content"><div class="case-top"><span class="case-index">Phát hiện ${String(index + 1).padStart(2, "0")}</span><span class="badge ${item.priority === "HIGH" ? "high" : "medium"}">${item.priority === "HIGH" ? "Ưu tiên cao" : "Ưu tiên vừa"}</span></div><h3>${title}</h3><div class="case-ip">${esc(item.src_ip)}</div><div class="case-facts"><span>${item.failed_count} lần thất bại</span><span>${sequence ? `${item.success_after_failures.length} lần thành công sau đó` : `${item.unique_failed_users} tài khoản`}</span></div><p class="case-users">${esc(item.users.join(" · "))}</p></div><button class="case-action" data-finding="${esc(item.src_ip)}"><span>Xem ${count} dòng log</span><span aria-hidden="true">→</span></button></article>`;
  }).join("") || '<div class="panel empty-state">Không có IP đạt ngưỡng.<p>Bạn vẫn có thể xem toàn bộ log ở bước 01.</p></div>';
  $$("[data-finding]").forEach((button) => button.addEventListener("click", () => openFinding(button.dataset.finding)));
  for (const kind of ["sequence", "spray"]) {
    const button = $(`[data-scenario="${kind}"]`);
    button.disabled = !scenarioFinding(kind);
    button.title = button.disabled ? "Không có nhóm log phù hợp trong dữ liệu hiện tại" : "";
  }
}
function openFinding(ip) {
  const item = state.analysis.findings.find((finding) => finding.src_ip === ip);
  if (!item) return;
  state.scenario = item.success_after_failures.length ? "sequence" : item.rules.includes("POSSIBLE_PASSWORD_SPRAY") ? "spray" : "all";
  state.selected = ip;
  $("#log-search").value = "";
  $("#event-filter").value = "all";
  state.sort = "timestamp"; state.sortDirection = 1;
  renderLogs(); showPage("logs");
}
function resetLogFilters() {
  state.scenario = "all"; state.selected = null;
  $("#log-search").value = ""; $("#event-filter").value = "all";
  state.sort = "timestamp"; state.sortDirection = 1;
  renderLogs();
}
$$("[data-scenario]").forEach((button) => button.addEventListener("click", () => {
  if (button.dataset.scenario === "all") { resetLogFilters(); return; }
  const finding = scenarioFinding(button.dataset.scenario);
  if (!finding) return;
  state.scenario = button.dataset.scenario; state.selected = finding.src_ip;
  $("#log-search").value = ""; $("#event-filter").value = "all";
  state.sort = "timestamp"; state.sortDirection = 1;
  renderLogs();
}));
function renderLogContext() {
  $$("[data-scenario]").forEach((button) => button.classList.toggle("selected", button.dataset.scenario === state.scenario));
  const finding = state.analysis?.findings.find((item) => item.src_ip === state.selected);
  $("#log-context").hidden = !finding;
  if (!finding) return;
  const success = finding.success_after_failures[0];
  const heading = state.scenario === "spray" ? `${finding.unique_failed_users} tài khoản từ cùng một IP` : success ? `${success.failures_before_success} lần thất bại → đăng nhập thành công` : `${finding.failed_count} lần đăng nhập thất bại`;
  const explanation = state.scenario === "spray" ? "Mỗi tài khoản có một lần thử hoặc nhiều hơn. Đây là dấu hiệu nghi password spraying, cần xác minh thêm." : success ? `Dòng xanh là lần thành công lúc ${timeLabel(success.timestamp)}. Cần kiểm tra phiên và kết quả MFA.` : "Nguồn này đã đạt ngưỡng cảnh báo thất bại lặp lại.";
  $("#log-context").innerHTML = `<h2>${esc(heading)}</h2><p><code>${esc(finding.src_ip)}</code> · ${esc(explanation)}</p>${state.scenario === "spray" ? `<div class="context-accounts">${finding.users.map((user) => `<span>${esc(user)}</span>`).join("")}</div>` : ""}`;
}
function filteredEvents() {
  if (!state.analysis) return [];
  const query = $("#log-search").value.trim().toLowerCase(), kind = $("#event-filter").value;
  return state.analysis.events.filter((row) => (!state.selected || row.src_ip === state.selected) && (kind === "all" || row.event === kind) && Object.values(row).join(" ").toLowerCase().includes(query)).sort((a, b) => (state.sort === "timestamp" ? Date.parse(a.timestamp) - Date.parse(b.timestamp) : String(a[state.sort]).localeCompare(String(b[state.sort]))) * state.sortDirection);
}
function readableDetails(value) {
  return value.replaceAll("reason=bad_password", "Sai mật khẩu").replaceAll("reason=unknown_user", "Tài khoản không tồn tại").replaceAll("reason=typo", "Nhập sai").replaceAll("MFA=passed", "MFA hợp lệ").replaceAll("MFA=unknown", "MFA chưa rõ").replaceAll("session_created=true", "Đã tạo phiên").replaceAll("; ", " · ").replaceAll(";", " · ");
}
function renderLogs() {
  if (!state.analysis) return;
  const rows = filteredEvents(), raw = $("#raw-log").checked;
  $("#log-rows").innerHTML = rows.slice(0, 1000).map((row) => `<tr class="${state.selected && row.event === "login_success" ? "success-evidence" : ""}"><td title="${esc(row.timestamp)}">${esc(raw ? row.timestamp.replace("T", " ") : timeLabel(row.timestamp))}</td><td>${esc(row.user)}</td><td>${esc(row.src_ip)}</td><td><span class="event-chip ${row.event === "login_success" ? "ok" : ""}">${esc(raw ? row.event : row.event === "login_success" ? "Thành công" : "Thất bại")}</span></td><td>${esc(row.asset)}</td><td title="${esc(row.details)}">${esc(raw ? row.details : readableDetails(row.details))}</td></tr>`).join("") || '<tr><td colspan="6" class="empty-state">Không có dòng log phù hợp.</td></tr>';
  $("#log-count").textContent = `${rows.length > 1000 ? `Hiển thị 1.000 / ${rows.length}` : rows.length} dòng${state.selected || $("#log-search").value || $("#event-filter").value !== "all" ? ` / ${state.analysis.events.length} sự kiện` : ""}`;
  $("#clear-log-filters").hidden = !state.selected && !$("#log-search").value && $("#event-filter").value === "all";
  renderLogContext();
}
$("#log-search").addEventListener("input", renderLogs);
$("#event-filter").addEventListener("change", renderLogs);
$("#raw-log").addEventListener("change", renderLogs);
$("#clear-log-filters").addEventListener("click", resetLogFilters);
$$("[data-sort]").forEach((button) => button.addEventListener("click", () => { state.sortDirection = state.sort === button.dataset.sort ? -state.sortDirection : 1; state.sort = button.dataset.sort; renderLogs(); }));
$("#export-logs").addEventListener("click", () => {
  const keys = ["timestamp", "user", "src_ip", "event", "asset", "details"];
  const cell = (value) => { let text = String(value); if (/^[=+@\-\t\r]/.test(text)) text = "'" + text; return '"' + text.replace(/"/g, '""') + '"'; };
  download("auth_events_filtered.csv", "\uFEFF" + [keys.join(","), ...filteredEvents().map((row) => keys.map((key) => cell(row[key])).join(","))].join("\r\n"), "text/csv");
});
$("#export-findings").addEventListener("click", () => { if (state.analysis) download("soc_findings.json", JSON.stringify(state.analysis, null, 2)); });

function renderChart() {
  if (!state.analysis) return;
  const groups = new Map();
  for (const row of state.analysis.events) {
    const key = state.chart === "ip" ? row.src_ip : row.timestamp.slice(0, 16);
    if (!groups.has(key)) groups.set(key, {failed: 0, success: 0});
    groups.get(key)[row.event === "login_failed" ? "failed" : "success"]++;
  }
  let entries = [...groups.entries()];
  if (entries.length > 24) {
    const chunk = Math.ceil(entries.length / 24);
    entries = Array.from({length: Math.ceil(entries.length / chunk)}, (_, i) => {
      const subset = entries.slice(i * chunk, (i + 1) * chunk);
      return [subset[0][0], subset.reduce((acc, [, value]) => ({failed: acc.failed + value.failed, success: acc.success + value.success}), {failed: 0, success: 0})];
    });
  }
  if (!entries.length) { $("#activity-chart").innerHTML = '<div class="empty-state">Không có sự kiện để vẽ biểu đồ.</div>'; return; }
  const w = 760, h = 230, left = 30, top = 15, bottom = state.chart === "ip" ? 45 : 29;
  const plotH = h - top - bottom, plotW = w - left - 16;
  const maximum = Math.max(2, ...entries.map(([, value]) => value.failed + value.success));
  const step = plotW / entries.length, width = Math.min(36, step * .48);
  let svg = `<svg viewBox="0 0 ${w} ${h}" role="img" aria-label="Số đăng nhập thất bại và thành công ${state.chart === "ip" ? "theo IP" : "theo thời gian"}">`;
  for (let i = 0; i <= 3; i++) {
    const y = top + plotH * i / 3;
    svg += `<line x1="${left}" x2="${w - 16}" y1="${y}" y2="${y}" stroke="#e4e8dc" stroke-dasharray="3 4"/><text x="${left - 10}" y="${y + 3}" text-anchor="end">${Math.round(maximum * (1 - i / 3))}</text>`;
  }
  entries.forEach(([key, value], index) => {
    const x = left + step * (index + .5), failH = value.failed / maximum * plotH, successH = value.success / maximum * plotH;
    const y = top + plotH - failH;
    svg += `<g><title>${esc(key)}: ${value.failed} thất bại, ${value.success} thành công</title><rect x="${x - width / 2}" y="${y}" width="${width}" height="${failH}" fill="#b7966c" rx="3"/><rect x="${x - width / 2}" y="${y - successH}" width="${width}" height="${successH}" fill="#7b9e84" rx="3"/>`;
    if (entries.length <= 12 || index % Math.ceil(entries.length / 10) === 0) {
      const label = state.chart === "ip" ? key : (key.slice(0, 10) !== entries[0][0].slice(0, 10) ? key.slice(5, 10) + " " + key.slice(11) : key.slice(11));
      svg += `<text x="${x}" y="${top + plotH + 18}" text-anchor="middle" ${state.chart === "ip" ? `transform="rotate(-18 ${x} ${top + plotH + 18})"` : ""}>${esc(label)}</text>`;
    }
    svg += "</g>";
  });
  $("#activity-chart").innerHTML = svg + "</svg>";
}
$$("[data-chart]").forEach((button) => button.addEventListener("click", () => { state.chart = button.dataset.chart; $$("[data-chart]").forEach((item) => item.classList.toggle("selected", item === button)); renderChart(); }));

function resetHash() {
  state.hash = null; state.hashInputVersion++;
  $("#hash-heading").textContent = "Chưa kiểm tra";
  $("#hash-result").innerHTML = '<div class="waiting-state"><span class="waiting-symbol">= ?</span><p>Kết quả sẽ xuất hiện ở đây.</p></div>';
  $("#hash-export-row").hidden = true;
}
function setHash(result) {
  state.hash = result;
  const match = result.status === "MATCH";
  $("#hash-heading").textContent = match ? "Tệp khớp baseline" : "Tệp khác baseline";
  $("#hash-result").innerHTML = `<div class="hash-summary ${match ? "match" : ""}">${match ? "Hai giá trị hash giống nhau." : "Hai giá trị hash không giống nhau. Chưa xác định nguyên nhân thay đổi."}</div><div class="hash-content"><div class="hash-meta"><span>${esc(result.file.split(/[\\/]/).pop())}</span><span class="badge ${match ? "success" : "medium"}">${esc(result.status)}</span></div><div class="hash-label">Hash chuẩn từ baseline</div><div class="hash-code">${esc(result.expected)}</div><div class="hash-label">Hash vừa tính từ tệp</div><div class="hash-code ${match ? "" : "different"}">${esc(result.actual)}</div><p class="hash-next">${match ? "Kết quả phụ thuộc vào độ tin cậy của baseline đã chọn." : "Tiếp theo: giữ bản sao bằng chứng, xác minh nguồn baseline và lịch sử sửa file."}</p></div>`;
  $("#hash-export-row").hidden = false;
}
$$("[data-hash-mode]").forEach((button) => button.addEventListener("click", () => {
  if (state.hashMode === button.dataset.hashMode) return;
  state.hashMode = button.dataset.hashMode;
  $$("[data-hash-mode]").forEach((item) => item.classList.toggle("selected", item === button));
  $("#sample-hash-input").hidden = state.hashMode !== "sample";
  $("#custom-hash-input").hidden = state.hashMode !== "custom";
  clearError(); resetHash();
}));
$("#artifact-upload").addEventListener("change", () => { state.artifact = $("#artifact-upload").files[0] || null; resetHash(); });
$("#baseline-input").addEventListener("input", resetHash);
$("#baseline-upload").addEventListener("change", (event) => busy($("#check-hash"), async () => {
  const file = event.target.files[0]; if (!file) return;
  resetHash();
  if (file.size > 16384) throw new Error("Baseline tối đa 16 KiB.");
  $("#baseline-input").value = await file.text();
}));
$("#check-hash").addEventListener("click", (event) => busy(event.currentTarget, async () => {
  const version = state.hashInputVersion;
  let result;
  if (state.hashMode === "sample") result = await api("/api/sample-hash");
  else {
    const file = state.artifact;
    if (!file) throw new Error("Chọn tệp cần kiểm tra trước.");
    if (file.size > 2 * 1024 * 1024) throw new Error("Tệp tối đa 2 MiB.");
    if (!$("#baseline-input").value.trim()) throw new Error("Chọn tệp baseline hoặc nhập giá trị hash.");
    const bytes = new Uint8Array(await file.arrayBuffer()); let binary = "";
    for (let i = 0; i < bytes.length; i += 8192) binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
    result = await api("/api/hash", {filename: file.name, file_base64: btoa(binary), baseline: $("#baseline-input").value});
  }
  if (version === state.hashInputVersion) setHash(result);
}));
$("#export-hash").addEventListener("click", () => { if (state.hash) download("hash_result.json", JSON.stringify(state.hash, null, 2)); });

$("#run-original").addEventListener("click", (event) => busy(event.currentTarget, async () => {
  $("#run-fixed").disabled = true;
  for (const id of ["original-result", "original-output", "fixed-result", "fixed-output", "repair-conclusion"]) $(`#${id}`).hidden = true;
  const result = (await api("/api/traceback", {version: "before"})).before;
  $("#traceback-before").textContent = result.output;
  $("#original-output").hidden = false;
  const expectedError = result.exit_code !== 0 && result.output.includes("TypeError");
  $("#original-result").innerHTML = `<strong>${expectedError ? "TypeError: không thể so sánh str và int" : `Mã thoát: ${result.exit_code}`}</strong><p>${expectedError ? 'Giá trị "5" đang là chuỗi, còn 4 là số nguyên.' : "Xem đầu ra đầy đủ bên dưới."}</p>`;
  $("#original-result").hidden = false;
  $("#run-fixed").disabled = !expectedError;
}));
$("#run-fixed").addEventListener("click", (event) => busy(event.currentTarget, async () => {
  const result = (await api("/api/traceback", {version: "after"})).after;
  $("#traceback-after").textContent = result.output;
  $("#fixed-output").hidden = false;
  const ok = result.exit_code === 0;
  $("#fixed-result").classList.toggle("ok", ok);
  $("#fixed-result").innerHTML = `<strong>${ok ? "Chạy thành công" : "Chưa chạy thành công"}</strong><p>Mã thoát: ${result.exit_code}</p><code>${esc(result.output.trim())}</code>`;
  $("#fixed-result").hidden = false;
  $("#repair-conclusion").textContent = ok ? "Đã kiểm tra giá trị và chuyển chuỗi sang int trước khi so sánh. Không còn lỗi kiểu dữ liệu." : "Bản sửa vẫn có lỗi. Xem đầu ra để xác định nguyên nhân.";
  $("#repair-conclusion").hidden = false;
}));

function inlineMarkdown(text) {
  return esc(text).replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, url) => {
    if (/^https:\/\//.test(url)) return `<a href="${url}" target="_blank" rel="noopener noreferrer">${label} ↗</a>`;
    const documents = {"BAO_CAO_SU_CO.md":"report", "PHIEU_RESEARCH.md":"research", "BAI_LAM_SOC_SHIFT.md":"assignment", "HUONG_DAN_CHAY.md":"guide"};
    return documents[url] ? `<a href="#documents" data-open-doc="${documents[url]}">${label}</a>` : label;
  });
}
function markdown(text) {
  const lines = text.split(/\r?\n/); let html = "", index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (line.trim() === "<details>") {
      index++;
      const summary = lines[index]?.match(/^<summary>(.*)<\/summary>$/);
      if (summary) index++;
      const body = [];
      while (index < lines.length && lines[index].trim() !== "</details>") body.push(lines[index++]);
      html += `<details class="document-details"><summary>${inlineMarkdown(summary ? summary[1] : "Xem chi tiết")}</summary><div>${markdown(body.join("\n"))}</div></details>`;
      index++;
      continue;
    }
    if (line.startsWith("```")) { const code = []; index++; while (index < lines.length && !lines[index].startsWith("```")) code.push(lines[index++]); html += `<pre>${esc(code.join("\n"))}</pre>`; index++; continue; }
    if (/^\|/.test(line)) { const rows = []; while (index < lines.length && /^\|/.test(lines[index])) rows.push(lines[index++]); const cells = (row) => row.replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim()); html += '<table><thead><tr>' + cells(rows[0]).map((cell) => `<th>${inlineMarkdown(cell)}</th>`).join("") + '</tr></thead><tbody>' + rows.slice(2).map((row) => '<tr>' + cells(row).map((cell) => `<td>${inlineMarkdown(cell)}</td>`).join("") + '</tr>').join("") + '</tbody></table>'; continue; }
    const heading = line.match(/^(#{1,3}) (.*)/); if (heading) { html += `<h${heading[1].length}>${inlineMarkdown(heading[2])}</h${heading[1].length}>`; index++; continue; }
    if (/^[-*] /.test(line) || /^\d+\. /.test(line)) { const ordered = /^\d+\. /.test(line), tag = ordered ? "ol" : "ul", expression = ordered ? /^\d+\. / : /^[-*] /; html += `<${tag}>`; while (index < lines.length && expression.test(lines[index])) html += `<li>${inlineMarkdown(lines[index++].replace(expression, ""))}</li>`; html += `</${tag}>`; continue; }
    if (line.trim()) html += `<p>${inlineMarkdown(line)}</p>`;
    index++;
  }
  return html;
}
let documentRequest = 0;
function arrangeReport(container) {
  const nodes = [...container.children];
  let grid = null, section = null;
  for (const node of nodes) {
    if (node.tagName === "H3" && /^[1-5]\. /.test(node.textContent)) {
      if (!grid) {
        grid = document.createElement("div");
        grid.className = "incident-sections";
        container.insertBefore(grid, node);
      }
      section = document.createElement("section");
      section.className = "incident-section";
      grid.appendChild(section);
      section.appendChild(node);
    } else if (section && node.tagName !== "DETAILS") {
      section.appendChild(node);
    } else if (node.tagName === "DETAILS") section = null;
  }
}
async function loadDocument(key) {
  const request = ++documentRequest;
  const data = await api(`/api/document?name=${encodeURIComponent(key)}`);
  if (request !== documentRequest) return;
  state.document = key; state.documentData = data;
  $$("[data-doc]").forEach((button) => button.classList.toggle("selected", button.dataset.doc === key));
  $("#document-body").innerHTML = markdown(data.content);
  $("#document-body").classList.toggle("report-document", key === "report");
  if (key === "report") arrangeReport($("#document-body"));
  $$("[data-open-doc]").forEach((anchor) => anchor.addEventListener("click", (event) => { event.preventDefault(); loadDocument(anchor.dataset.openDoc).catch((err) => error(err.message)); }));
}
$$("[data-doc]").forEach((button) => button.addEventListener("click", () => loadDocument(button.dataset.doc).catch((err) => error(err.message))));
$("#download-document").addEventListener("click", () => { if (state.documentData) download(state.documentData.filename, state.documentData.content, "text/markdown"); });



async function loadSample() {
  const request = ++state.analysisRequest;
  const data = await api("/api/dashboard");
  if (request !== state.analysisRequest) return;
  state.customCsv = null; setAnalysis(data.analysis);
}
$("#upload-button").addEventListener("click", () => $("#csv-upload").click());
$("#csv-upload").addEventListener("change", async () => {
  const file = $("#csv-upload").files[0]; if (!file) return;
  await busy($("#upload-button"), async () => {
    if (file.size > 2 * 1024 * 1024) throw new Error("CSV tối đa 2 MiB.");
    const request = ++state.analysisRequest;
    const csv = await file.text(), analysis = await api("/api/analyze", {csv, filename: file.name});
    if (request !== state.analysisRequest) return;
    state.customCsv = {csv, filename: file.name}; setAnalysis(analysis);
    toast(`Đã đọc ${analysis.stats.total} sự kiện`);
  });
  $("#csv-upload").value = "";
});
$("#refresh-button").addEventListener("click", (event) => busy(event.currentTarget, async () => {
  if (state.customCsv) {
    const request = ++state.analysisRequest;
    const data = await api("/api/analyze", state.customCsv);
    if (request === state.analysisRequest) setAnalysis(data);
  } else await loadSample();
  toast("Đã đọc lại log");
}));
$("#restore-button").addEventListener("click", (event) => busy(event.currentTarget, async () => { await loadSample(); toast("Đang dùng dữ liệu mẫu"); }));
showPage(location.hash.slice(1) || "overview", false);
loadSample().catch((err) => error(`Không đọc được dữ liệu: ${err.message}. Kiểm tra cửa sổ chạy python app.py.`));
