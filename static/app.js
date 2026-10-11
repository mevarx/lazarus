"use strict";

const state = {
  findings: [],
  payload: null,
  graph: null,
  selectedDomain: null,
  compareController: null,
  eventSource: null,
  recentScanMode: null,
  sortDescending: true
};

const $ = (selector, root = document) => root.querySelector(selector);
const EMAIL_PATTERN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const API_KEY_PATTERN = /\bAIza[A-Z0-9_-]{20,}\b/gi;
const BEARER_PATTERN = /\bBearer\s+[A-Z0-9._~+/-]+=*/gi;
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined && value !== null) node.textContent = String(value);
  return node;
}

function cleanText(value, finding) {
  let result = typeof value === "string" ? value : String(value ?? "");
  result = result.replace(EMAIL_PATTERN, "[redacted email]");
  result = result.replace(API_KEY_PATTERN, "[redacted secret]").replace(BEARER_PATTERN, "[redacted secret]");
  const names = Array.isArray(finding?.maintainers) ? finding.maintainers : [];
  for (const item of names) {
    const name = typeof item === "string" ? item : item?.name;
    if (typeof name === "string" && name.trim().length > 1) {
      result = result.replace(new RegExp(escapeRegExp(name.trim()), "gi"), "the maintainer");
    }
  }
  return result;
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function shown(value, fallback = "—") {
  return value === null || value === undefined || value === "" ? fallback : String(value);
}

function numberText(value) {
  if (value === null || value === undefined || value === "") return "—";
  const number = Number(value);
  return Number.isFinite(number) ? new Intl.NumberFormat().format(number) : "—";
}

function safeSeverity(value) {
  const severity = String(value || "UNKNOWN").toUpperCase();
  return SEVERITIES.includes(severity) ? severity : "UNKNOWN";
}

function setMode(mode, replay = false) {
  const badge = $("#mode-badge");
  const isReplay = replay || mode === "replay" || mode === "demo";
  if (isReplay) {
    badge.textContent = "REPLAY · recorded data, not a live scan";
    badge.className = "mode-badge mode-replay";
    $("#replay-notice").hidden = false;
  } else if (mode === "live") {
    badge.textContent = "LIVE · scan results";
    badge.className = "mode-badge mode-live";
    $("#replay-notice").hidden = true;
  } else {
    badge.textContent = "MODE UNKNOWN";
    badge.className = "mode-badge mode-unknown";
    $("#replay-notice").hidden = true;
  }
}

function updateProviderStatus(payload) {
  const backend = payload?.backend;
  const live = payload?.live;
  const hasKey = payload?.has_key;
  const backendText = backend === undefined || backend === null ? "unknown" : cleanText(backend);
  const liveText = typeof live === "boolean" ? (live ? "yes" : "no") : "unknown";
  const keyText = typeof hasKey === "boolean" ? (hasKey ? "available" : "unavailable") : "unknown";
  $("#provider-status").textContent = `Answering provider: ${backendText} · Live: ${liveText} · API key: ${keyText}`;
}

function updateOverview(payload) {
  state.payload = payload || {};
  state.findings = Array.isArray(payload?.findings) ? payload.findings : [];
  updateProviderStatus(payload);
  const mode = payload?.mode ?? payload?.meta?.mode ?? payload?.run?.mode;
  if (payload?.seeded === true || ["cached", "seed", "replay", "demo"].includes(payload?.source) || mode === "replay" || mode === "demo") {
    setMode("replay", true);
  } else if (mode === "live") {
    setMode("live");
  } else if (state.recentScanMode && payload?.source === "last-run") {
    setMode(state.recentScanMode);
  } else {
    setMode("unknown");
  }

  const stats = payload?.stats || {};
  for (const [key, id] of [["total", "total"], ["critical", "critical"], ["high", "high"], ["medium", "medium"], ["low", "low"]]) {
    $(`#stat-${id}`).textContent = numberText(stats[key]);
  }
  const radius = payload?.blast_radius || {};
  $("#blast-domains").textContent = numberText(radius.at_risk_domains);
  $("#blast-packages").textContent = numberText(radius.at_risk_packages);
  $("#blast-downloads").textContent = numberText(radius.combined_weekly_downloads);
  $("#blast-dependents").textContent = numberText(radius.combined_dependents);
  const largest = radius.largest_single_domain;
  $("#blast-largest").textContent = `Largest single domain: ${largest ? cleanText(largest) : "—"} · ${numberText(radius.largest_single_downloads)} weekly downloads`;
  $("#finding-count").textContent = numberText(payload?.count ?? state.findings.length);
  const updated = payload?.updated_at || payload?.generated || payload?.generated_at;
  $("#updated-at").textContent = `Updated ${formatDate(updated)}`;
  $("#findings-error").hidden = true;
  renderFindings();
  if (state.graph) renderGraph(state.graph);
  if (state.selectedDomain) {
    const selected = state.findings.find(item => item.domain === state.selectedDomain);
    if (selected) renderDetail(selected);
    else clearDetail();
  }
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? cleanText(value) : date.toLocaleString();
}

async function getJson(path, signal) {
  const response = await fetch(path, { headers: { Accept: "application/json" }, signal });
  let body;
  try { body = await response.json(); } catch { body = {}; }
  if (!response.ok) throw new Error(body?.error || `Request failed (${response.status})`);
  return body;
}

async function refreshDashboard() {
  const findingsJob = getJson("/api/findings").then(updateOverview).catch(error => {
    $("#findings-body").replaceChildren(messageRow("Findings could not be loaded."));
    $("#findings-error").hidden = false;
    $("#findings-error").textContent = `${cleanText(error.message)} `;
    const retry = element("button", "text-button", "Retry");
    retry.type = "button";
    retry.addEventListener("click", refreshDashboard);
    $("#findings-error").append(retry);
  });
  const graphJob = getJson("/api/graph").then(renderGraph).catch(error => {
    $("#graph-region").replaceChildren(element("p", "table-message", "Dependency graph unavailable."));
    $("#graph-error").hidden = false;
    $("#graph-error").textContent = cleanText(error.message);
  });
  await Promise.all([findingsJob, graphJob]);
}

function messageRow(text) {
  const row = document.createElement("tr");
  const cell = element("td", "table-message", text);
  cell.colSpan = 4;
  row.append(cell);
  return row;
}

function renderFindings() {
  const body = $("#findings-body");
  const term = $("#search-findings").value.trim().toLowerCase();
  const filter = $("#severity-filter").value;
  const filtered = state.findings.filter(finding => {
    const severity = safeSeverity(finding.severity);
    const packages = Array.isArray(finding.packages) ? finding.packages.join(" ") : "";
    const matchesText = `${finding.domain || ""} ${packages}`.toLowerCase().includes(term);
    return matchesText && (filter === "all" || severity === filter);
  });
  filtered.sort((a, b) => {
    const difference = (Number(a.risk) || 0) - (Number(b.risk) || 0);
    return state.sortDescending ? -difference : difference;
  });
  body.replaceChildren();
  if (!filtered.length) {
    body.append(messageRow(state.findings.length ? "No findings match these filters." : "No findings in this run."));
    return;
  }
  for (const finding of filtered) {
    const row = document.createElement("tr");
    row.className = finding.domain === state.selectedDomain ? "finding-row is-selected" : "finding-row";
    const domainCell = document.createElement("td");
    const select = element("button", "domain-button", cleanText(finding.domain || "Unknown domain", finding));
    select.type = "button";
    select.setAttribute("aria-label", `Show details for ${cleanText(finding.domain || "finding", finding)}`);
    select.addEventListener("click", () => selectFinding(finding));
    domainCell.append(select);
    const severityCell = document.createElement("td");
    const severity = safeSeverity(finding.severity);
    severityCell.append(element("span", `severity-badge severity-${severity.toLowerCase()}`, severity));
    const riskCell = element("td", "risk-cell", numberText(finding.risk));
    const ecosystemCell = element("td", "ecosystem-cell", cleanText(finding.ecosystem || "—", finding));
    row.append(domainCell, severityCell, riskCell, ecosystemCell);
    body.append(row);
  }
}

function selectFinding(finding) {
  state.selectedDomain = finding.domain || null;
  renderFindings();
  renderDetail(finding);
}

function detailPair(label, value, finding) {
  const item = element("div", "detail-pair");
  item.append(element("dt", "", label), element("dd", "", cleanText(shown(value), finding)));
  return item;
}

function listSection(title, values, finding, emptyMessage = "No data available.") {
  const section = element("section", "detail-section");
  section.append(element("h3", "detail-section-title", title));
  if (!Array.isArray(values) || values.length === 0) {
    section.append(element("p", "muted-copy", emptyMessage));
    return section;
  }
  const list = element("ul", "text-list");
  for (const value of values) list.append(element("li", "", cleanText(value, finding)));
  section.append(list);
  return section;
}

function renderDetail(finding) {
  const pane = $("#detail-pane");
  pane.replaceChildren();
  const header = element("div", "detail-header");
  const titles = element("div", "");
  titles.append(element("p", "eyebrow", "Selected finding"));
  titles.append(element("h2", "detail-domain", cleanText(finding.domain || "Unknown domain", finding)));
  const close = element("button", "close-button", "Close");
  close.type = "button";
  close.setAttribute("aria-label", "Close finding details");
  close.addEventListener("click", clearDetail);
  header.append(titles, close);
  pane.append(header);

  const severity = safeSeverity(finding.severity);
  const summary = element("div", "detail-summary");
  summary.append(element("span", `severity-badge severity-${severity.toLowerCase()}`, severity));
  summary.append(element("span", "detail-risk", `Rules score ${numberText(finding.risk)}`));
  if (finding.verification?.needs_manual_check || finding.needs_manual_check) {
    summary.append(element("span", "manual-badge", "Needs manual check"));
  }
  pane.append(summary);

  const overview = document.createElement("dl");
  overview.className = "detail-grid";
  overview.append(detailPair("Ecosystem", finding.ecosystem, finding));
  overview.append(detailPair("Packages", Array.isArray(finding.packages) ? finding.packages.join(", ") : null, finding));
  overview.append(detailPair("Dependents", numberText(finding.dependents), finding));
  overview.append(detailPair("Weekly downloads", numberText(finding.downloads_week), finding));
  overview.append(detailPair("RDAP created", finding.rdap?.created, finding));
  overview.append(detailPair("RDAP expires", finding.rdap?.expires, finding));
  overview.append(detailPair("RDAP status", Array.isArray(finding.rdap?.status) ? finding.rdap.status.join(", ") : finding.rdap?.status, finding));
  const verification = finding.verification?.status || finding.verified_severity;
  if (verification !== undefined || finding.verification) overview.append(detailPair("Verification", verification, finding));
  pane.append(overview);

  pane.append(listSection("Risk signals", finding.signals, finding));
  pane.append(listSection("Rules reasoning", finding.reasoning, finding));
  const compare = element("section", "comparison-section");
  compare.id = "comparison-panel";
  compare.setAttribute("aria-labelledby", "comparison-title");
  const compareTitle = element("h3", "detail-section-title", "Rules vs Gemma");
  compareTitle.id = "comparison-title";
  compare.append(compareTitle);
  const comparisonContent = element("div", "comparison-content", "Loading comparison…");
  comparisonContent.setAttribute("aria-live", "polite");
  comparisonContent.id = "comparison-content";
  compare.append(comparisonContent);
  pane.append(compare);
  loadComparison(finding, comparisonContent);
  pane.focus?.({ preventScroll: true });
}

function clearDetail() {
  if (state.compareController) state.compareController.abort();
  state.compareController = null;
  const returnDomain = state.selectedDomain;
  state.selectedDomain = null;
  const pane = $("#detail-pane");
  pane.replaceChildren();
  const content = element("div", "detail-empty");
  content.append(element("span", "detail-mark", "L"));
  content.append(element("h2", "", "Finding details"));
  content.append(element("p", "", "Select a finding to inspect its signals and comparison."));
  pane.append(content);
  renderFindings();
  const returnButton = [...document.querySelectorAll(".domain-button")].find(button => button.textContent === returnDomain);
  returnButton?.focus();
}

function agreementBadge(status, detail) {
  const labels = {
    agree: ["AGREE", "agreement-agree"],
    partial: ["PARTIAL", "agreement-partial"],
    disagree: ["DISAGREE", "agreement-disagree"],
    not_independent: ["NOT INDEPENDENT", "agreement-neutral"],
    unavailable: ["UNAVAILABLE", "agreement-neutral"]
  };
  const [label, className] = labels[status] || labels.unavailable;
  const wrap = element("div", "agreement-wrap");
  wrap.append(element("span", `agreement-badge ${className}`, label));
  if (status === "not_independent") {
    wrap.append(element("p", "agreement-detail", cleanText(detail || "The offline template restates the rules and is not an independent assessment.")));
  } else if (detail) {
    wrap.append(element("p", "agreement-detail", cleanText(detail)));
  }
  return wrap;
}

function providerChip(provider) {
  const chip = element("div", "provider-chip");
  const family = provider?.family;
  const allowedFamily = ["Gemma 4", "Gemma 3", "Offline template"].includes(family) ? family : "";
  let label = typeof provider?.label === "string" ? provider.label : "";
  if (family !== "Gemma 4") label = label.replace(/Gemma[\s-]*4/gi, "model");
  if (family !== "Gemma 3") label = label.replace(/Gemma[\s-]*3/gi, "model");
  const backend = String(provider?.backend || "unknown").toLowerCase();
  const backendLabel = backend === "gemini" ? "Gemini API" : backend === "ollama" ? "local Ollama" : backend === "offline" ? "no model ran" : cleanText(provider?.backend || "provider unknown");
  const parts = [];
  if (allowedFamily) parts.push(allowedFamily);
  if (provider?.model) parts.push(cleanText(provider.model));
  parts.push(backendLabel);
  if (label && !parts.join(" · ").includes(label)) parts.push(cleanText(label));
  chip.textContent = parts.join(" · ");
  if (provider?.models_verified === false) chip.append(element("span", "unverified-label", "model id unverified"));
  return chip;
}

function renderFallbackChain(provider) {
  if (!provider?.degraded_from && (!Array.isArray(provider?.fallback_chain) || provider.fallback_chain.length === 0)) return null;
  const details = document.createElement("details");
  details.className = "fallback-details";
  const summary = element("summary", "", "Fallback details");
  details.append(summary);
  if (provider.degraded_from) details.append(element("p", "fallback-note", `Fell back from ${cleanText(provider.degraded_from)}.`));
  const chain = Array.isArray(provider.fallback_chain) ? provider.fallback_chain : [];
  if (chain.length) {
    const list = element("ul", "text-list fallback-list");
    for (const attempt of chain) {
      const attemptLabel = [attempt.backend, attempt.model, attempt.outcome].filter(Boolean).map(value => cleanText(value)).join(" · ");
      list.append(element("li", "", attemptLabel || "unverified"));
    }
    details.append(list);
  }
  return details;
}

function renderComparison(data, finding, container) {
  const rules = data?.rules || {};
  const gemma = data?.gemma || {};
  const provider = data?.provider || {};
  container.replaceChildren();
  container.append(agreementBadge(data?.agreement?.status, cleanText(data?.agreement?.detail || "", finding)));
  container.append(providerChip(provider));
  const fallback = renderFallbackChain(provider);
  if (fallback) container.append(fallback);
  const columns = element("div", "comparison-columns");
  const rulesCard = element("section", "assessment-card rules-card");
  rulesCard.append(element("h4", "assessment-title", "Rules engine"));
  const rulesMetric = element("div", "assessment-metric");
  rulesMetric.append(element("strong", "", numberText(rules.risk)));
  rulesMetric.append(element("span", `severity-badge severity-${safeSeverity(rules.severity).toLowerCase()}`, safeSeverity(rules.severity)));
  rulesCard.append(rulesMetric);
  rulesCard.append(listSection("Signals", rules.signals, finding));
  rulesCard.append(listSection("Reasoning", rules.reasoning, finding));
  columns.append(rulesCard);

  const modelCard = element("section", "assessment-card gemma-card");
  modelCard.append(element("h4", "assessment-title", "Gemma assessment"));
  if (gemma.available === false) {
    modelCard.append(element("p", "muted-copy", "No structured assessment is available."));
  } else {
    const metric = element("div", "assessment-metric");
    metric.append(element("strong", "", numberText(gemma.risk)));
    metric.append(element("span", `severity-badge severity-${safeSeverity(gemma.severity).toLowerCase()}`, safeSeverity(gemma.severity)));
    modelCard.append(metric);
    modelCard.append(element("p", "confidence-label", `Confidence: ${shown(gemma.confidence, "unverified")}`));
    modelCard.append(listSection("Cited evidence", gemma.evidence, finding));
    modelCard.append(listSection("Risk reasoning", gemma.risk_reasoning, finding));
  }
  columns.append(modelCard);
  container.append(columns);
  const email = typeof gemma.disclosure_email === "string" ? cleanText(gemma.disclosure_email, finding) : "";
  const emailSection = element("section", "email-section");
  const emailHeader = element("div", "email-header");
  emailHeader.append(element("h4", "assessment-title", "Drafted disclosure email"));
  const copy = element("button", "button button-secondary copy-button", "Copy");
  copy.type = "button";
  copy.disabled = !email;
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(email);
      copy.textContent = "Copied";
    } catch {
      copy.textContent = "Copy unavailable";
    }
  });
  emailHeader.append(copy);
  emailSection.append(emailHeader);
  emailSection.append(element("pre", "email-draft", email || "No draft available."));
  container.append(emailSection);
}

async function loadComparison(finding, container) {
  if (state.compareController) state.compareController.abort();
  const controller = new AbortController();
  state.compareController = controller;
  container.replaceChildren(element("p", "muted-copy", "Loading rules and model assessment…"));
  const retry = element("button", "button button-secondary", "Retry comparison");
  retry.type = "button";
  try {
    const result = await getJson(`/api/compare?domain=${encodeURIComponent(finding.domain || "")}`, controller.signal);
    if (controller.signal.aborted || state.selectedDomain !== finding.domain) return;
    renderComparison(result, finding, container);
  } catch (error) {
    if (controller.signal.aborted) return;
    container.replaceChildren(element("p", "error-message", `Comparison unavailable: ${cleanText(error.message, finding)}`));
    retry.addEventListener("click", () => loadComparison(finding, container));
    container.append(retry);
  }
}

function svgElement(name, attributes = {}) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", name);
  for (const [key, value] of Object.entries(attributes)) node.setAttribute(key, String(value));
  return node;
}

function renderGraph(graph) {
  state.graph = graph;
  const region = $("#graph-region");
  region.replaceChildren();
  const rawNodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
  const nodes = rawNodes.filter(node => ["domain", "package"].includes(String(node.type || "").toLowerCase()));
  if (!nodes.length) {
    region.append(element("p", "table-message", "No dependency relationships available."));
    region.setAttribute("aria-label", "No dependency relationships available");
    return;
  }
  const domains = nodes.filter(node => String(node.type).toLowerCase() === "domain");
  const packages = nodes.filter(node => String(node.type).toLowerCase() === "package");
  const positions = new Map();
  const compact = window.innerWidth <= 680;
  const width = compact ? 360 : 800;
  const margin = compact ? 42 : 80;
  const xPosition = (index, count) => count < 2 ? width / 2 : margin + index * ((width - margin * 2) / (count - 1));
  domains.forEach((node, index) => positions.set(node.id, { x: xPosition(index, domains.length), y: compact ? 74 : 82 }));
  packages.forEach((node, index) => positions.set(node.id, { x: xPosition(index, packages.length), y: compact ? 208 : 218 }));
  const svg = svgElement("svg", { viewBox: `0 0 ${width} 280`, role: "img", "aria-label": "Dependency relationships between domains and packages", class: "dependency-svg" });
  const edges = Array.isArray(graph.edges) ? graph.edges : [];
  const visibleEdges = new Set();
  const addVisibleEdge = (source, target) => {
    if (positions.has(source) && positions.has(target)) visibleEdges.add(`${source}\u0000${target}`);
  };
  for (const edge of edges) addVisibleEdge(edge.source, edge.target);
  for (const finding of state.findings) {
    const domain = domains.find(node => node.label === finding.domain || node.id === `domain:${finding.domain}`);
    if (!domain || !Array.isArray(finding.packages)) continue;
    for (const packageName of finding.packages) {
      const packageNode = packages.find(node => node.label === packageName || node.id === `package:${packageName}`);
      if (packageNode) addVisibleEdge(domain.id, packageNode.id);
    }
  }
  for (const relation of visibleEdges) {
    const [source, target] = relation.split("\u0000");
    const from = positions.get(source);
    const to = positions.get(target);
    svg.append(svgElement("line", { x1: from.x, y1: from.y, x2: to.x, y2: to.y, class: "graph-edge" }));
  }
  for (const node of nodes) {
    const position = positions.get(node.id);
    if (!position) continue;
    const group = svgElement("g", { class: `graph-node graph-${String(node.type).toLowerCase()}` });
    const circle = svgElement("circle", { cx: position.x, cy: position.y, r: compact ? 9 : 8 });
    const title = svgElement("title");
    title.textContent = cleanText(node.label || node.id);
    const text = svgElement("text", { x: position.x, y: position.y + 27, "text-anchor": "middle" });
    const label = cleanText(node.label || node.id);
    const limit = compact ? 8 : 27;
    text.textContent = label.length > limit ? `${label.slice(0, limit - 1)}…` : label;
    group.append(circle, title, text);
    svg.append(group);
  }
  region.append(svg);
  region.setAttribute("aria-label", `Dependency graph with ${domains.length} domains and ${packages.length} packages`);
}

function setScanBusy(busy, message = "") {
  $("#run-scan").disabled = busy;
  $("#scan-mode").disabled = busy;
  $("#scan-status").hidden = !busy && !message;
  $("#scan-message").textContent = message;
}

function runScan() {
  if (state.eventSource) state.eventSource.close();
  const mode = $("#scan-mode").value;
  const params = mode === "live" ? "live=1" : "demo=1";
  const stream = new EventSource(`/api/run?${params}`);
  state.eventSource = stream;
  setScanBusy(true, mode === "live" ? "Starting live scan…" : "Loading recorded replay…");
  stream.addEventListener("start", event => {
    let data = {};
    try { data = JSON.parse(event.data); } catch { /* Keep a safe unknown state. */ }
    if (data.mode === "live") setMode("live");
    else if (data.mode === "demo" || data.mode === "replay") setMode("replay", true);
    updateProviderStatus(state.payload || {});
    setScanBusy(true, data.message || "Scan started…");
  });
  stream.addEventListener("progress", event => {
    let data = {};
    try { data = JSON.parse(event.data); } catch { data = {}; }
    setScanBusy(true, cleanText(data.message || "Scan in progress…"));
  });
  stream.addEventListener("finding", () => setScanBusy(true, "Reviewing findings…"));
  stream.addEventListener("done", event => {
    let data = {};
    try { data = JSON.parse(event.data); } catch { data = {}; }
    stream.close();
    state.eventSource = null;
    state.recentScanMode = data.mode === "live" ? "live" : "replay";
    setMode(state.recentScanMode, state.recentScanMode === "replay");
    setScanBusy(false, "Scan complete.");
    refreshDashboard();
  });
  stream.addEventListener("failed", event => {
    let data = {};
    try { data = JSON.parse(event.data); } catch { data = {}; }
    stream.close();
    state.eventSource = null;
    setScanBusy(false, `Scan failed: ${cleanText(data.message || "Unknown error")}`);
  });
  stream.onerror = () => {
    stream.close();
    state.eventSource = null;
    setScanBusy(false, "Scan stream disconnected. Refreshing available results…");
    refreshDashboard();
  };
}

function setupTheme() {
  const button = $("#theme-toggle");
  let theme = "dark";
  try { theme = localStorage.getItem("lazarus-theme") || "dark"; } catch { /* Storage may be unavailable. */ }
  document.documentElement.dataset.theme = theme === "light" ? "light" : "dark";
  const update = () => {
    const light = document.documentElement.dataset.theme === "light";
    button.textContent = light ? "Dark" : "Light";
    button.setAttribute("aria-label", `Switch to ${light ? "dark" : "light"} theme`);
    button.title = `Switch to ${light ? "dark" : "light"} theme`;
  };
  button.addEventListener("click", () => {
    document.documentElement.dataset.theme = document.documentElement.dataset.theme === "light" ? "dark" : "light";
    try { localStorage.setItem("lazarus-theme", document.documentElement.dataset.theme); } catch { /* Theme still works for this page. */ }
    update();
  });
  update();
}

$("#search-findings").addEventListener("input", renderFindings);
$("#severity-filter").addEventListener("change", renderFindings);
$("#sort-risk").addEventListener("click", event => {
  state.sortDescending = !state.sortDescending;
  event.currentTarget.textContent = `Risk ${state.sortDescending ? "↓" : "↑"}`;
  event.currentTarget.setAttribute("aria-label", `Sort findings by risk ${state.sortDescending ? "descending" : "ascending"}`);
  renderFindings();
});
$("#run-scan").addEventListener("click", runScan);
document.addEventListener("keydown", event => {
  if (event.key === "Escape" && state.selectedDomain) clearDetail();
});
window.addEventListener("resize", () => {
  if (state.graph) renderGraph(state.graph);
});
setupTheme();
refreshDashboard();
