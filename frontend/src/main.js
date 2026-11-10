import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { LAYOUT } from "./layout.js";
import { ICON_FILES, iconStyles, installedIcons } from "./icons.js";
import {
  ALL_REGIONS, classesFor, defaultRegion, detailRows, facets, parseGraph, portText, regionsFor, summary,
  toCyElements, visibleIds, warnings,
} from "./model.js";
import {
  PILLARS, costSummary, filterFindings, findingFacets, findingsFor, hasEnrichment, hostRows, integrationStatus,
  money, postureRows, postureSummary, safeUrl, sortFindings, sortRows,
} from "./views.js";

cytoscape.use(fcose);

// AWS icons, if installed (npm run icons). Missing icons fall back to the shapes below.
const ICON_URLS = installedIcons(import.meta.glob("../icons/*.svg", { eager: true, query: "?url", import: "default" }));

// Every value from the graph is untrusted (AWS tags and names). Use textContent only, never innerHTML.

const $ = (id) => document.getElementById(id);
let cy = null;
let elements = [];
let filters = null;
let graph = null;
let colourMode = "exposure";
let hostSort = { key: "findings", descending: true };

// Dark, high-contrast theme. Colours on #0d1117: text >= 4.5:1, shapes and lines >= 3:1.
const C = {
  bg: "#0d1117", text: "#ffffff", line: "#9ca3af",
  vpc: "#58a6ff", subnet: "#79c0ff", instance: "#e6edf3", sg: "#d2a8ff", acl: "#c297ff",
  rt: "#56d4dd", igw: "#ffd33d", exposed: "#ff5c5c", unknown: "#ffa657",
  bucket: "#8ddb8c", fn: "#ffa657", iam: "#ff7b9c", admin: "#ffd33d",
};

const STYLE = [
  { selector: "node", style: {
    label: "data(display_label)", "font-size": 15, "font-weight": 600, color: C.text,
    "text-valign": "bottom", "text-margin-y": 6,
    "text-outline-color": C.bg, "text-outline-width": 3, // keeps labels readable over lines
    "background-color": C.line, width: 38, height: 38, "border-width": 2, "border-color": C.bg,
    "min-zoomed-font-size": 6,
  } },
  { selector: ":parent", style: {
    "text-valign": "top", "text-halign": "center", "text-margin-y": -6, "font-size": 17,
    "background-color": C.bg, "background-opacity": 1, "border-width": 2, padding: 24,
  } },
  { selector: "node.type-vpc", style: { "border-color": C.vpc, "border-width": 3, color: C.vpc, "background-color": "#0b1d33" } },
  { selector: "node.type-vpc:childless", style: { "background-color": C.vpc } },
  { selector: "node.type-subnet", style: { "border-color": C.subnet, "border-style": "dashed", color: C.subnet, "background-color": "#0f2237" } },
  { selector: "node.type-subnet:childless", style: { "background-color": C.subnet } },
  { selector: "node.type-instance", style: { shape: "round-rectangle", "background-color": C.instance, width: 46, height: 34 } },
  { selector: "node.type-security-group", style: { shape: "diamond", "background-color": C.sg } },
  { selector: "node.type-network-acl", style: { shape: "hexagon", "background-color": C.acl } },
  { selector: "node.type-route-table", style: { shape: "tag", "background-color": C.rt } },
  { selector: "node.type-internet-gateway", style: { shape: "star", "background-color": C.igw, width: 46, height: 46 } },
  { selector: "node.type-bucket", style: { shape: "barrel", "background-color": C.bucket } },
  { selector: "node.type-function", style: { shape: "round-triangle", "background-color": C.fn } },
  { selector: "node.type-role", style: { shape: "round-pentagon", "background-color": C.iam } },
  { selector: "node.type-user", style: { shape: "ellipse", "background-color": C.iam } },
  { selector: "node.type-group", style: { shape: "round-octagon", "background-color": C.iam } },
  { selector: "node.type-policy", style: { shape: "round-tag", "background-color": C.iam, width: 30, height: 30 } },
  // Admin principals: yellow double border and a ★ in the label (not colour alone).
  { selector: "node.admin", style: { "border-width": 5, "border-style": "double", "border-color": C.admin, color: C.admin } },
  { selector: "node.exposure-exposed", style: {
    "background-color": C.exposed, "border-color": "#ffffff", "border-width": 4, color: C.exposed, "font-size": 17,
  } },
  { selector: "node.exposure-unknown", style: {
    "background-color": C.unknown, "border-color": "#ffffff", "border-width": 4, "border-style": "dashed", color: C.unknown,
  } },
  // Colour by worst finding or by cost (one scheme at a time; see classesFor).
  { selector: "node.sev-critical", style: { "background-color": "#ff5c5c", "border-color": "#ffffff", "border-width": 4 } },
  { selector: "node.sev-high", style: { "background-color": "#ffa657", "border-color": "#ffffff", "border-width": 3 } },
  { selector: "node.sev-medium", style: { "background-color": "#ffd33d" } },
  { selector: "node.sev-low, node.sev-info", style: { "background-color": "#d0d7de" } },
  { selector: "node.cost-high", style: { "background-color": "#ff7b72", "border-color": "#ffffff", "border-width": 4 } },
  { selector: "node.cost-medium", style: { "background-color": "#d29922" } },
  { selector: "node.cost-low", style: { "background-color": "#3fb950" } },
  { selector: "edge", style: {
    width: 2, "line-color": C.line, "target-arrow-shape": "triangle", "target-arrow-color": C.line,
    "curve-style": "bezier", "arrow-scale": 1,
  } },
  { selector: "edge[type = 'uses']", style: { "line-color": C.sg, "target-arrow-color": C.sg } },
  { selector: "edge[type = 'routes_to']", style: { "line-color": C.igw, "target-arrow-color": C.igw, width: 3 } },
  { selector: "edge[type = 'assumes']", style: { "line-color": C.iam, "target-arrow-color": C.iam, "line-style": "dashed" } },
  { selector: "edge[type = 'attached']", style: { "line-color": C.iam, "target-arrow-color": C.iam } },
  { selector: "edge[type = 'filters']", style: { "line-color": C.acl, "target-arrow-color": C.acl, "line-style": "dashed" } },
  { selector: ".hidden", style: { display: "none" } },
  { selector: "node:selected", style: { "border-width": 6, "border-color": "#ffffff", "overlay-color": "#ffffff", "overlay-opacity": 0.15 } },
];

// Below this zoom, 15px labels are under about 11px on screen. Fit, but never zoom out further.
const MIN_READABLE_ZOOM = 0.75;

function load(json, source) {
  try {
    graph = parseGraph(json);
  } catch (err) {
    showWarnings([`Could not load ${source}: ${err.message}`]);
    return;
  }
  elements = toCyElements(graph);
  const f = facets(graph);
  const region = defaultRegion(graph);
  filters = { types: new Set(f.types), regions: regionsFor(region, graph), onlyExposed: false, search: "" };
  $("search").value = "";
  $("only-exposed").checked = false;

  $("source").textContent = `${source} · account ${graph.meta?.account_id ?? "?"} · ${graph.meta?.collected_at ?? ""}`;
  showWarnings(warnings(graph));
  checkboxes($("types"), f.types, filters.types);
  regionChoice($("region"), f.regions, region, graph);
  const s = summary(graph);
  $("summary").textContent =
    `${s.nodes} resources, ${s.edges} links. Exposure checked on ${s.checked}: exposed ${s.exposed}, unknown ${s.unknown}. Admin principals: ${s.admins}.`;
  $("checks").textContent = [
    graph.meta?.exposure_checks && `Exposure checks: ${graph.meta.exposure_checks}`,
    graph.meta?.admin_checks && `Admin checks: ${graph.meta.admin_checks}`,
  ].filter(Boolean).join(" ");
  clearDetails();

  if (cy) cy.destroy();
  // Exposure rules come last so their red or amber border stays on top of the icon styles.
  const style = [...STYLE, ...iconStyles(ICON_URLS), ...STYLE.filter((r) => /exposure-|sev-|cost-|:selected|hidden/.test(r.selector))];
  cy = cytoscape({ container: $("cy"), elements, style, wheelSensitivity: 0.3, minZoom: 0.1, maxZoom: 4 });
  cy.on("tap", "node", (evt) => showDetails(evt.target.data()));
  cy.on("tap", (evt) => { if (evt.target === cy) clearDetails(); });
  recolour();
  apply();
  renderIntegrations();
  const enriched = hasEnrichment(graph);
  for (const b of document.querySelectorAll("#views button")) {
    if (b.dataset.view !== "map") b.disabled = !enriched;
  }
  if (enriched) {
    sourceOptions();
    renderFindings();
    renderHosts();
    renderCost();
    renderWa();
  }
  showView("map");
}

/** Re-apply node classes for the colour mode, keeping hidden nodes hidden. */
function recolour() {
  if (!cy) return;
  const maxCost = Math.max(0, ...cy.nodes().map((n) => n.data("cost")?.monthly_usd ?? 0));
  cy.batch(() => cy.nodes().forEach((n) => {
    const hidden = n.hasClass("hidden");
    n.classes(classesFor(n.data(), colourMode, { maxCost }));
    if (hidden) n.addClass("hidden");
  }));
  for (const mode of ["exposure", "severity", "cost"]) $(`legend-${mode}`).hidden = mode !== colourMode;
}

function showView(name) {
  for (const b of document.querySelectorAll("#views button")) b.setAttribute("aria-pressed", String(b.dataset.view === name));
  $("view-map").hidden = name !== "map";
  for (const v of ["findings", "hosts", "cost", "wa"]) $(`view-${v}`).hidden = name !== v;
  if (name === "map" && cy) cy.resize();
}

/** Show one resource on the map: its region, selected, centred, details open. */
function openOnMap(id) {
  if (!cy) return;
  const node = cy.getElementById(id);
  if (node.empty()) return;
  showView("map");
  if (!filters.regions.has(node.data("region"))) {
    $("region").value = node.data("region");
    filters.regions = regionsFor(node.data("region"), graph);
    apply();
  }
  cy.elements().unselect();
  node.select();
  cy.animate({ center: { eles: node }, zoom: Math.max(cy.zoom(), 1) }, { duration: 300 });
  showDetails(node.data());
}

function el(tag, props = {}, children = []) {
  const e = Object.assign(document.createElement(tag), props);
  e.append(...children.filter((c) => c !== null && c !== undefined));
  return e;
}

function link(url, text) {
  const safe = safeUrl(url);
  if (!safe) return document.createTextNode(text);
  return el("a", { href: safe, target: "_blank", rel: "noopener noreferrer", textContent: text });
}

function table(headers, rows) {
  const t = document.createElement("table");
  t.className = "grid";
  const head = t.createTHead().insertRow();
  for (const h of headers) head.append(el("th", {}, [typeof h === "string" ? document.createTextNode(h) : h]));
  const body = t.createTBody();
  for (const cells of rows) {
    const tr = body.insertRow();
    for (const c of cells) {
      const td = tr.insertCell();
      if (c instanceof Node) td.append(c);
      else if (c && typeof c === "object") { td.className = c.className ?? ""; td.append(c.node ?? document.createTextNode(c.text ?? "")); }
      else td.textContent = c ?? "";
    }
  }
  return t;
}

const sevBadge = (s) => el("span", { className: `sev ${s}`, textContent: s });

function renderIntegrations() {
  const box = $("integrations");
  const list = integrationStatus(graph);
  box.hidden = list.length === 0;
  box.textContent = list.length ? "Sources: " + list.map((i) => `${i.name} ${i.loaded ? "✓" : i.error ? "✗ error" : "– not loaded"}${i.unmatched.length ? ` (${i.unmatched.length} unmatched)` : ""}`).join(" · ") : "";
  const errors = list.filter((i) => i.error).map((i) => `${i.name}: ${i.error}`);
  if (errors.length) showWarnings([...warnings(graph), ...errors.map((e) => `Integration not loaded. ${e}`)]);
}

function sourceOptions() {
  const select = $("f-source");
  select.replaceChildren(el("option", { value: "", textContent: "All" }),
    ...findingFacets(graph.findings).sources.map((s) => el("option", { value: s, textContent: s })));
}

function renderFindings() {
  const one = (id) => ($(id).value ? new Set([$(id).value]) : null);
  const rows = sortFindings(filterFindings(graph.findings, {
    pillars: one("f-pillar"), severities: one("f-severity"), sources: one("f-source"), search: $("f-search").value,
  }));
  const nodeIds = new Set(cy ? cy.nodes().map((n) => n.id()) : []);
  $("f-count").textContent = `${rows.length} of ${graph.findings.length} findings`;
  const t = table(["Severity", "Pillar", "Finding", "Resource", "Source", "Best practices", "Detail"], rows.map((f) => [
    sevBadge(f.severity), f.pillar, f.title,
    nodeIds.has(f.resource) ? el("button", { type: "button", className: "link-button", textContent: f.resource_name, onclick: () => openOnMap(f.resource) }) : f.resource_name,
    f.source,
    el("span", {}, f.best_practices.flatMap((bp, i) => [i ? document.createTextNode(", ") : null,
      link(graph.posture?.[f.pillar]?.best_practices.find((r) => r.id === bp)?.url, bp)])),
    [f.detail, f.remediation].filter(Boolean).join(" Fix: "),
  ]));
  t.id = "findings-table";
  $("findings-table").replaceWith(t);
}

const HOST_COLUMNS = [
  ["name", "Instance"], ["region", "Region"], ["state", "State"], ["exposure", "Exposure"], ["os", "OS (Wazuh)"],
  ["agent", "Agent"], ["vuln_score", "Vulns C/H/M/L"], ["deploy", "Last deploy"], ["ansible", "Ansible"],
  ["cpu_avg", "CPU avg %"], ["alarms", "Alarms"], ["prom_up", "Prometheus up"], ["cost", "Cost / month"], ["findings", "Findings"],
];

function renderHosts() {
  const rows = sortRows(hostRows(graph), hostSort.key, hostSort.descending);
  const headers = HOST_COLUMNS.map(([key, label]) => el("button", {
    type: "button", textContent: label + (hostSort.key === key ? (hostSort.descending ? " ▼" : " ▲") : ""),
    onclick: () => { hostSort = { key, descending: hostSort.key === key ? !hostSort.descending : false }; renderHosts(); },
  }));
  const t = table(headers, rows.map((r) => [
    el("button", { type: "button", className: "link-button", textContent: r.name, onclick: () => openOnMap(r.id) }),
    r.region, r.state, r.exposure.replace("_", " "), r.os, r.agent, r.vulns, r.deploy, r.ansible,
    { text: r.cpu_avg ?? "", className: "num" }, { text: r.alarms ?? "", className: "num" },
    { text: r.prom_up ?? "", className: "num" }, { text: money(r.cost), className: "num" }, { text: r.findings, className: "num" },
  ]));
  t.id = "hosts-table";
  $("hosts-table").replaceWith(t);
}

function renderCost() {
  const s = costSummary(graph);
  const body = $("cost-body");
  if (!s) {
    body.replaceChildren(el("p", { className: "muted", textContent: "Cost Explorer data is not loaded (integrations/cost.json)." }));
    return;
  }
  const section = (title, node) => el("section", {}, [el("h2", { textContent: title }), node]);
  body.replaceChildren(
    el("p", { textContent: `Last full month (${s.lastFullMonth?.start.slice(0, 7) ?? "none"}): ${money(s.lastFullMonth?.total)}. `
      + `Idle instances (CPU under 5% average and 20% peak) cost about ${money(s.idle)} a month.`
      + (s.estimated ? " Figures for the current month are estimated by AWS." : "") }),
    el("div", { className: "cost-grid" }, [
      section("By month", table(["Month", "Total"], s.months.map((m) => [m.start.slice(0, 7) + (m.estimated ? " (so far, estimated)" : ""), { text: money(m.total), className: "num" }]))),
      section("Top services, last full month", table(["Service", "Cost"], s.topServices.map(([k, v]) => [k, { text: money(v), className: "num" }]))),
      section(`By tag '${s.tagKey}', last full month`, table(["Value", "Cost"], s.byTag.map(([k, v]) => [k, { text: money(v), className: "num" }]))),
      section("Top instances (last 14 days, scaled to 30)", table(["Instance", "Cost / month"], s.topResources.map((r) => [
        el("button", { type: "button", className: "link-button", textContent: r.label, onclick: () => openOnMap(r.arn) }),
        { text: money(r.monthly_usd), className: "num" }]))),
    ]),
  );
}

function renderWa() {
  const statuses = new Set([...document.querySelectorAll(".wa-status")].filter((b) => b.checked).map((b) => b.value));
  const parts = [];
  for (const s of postureSummary(graph)) {
    parts.push(el("section", { className: "wa-pillar" }, [
      el("h2", { textContent: `${s.pillar}: ${s.issues} with issues, ${s.clear} clear, ${s.not_checked} not checked` }),
      table(["Best practice", "Status", "Findings", "Checked by"], postureRows(graph, s.pillar, statuses).map((r) => [
        link(r.url, `${r.id} ${r.title}`), el("span", { className: `status ${r.status}`, textContent: r.status.replace("_", " ") }),
        { text: r.findings || "", className: "num" }, r.checked_by.join(", "),
      ])),
    ]));
  }
  $("wa-body").replaceChildren(...parts);
}

function apply() {
  if (!cy) return;
  const ids = visibleIds(elements, filters);
  cy.batch(() => {
    cy.nodes().forEach((n) => n.toggleClass("hidden", !ids.has(n.id())));
    cy.edges().forEach((e) => e.toggleClass("hidden", !(ids.has(e.source().id()) && ids.has(e.target().id()))));
  });
  const visible = cy.elements().not(".hidden");
  const layout = visible.layout(LAYOUT);
  layout.one("layoutstop", () => fitReadable(visible));
  layout.run();
}

/** Fit what is shown; if that makes text too small, zoom to a readable size centred on what matters most. */
function fitReadable(visible) {
  cy.fit(visible, 30);
  if (cy.zoom() >= MIN_READABLE_ZOOM) return;
  const risky = visible.filter("node.exposure-exposed, node.exposure-unknown");
  cy.zoom(MIN_READABLE_ZOOM);
  cy.center(risky.length ? risky : visible);
}

function zoomBy(factor) {
  if (!cy) return;
  const level = Math.min(cy.maxZoom(), Math.max(cy.minZoom(), cy.zoom() * factor));
  cy.zoom({ level, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
}

function regionChoice(select, regions, chosen, graph) {
  const options = [[ALL_REGIONS, `All regions (${regions.length})`], ...regions.map((r) => [r, r])];
  select.replaceChildren(...options.map(([value, text]) => Object.assign(document.createElement("option"), { value, text })));
  select.value = chosen;
  select.onchange = () => {
    filters.regions = regionsFor(select.value, graph);
    apply();
  };
}

function checkboxes(container, values, selected) {
  container.replaceChildren();
  for (const v of values) {
    const label = document.createElement("label");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = true;
    box.addEventListener("change", () => {
      if (box.checked) selected.add(v); else selected.delete(v);
      apply();
    });
    label.append(box, ` ${v}`);
    container.append(label);
  }
}

function showWarnings(list) {
  const box = $("warnings");
  box.replaceChildren(...list.map((w) => Object.assign(document.createElement("p"), { textContent: w })));
  box.hidden = list.length === 0;
}

function clearDetails() {
  const p = Object.assign(document.createElement("p"), { className: "muted", textContent: "Click a resource to see its details." });
  $("details").replaceChildren(p);
}

function showDetails(node) {
  const panel = $("details");
  const parts = [Object.assign(document.createElement("h2"), { textContent: `${node.type}: ${node.label}` })];

  if (node.admin && node.type !== "policy") {
    parts.push(Object.assign(document.createElement("p"), {
      className: "admin-badge", textContent: `★ admin: ${node.admin_reason}`,
    }));
  }
  if (node.exposure) {
    parts.push(Object.assign(document.createElement("p"), {
      className: `exposure ${node.exposure}`,
      textContent: `${node.exposure.replace("_", " ")}${node.exposure_reason ? `: ${node.exposure_reason}` : ""}`,
    }));
    if (node.exposed_ports?.length) parts.push(list("Exposed ports", node.exposed_ports.map(portText)));
  }

  const table = document.createElement("table");
  for (const [k, v] of detailRows(node)) {
    const tr = table.insertRow();
    tr.insertCell().textContent = k;
    tr.insertCell().textContent = v;
  }
  parts.push(table);

  for (const key of ["ingress", "egress", "routes", "entries"]) {
    if (Array.isArray(node[key]) && node[key].length) {
      parts.push(list(key, node[key].map((x) => JSON.stringify(x))));
    }
  }

  const mine = graph ? findingsFor(graph, node.id) : [];
  if (mine.length) parts.push(list(`Findings (${mine.length})`, mine.map((f) => `${f.severity.toUpperCase()} ${f.title} [${f.best_practices.join(", ") || f.check_id}]`)));
  const w = node.wazuh;
  if (w) {
    parts.push(list("Wazuh", [`agent ${w.agent_id} ${w.status}, last keep-alive ${w.last_keepalive ?? "never"}`,
      `OS ${w.os_name ?? "?"} ${w.os_version ?? ""}`,
      `vulnerabilities: ${w.vulns.critical} critical, ${w.vulns.high} high, ${w.vulns.medium} medium, ${w.vulns.low} low`,
      ...w.top_packages.map((p) => `${p.name} ${p.version}: ${p.count} CVE(s)`)]));
  }
  const d = node.deploy;
  if (d) {
    const section = list("Deployment (GitHub)", [`${d.state}: ${d.repo} ${d.sha} to ${d.environment} at ${d.created_at}`]);
    section.append(link(d.url, "Open deployments on GitHub"));
    parts.push(section);
  }
  const c = node.config_run;
  if (c) parts.push(list(`Ansible (${c.mode} mode)`, [`ok ${c.ok}, changed ${c.changed}, failed ${c.failures}, unreachable ${c.unreachable}`, `run at ${c.ran_at ?? "?"}`]));
  const m = node.metrics;
  if (m) {
    parts.push(list("Monitoring", [
      m.cpu_avg !== undefined ? `CPU ${m.cpu_avg ?? "no data"}% average, ${m.cpu_max ?? "?"}% peak (${m.days} days)` : null,
      m.alarms !== undefined ? `CloudWatch alarms: ${m.alarms}` : null,
      m.prom_up !== undefined ? `Prometheus up: ${m.prom_up}` : null].filter(Boolean)));
  }
  if (node.cost) parts.push(list("Cost", [`${money(node.cost.monthly_usd)} a month (${node.cost.basis})`]));
  panel.replaceChildren(...parts);
}

function list(title, items) {
  const section = document.createElement("section");
  const ul = document.createElement("ul");
  ul.append(...items.map((t) => Object.assign(document.createElement("li"), { textContent: t })));
  section.append(Object.assign(document.createElement("h3"), { textContent: title }), ul);
  return section;
}

$("file").addEventListener("change", async (evt) => {
  const file = evt.target.files?.[0];
  if (file) load(await file.text(), file.name); // read in the browser; the file is never uploaded
});
$("sample").addEventListener("click", async () => {
  const res = await fetch("/demo.graph.json");
  load(await res.text(), "sample (made-up data)");
});
$("zoom-in").addEventListener("click", () => zoomBy(1.25));
$("zoom-out").addEventListener("click", () => zoomBy(0.8));
$("zoom-fit").addEventListener("click", () => cy && cy.fit(cy.elements().not(".hidden"), 30));
$("search").addEventListener("input", (evt) => { if (filters) { filters.search = evt.target.value; apply(); } });
$("only-exposed").addEventListener("change", (evt) => { if (filters) { filters.onlyExposed = evt.target.checked; apply(); } });
$("colour-by").addEventListener("change", (evt) => { colourMode = evt.target.value; recolour(); });
for (const b of document.querySelectorAll("#views button")) b.addEventListener("click", () => showView(b.dataset.view));
for (const id of ["f-pillar", "f-severity", "f-source"]) $(id).addEventListener("change", () => graph && renderFindings());
$("f-search").addEventListener("input", () => graph && renderFindings());
for (const b of document.querySelectorAll(".wa-status")) b.addEventListener("change", () => graph && renderWa());

function typeLegend() {
  const names = {
    "vpc": "VPC", "subnet-public": "Public subnet", "subnet-private": "Private subnet",
    "instance": "EC2 instance", "security-group": "Security group", "network-acl": "Network ACL",
    "route-table": "Route table", "internet-gateway": "Internet gateway",
    "bucket": "S3 bucket", "function": "Lambda function", "role": "IAM role", "user": "IAM user",
    "group": "IAM group", "policy": "IAM policy",
  };
  const items = Object.keys(ICON_FILES).filter((k) => ICON_URLS[k]).map((k) => {
    const li = document.createElement("li");
    const img = Object.assign(document.createElement("img"), { src: ICON_URLS[k], alt: "", width: 20, height: 20 });
    li.append(img, ` ${names[k]}`);
    return li;
  });
  $("type-legend").replaceChildren(...items);
  $("type-legend").hidden = items.length === 0;
}

typeLegend();
showWarnings([]);
