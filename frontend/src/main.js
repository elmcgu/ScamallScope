import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { LAYOUT } from "./layout.js";
import { ICON_FILES, iconStyles, installedIcons } from "./icons.js";
import {
  ALL_REGIONS, defaultRegion, detailRows, facets, parseGraph, portText, regionsFor, summary,
  toCyElements, visibleIds, warnings,
} from "./model.js";

cytoscape.use(fcose);

// AWS icons, if installed (npm run icons). Missing icons fall back to the shapes below.
const ICON_URLS = installedIcons(import.meta.glob("../icons/*.svg", { eager: true, query: "?url", import: "default" }));

// Every value from the graph is untrusted (AWS tags and names). Use textContent only, never innerHTML.

const $ = (id) => document.getElementById(id);
let cy = null;
let elements = [];
let filters = null;

// Dark, high-contrast theme. Colours on #0d1117: text >= 4.5:1, shapes and lines >= 3:1.
const C = {
  bg: "#0d1117", text: "#ffffff", line: "#9ca3af",
  vpc: "#58a6ff", subnet: "#79c0ff", instance: "#e6edf3", sg: "#d2a8ff", acl: "#c297ff",
  rt: "#56d4dd", igw: "#ffd33d", exposed: "#ff5c5c", unknown: "#ffa657",
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
  { selector: "node.exposure-exposed", style: {
    "background-color": C.exposed, "border-color": "#ffffff", "border-width": 4, color: C.exposed, "font-size": 17,
  } },
  { selector: "node.exposure-unknown", style: {
    "background-color": C.unknown, "border-color": "#ffffff", "border-width": 4, "border-style": "dashed", color: C.unknown,
  } },
  { selector: "edge", style: {
    width: 2, "line-color": C.line, "target-arrow-shape": "triangle", "target-arrow-color": C.line,
    "curve-style": "bezier", "arrow-scale": 1,
  } },
  { selector: "edge[type = 'uses']", style: { "line-color": C.sg, "target-arrow-color": C.sg } },
  { selector: "edge[type = 'routes_to']", style: { "line-color": C.igw, "target-arrow-color": C.igw, width: 3 } },
  { selector: "edge[type = 'filters']", style: { "line-color": C.acl, "target-arrow-color": C.acl, "line-style": "dashed" } },
  { selector: ".hidden", style: { display: "none" } },
  { selector: "node:selected", style: { "border-width": 6, "border-color": "#ffffff", "overlay-color": "#ffffff", "overlay-opacity": 0.15 } },
];

// Below this zoom, 15px labels are under about 11px on screen. Fit, but never zoom out further.
const MIN_READABLE_ZOOM = 0.75;

function load(json, source) {
  let graph;
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
    `${s.nodes} resources, ${s.edges} links. Instances: ${s.instances}, exposed ${s.exposed}, unknown ${s.unknown}.`;
  $("checks").textContent = graph.meta?.exposure_checks ? `Exposure checks: ${graph.meta.exposure_checks}` : "";
  clearDetails();

  if (cy) cy.destroy();
  // Exposure rules come last so their red or amber border stays on top of the icon styles.
  const style = [...STYLE, ...iconStyles(ICON_URLS), ...STYLE.filter((r) => /exposure-|:selected|hidden/.test(r.selector))];
  cy = cytoscape({ container: $("cy"), elements, style, wheelSensitivity: 0.3, minZoom: 0.1, maxZoom: 4 });
  cy.on("tap", "node", (evt) => showDetails(evt.target.data()));
  cy.on("tap", (evt) => { if (evt.target === cy) clearDetails(); });
  apply();
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

function typeLegend() {
  const names = {
    "vpc": "VPC", "subnet-public": "Public subnet", "subnet-private": "Private subnet",
    "instance": "EC2 instance", "security-group": "Security group", "network-acl": "Network ACL",
    "route-table": "Route table", "internet-gateway": "Internet gateway",
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
