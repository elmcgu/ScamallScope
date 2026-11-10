// Data logic for the Findings, Hosts, Cost and Well-Architected views (spec 09).
// No DOM here, so vitest can test it. Every value is untrusted text; main.js sets it with textContent.

import { SEVERITIES, nodesOf } from "./model.js";

export const PILLARS = ["security", "reliability", "cost"];
export const STATUSES = ["issues", "clear", "not_checked"];
export const VIEWS = ["overview", "map", "findings", "hosts", "cost", "wa", "availability"];
export const PILLAR_LABELS = { security: "Security", cost: "Cost", reliability: "Availability (Reliability)" };
const OVERVIEW_ORDER = ["security", "cost", "reliability"];
// Sources whose absence means some checks for that column did not run.
const COLUMN_SOURCES = {
  security: { prowler: "Prowler checks", wazuh: "Wazuh vulnerabilities and agents" },
  cost: { costhub: "Cost Optimization Hub: savings are estimates from our own rules", cost: "Cost Explorer spend and commitment coverage" },
  reliability: { cloudwatch: "CloudWatch alarms and recover actions", prometheus: "Prometheus monitoring", ansible: "Ansible configuration runs" },
};

export function hasEnrichment(graph) {
  return graph?.schema_version >= 2 && Array.isArray(graph.findings);
}

/** Only https URLs are used as links. Anything else (javascript:, http:, data:) is dropped. */
export function safeUrl(value) {
  if (typeof value !== "string") return null;
  try {
    const u = new URL(value);
    return u.protocol === "https:" ? u.href : null;
  } catch {
    return null;
  }
}

/** filters: { pillars: Set, severities: Set, sources: Set, search: string }; empty sets mean "all". */
export function filterFindings(findings, filters = {}) {
  const search = (filters.search || "").trim().toLowerCase();
  const inSet = (set, v) => !set || set.size === 0 || set.has(v);
  return findings.filter((f) =>
    inSet(filters.pillars, f.pillar) && inSet(filters.severities, f.severity) && inSet(filters.sources, f.source)
    && (!search || [f.title, f.resource_name, f.check_id, f.detail, ...(f.best_practices || [])].join(" ").toLowerCase().includes(search)));
}

export function sortFindings(findings) {
  const rank = (s) => { const i = SEVERITIES.indexOf(s); return i < 0 ? SEVERITIES.length : i; };
  return [...findings].sort((a, b) =>
    rank(a.severity) - rank(b.severity) || PILLARS.indexOf(a.pillar) - PILLARS.indexOf(b.pillar)
    || a.title.localeCompare(b.title));
}

export function findingFacets(findings) {
  return { sources: [...new Set(findings.map((f) => f.source))].sort() };
}

const fmtVulns = (v) => (v ? `${v.critical}/${v.high}/${v.medium}/${v.low}` : "");

/** One row per EC2 instance, joining every source. Missing data is "" (source not loaded or no match). */
export function hostRows(graph) {
  return nodesOf(graph).filter((n) => n.type === "instance").map((n) => ({
    id: n.id,
    name: n.label,
    region: n.region,
    state: n.state ?? "",
    exposure: n.exposure ?? "",
    os: n.wazuh ? `${n.wazuh.os_name ?? ""} ${n.wazuh.os_version ?? ""}`.trim() : "",
    agent: n.wazuh?.status ?? "",
    vulns: fmtVulns(n.wazuh?.vulns),
    vuln_score: n.wazuh?.vulns ? n.wazuh.vulns.critical * 1000 + n.wazuh.vulns.high * 100 + n.wazuh.vulns.medium * 10 + n.wazuh.vulns.low : -1,
    deploy: n.deploy ? `${n.deploy.state} ${n.deploy.sha} (${n.deploy.environment})` : "",
    ansible: n.config_run ? configText(n.config_run) : "",
    cpu_avg: n.metrics?.cpu_avg ?? null,
    alarms: n.metrics?.alarms ?? null,
    prom_up: n.metrics?.prom_up ?? null,
    cost: n.cost?.monthly_usd ?? null,
    findings: Object.values(n.finding_counts || {}).reduce((a, b) => a + b, 0),
  }));
}

function configText(c) {
  if (c.failures || c.unreachable) return `failed (${c.failures} failed, ${c.unreachable} unreachable)`;
  if (c.mode === "check" && c.changed) return `drift (${c.changed} would change)`;
  return "ok";
}

/** Sort rows by a column; nulls and "" last. */
export function sortRows(rows, key, descending = false) {
  const empty = (v) => v === null || v === undefined || v === "" || v === -1;
  return [...rows].sort((a, b) => {
    const x = a[key], y = b[key];
    if (empty(x) || empty(y)) return empty(x) - empty(y);
    const c = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y));
    return descending ? -c : c;
  });
}

/** Totals for the Cost view. `today` decides which month is the last full one. */
export function costSummary(graph, today = new Date()) {
  const cost = graph.cost;
  if (!cost) return null;
  const current = `${today.getUTCFullYear()}-${String(today.getUTCMonth() + 1).padStart(2, "0")}-01`;
  const full = cost.months.filter((m) => m.start < current);
  const last = full[full.length - 1] ?? null;
  const tagMonth = last ? cost.by_tag?.months?.find((m) => m.start === last.start) : null;
  return {
    currency: cost.currency,
    months: cost.months.map((m) => ({ start: m.start, total: m.total, estimated: m.estimated })),
    lastFullMonth: last ? { start: last.start, total: last.total } : null,
    topServices: last ? Object.entries(last.by_service).sort((a, b) => b[1] - a[1]).slice(0, 10) : [],
    byTag: tagMonth ? Object.entries(tagMonth.values).sort((a, b) => b[1] - a[1]).map(([k, v]) => [k || "(untagged)", v]) : [],
    tagKey: cost.by_tag?.key ?? "",
    topResources: cost.top_resources ?? [],
    idle: cost.idle_monthly_usd ?? 0,
    estimated: cost.estimated,
  };
}

export function money(v) {
  return typeof v === "number" ? `$${v.toFixed(2)}` : "";
}

/** Best-practice rows for one pillar, filtered by status. */
export function postureRows(graph, pillar, statuses = new Set(["issues", "clear"])) {
  const rows = graph.posture?.[pillar]?.best_practices ?? [];
  return rows.filter((r) => statuses.has(r.status));
}

export function postureSummary(graph) {
  return PILLARS.map((p) => ({ pillar: p, ...(graph.posture?.[p]?.summary ?? { issues: 0, clear: 0, not_checked: 0 }) }));
}

/** Findings about one resource, worst first (for the details panel). */
/** A resource's findings, each issue once (duplicates from other sources are left out, spec 13). */
export function findingsFor(graph, id) {
  return sortFindings((graph.findings || []).filter((f) => f.resource === id && !f.duplicate_of));
}

/** Which integrations were loaded, for the header. */
export function integrationStatus(graph) {
  return Object.entries(graph.meta?.integrations ?? {}).map(([name, m]) => ({
    name, loaded: !!m.loaded, error: m.error ?? null, unmatched: m.unmatched ?? [],
  }));
}

/** Primary findings (each issue once, spec 13). */
export function primaryFindings(graph) {
  return (graph.findings || []).filter((f) => !f.duplicate_of);
}

function byPriority(a, b) {
  return (b.priority ?? 0) - (a.priority ?? 0) || a.title.localeCompare(b.title);
}

/** Best-practice title and AWS link for an id, from the scorecard. */
export function bpInfo(graph, id) {
  for (const p of PILLARS) {
    const row = graph.posture?.[p]?.best_practices?.find((r) => r.id === id);
    if (row) return { id, title: row.title, url: row.url };
  }
  return { id, title: "", url: null };
}

/** Notes for a column: which sources it would use are not loaded (or loaded but switched off). */
export function columnNotes(graph, pillar) {
  const meta = graph.meta?.integrations ?? {};
  const notes = [];
  for (const [source, what] of Object.entries(COLUMN_SOURCES[pillar])) {
    const m = meta[source];
    if (!m?.loaded) notes.push(`${source} not loaded: ${what} did not run.`);
    else if (source === "costhub" && m.enabled === false) notes.push("Cost Optimization Hub is not enabled: savings are estimates from our own rules.");
    else if (source === "costhub" && m.compute_optimizer && m.compute_optimizer !== "Active") {
      notes.push(`Compute Optimizer is ${m.compute_optimizer}: no rightsizing or idle recommendations yet.`);
    }
  }
  return notes;
}

/** The three Overview columns: top n primary findings per pillar by priority (spec 14, VIEW-9). */
export function overviewColumns(graph, n = 10) {
  const primary = primaryFindings(graph);
  return OVERVIEW_ORDER.map((pillar) => {
    const all = primary.filter((f) => f.pillar === pillar).sort(byPriority);
    return { pillar, label: PILLAR_LABELS[pillar], items: all.slice(0, n), more: Math.max(0, all.length - n), notes: columnNotes(graph, pillar) };
  });
}

/** Header totals for the Overview, from the graph summary. */
export function overviewTotals(graph) {
  const s = graph.summary ?? {};
  const open = s.open ?? {};
  return {
    critical: open.critical ?? 0, high: open.high ?? 0, medium: open.medium ?? 0, low: (open.low ?? 0) + (open.info ?? 0),
    savings: s.savings_usd ?? 0, savingsEstimated: !!s.savings_estimated, spof: s.single_points_of_failure ?? 0,
  };
}

/** "$12.50 a month", or "" when there is no saving (VIEW-10). */
export function savingText(v) {
  return typeof v === "number" && v > 0 ? `${money(v)} a month` : "";
}

/** Availability view rows (spec 14). The graph already sorts them; prodOnly keeps prod workloads (VIEW-12). */
export function workloadRows(graph, prodOnly = false) {
  return (graph.workloads ?? []).filter((w) => !prodOnly || w.prod).map((w) => ({
    ...w, az_count: w.azs.length, azs_text: w.azs.join(", ") || "?",
  }));
}
