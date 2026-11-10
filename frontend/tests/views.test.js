import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { classesFor, parseGraph, worstSeverity } from "../src/model.js";
import {
  bpInfo, columnNotes, costSummary, filterFindings, findingsFor, hasEnrichment, hostRows, overviewColumns,
  overviewTotals, postureRows, postureSummary, safeUrl, savingText, sortFindings, sortRows,
} from "../src/views.js";

const sample = parseGraph(readFileSync(new URL("../../samples/demo.graph.json", import.meta.url), "utf8"));
const f = (severity, pillar, title, extra = {}) => ({ severity, pillar, title, source: "x", resource_name: "r", check_id: "c", detail: "", best_practices: [], ...extra });

describe("findings", () => {
  it("VIEW-1 filters by pillar and severity", () => {
    const list = [f("high", "security", "a"), f("low", "cost", "b"), f("high", "cost", "c")];
    const out = filterFindings(list, { pillars: new Set(["cost"]), severities: new Set(["high"]) });
    expect(out.map((x) => x.title)).toEqual(["c"]);
    expect(filterFindings(list, { search: "B" }).map((x) => x.title)).toEqual(["b"]);
    expect(filterFindings(list, {})).toHaveLength(3);
  });

  it("VIEW-2 sorts critical first, then pillar, then title", () => {
    const list = [f("low", "security", "z"), f("critical", "cost", "b"), f("critical", "security", "y"), f("critical", "security", "a")];
    expect(sortFindings(list).map((x) => x.title)).toEqual(["a", "y", "b", "z"]);
  });

  it("finds a resource's findings in the sample", () => {
    const web = sample.elements.find((e) => e.data.label === "prod-web-1").data;
    const mine = findingsFor(sample, web.id);
    expect(mine.length).toBe(Object.values(web.finding_counts).reduce((a, b) => a + b, 0));
    expect(mine[0].severity).toBe("critical");
  });
});

describe("hosts", () => {
  it("VIEW-3 one row per instance with Wazuh data", () => {
    const rows = hostRows(sample);
    const instances = sample.elements.filter((e) => e.data.type === "instance");
    expect(rows).toHaveLength(instances.length);
    const web = rows.find((r) => r.name === "prod-web-1");
    expect(web.os).toBe("Ubuntu 22.04.4 LTS");
    expect(web.vulns).toBe("1/2/1/0");
    expect(web.deploy).toMatch(/^success /);
    expect(rows.find((r) => r.name === "prod-app-1").ansible).toMatch(/^drift/);
  });

  it("sorts with empty values last", () => {
    const rows = [{ c: null }, { c: 5 }, { c: 1 }];
    expect(sortRows(rows, "c").map((r) => r.c)).toEqual([1, 5, null]);
    expect(sortRows(rows, "c", true).map((r) => r.c)).toEqual([5, 1, null]);
  });
});

describe("cost", () => {
  it("VIEW-4 last full month and top services", () => {
    const s = costSummary(sample, new Date(Date.UTC(2026, 10, 4)));
    expect(s.lastFullMonth.start).toBe("2026-10-01");
    expect(s.topServices[0][0]).toBe("Amazon Elastic Compute Cloud - Compute");
    expect(s.topServices[0][1]).toBeGreaterThanOrEqual(s.topServices[1][1]);
    expect(s.byTag.some(([k]) => k === "(untagged)")).toBe(true);
    expect(s.idle).toBeGreaterThan(0);
  });

  it("is null for a graph without cost", () => {
    expect(costSummary({ cost: null })).toBeNull();
  });
});

describe("well-architected", () => {
  it("VIEW-5 filters by status", () => {
    const issues = postureRows(sample, "security", new Set(["issues"]));
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.every((r) => r.status === "issues")).toBe(true);
    const all = postureRows(sample, "security", new Set(["issues", "clear", "not_checked"]));
    const s = postureSummary(sample).find((x) => x.pillar === "security");
    expect(all.length).toBe(s.issues + s.clear + s.not_checked);
  });
});

describe("safety and modes", () => {
  it("VIEW-6 only https links", () => {
    expect(safeUrl("https://docs.aws.amazon.com/x")).toBe("https://docs.aws.amazon.com/x");
    expect(safeUrl("javascript:alert(1)")).toBeNull();
    expect(safeUrl("http://example.com")).toBeNull();
    expect(safeUrl("data:text/html,x")).toBeNull();
    expect(safeUrl(42)).toBeNull();
  });

  it("VIEW-7 colour by worst severity or cost", () => {
    const node = { type: "instance", exposure: "exposed", finding_counts: { critical: 0, high: 2, low: 1 }, cost: { monthly_usd: 10 } };
    expect(worstSeverity(node)).toBe("high");
    expect(classesFor(node, "severity")).toContain("sev-high");
    expect(classesFor(node, "severity")).not.toContain("exposure-");
    expect(classesFor(node, "cost", { maxCost: 12 })).toContain("cost-high");
    expect(classesFor(node)).toContain("exposure-exposed");
  });

  it("VIEW-8 v1 graph has no enrichment", () => {
    expect(hasEnrichment({ schema_version: 1, elements: [] })).toBe(false);
    expect(hasEnrichment(sample)).toBe(true);
  });
});

describe("overview", () => {
  const g = (findings, integrations = {}) => ({ schema_version: 2, findings, meta: { integrations }, posture: {}, summary: {} });

  it("VIEW-9 three columns, top 10 by priority, no duplicates", () => {
    const many = Array.from({ length: 12 }, (_, i) => f("high", "security", `s${i}`, { priority: i }));
    const dup = f("critical", "security", "dup", { priority: 999, duplicate_of: "x" });
    const cols = overviewColumns(g([...many, dup, f("low", "cost", "c", { priority: 5 })]));
    expect(cols.map((c) => c.pillar)).toEqual(["security", "cost", "reliability"]);
    expect(cols[0].items).toHaveLength(10);
    expect(cols[0].items[0].title).toBe("s11");
    expect(cols[0].items.some((x) => x.title === "dup")).toBe(false);
    expect(cols[0].more).toBe(2);
    expect(cols[1].items.map((x) => x.title)).toEqual(["c"]);
    expect(cols[2].label).toBe("Availability (Reliability)");
  });

  it("VIEW-10 savings text has two decimals", () => {
    expect(savingText(12.5)).toBe("$12.50 a month");
    expect(savingText(null)).toBe("");
    expect(savingText(0)).toBe("");
  });

  it("VIEW-11 a column lists the sources that did not run", () => {
    const notes = columnNotes(g([], { prowler: { loaded: true }, wazuh: { loaded: false } }), "security");
    expect(notes).toEqual(["wazuh not loaded: Wazuh vulnerabilities and agents did not run."]);
    const hubOff = columnNotes(g([], { cost: { loaded: true }, costhub: { loaded: true, enabled: false } }), "cost");
    expect(hubOff[0]).toMatch(/not enabled/);
    const coOff = columnNotes(g([], { cost: { loaded: true }, costhub: { loaded: true, enabled: true, compute_optimizer: "Inactive" } }), "cost");
    expect(coOff[0]).toMatch(/Compute Optimizer is Inactive/);
  });

  it("sample overview has cards in every column and totals from the summary", () => {
    const cols = overviewColumns(sample);
    expect(cols.every((c) => c.items.length > 0)).toBe(true);
    expect(cols[1].items[0].savings_usd).toBeGreaterThan(0);
    const t = overviewTotals(sample);
    expect(t.savings).toBe(sample.summary.savings_usd);
    expect(t.spof).toBeGreaterThan(0);
    const first = cols[0].items[0];
    expect(bpInfo(sample, first.best_practices[0]).url).toMatch(/^https:\/\/docs\.aws\.amazon\.com\//);
  });
});
