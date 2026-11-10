import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  ALL_REGIONS, classesFor, defaultRegion, detailRows, displayLabel, facets, regionsFor, parseGraph, portText, resourceId, summary, toCyElements, visibleIds, warnings,
} from "../src/model.js";

const sample = parseGraph(readFileSync(new URL("../../samples/demo.graph.json", import.meta.url), "utf8"));
const filtersFor = (g, extra = {}) => {
  const f = facets(g);
  return { types: new Set(f.types), regions: new Set(f.regions), onlyExposed: false, search: "", ...extra };
};
const byLabel = (els, label) => els.find((e) => e.group === "nodes" && e.data.label === label).data;

describe("parseGraph", () => {
  it("rejects files that are not a graph", () => {
    expect(() => parseGraph("{}")).toThrow(/no elements/);
    expect(() => parseGraph({ schema_version: 99, elements: [] })).toThrow(/schema_version 99/);
  });
});

describe("toCyElements", () => {
  const els = toCyElements(sample);

  it("nests subnet in VPC and instance in subnet", () => {
    const vpc = byLabel(els, "prod");
    const subnet = byLabel(els, "prod-public");
    const web = byLabel(els, "prod-web-1");
    expect(subnet.parent).toBe(vpc.id);
    expect(web.parent).toBe(subnet.id);
    expect(byLabel(els, "prod-web").parent).toBe(vpc.id); // security group inside its VPC
  });

  it("drops only the contains edges that became nesting", () => {
    const edges = els.filter((e) => e.group === "edges").map((e) => e.data);
    const ids = new Set(els.filter((e) => e.group === "nodes").map((e) => e.data.id));
    expect(edges.every((e) => ids.has(e.source) && ids.has(e.target))).toBe(true);
    const nested = edges.filter((e) => {
      const child = els.find((n) => n.data.id === e.target);
      return e.type === "contains" && child?.data.parent === e.source;
    });
    expect(nested).toEqual([]);
    expect(edges.some((e) => e.type === "uses")).toBe(true);
    expect(edges.some((e) => e.type === "routes_to")).toBe(true);
  });

  it("does not change the input graph", () => {
    const before = JSON.stringify(sample);
    toCyElements(sample);
    expect(JSON.stringify(sample)).toBe(before);
  });

  it("marks exposure in the label as well as by colour", () => {
    expect(byLabel(els, "prod-web-1").display_label).toBe("⚠ prod-web-1");
    expect(byLabel(els, "prod-db-1").display_label).toBe("prod-db-1");
    expect(displayLabel({ label: "x", exposure: "unknown" })).toBe("? x");
  });

  it("adds type and exposure classes", () => {
    const web = els.find((e) => e.data.label === "prod-web-1");
    expect(web.classes).toBe("type-instance icon-instance exposure-exposed");
  });
});

describe("visibleIds", () => {
  const els = toCyElements(sample);

  it("shows everything with no filters", () => {
    expect(visibleIds(els, filtersFor(sample)).size).toBe(els.filter((e) => e.group === "nodes").length);
  });

  it("only exposed: exposed instances, their parents, and the groups and ACLs that explain them", () => {
    const ids = visibleIds(els, filtersFor(sample, { onlyExposed: true }));
    const labels = els.filter((e) => ids.has(e.data.id)).map((e) => e.data.label).sort();
    expect(labels).toContain("prod-web-1");
    expect(labels).toContain("staging-web-1");
    expect(labels).toContain("prod-web"); // its security group
    expect(labels).toContain("staging-web");
    expect(labels).toContain("prod"); // parents
    expect(labels).toContain("prod-public");
    expect(labels).not.toContain("prod-db-1");
    expect(labels).not.toContain("tools-bastion-1");
  });

  it("filters by region and keeps parents of matches", () => {
    const ids = visibleIds(els, filtersFor(sample, { regions: new Set(["us-east-1"]) }));
    const nodes = els.filter((e) => ids.has(e.data.id)).map((e) => e.data);
    expect(nodes.every((n) => n.region === "us-east-1")).toBe(true);
    expect(nodes.some((n) => n.label === "tools-bastion-1")).toBe(true);
  });

  it("search matches tags and pulls in parents", () => {
    const ids = visibleIds(els, filtersFor(sample, { search: "BASTION" }));
    const labels = els.filter((e) => ids.has(e.data.id)).map((e) => e.data.label);
    expect(labels).toEqual(expect.arrayContaining(["tools-bastion-1", "tools-public", "tools"]));
    expect(labels).not.toContain("prod-web-1");
  });

  it("hiding a type keeps parents of what is still shown", () => {
    const f = filtersFor(sample);
    f.types.delete("subnet");
    const ids = visibleIds(els, f);
    // The subnet comes back because an instance inside it is shown.
    expect(ids.has(byLabel(els, "prod-public").id)).toBe(true);
  });
});

describe("summary and warnings", () => {
  it("counts exposure across all checked types, and admin principals", () => {
    // 9 instances, 4 buckets, 3 functions; exposed: 3 instances, 1 bucket, 1 function
    expect(summary(sample)).toMatchObject({ checked: 16, exposed: 5, unknown: 0, admins: 2 });
  });

  it("warns about a partial snapshot and dropped links", () => {
    const g = { schema_version: 1, elements: [], meta: {
      complete: false, dropped_edges: 2,
      failed_units: [{ region: "eu-west-1", service: "ec2", resource_type: "network-acl", error: "AccessDenied: x" }],
    } };
    const w = warnings(g);
    expect(w[0]).toMatch(/Partial snapshot: 1 collection unit/);
    expect(w[0]).toMatch(/network-acl/);
    expect(w[1]).toMatch(/2 link\(s\) dropped/);
    expect(warnings(sample)).toEqual([]);
  });
});

describe("details", () => {
  it("returns tag text as is, for the UI to set as text (not HTML)", () => {
    const rows = detailRows({ id: "arn:x/i-1", label: "a", type: "instance", tags: { Name: "<img src=x onerror=alert(1)>" } });
    expect(rows).toContainEqual(["tag:Name", "<img src=x onerror=alert(1)>"]);
  });

  it("formats exposed ports", () => {
    expect(portText({ protocol: "tcp", from_port: 22, to_port: 22, family: "ipv4", security_group: "sg-1", network_acl: "acl-1" }))
      .toBe("tcp 22 (ipv4) via sg-1, acl-1");
    expect(portText({ protocol: "udp", from_port: 0, to_port: 65535, family: "ipv6", security_group: "sg-1" }))
      .toBe("udp 0-65535 (ipv6) via sg-1");
    expect(portText({ protocol: "icmp", from_port: null, to_port: null, family: "ipv4", security_group: "sg-1" }))
      .toBe("icmp all (ipv4) via sg-1");
  });

  it("gets the resource id from an ARN", () => {
    expect(resourceId({ id: "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-1" })).toBe("sg-1");
  });
});

describe("region choice", () => {
  const node = (region, exposure) => ({ group: "nodes", data: { id: `${region}-${Math.random()}`, region, exposure } });
  const graph = (...nodes) => ({ schema_version: 1, elements: nodes });

  it("starts on the region with the most exposed or unknown instances", () => {
    expect(defaultRegion(sample)).toBe("eu-west-1");
    const g = graph(node("a"), node("a"), node("a"), node("b", "unknown"));
    expect(defaultRegion(g)).toBe("b");
  });

  it("breaks ties by size, then by name", () => {
    expect(defaultRegion(graph(node("b"), node("a"), node("a")))).toBe("a");
    expect(defaultRegion(graph(node("b"), node("a")))).toBe("a");
  });

  it("falls back to all regions for an empty graph", () => {
    expect(defaultRegion(graph())).toBe(ALL_REGIONS);
  });

  it("turns a choice into a region set", () => {
    expect(regionsFor("us-east-1", sample)).toEqual(new Set(["us-east-1"]));
    expect(regionsFor(ALL_REGIONS, sample)).toEqual(new Set(["eu-west-1", "global", "us-east-1"]));
  });
});

describe("admin and details", () => {
  it("marks admins in the label and classes", () => {
    expect(displayLabel({ label: "alex", admin: true })).toBe("★ alex");
    expect(displayLabel({ label: "fn", exposure: "exposed", admin: false })).toBe("⚠ fn");
    expect(classesFor({ type: "user", admin: true })).toContain("admin");
  });

  it("shows lists and flat objects as text, and skips deeper data", () => {
    const rows = Object.fromEntries(detailRows({
      id: "arn:x", label: "r", type: "role", trusted_principals: ["ec2.amazonaws.com"], inline_policies: [],
      block_public_access: { IgnorePublicAcls: true }, deep: [{ a: 1 }],
    }));
    expect(rows.trusted_principals).toBe("ec2.amazonaws.com");
    expect(rows.inline_policies).toBe("(none)");
    expect(rows.block_public_access).toBe("IgnorePublicAcls: true");
    expect(rows.deep).toBeUndefined();
  });

  it("the sample has admin, public bucket and public function nodes", () => {
    const n = Object.fromEntries(nodesOfSample().map((d) => [d.label, d]));
    expect(n["alex.admin"].admin).toBe(true);
    expect(n["ci-deployer"].admin).toBe(false);
    expect(n["demo-site-public"].exposure).toBe("exposed");
    expect(n["demo-reports"].exposure).toBe("not_exposed");
    expect(n["orders-webhook"].exposure).toBe("exposed");
  });
});

function nodesOfSample() {
  return sample.elements.filter((e) => e.group === "nodes").map((e) => e.data);
}

describe("map types", () => {
  it("snapshots, settings and other rule inputs are not drawn", async () => {
    const { toCyElements, facets } = await import("../src/model.js");
    const g = { schema_version: 2, elements: [
      { group: "nodes", data: { id: "v", type: "volume", region: "r", label: "v" } },
      { group: "nodes", data: { id: "s", type: "snapshot", region: "r", label: "s" } },
      { group: "nodes", data: { id: "x", type: "setting", region: "r", label: "x" } },
      { group: "edges", data: { id: "e", source: "s", target: "v", type: "snapshot_of" } }] };
    const els = toCyElements(g);
    expect(els.map((e) => e.data.id)).toEqual(["v"]);
    expect(facets(g).types).toEqual(["volume"]);
  });
});
