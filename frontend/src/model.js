// Pure data logic for the network view. No DOM and no Cytoscape here, so vitest can test it.

import { iconKind } from "./icons.js";

export const SCHEMA_VERSION = 1;

// "contains" edges that become nesting (child drawn inside parent) instead of lines.
const NEST = {
  vpc: new Set(["subnet", "security-group", "route-table", "network-acl"]),
  subnet: new Set(["instance"]),
};

export function parseGraph(json) {
  const g = typeof json === "string" ? JSON.parse(json) : json;
  if (!g || typeof g !== "object" || !Array.isArray(g.elements)) {
    throw new Error("Not a ScamallScope graph: no elements list");
  }
  if (g.schema_version !== SCHEMA_VERSION) {
    throw new Error(`Unsupported graph schema_version ${g.schema_version} (expected ${SCHEMA_VERSION})`);
  }
  return g;
}

export function nodesOf(graph) {
  return graph.elements.filter((e) => e.group === "nodes").map((e) => e.data);
}

export function edgesOf(graph) {
  return graph.elements.filter((e) => e.group === "edges").map((e) => e.data);
}

/** Cytoscape elements: nest VPC > subnet > instance, and drop the "contains" lines that became nesting. */
export function toCyElements(graph) {
  const nodes = new Map(nodesOf(graph).map((n) => [n.id, { ...n }]));
  const edges = [];
  for (const e of edgesOf(graph)) {
    const src = nodes.get(e.source);
    const dst = nodes.get(e.target);
    if (e.type === "contains" && src && dst && NEST[src.type]?.has(dst.type) && !dst.parent) {
      dst.parent = src.id;
    } else {
      edges.push({ group: "edges", data: { ...e } });
    }
  }
  const out = [...nodes.values()].map((n) => ({
    group: "nodes", data: { ...n, display_label: displayLabel(n) }, classes: classesFor(n),
  }));
  return [...out, ...edges];
}

// Exposure is shown by a text marker as well as colour, so it does not rely on colour alone.
const MARKERS = { exposed: "⚠ ", unknown: "? " };

export function displayLabel(node) {
  return `${MARKERS[node.exposure] ?? ""}${node.admin ? "★ " : ""}${node.label}`;
}

export function classesFor(node) {
  const c = [`type-${node.type}`];
  const kind = iconKind(node);
  if (kind) c.push(`icon-${kind}`);
  if (node.exposure) c.push(`exposure-${node.exposure}`);
  if (node.admin) c.push("admin");
  return c.join(" ");
}

export function facets(graph) {
  const nodes = nodesOf(graph);
  return {
    types: [...new Set(nodes.map((n) => n.type))].sort(),
    regions: [...new Set(nodes.map((n) => n.region))].sort(),
  };
}

export const ALL_REGIONS = "*";

/**
 * Region to show first: the one with the most exposed or unknown instances, then the most
 * resources, then by name. One region at a time keeps the view readable on big estates.
 */
export function defaultRegion(graph) {
  const score = new Map();
  for (const n of nodesOf(graph)) {
    const [risky, total] = score.get(n.region) ?? [0, 0];
    const bad = n.exposure === "exposed" || n.exposure === "unknown" ? 1 : 0;
    score.set(n.region, [risky + bad, total + 1]);
  }
  const ranked = [...score.entries()].sort(
    ([ra, [xa, ta]], [rb, [xb, tb]]) => xb - xa || tb - ta || ra.localeCompare(rb),
  );
  return ranked[0]?.[0] ?? ALL_REGIONS;
}

/** The set of regions for a region choice ("*" means all). */
export function regionsFor(choice, graph) {
  return new Set(choice === ALL_REGIONS ? facets(graph).regions : [choice]);
}

/**
 * Ids of nodes to show.
 * filters: { types: Set, regions: Set, onlyExposed: boolean, search: string }
 * - onlyExposed keeps instances that are exposed or unknown, plus the security groups
 *   and network ACLs named in their exposed ports, so the view shows why.
 * - Parents of a shown node are always shown (a hidden parent hides its children).
 */
export function visibleIds(elements, filters) {
  const nodes = elements.filter((e) => e.group === "nodes").map((e) => e.data);
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const search = (filters.search || "").trim().toLowerCase();

  let shown = nodes.filter(
    (n) => filters.types.has(n.type) && filters.regions.has(n.region) && matches(n, search),
  );

  if (filters.onlyExposed) {
    const risky = shown.filter((n) => n.exposure === "exposed" || n.exposure === "unknown");
    // Exposed ports name groups and ACLs by resource id (sg-..., acl-...); ids are unique per region.
    const why = new Set();
    for (const n of risky) {
      for (const p of n.exposed_ports || []) {
        why.add(`${n.region}|${p.security_group}`);
        if (p.network_acl) why.add(`${n.region}|${p.network_acl}`);
      }
    }
    const reasons = nodes.filter((n) => why.has(`${n.region}|${resourceId(n)}`));
    shown = [...risky, ...reasons];
  }

  const ids = new Set(shown.map((n) => n.id));
  for (const id of [...ids]) {
    let p = byId.get(id)?.parent;
    while (p && !ids.has(p)) {
      ids.add(p);
      p = byId.get(p)?.parent;
    }
  }
  return ids;
}

/** "arn:aws:ec2:eu-west-1:123456789012:security-group/sg-1" -> "sg-1" */
export function resourceId(node) {
  return node.id.split("/").pop();
}

function matches(node, search) {
  if (!search) return true;
  const hay = [node.label, node.id, ...Object.entries(node.tags || {}).flat()].join(" ").toLowerCase();
  return hay.includes(search);
}

/** Warnings to show above the graph. */
export function warnings(graph) {
  const m = graph.meta || {};
  const out = [];
  if (m.complete === false) {
    const units = (m.failed_units || []).map((u) => `${u.region} ${u.service}:${u.resource_type} (${u.error})`);
    out.push(`Partial snapshot: ${units.length} collection unit(s) failed. Results there may be "unknown". ${units.join("; ")}`);
  }
  if (m.dropped_edges) out.push(`${m.dropped_edges} link(s) dropped: they point to resources not in the snapshot.`);
  return out;
}

export function summary(graph) {
  const nodes = nodesOf(graph);
  const checked = nodes.filter((n) => n.exposure);
  return {
    nodes: nodes.length,
    edges: edgesOf(graph).length,
    checked: checked.length,
    exposed: checked.filter((n) => n.exposure === "exposed").length,
    unknown: checked.filter((n) => n.exposure === "unknown").length,
    admins: nodes.filter((n) => n.admin && n.type !== "policy").length,
  };
}

/** Rows [label, value] for the details panel. Values are plain strings; the UI sets them as text. */
export function detailRows(node) {
  const skip = new Set(["id", "parent", "label", "display_label", "exposed_ports", "tags", "ingress", "egress", "routes", "entries"]);
  const rows = [["Name", node.label], ["ARN", node.id]];
  for (const [k, v] of Object.entries(node)) {
    if (skip.has(k) || v === null || v === undefined) continue;
    const text = valueText(v);
    if (text !== null) rows.push([k, text]);
  }
  for (const [k, v] of Object.entries(node.tags || {})) rows.push([`tag:${k}`, v]);
  return rows;
}

/** Plain text for a value: primitives, lists of primitives, and flat objects. Null for anything deeper. */
function valueText(v) {
  const flat = (x) => x === null || ["string", "number", "boolean"].includes(typeof x);
  if (flat(v)) return String(v);
  if (Array.isArray(v)) return v.every(flat) ? (v.length ? v.join(", ") : "(none)") : null;
  if (typeof v === "object" && Object.values(v).every(flat)) {
    return Object.entries(v).map(([k, x]) => `${k}: ${x}`).join(", ");
  }
  return null;
}

export function portText(p) {
  const ports = p.from_port === null || p.from_port === undefined
    ? "all"
    : p.from_port === p.to_port ? `${p.from_port}` : `${p.from_port}-${p.to_port}`;
  return `${p.protocol} ${ports} (${p.family}) via ${p.security_group}${p.network_acl ? `, ${p.network_acl}` : ""}`;
}
