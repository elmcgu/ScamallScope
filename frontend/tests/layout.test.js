// Runs the real fcose layout headless on the sample graph (no browser).
import { readFileSync } from "node:fs";
import cytoscape from "cytoscape";
import fcose from "cytoscape-fcose";
import { describe, expect, it } from "vitest";
import { LAYOUT } from "../src/layout.js";
import { parseGraph, regionsFor, toCyElements, visibleIds, facets } from "../src/model.js";

cytoscape.use(fcose);
const sample = parseGraph(readFileSync(new URL("../../samples/demo.graph.json", import.meta.url), "utf8"));

function laidOut(regions) {
  const elements = toCyElements(sample);
  const ids = visibleIds(elements, { types: new Set(facets(sample).types), regions, onlyExposed: false, search: "" });
  const shown = elements.filter((e) => (e.group === "nodes" ? ids.has(e.data.id) : ids.has(e.data.source) && ids.has(e.data.target)));
  const cy = cytoscape({
    headless: true, styleEnabled: true, elements: shown,
    style: [{ selector: "node", style: { width: 38, height: 38, label: "data(display_label)", "font-size": 15 } },
            { selector: ":parent", style: { padding: 24 } }],
  });
  cy.layout(LAYOUT).run();
  return cy;
}

describe("fcose layout of the sample", () => {
  for (const region of ["eu-west-1", "*"]) {
    it(`places every node at a finite position (${region})`, () => {
      const cy = laidOut(regionsFor(region, sample));
      expect(cy.nodes().length).toBeGreaterThan(5);
      cy.nodes().forEach((n) => {
        expect(Number.isFinite(n.position("x")) && Number.isFinite(n.position("y"))).toBe(true);
      });
    });
  }

  it("keeps children inside their parent box", () => {
    const cy = laidOut(regionsFor("eu-west-1", sample));
    cy.nodes(":child").forEach((child) => {
      const p = child.parent().boundingBox({ includeLabels: false });
      const c = child.position();
      expect(c.x).toBeGreaterThanOrEqual(p.x1);
      expect(c.x).toBeLessThanOrEqual(p.x2);
      expect(c.y).toBeGreaterThanOrEqual(p.y1);
      expect(c.y).toBeLessThanOrEqual(p.y2);
    });
  });

  it("one region is much more compact than all regions", () => {
    const area = (cy) => { const b = cy.elements().boundingBox(); return b.w * b.h; };
    expect(area(laidOut(regionsFor("eu-west-1", sample)))).toBeLessThan(area(laidOut(regionsFor("*", sample))));
  });
});
