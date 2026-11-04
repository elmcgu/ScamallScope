import { describe, expect, it } from "vitest";
import { ICON_FILES, UNSAFE_SVG, iconKind, iconStyles, installedIcons } from "../src/icons.js";
import { classesFor } from "../src/model.js";

describe("icons", () => {
  it("splits subnets into public and private, and gives unknown no icon", () => {
    expect(iconKind({ type: "subnet", internet_route: true })).toBe("subnet-public");
    expect(iconKind({ type: "subnet", internet_route: false })).toBe("subnet-private");
    expect(iconKind({ type: "subnet", internet_route: null })).toBeNull();
    expect(iconKind({ type: "instance" })).toBe("instance");
  });

  it("adds an icon class that matches the kind", () => {
    expect(classesFor({ type: "subnet", internet_route: true })).toContain("icon-subnet-public");
    expect(classesFor({ type: "subnet", internet_route: null })).not.toContain("icon-");
    expect(classesFor({ type: "instance", exposure: "exposed" })).toBe("type-instance icon-instance exposure-exposed");
  });

  it("makes styles only for installed icons", () => {
    expect(iconStyles({})).toEqual([]);
    const styles = iconStyles({ instance: "/icons/instance.svg", vpc: "/icons/vpc.svg", other: "/x.svg" });
    expect(styles.map((s) => s.selector)).toEqual(["node.icon-instance", "node.icon-vpc", "node.icon-vpc:parent"]);
    expect(styles[0].style["background-image"]).toBe("/icons/instance.svg");
  });

  it("reads installed icons from a Vite glob result and ignores unknown files", () => {
    const urls = installedIcons({ "../icons/instance.svg": "/a.svg", "../icons/evil.svg": "/b.svg" });
    expect(urls).toEqual({ instance: "/a.svg" });
  });

  it("maps every node kind to a file", () => {
    expect(Object.keys(ICON_FILES).sort()).toEqual([
      "instance", "internet-gateway", "network-acl", "route-table", "security-group",
      "subnet-private", "subnet-public", "vpc",
    ]);
  });

  it("refuses SVGs with active content or external references", () => {
    for (const bad of [
      '<svg><script>alert(1)</script></svg>',
      '<svg onload="alert(1)"></svg>',
      '<svg><a href="javascript:alert(1)"/></svg>',
      '<svg><image href="https://evil.example/x.png"/></svg>',
      '<svg><foreignObject></foreignObject></svg>',
    ]) expect(UNSAFE_SVG.test(bad), bad).toBe(true);
    for (const ok of [
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path fill="#ED7100" d="M0 0"/></svg>',
      '<svg><use href="#a"/></svg>',
    ]) expect(UNSAFE_SVG.test(ok), ok).toBe(false);
  });
});
