// AWS Architecture Icons for each node kind. Files live in frontend/icons/ (git-ignored),
// installed by scripts/install-icons.mjs. Without them the page uses plain shapes.

/** Icons are drawn by the browser: the installer refuses SVGs with active content or external references. */
export const UNSAFE_SVG = /<script|<foreignObject|\son[a-z]+\s*=|javascript:|(?:href|src)\s*=\s*["'](?!#|data:image)/i;

/** Node kind -> file name in the AWS icon package (release 07312026). */
export const ICON_FILES = {
  "instance": "Res_Amazon-EC2_Instance_48.svg",
  "vpc": "Virtual-private-cloud-VPC_32.svg",
  "subnet-public": "Public-subnet_32.svg",
  "subnet-private": "Private-subnet_32.svg",
  "internet-gateway": "Res_Amazon-VPC_Internet-Gateway_48.svg",
  "route-table": "Res_Amazon-VPC_Router_48.svg",
  "network-acl": "Res_Amazon-VPC_Network-Access-Control-List_48.svg",
  // AWS has no security group icon; the general white shield is for dark backgrounds.
  "security-group": "Res_Shield_48_Dark.svg",
};

/** Icon kind for a node: subnets split into public and private by their internet route. */
export function iconKind(node) {
  if (node.type !== "subnet") return node.type;
  if (node.internet_route === true) return "subnet-public";
  if (node.internet_route === false) return "subnet-private";
  return null; // unknown: no icon rather than a wrong one
}

/** Cytoscape style entries for the icons that are installed. `urls` maps kind -> URL. */
export function iconStyles(urls) {
  const styles = [];
  for (const [kind, url] of Object.entries(urls)) {
    if (!(kind in ICON_FILES)) continue;
    const selector = `node.icon-${kind}`;
    const groupBox = kind === "vpc" || kind.startsWith("subnet-");
    // Leaf nodes: the icon fills the node. VPC and subnet boxes: a badge in the top-left corner.
    styles.push({ selector, style: {
      "background-image": url, "background-fit": "contain", "background-clip": "none",
      "background-color": "#0d1117", "background-image-containment": "over",
      ...(groupBox ? {} : { "background-width": "80%", "background-height": "80%" }),
    } });
    if (groupBox) {
      styles.push({ selector: `${selector}:parent`, style: {
        "background-fit": "none", "background-width": 28, "background-height": 28,
        "background-position-x": 0, "background-position-y": 0, "background-repeat": "no-repeat",
        "background-color": "#0d1117",
      } });
    }
  }
  return styles;
}

/** Icons found in frontend/icons/ at build time (empty if none installed). */
export function installedIcons(glob) {
  const urls = {};
  for (const [path, url] of Object.entries(glob)) {
    const kind = path.split("/").pop().replace(/\.svg$/, "");
    if (kind in ICON_FILES) urls[kind] = url;
  }
  return urls;
}
