// Copy the AWS Architecture Icons ScamallScope uses into frontend/icons/ (git-ignored).
//
// AWS allows customers to use these icons to create architecture diagrams. They are not
// committed to this repo. Download the package from https://aws.amazon.com/architecture/icons/,
// unzip it, then run:  npm run icons -- /path/to/unzipped/package

import { copyFileSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { ICON_FILES, UNSAFE_SVG } from "../src/icons.js";

const root = process.argv[2];
if (!root) {
  console.error("Usage: npm run icons -- <unzipped AWS icon package folder>");
  process.exit(1);
}

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    if (name === "__MACOSX" || name.startsWith(".")) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) yield* walk(path);
    else yield path;
  }
}

const found = new Map();
for (const path of walk(resolve(root))) found.set(basename(path), path);


const out = resolve(import.meta.dirname, "../icons");
mkdirSync(out, { recursive: true });
const missing = [];
for (const [key, file] of Object.entries(ICON_FILES)) {
  const path = found.get(file);
  if (!path) { missing.push(file); continue; }
  if (UNSAFE_SVG.test(readFileSync(path, "utf8"))) {
    console.error(`Refusing ${file}: it contains active content or an external reference`);
    process.exit(1);
  }
  copyFileSync(path, join(out, `${key}.svg`));
  console.log(`${key.padEnd(18)} <- ${file}`);
}
writeFileSync(join(out, "SOURCE.txt"),
  `AWS Architecture Icons, from ${resolve(root)}\nhttps://aws.amazon.com/architecture/icons/\n` +
  "Used under AWS terms for architecture diagrams. Do not commit or redistribute.\n");

if (missing.length) {
  console.error(`Not found (the page falls back to shapes for these): ${missing.join(", ")}`);
  process.exit(2);
}
