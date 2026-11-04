# scamallscope frontend

Network view of a ScamallScope graph JSON, drawn with Cytoscape.js.

## Run

```bash
cd frontend
npm ci
npm run dev      # http://localhost:5173, then "Load sample" or "Open graph JSON"
npm test
npm run build    # static files in dist/
```

"Open graph JSON" reads the file in the browser. It is never uploaded.
"Load sample" loads `samples/demo.graph.json` (made-up data, rebuilt with
`uv run python scripts/make_sample.py` in `collector/`).

## AWS icons (optional)

The page can show the official [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/).
AWS allows customers to use them to create architecture diagrams, so they are **not** in this repo
(`frontend/icons/` is git-ignored). Without them the page uses plain shapes.

```bash
# Download the "Icon package" zip from the page above, then:
unzip -q Icon-package_*.zip -d ~/aws-icons
cd frontend && npm run icons -- ~/aws-icons
```

The script copies only the icons in `src/icons.js` and refuses any SVG with scripts, event
handlers or external links. A build (`dist/`) then contains the icons: keep it private.

## What it shows

- VPC > subnet > instance as nested boxes. Security groups, route tables and network ACLs sit in their VPC.
- Lines: instance **uses** security group, route table **routes** subnet and **routes_to** internet gateway,
  network ACL **filters** subnet, internet gateway **attached** to VPC.
- Red: exposed to the internet. Amber: unknown (a collection unit failed). Click a node for details and exposed ports.
- Region: one at a time, starting with the region that has the most exposed or unknown instances.
  "All regions" is in the list.
- Filters: search (name, id, tags), type, and "only exposed or unknown", which also shows the
  security groups and network ACLs that explain the exposure.
- Layout: `cytoscape-fcose` (options in `src/layout.js`, tested headless in `tests/layout.test.js`).

## Security

Graph data (names, tags) is untrusted. The UI sets it with `textContent` only, never `innerHTML`, and
`index.html` has a Content Security Policy that allows scripts from this site only.
