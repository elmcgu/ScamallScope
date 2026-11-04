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

## What it shows

- VPC > subnet > instance as nested boxes. Security groups, route tables and network ACLs sit in their VPC.
- Lines: instance **uses** security group, route table **routes** subnet and **routes_to** internet gateway,
  network ACL **filters** subnet, internet gateway **attached** to VPC.
- Red: exposed to the internet. Amber: unknown (a collection unit failed). Click a node for details and exposed ports.
- Filters: search (name, id, tags), type, region, and "only exposed or unknown", which also shows the
  security groups and network ACLs that explain the exposure.

## Security

Graph data (names, tags) is untrusted. The UI sets it with `textContent` only, never `innerHTML`, and
`index.html` has a Content Security Policy that allows scripts from this site only.
