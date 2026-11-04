import { defineConfig } from "vite";

export default defineConfig({
  // samples/ holds made-up data only; it is served at / in dev and copied into the build.
  publicDir: "../samples",
  test: { environment: "node" },
});
