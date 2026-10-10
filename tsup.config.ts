import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/olefile.ts", "src/cli.ts"],
  format: ["esm", "cjs"],
  // The CLI is an executable, not an importable module — no typings needed.
  dts: { entry: ["src/index.ts", "src/olefile.ts"] },
  clean: true,
  splitting: false,
  sourcemap: true,
  target: "node18",
});
