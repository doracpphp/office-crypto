import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts", "src/olefile.ts", "src/cli.ts"],
  format: ["esm", "cjs"],
  dts: true,
  clean: true,
  splitting: false,
  sourcemap: true,
  target: "node18",
  banner: ({ format }) => {
    return format === "esm" ? {} : {};
  },
});
