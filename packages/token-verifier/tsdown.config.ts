import { defineConfig } from "tsdown"

// Published build. Inside the workspace, consumers import the TypeScript source directly.
export default defineConfig({
  entry: ["src/index.ts"],
  format: "esm",
  platform: "node",
  target: "node22",
  dts: true,
  fixedExtension: false,
})
