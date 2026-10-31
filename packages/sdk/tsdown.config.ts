import { defineConfig } from "tsdown"

// Published build. Inside the workspace, consumers import the TypeScript source directly.
export default defineConfig({
  entry: ["src/index.ts", "src/protocol.ts"],
  format: "esm",
  platform: "browser",
  target: "es2022",
  dts: true,
})
