import path from "node:path";

import { defineConfig } from "vite-plus";

export default defineConfig({
  build: {
    lib: {
      entry: path.join(import.meta.dirname, "src/main/index.ts"),
      fileName: () => "index.js",
      formats: ["es"],
    },
    outDir: "dist/main",
    rolldownOptions: { external: ["electron", "electron-updater"] },
    ssr: true,
    target: "node22",
  },
  publicDir: false,
  ssr: { noExternal: true },
});
