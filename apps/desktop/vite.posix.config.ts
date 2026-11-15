import path from "node:path";

import { defineConfig } from "vite-plus";

export default defineConfig({
  build: {
    lib: {
      entry: {
        client: path.join(import.meta.dirname, "src/posix/client.ts"),
        "native-host": path.join(import.meta.dirname, "src/posix/native-host.ts"),
      },
      fileName: (_format, name) => name + ".cjs",
      formats: ["cjs"],
    },
    outDir: "dist/posix",
    ssr: true,
    target: "node22",
    rolldownOptions: { output: { chunkFileNames: "[name]-[hash].cjs" } },
  },
  publicDir: false,
  ssr: { noExternal: true },
});
