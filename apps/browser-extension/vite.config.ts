import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

import { defineConfig } from "vite-plus";

import { browserExtensionId, nativeVersion } from "@ip-guard/electron";

const root = import.meta.dirname;
export default defineConfig({
  plugins: [
    {
      name: "extension-manifest",
      generateBundle() {
        this.emitFile({
          type: "asset",
          fileName: "icon.png",
          source: readFileSync(path.join(root, "../desktop/assets/tray.png")),
        });
        const source: unknown = JSON.parse(readFileSync(path.join(root, "manifest.json"), "utf8"));
        if (
          !source ||
          typeof source !== "object" ||
          !("key" in source) ||
          typeof source.key !== "string"
        )
          throw new Error("Invalid extension manifest");
        const key = source.key;
        const id = createHash("sha256")
          .update(Buffer.from(key, "base64"))
          .digest("hex")
          .slice(0, 32)
          .replace(/[0-9a-f]/g, (x) => String.fromCharCode(97 + parseInt(x, 16)));
        if (id !== browserExtensionId) throw new Error("Extension identity mismatch");
        this.emitFile({
          type: "asset",
          fileName: "manifest.json",
          source: JSON.stringify({ ...source, version: nativeVersion }, null, 2),
        });
      },
    },
  ],
  build: {
    rolldownOptions: {
      input: {
        worker: path.join(root, "src/worker.ts"),
        popup: path.join(root, "popup.html"),
        blocked: path.join(root, "blocked.html"),
      },
      output: { entryFileNames: "[name].js", chunkFileNames: "chunks/[name].js" },
    },
  },
});
