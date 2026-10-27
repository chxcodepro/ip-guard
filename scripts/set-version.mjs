import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const version = process.argv[2];
if (!version || !/^\d+\.\d+\.\d+$/.test(version))
  throw new Error("Usage: pnpm run version:app 0.8.1");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const contract = path.join(root, "packages/electron/src/index.ts");
const source = readFileSync(contract, "utf8");
const pattern = /export const nativeVersion\s*=\s*"[^"]+";/g;
if ([...source.matchAll(pattern)].length !== 1)
  throw new Error("Expected one nativeVersion declaration.");
const files = [
  "package.json",
  "apps/desktop/package.json",
  "apps/browser-extension/manifest.json",
].map((name) => {
  const filename = path.join(root, name);
  const value = JSON.parse(readFileSync(filename, "utf8"));
  if (!value || typeof value !== "object" || typeof value.version !== "string")
    throw new Error(`Invalid version file: ${name}`);
  return { filename, value: { ...value, version } };
});
for (const { filename, value } of files)
  writeFileSync(filename, JSON.stringify(value, null, 2) + "\n");
writeFileSync(contract, source.replace(pattern, `export const nativeVersion = "${version}";`));
console.log(`IP Guard ${version}`);
