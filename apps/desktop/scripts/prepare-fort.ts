import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const desktop = path.resolve(import.meta.dirname, "..");
const root = path.resolve(desktop, "../..");
const cache = path.join(desktop, "dist/fort-cache");
const output = path.join(desktop, "dist/drivers/fort");
await mkdir(cache, { recursive: true });
await mkdir(output, { recursive: true });
async function acquire(name: string, url: string, integrity?: string) {
  const file = path.join(cache, name);
  let data: Buffer;
  try {
    data = await readFile(file);
  } catch (error) {
    if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT") throw error;
    const response = await fetch(url, { signal: AbortSignal.timeout(120000) });
    if (!response.ok) throw new Error(`Fort dependency download failed: ${response.status}`);
    data = Buffer.from(await response.arrayBuffer());
    await writeFile(file, data);
  }
  // Executed extraction tools and kernel packages are pinned security artifacts.
  if (integrity && createHash("sha256").update(data).digest("hex") !== integrity)
    throw new Error(`Fort artifact integrity mismatch: ${name}`);
  return file;
}
const setup = await acquire(
  "FortFirewall-3.20.9-x64.exe",
  "https://github.com/tnodir/fort/releases/download/v3.20.9/FortFirewall-3.20.9-windows10-x86_64.exe",
  "a879611d0426900f5398b8665a385a02fa0cc465a8163f3d6cac91ad05378215",
);
const tool = await acquire(
  "innounp-2.zip",
  "https://raw.githubusercontent.com/jrathlev/InnoUnpacker-Windows-GUI/75ded58da3a81c029db4f73ab803b9b4154400e9/innounp-2/bin/innounp-2.zip",
  "f8e45c9676bebc7d7570108ab572673b541fcf7a7d3d24a04319ac6b5315b4e8",
);
const tools = path.join(cache, "tools");
const extracted = path.join(cache, "extracted");
const expanded = spawnSync(
  "powershell.exe",
  ["-NoProfile", "-NonInteractive", "-Command", "Expand-Archive -LiteralPath $env:FORT_ARCHIVE -DestinationPath $env:FORT_TOOLS -Force"],
  { windowsHide: true, stdio: "inherit", env: { ...process.env, FORT_ARCHIVE: tool, FORT_TOOLS: tools } },
);
if (expanded.error) throw expanded.error;
if (expanded.status !== 0) throw new Error("Fort extraction helper expansion failed");
const extraction = spawnSync(
  path.join(tools, "innounp.exe"),
  ["-x", "-b", `-d${extracted}`, setup, "{app}\\driver\\x86_64\\fortfw.sys"],
  { windowsHide: true, stdio: "inherit" },
);
if (extraction.error) throw extraction.error;
if (extraction.status !== 0) throw new Error("Fort driver offline extraction failed");
const driver = await readFile(path.join(extracted, "{app}/driver/x86_64/fortfw.sys"));
if (createHash("sha256").update(driver).digest("hex") !== "58681fa853a92b15df5cd53cc96c93bebf3c8769cb5851a2ceaebcf70766dd6b")
  throw new Error("Fort driver does not match the reviewed signed image");
await writeFile(path.join(output, "fortfw.sys"), driver);
const source = await acquire("Fort-3.20.9-source.zip", "https://github.com/tnodir/fort/archive/refs/tags/v3.20.9.zip");
await copyFile(source, path.join(output, "Fort-3.20.9-source.zip"));
await copyFile(path.join(root, "LICENSE"), path.join(output, "COPYING.GPL-3.0.txt"));
await writeFile(path.join(output, "NOTICE.txt"), "Fort Firewall 3.20.9 / driver ABI 65\nCopyright Nodir Temirkhodjaev and contributors. GPL-3.0.\nOriginal, unmodified x64 driver; Microsoft Windows Hardware Compatibility Publisher signature.\nCorresponding source and build files: Fort-3.20.9-source.zip\nUpstream: https://github.com/tnodir/fort/tree/v3.20.9\n\nThis installer places files only. Driver installation and activation require explicit confirmation in IP Guard.\n");
console.log("Prepared original Fort driver and corresponding GPL source; no installer or driver was run.");
