import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import path from "node:path";

import "./build-native.ts";

const desktop = path.resolve(import.meta.dirname, "..");
const root = path.resolve(desktop, "../..");
const prototype = path.join(desktop, "experiments/process-network");
const output = path.join(root, "artifacts/process-network-prototype");
mkdirSync(output, { recursive: true });
const sources = [path.join(desktop, "native"), prototype].flatMap((folder) =>
  readdirSync(folder, { recursive: true, withFileTypes: true })
    .filter((file) => file.isFile() && file.name.endsWith(".cs"))
    .map((file) => path.join(file.parentPath, file.name)),
);
for (const entry of [
  { main: "OfflineReview", file: "IpGuard.ProcessNetwork.Review.exe" },
  { main: "RecoveryProgram", file: "IpGuard.ProcessNetwork.Recovery.exe" },
]) {
  const executable = path.join(output, entry.file);
  const result = spawnSync(
    path.join(process.env.WINDIR ?? "C:\\Windows", "Microsoft.NET/Framework64/v4.0.30319/csc.exe"),
    [
      "/nologo",
      "/target:exe",
      `/main:IpGuard.ProcessNetwork.${entry.main}`,
      "/platform:x64",
      "/optimize+",
      "/utf8output",
      "/reference:System.Web.Extensions.dll",
      "/reference:Microsoft.CSharp.dll",
      "/reference:System.Windows.Forms.dll",
      "/reference:System.Drawing.dll",
      "/reference:System.Management.dll",
      `/out:${executable}`,
      path.join(desktop, "dist/native-build-info.g.cs"),
      ...sources,
    ],
    { stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
  console.log(`Compiled offline prototype: ${executable}`);
}
console.log("No executable, driver, or self-check was started.");
