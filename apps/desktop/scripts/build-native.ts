import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import {
  browserExtensionId,
  claudeIpv4Endpoint,
  nativeProtocol,
  nativeVersion,
} from "@ip-guard/electron";

if (process.platform !== "win32") throw new Error("Native guardian requires Windows.");
const root = path.resolve(import.meta.dirname, "..");
const metadata: unknown = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
if (!metadata || typeof metadata !== "object" || Reflect.get(metadata, "version") !== nativeVersion)
  throw new Error("Desktop and native component versions must match.");
const output = path.join(root, "dist/native", nativeVersion);
mkdirSync(output, { recursive: true });
const buildInfo = path.join(root, "dist/native-build-info.g.cs");
writeFileSync(
  buildInfo,
  `using System.Reflection;
[assembly: AssemblyVersion("${nativeVersion}.0")]
[assembly: AssemblyFileVersion("${nativeVersion}.0")]
namespace IpGuard { public static class BuildInfo {
 public const string Version = ${JSON.stringify(nativeVersion)};
 public const string ExtensionId = ${JSON.stringify(browserExtensionId)};
 public const int Protocol = ${nativeProtocol};
 public const string Endpoint = ${JSON.stringify(claudeIpv4Endpoint)};
} }`,
  "utf8",
);
writeFileSync(
  path.join(root, "dist/recover.cmd"),
  readFileSync(path.join(root, "scripts/recover.cmd"), "utf8").replaceAll(
    "@NATIVE_VERSION@",
    nativeVersion,
  ),
);
const compiler = path.join(
  process.env.WINDIR ?? "C:\\Windows",
  "Microsoft.NET/Framework64/v4.0.30319/csc.exe",
);
const sources = readdirSync(path.join(root, "native"))
  .filter((file) => file.endsWith(".cs"))
  .map((file) => path.join(root, "native", file));
for (const entry of [
  { target: "winexe", main: "Program", file: "IpGuard.Native.exe" },
  { target: "exe", main: "TerminalProgram", file: "IpGuard.Terminal.exe" },
]) {
  const result = spawnSync(
    compiler,
    [
      "/nologo",
      `/target:${entry.target}`,
      `/main:IpGuard.${entry.main}`,
      "/platform:x64",
      "/optimize+",
      "/utf8output",
      "/reference:System.Web.Extensions.dll",
      "/reference:Microsoft.CSharp.dll",
      "/reference:System.Windows.Forms.dll",
      "/reference:System.Drawing.dll",
      `/out:${path.join(output, entry.file)}`,
      buildInfo,
      ...sources,
    ],
    { stdio: "inherit" },
  );
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
