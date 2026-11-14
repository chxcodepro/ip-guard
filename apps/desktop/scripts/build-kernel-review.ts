import { spawnSync } from "node:child_process";
import { mkdirSync, readdirSync } from "node:fs";
import path from "node:path";
import "./build-native.ts";

const desktop = path.resolve(import.meta.dirname, "..");
const output = path.resolve(desktop, "../../artifacts/kernel-integration-review");
mkdirSync(output, { recursive: true });
const sources = readdirSync(path.join(desktop, "native"), { recursive: true, withFileTypes: true }).filter((file) => file.isFile() && file.name.endsWith(".cs")).map((file) => path.join(file.parentPath, file.name));
const entries: { main: string; file: string }[] = [{ main: "KernelReview", file: "IpGuard.Native.exe" }, { main: "ReviewClient", file: "claude.exe" }, { main: "ReviewClient", file: "child.exe" }];
for (const { main, file } of entries) {
  const result = spawnSync(path.join(process.env.WINDIR ?? "C:\\Windows", "Microsoft.NET/Framework64/v4.0.30319/csc.exe"), ["/nologo", "/target:exe", "/platform:x64", `/main:${main}`, `/out:${path.join(output, file)}`, "/reference:System.Web.Extensions.dll", "/reference:Microsoft.CSharp.dll", "/reference:System.Windows.Forms.dll", "/reference:System.Drawing.dll", "/reference:System.Management.dll", path.join(desktop, "dist/native-build-info.g.cs"), ...sources, path.join(desktop, "tests/native/KernelReview.cs")], { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
}
console.log(`Compiled isolated kernel review: ${output}. No driver or test started.`);
