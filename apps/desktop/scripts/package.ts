import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";

const root = path.resolve(import.meta.dirname, "..");
const repository = process.env.GITHUB_REPOSITORY ?? "";
if (repository && !/^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9_.-]{1,100}$/.test(repository))
  throw new Error("Invalid GITHUB_REPOSITORY");
writeFileSync(path.join(root, "dist/release-info.json"), JSON.stringify({ repository }), "utf8");
const args = ["--config", "electron-builder.yml", "--publish", "never"];
if (repository) {
  const [owner, repo] = repository.split("/");
  args.push(
    "--config.publish.provider=github",
    `--config.publish.owner=${owner}`,
    `--config.publish.repo=${repo}`,
  );
}
const cli = createRequire(import.meta.url).resolve("electron-builder/cli.js");
const result = spawnSync(process.execPath, [cli, ...args], {
  cwd: root,
  stdio: "inherit",
});
if (result.error) throw result.error;
if (result.status === 0) {
  const metadata: unknown = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
  if (
    !metadata ||
    typeof metadata !== "object" ||
    !("version" in metadata) ||
    typeof metadata.version !== "string"
  )
    throw new Error("Invalid package metadata");
  const zip = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-NonInteractive",
      "-Command",
      "$ErrorActionPreference='Stop'; Get-ChildItem -LiteralPath $env:IP_GUARD_EXTENSION_DIR | Compress-Archive -DestinationPath $env:IP_GUARD_EXTENSION_ZIP -Force",
    ],
    {
      env: {
        ...process.env,
        IP_GUARD_EXTENSION_DIR: path.resolve(root, "../browser-extension/dist"),
        IP_GUARD_EXTENSION_ZIP: path.join(
          root,
          "release",
          `IP-Guard-Browser-${metadata.version}.zip`,
        ),
      },
      windowsHide: true,
      stdio: "inherit",
    },
  );
  if (zip.error) throw zip.error;
  if (zip.status !== 0) throw new Error("Browser extension archive failed");
}
process.exitCode = result.status ?? 1;
