import { spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
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
process.exitCode = result.status ?? 1;
