import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { once } from "node:events";
import { mkdir, readFile } from "node:fs/promises";
import path from "node:path";

assert.equal(process.env.GITHUB_ACTIONS, "true");
assert.equal(process.env.RUNNER_ENVIRONMENT, "github-hosted");
assert(process.env.RUNNER_TEMP);
const root = path.resolve(import.meta.dirname, "../../.."),
  version = JSON.parse(
    await readFile(path.join(root, "apps/desktop/package.json"), "utf8"),
  ).version;
const packaged = path.join(root, "apps/desktop/release/win-unpacked");
const native = path.join(packaged, "resources/native", version, "IpGuard.Native.exe");
const component = JSON.parse(
  execFileSync(native, ["version"], { encoding: "utf8", windowsHide: true }),
);
assert.equal(component.version, version);
const home = path.join(process.env.RUNNER_TEMP, "ipguard-release-smoke"),
  local = path.join(home, "local"),
  roaming = path.join(home, "roaming");
await mkdir(local, { recursive: true });
await mkdir(roaming, { recursive: true });
const child = spawn(path.join(packaged, "IP Guard.exe"), ["--windows-smoke"], {
  cwd: root,
  env: { ...process.env, LOCALAPPDATA: local, APPDATA: roaming },
  windowsHide: true,
  stdio: ["ignore", "pipe", "pipe"],
});
let output = "";
child.stdout.on("data", (data) => (output += data.toString()));
child.stderr.on("data", (data) => (output += data.toString()));
const timer = setTimeout(() => child.kill(), 60000);
try {
  const [code] = await once(child, "exit");
  assert.equal(code, 0, output);
  const result = JSON.parse(
    await readFile(path.join(root, "artifacts/windows-release-smoke/windows.json"), "utf8"),
  );
  assert.equal(result.nativeVersion, version);
  assert.equal(result.online, true);
  console.log("PASS packaged Windows renderer and native handshake " + version);
} finally {
  clearTimeout(timer);
  if (child.exitCode === null) child.kill();
}
