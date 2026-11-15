import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import { createConnection } from "node:net";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { networkPolicySchema } from "@ip-guard/electron";

import { sessionArguments } from "../posix/settings.ts";
import type { ProbeProgress } from "./claude-ip.ts";
import { NetworkPolicies } from "./network-policies.ts";
import { PosixGuard } from "./posix-guard.ts";
import { preparePosixBroker } from "./posix-launch.ts";
import { shellArgument } from "./posix-platform.ts";

vi.mock("electron", () => ({ app: { getPath: () => "/unused-ci-metadata" } }));

class Probe extends EventEmitter<{ progress: [ProbeProgress] }> {
  ip = "8.8.8.8";
  route = "system";
  invalidate() {}
  async useFixedProxy(address: string) {
    this.route = address;
  }
  async useSystemProxy() {
    this.route = "system";
  }
  async check(_source: string) {
    return {
      ip: this.ip,
      error: "",
      checkedAt: new Date().toISOString(),
      adapter: "isolated fixture",
    };
  }
  stop() {}
}
describe.runIf(process.platform !== "win32")("POSIX managed sessions", () => {
  let folder = "",
    guard: PosixGuard | undefined;
  beforeEach(async () => {
    guard = undefined;
    folder = await mkdtemp(path.join(os.tmpdir(), "ipguard-ci-"));
    vi.stubEnv("HOME", folder);
    vi.stubEnv("XDG_CONFIG_HOME", folder);
  });
  afterEach(async () => {
    guard?.stop();
    vi.unstubAllEnvs();
    await rm(folder, { recursive: true, force: true });
  });
  it("keeps a managed session, closes its proxy after a mismatching IP, then restores it", async () => {
    const probe = new Probe(),
      policies = new NetworkPolicies();
    guard = new PosixGuard(probe, policies, async () => "DIRECT");
    await guard.initialize();
    const executable = path.join(folder, "claude");
    await writeFile(executable, "#!/bin/sh\nexit 0\n");
    await chmod(executable, 0o700);
    const id = randomUUID();
    await guard.add({
      id,
      name: "fixture",
      path: executable,
      arguments: "",
      apiScope: "claude",
      enhanced: false,
      enabled: false,
    });
    await guard.lock({
      expectedIps: ["8.8.8.8"],
      intervalSeconds: 60,
      ipv4Url: "https://claude.ai/cdn-cgi/trace",
    });
    await guard.protect(id, true);
    const server = createServer((_request, response) => response.end("local-preview"));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Fixture not bound");
    policies.commit({
      revision: randomUUID(),
      settings: networkPolicySchema.parse({
        rules: [
          {
            id: randomUUID(),
            enabled: true,
            host: "localhost",
            port: address.port,
            action: "direct",
          },
        ],
      }),
    });
    let stopped = false;
    const session = await guard.createSession(id, () => {
      stopped = true;
    });
    if (session.scope !== "guarded") throw new Error("Claude fixture must receive a guarded proxy");
    const port = Number(new URL(session.proxy).port);
    const exchange = () =>
      new Promise<string>((resolve, reject) => {
        const socket = createConnection({ host: "127.0.0.1", port });
        let text = "";
        socket.once("connect", () =>
          socket.write(
            `GET http://localhost:${address.port}/ HTTP/1.1\r\nHost: localhost:${address.port}\r\n\r\n`,
          ),
        );
        socket.on("data", (data) => (text += data.toString()));
        socket.on("error", reject);
        socket.once("close", () => resolve(text));
      });
    try {
      expect(await exchange()).toContain("local-preview");
      await guard.setProxy({ mode: "manual", address: "http://127.0.0.1:10808" });
      expect(probe.route).toBe("http://127.0.0.1:10808");
      await guard.setProxy({ mode: "system" });
      expect(probe.route).toBe("system");
      probe.ip = "1.1.1.1";
      await guard.check();
      expect(guard.snapshot.ready).toBe(false);
      expect(guard.snapshot.running).toContain(id);
      expect(stopped).toBe(false);
      const denied = await exchange().catch((error) => {
        if (error && typeof error === "object" && Reflect.get(error, "code") === "ECONNRESET")
          return "";
        throw error;
      });
      expect(denied).toBe("");
      probe.ip = "8.8.8.8";
      await guard.check();
      expect(await exchange()).toContain("local-preview");
      session.release();
      expect(guard.snapshot.running).toEqual([]);
      await guard.setScope(id, "auto");
      await guard.unlock();
      const other = await guard.createSession(id, () => {}, "other");
      expect(other.scope).toBe("other");
      expect(guard.snapshot.otherModelRunning).toContain(id);
      await expect(guard.createSession(id, () => {}, "unknown")).rejects.toThrow();
      other.release();
    } finally {
      guard.stop();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
  it("discards a previous-source reply while locking a different IPv4 API", async () => {
    class DelayedProbe extends Probe {
      release: (() => void) | undefined;
      override invalidate() {
        this.release?.();
        this.release = undefined;
      }
      override check(source: string) {
        const value = {
          ip: source.includes("ipify") ? "1.1.1.1" : "8.8.8.8",
          error: "",
          checkedAt: new Date().toISOString(),
          adapter: "fixture",
        };
        if (source.includes("ipify")) return Promise.resolve(value);
        return new Promise<typeof value>((resolve) => {
          this.release = () => resolve(value);
        });
      }
    }
    const probe = new DelayedProbe();
    guard = new PosixGuard(probe, new NetworkPolicies(), async () => "DIRECT");
    await guard.initialize();
    await guard.lock({
      expectedIps: ["8.8.8.8"],
      intervalSeconds: 60,
      ipv4Url: "https://api.ipify.org/?format=json",
    });
    expect(guard.snapshot.settings.ipv4Url).toContain("ipify");
    expect(guard.snapshot.currentIp).toBe("1.1.1.1");
    expect(guard.snapshot.ready).toBe(false);
  });
  it.each([false, true])(
    "launches the real broker and client and cleans up its child (PTY=%s)",
    async (pty) => {
      const probe = new Probe(),
        policies = new NetworkPolicies();
      guard = new PosixGuard(probe, policies, async () => "DIRECT");
      await guard.initialize();
      const marker = path.join(folder, "child-state"),
        executable = path.join(folder, "claude");
      await writeFile(
        executable,
        `#!/bin/sh\nprintf '%s\\n%s\\n' "$$" "$HTTPS_PROXY" > "$1"\nwhile :; do sleep 1; done\n`,
      );
      await chmod(executable, 0o700);
      const id = randomUUID();
      await guard.add({
        id,
        name: "controlled fixture",
        path: executable,
        arguments: shellArgument(marker),
        apiScope: "claude",
        enhanced: false,
        enabled: false,
      });
      await guard.lock({
        expectedIps: ["8.8.8.8"],
        intervalSeconds: 60,
        ipv4Url: "https://claude.ai/cdn-cgi/trace",
      });
      await guard.protect(id, true);
      const client = path.resolve("apps/desktop/dist/posix/client.cjs"),
        endpoint = path.join(folder, "control.sock");
      const broker = await preparePosixBroker(guard, process.execPath, client, endpoint);
      const launchArgs = [client, endpoint, id, "--"];
      const executableCommand = pty ? "/usr/bin/script" : process.execPath;
      const commandArgs = pty
        ? process.platform === "darwin"
          ? ["-q", "/dev/null", process.execPath, ...launchArgs]
          : [
              "-q",
              "-e",
              "-c",
              [process.execPath, ...launchArgs].map(shellArgument).join(" "),
              "/dev/null",
            ]
        : launchArgs;
      const helper = spawn(executableCommand, commandArgs, {
        cwd: folder,
        stdio: ["ignore", "ignore", "pipe"],
      });
      let error = "";
      helper.stderr.on("data", (chunk) => (error += chunk.toString()));
      const ended = once(helper, "exit");
      void ended.catch(() => undefined);
      try {
        let state = "";
        for (let i = 0; i < 150 && helper.exitCode === null; i++) {
          try {
            state = await readFile(marker, "utf8");
            break;
          } catch (cause) {
            if (!cause || typeof cause !== "object" || Reflect.get(cause, "code") !== "ENOENT")
              throw cause;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        expect(state, error).toContain("http://127.0.0.1:");
        const pid = Number(state.split("\n")[0]);
        expect(pid).toBeGreaterThan(0);
        probe.ip = "1.1.1.1";
        await guard.check();
        expect(process.kill(pid, 0)).toBe(true);
        expect(helper.exitCode).toBeNull();
        guard.stopSessions();
        await Promise.race([
          ended,
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Owned session did not stop")), 5000),
          ),
        ]);
        for (let i = 0; i < 100; i++) {
          try {
            process.kill(pid, 0);
          } catch {
            break;
          }
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
        expect(() => process.kill(pid, 0)).toThrow();
        expect(guard.snapshot.running).toEqual([]);
      } finally {
        guard.stop();
        if (helper.exitCode === null) helper.kill();
        await new Promise<void>((resolve) => broker.close(() => resolve()));
      }
    },
    15000,
  );
  it("merges CLI settings in a private file and leaves the source unchanged", async () => {
    const original = path.join(folder, "original.json");
    const text = JSON.stringify({
      model: "deepseek-chat",
      env: { ANTHROPIC_BASE_URL: "https://api.deepseek.com", HTTPS_PROXY: "http://old.invalid:1" },
    });
    await writeFile(original, text);
    const prepared = await sessionArguments(
      ["--settings", original, "--verbose"],
      folder,
      { HTTP_PROXY: "http://127.0.0.1:12345", HTTPS_PROXY: "http://127.0.0.1:12345" },
      true,
    );
    const { readFile, stat } = await import("node:fs/promises");
    const file = prepared.args.at(-1);
    if (!file) throw new Error("Session file missing");
    try {
      const value: unknown = JSON.parse(await readFile(file, "utf8"));
      expect(value).toMatchObject({
        model: "deepseek-chat",
        env: {
          ANTHROPIC_BASE_URL: "https://api.deepseek.com",
          HTTPS_PROXY: "http://127.0.0.1:12345",
        },
      });
      expect(await readFile(original, "utf8")).toBe(text);
      expect((await stat(file)).mode & 0o777).toBe(0o600);
    } finally {
      await prepared.cleanup();
    }
  });
});
