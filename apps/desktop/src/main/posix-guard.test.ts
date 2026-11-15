import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
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

vi.mock("electron", () => ({ app: { getPath: () => "/unused-ci-metadata" } }));

class Probe extends EventEmitter<{ progress: [ProbeProgress] }> {
  ip = "8.8.8.8";
  async check() {
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
    } finally {
      guard.stop();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
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
