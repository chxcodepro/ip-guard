import { ChildProcess } from "node:child_process";
import type { ExecFileOptions } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { PassThrough } from "node:stream";

import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

import { NetworkPolicies } from "./network-policies.ts";
import { ProxyEnhancement } from "./proxy-enhancement.ts";

const external = vi.hoisted(() => ({
  execute: vi.fn(),
  spawn: vi.fn(),
  resolveProxy: vi.fn(),
  fetch: vi.fn(),
}));
// The Windows discovery command, native core process and Electron transport are external.
// Route ownership, source/config retention, proof expiry and connection permission use the real stack.
vi.mock("node:child_process", async (original) => {
  const actual = await original<typeof import("node:child_process")>();
  const { promisify } = await import("node:util");
  return {
    ...actual,
    execFile: Object.assign(vi.fn(), { [promisify.custom]: external.execute }),
    spawn: external.spawn,
  };
});
vi.mock("electron", () => ({
  app: { isPackaged: false },
  session: {
    fromPartition: () => ({
      forceReloadProxyConfig: async () => undefined,
      resolveProxy: external.resolveProxy,
      setProxy: async () => undefined,
      closeAllConnections: async () => undefined,
      fetch: external.fetch,
    }),
  },
}));

describe.runIf(process.platform === "win32")("dedicated proxy source refresh", () => {
  let folder: string;
  let config: string;
  let route: ProxyEnhancement;
  let server: Server | undefined;
  let child: ChildProcess | undefined;
  const changed = vi.fn();
  const diagnostic = vi.fn();
  beforeEach(async () => {
    folder = await mkdtemp(path.join(os.tmpdir(), "ip-guard-source-"));
    vi.stubEnv("LOCALAPPDATA", folder);
    const executable = path.join(folder, "xray.exe");
    config = path.join(folder, "config.json");
    await writeFile(executable, "isolated-native-core-fixture");
    await writeFile(
      config,
      JSON.stringify({
        outbounds: [
          {
            protocol: "vless",
            settings: {
              vnext: [{ address: "proxy.example", port: 443, users: [{ id: "fixture" }] }],
            },
          },
        ],
      }),
    );
    external.resolveProxy.mockResolvedValue("PROXY 127.0.0.1:7784");
    external.execute.mockImplementation(
      async (_file: string, _args: string[], options: ExecFileOptions) => ({
        stdout: JSON.stringify(
          options.env?.IPGUARD_EXPECTED_IMAGE
            ? { executable: options.env.IPGUARD_EXPECTED_IMAGE, pid: 100 }
            : { executable, config, pid: 200 },
        ),
        stderr: "",
      }),
    );
    external.spawn.mockImplementation(() => {
      const input = new PassThrough();
      const owned = Object.assign(new ChildProcess(), { pid: 100, stdin: input });
      child = owned;
      input.once("data", (data: Buffer) => {
        const value: unknown = JSON.parse(data.toString());
        if (!value || typeof value !== "object") throw new Error("Missing core configuration");
        const inbounds: unknown = Reflect.get(value, "inbounds");
        const inbound: unknown = Array.isArray(inbounds) ? inbounds[0] : undefined;
        const port: unknown =
          inbound && typeof inbound === "object" ? Reflect.get(inbound, "port") : undefined;
        if (typeof port !== "number") throw new Error("Missing dedicated port");
        server = createServer((socket) => socket.end());
        server.listen(port, "127.0.0.1");
      });
      input.once("finish", () => {
        Object.defineProperty(owned, "exitCode", { value: 0, configurable: true });
        owned.emit("exit", 0, null);
      });
      return owned;
    });
    external.fetch.mockImplementation(
      async () => new Response("当前 IP：8.8.8.8 来自于：测试地区"),
    );
    const policies = new NetworkPolicies();
    policies.observeKernel(policies.record.revision);
    route = new ProxyEnhancement(policies);
    route.onDiagnostic = diagnostic;
    route.approve();
    await route.setNeeded(true);
    await route.exit.check(["8.8.8.8"], "http://127.0.0.1:4693", true);
    route.setAllowed(true);
    route.onChange = changed;
    vi.spyOn(performance, "now").mockReturnValue(performance.now() + 11000);
  });
  afterEach(async () => {
    await route.stop();
    if (server) await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
    child = undefined;
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    vi.clearAllMocks();
    if (
      path.dirname(folder) !== os.tmpdir() ||
      !path.basename(folder).startsWith("ip-guard-source-")
    )
      throw new Error("Unexpected fixture cleanup directory");
    await rm(folder, { recursive: true, force: true });
  });
  it("retains the owned route on a discovery timeout without requesting a base-network recheck", async () => {
    const endpoint = route.state.endpoint,
      checkedAt = route.exit.state.checkedAt;
    external.execute.mockRejectedValue({ killed: true });
    await route.refresh();
    expect(route.routeActive).toBe(true);
    expect(route.sourceReady).toBe(false);
    expect(route.state.endpoint).toBe(endpoint);
    expect(route.exit.state.checkedAt).toBe(checkedAt);
    expect(route.forwardingAllowed).toBe(true);
    expect(changed).not.toHaveBeenCalled();
    expect(external.spawn).toHaveBeenCalledTimes(1);
    await route.refresh();
    expect(diagnostic).toHaveBeenCalledTimes(1);
  });
  it.each(["config", "entry", "listener"])(
    "revokes rather than retaining when %s changes or is explicitly unavailable",
    async (change) => {
      external.execute.mockRejectedValue(
        change === "listener"
          ? { stderr: "IPGUARD_DISCOVERY: Proxy listener is unavailable" }
          : { killed: true },
      );
      if (change === "config") await writeFile(config, "changed-config");
      if (change === "entry") external.resolveProxy.mockResolvedValue("PROXY 127.0.0.1:7785");
      await route.refresh();
      expect(route.routeActive).toBe(false);
      expect(route.forwardingAllowed).toBe(false);
      expect(route.exit.ready).toBe(false);
      expect(changed).toHaveBeenCalledTimes(1);
    },
  );
  it("records the native core exit code once and revokes the connection gate immediately", () => {
    if (!child) throw new Error("Missing native core fixture");
    Object.defineProperty(child, "exitCode", { value: 7, configurable: true });
    child.emit("exit", 7, null);
    child.emit("exit", 7, null);
    expect(route.routeActive).toBe(false);
    expect(route.forwardingAllowed).toBe(false);
    expect(diagnostic).toHaveBeenCalledTimes(1);
    expect(diagnostic.mock.calls[0]?.[1]).toContain("exit=0x7");
  });
  it("retains the eventual exit code after a pipe failure without repeating the topology change", () => {
    if (!child?.stdin) throw new Error("Missing native core fixture");
    child.stdin.emit("error", Object.assign(new Error("closed"), { code: "EPIPE" }));
    expect(route.forwardingAllowed).toBe(false);
    Object.defineProperty(child, "exitCode", { value: 9, configurable: true });
    child.emit("exit", 9, null);
    expect(changed).toHaveBeenCalledTimes(1);
    expect(diagnostic.mock.calls.map((call) => call[1])).toEqual([
      "专用核心输入通道中断（EPIPE）",
      "专用核心退出（exit=0x9，signal=none）",
    ]);
  });
});
