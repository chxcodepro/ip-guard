import { chmod } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { z } from "zod";

import {
  extensionVersionSchema,
  ipv4ProbeTimeoutMs,
  isNewerExtensionVersion,
  nativeVersion,
} from "@ip-guard/electron";
import type { BrowserState, ExtensionStatus } from "@ip-guard/electron";

import { browserInstallations } from "#src/main/browser-installation.ts";
import { ClaudeIPv4 } from "#src/main/claude-ip.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

import { posixBrowserSocketPath } from "./posix-platform.ts";

interface BrowserGuardSource {
  snapshot?: import("@ip-guard/electron").Snapshot;
  error: string;
  on(event: "identity", listener: (id: string) => void): unknown;
  on(event: "snapshot", listener: () => void): unknown;
}

const clientSchema = z
  .object({ extensionVersion: z.union([z.literal(""), extensionVersionSchema]) })
  .strict();

export class BrowserBridge {
  private server: Server | undefined;
  private clients = new Map<Socket, string | undefined>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private guardian: BrowserGuardSource;
  private updates: ApplicationUpdates;
  private systemProbe: ClaudeIPv4 | undefined;
  private systemChecking = false;
  constructor(guardian: BrowserGuardSource, updates: ApplicationUpdates) {
    this.guardian = guardian;
    this.updates = updates;
    guardian.on("identity", (sid: string) => this.listen(sid));
    guardian.on("snapshot", () => this.publish());
  }
  private latestVersion() {
    const candidate = this.updates.state.latestVersion;
    return isNewerExtensionVersion(candidate, nativeVersion) ? candidate : nativeVersion;
  }
  private state(): BrowserState {
    const value = this.guardian.snapshot;
    // EXE enhancement can use a separate route; web authorization follows the unmodified system route.
    const result = value ? this.systemProbe?.latest(value.settings.ipv4Url) : undefined;
    const currentIp = result?.ip ?? "";
    const checkedAt = result?.checkedAt ?? "";
    const checking = this.systemChecking;
    const base: BrowserState = {
      protocol: 1,
      appVersion: nativeVersion,
      latestExtensionVersion: this.latestVersion(),
      phase: "offline",
      currentIp,
      expectedIps: value?.settings.expectedIps ?? [],
      checkedAt,
      reason: "请启动 IP Guard",
    };
    if (!value?.online || this.guardian.error) return base;
    if (!value.rulesLocked)
      return { ...base, phase: "unlocked", reason: "请在 IP Guard 中锁定允许的 IPv4" };
    const age = Date.now() - Date.parse(checkedAt);
    if (
      value.settings.expectedIps.includes(currentIp) &&
      currentIp &&
      Number.isFinite(age) &&
      age >= -5000 &&
      age <=
        (value.settings.intervalSeconds + (checking ? ipv4ProbeTimeoutMs / 1000 + 2 : 8)) * 1000
    )
      return {
        ...base,
        phase: "allowed",
        reason: checking ? "正在复核 IPv4，保留本次连接" : "IPv4 命中允许列表",
      };
    return {
      ...base,
      phase: checking && !currentIp ? "checking" : "blocked",
      reason:
        result?.error || (currentIp ? "网页出口 IPv4 未命中允许列表" : "等待网页出口 IPv4 校验"),
    };
  }
  private listen(sid: string) {
    if (this.server) return;
    const server = createServer((socket) => {
      if (this.clients.size >= 16) {
        socket.destroy();
        return;
      }
      this.clients.set(socket, undefined);
      let input = "";
      let received = false;
      socket.setEncoding("utf8");
      socket.on("data", (chunk: string) => {
        input += chunk;
        if (received || Buffer.byteLength(input, "utf8") > 512) {
          socket.destroy();
          return;
        }
        if (!input.includes("\n")) return;
        try {
          const value: unknown = JSON.parse(input);
          this.clients.set(socket, clientSchema.parse(value).extensionVersion);
          received = true;
        } catch {
          socket.destroy();
        }
      });
      socket.on("error", () => socket.destroy());
      socket.on("close", () => this.clients.delete(socket));
      this.send(socket);
    });
    server.on("error", (error) => {
      console.error("浏览器连接服务", error);
      this.close();
    });
    const endpoint =
      process.platform === "win32"
        ? `\\\\.\\pipe\\IPGuard-Browser-${sid}`
        : posixBrowserSocketPath();
    if (process.platform !== "win32")
      server.once("listening", () => void chmod(endpoint, 0o600).catch(() => this.close()));
    server.listen(endpoint);
    this.server = server;
    this.timer = setInterval(() => this.publish(), 1000);
  }
  private send(socket: Socket) {
    if (socket.destroyed) return;
    if (socket.writableLength > 16384) {
      socket.destroy();
      return;
    }
    const state = this.state();
    // Protocol-1 extensions require the matching address to retain their equality check.
    const expectedIp = state.expectedIps.includes(state.currentIp)
      ? state.currentIp
      : (state.expectedIps[0] ?? "");
    socket.write(`${JSON.stringify({ ...state, expectedIp })}\n`);
  }
  private publish() {
    const snapshot = this.guardian.snapshot;
    if (
      snapshot?.online &&
      !this.guardian.error &&
      snapshot.rulesLocked &&
      this.clients.size &&
      !this.systemChecking
    ) {
      const probe = (this.systemProbe ??= new ClaudeIPv4("ip-guard-browser-ipv4"));
      const latest = probe.latest(snapshot.settings.ipv4Url);
      if (
        !latest ||
        Date.now() - Date.parse(latest.checkedAt) >= snapshot.settings.intervalSeconds * 1000
      ) {
        this.systemChecking = true;
        void probe.check(snapshot.settings.ipv4Url).finally(() => {
          if (this.systemProbe === probe) {
            this.systemChecking = false;
            this.publish();
          }
        });
      }
    }
    for (const socket of this.clients.keys()) this.send(socket);
  }
  async status(): Promise<ExtensionStatus> {
    const latestVersion = this.latestVersion();
    const info = await browserInstallations(latestVersion);
    const connections = this.clients.size;
    const outdatedConnections = [...this.clients.values()].filter(
      (version) =>
        version !== undefined &&
        (version === "" || isNewerExtensionVersion(latestVersion, version)),
    ).length;
    return {
      ...info,
      latestVersion,
      outdatedConnections,
      connections,
      phase:
        connections > 0
          ? "running"
          : info.installedBrowsers.length
            ? "installed"
            : info.error
              ? "unknown"
              : "missing",
    };
  }
  close() {
    this.systemProbe?.stop();
    this.systemProbe = undefined;
    this.systemChecking = false;
    clearInterval(this.timer);
    for (const socket of this.clients.keys()) socket.destroy();
    this.clients.clear();
    this.server?.close();
    this.server = undefined;
  }
}
