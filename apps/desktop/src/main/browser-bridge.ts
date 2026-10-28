import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { z } from "zod";

import { extensionVersionSchema, isNewerExtensionVersion, nativeVersion } from "@ip-guard/electron";
import type { BrowserState, ExtensionStatus } from "@ip-guard/electron";

import { browserInstallations } from "#src/main/browser-installation.ts";
import type { Guardian } from "#src/main/guardian.ts";
import type { ApplicationUpdates } from "#src/main/updates.ts";

const clientSchema = z
  .object({ extensionVersion: z.union([z.literal(""), extensionVersionSchema]) })
  .strict();

export class BrowserBridge {
  private server: Server | undefined;
  private clients = new Map<Socket, string | undefined>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private guardian: Guardian;
  private updates: ApplicationUpdates;
  constructor(guardian: Guardian, updates: ApplicationUpdates) {
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
    const base: BrowserState = {
      protocol: 1,
      appVersion: nativeVersion,
      latestExtensionVersion: this.latestVersion(),
      phase: "offline",
      currentIp: value?.currentIp ?? "",
      expectedIp: value?.settings.expectedIp ?? "",
      checkedAt: value?.lastChecked ?? "",
      reason: "请启动 IP Guard",
    };
    if (!value?.online || this.guardian.error) return base;
    if (!value.rulesLocked)
      return { ...base, phase: "unlocked", reason: "请在 IP Guard 中锁定允许的 IPv4" };
    const age = Date.now() - Date.parse(value.lastChecked);
    if (
      value.ready &&
      value.currentIp === value.settings.expectedIp &&
      value.currentIp &&
      Number.isFinite(age) &&
      age >= -5000 &&
      age <= (value.settings.intervalSeconds + 8) * 1000
    )
      return { ...base, phase: "allowed", reason: "IPv4 与锁定地址匹配" };
    return {
      ...base,
      phase: value.checking && !value.currentIp ? "checking" : "blocked",
      reason: value.reason || "等待新的 IPv4 校验结果",
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
    server.listen(`\\\\.\\pipe\\IPGuard-Browser-${sid}`);
    this.server = server;
    this.timer = setInterval(() => this.publish(), 1000);
  }
  private send(socket: Socket) {
    if (socket.destroyed) return;
    if (socket.writableLength > 16384) {
      socket.destroy();
      return;
    }
    socket.write(`${JSON.stringify(this.state())}\n`);
  }
  private publish() {
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
    clearInterval(this.timer);
    for (const socket of this.clients.keys()) socket.destroy();
    this.clients.clear();
    this.server?.close();
    this.server = undefined;
  }
}
