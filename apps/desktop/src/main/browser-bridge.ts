import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { nativeVersion } from "@ip-guard/electron";
import type { BrowserState } from "@ip-guard/electron";

import type { Guardian } from "#src/main/guardian.ts";

export class BrowserBridge {
  private server: Server | undefined;
  private clients = new Set<Socket>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private guardian: Guardian;
  constructor(guardian: Guardian) {
    this.guardian = guardian;
    guardian.on("identity", (sid: string) => this.listen(sid));
    guardian.on("snapshot", () => this.publish());
  }
  private state(): BrowserState {
    const value = this.guardian.snapshot;
    const base: BrowserState = {
      protocol: 1,
      appVersion: nativeVersion,
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
      this.clients.add(socket);
      socket.on("data", () => socket.destroy());
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
    for (const socket of this.clients) this.send(socket);
  }
  close() {
    clearInterval(this.timer);
    for (const socket of this.clients) socket.destroy();
    this.clients.clear();
    this.server?.close();
    this.server = undefined;
  }
}
