import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";

import { z } from "zod";

import {
  appSchema,
  initialCommandProtection,
  ipv4IntervalSeconds,
  claudeIpv4Endpoint,
  nativeVersion,
  snapshotSchema,
  settingsSchema,
  proxySettingsSchema,
} from "@ip-guard/electron";
import type { ProtectedApp, Settings, Snapshot, ProxySettings } from "@ip-guard/electron";

import type { ClaudeIPv4Result, ProbeProgress } from "./claude-ip.ts";
import { acceptHttpProxy, ProxyRequestError } from "./http-proxy.ts";
import type { NetworkPolicies } from "./network-policies.ts";
import { launcherPath } from "./posix-launch.ts";
import {
  argumentWords,
  executablePath,
  isPosixCli,
  posixDataDirectory,
  readOptionalJson,
  writePrivate,
} from "./posix-platform.ts";
import { openDirect, systemProxyEndpoint } from "./proxy-tunnel.ts";

const configurationSchema = z.object({
  locked: z.boolean(),
  settings: snapshotSchema.shape.settings,
  apps: z.array(appSchema).max(64),
  adapterId: z.string(),
  autostart: z.boolean(),
  proxy: proxySettingsSchema,
});
const file = () => path.join(posixDataDirectory(), "settings.json");
type SessionRecord = {
  appId: string;
  guarded: boolean;
  close: () => void;
  server: Server;
  sockets: Set<Socket>;
};
interface PosixProbe {
  on(event: "progress", listener: (value: ProbeProgress) => void): unknown;
  check(source: string): Promise<Pick<ClaudeIPv4Result, "ip" | "error" | "checkedAt" | "adapter">>;
  stop(): void;
  invalidate(): void;
  useFixedProxy(address: string): Promise<void>;
  useSystemProxy(): Promise<void>;
}
export class PosixGuard extends EventEmitter<{ snapshot: [Snapshot]; identity: [string] }> {
  readonly platform = process.platform === "darwin" ? "darwin" : "linux";
  error = "";
  private data: z.infer<typeof configurationSchema> = {
    locked: false,
    settings: {
      expectedIps: [],
      intervalSeconds: ipv4IntervalSeconds,
      ipv4Url: claudeIpv4Endpoint,
    },
    apps: [],
    adapterId: "",
    autostart: false,
    proxy: { mode: "system" },
  };
  private checking: Promise<Snapshot> | undefined;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private monitor: ReturnType<typeof setInterval> | undefined;
  private network = "";
  private epoch = 0;
  private sessions = new Map<string, SessionRecord>();
  readonly snapshot: Snapshot = {
    platform: this.platform,
    networkPolicy: { revision: randomUUID(), localPorts: [] },
    enhancementReady: false,
    enhancementReason: "系统级进程树过滤正在移植",
    enhancementPhase: "idle",
    driver: {
      ...initialCommandProtection,
      version: "POSIX 开发版",
      error: "系统级进程树过滤尚未接入",
    },
    commandBlockId: "",
    commandBlockReason: "",
    commandBlockAppId: "",
    egress: null,
    online: true,
    admin: false,
    ready: false,
    checking: false,
    probe: { round: 0, attempt: 0, phase: "idle" },
    networkIssue: "idle",
    nativeVersion,
    ipSource: claudeIpv4Endpoint,
    currentIp: "",
    adapter: "",
    lastChecked: "",
    reason: "请锁定允许的 IPv4",
    detection: "受管代理基础防护",
    running: [],
    otherModelRunning: [],
    autostart: false,
    startup: { enabled: false, state: "off", message: "" },
    rulesLocked: false,
    networkAdapters: [],
    watchedAdapter: { id: "", name: "自动识别", exists: false, up: false, ipv4: false, error: "" },
    networkAdapterId: "",
    settings: {
      expectedIps: [],
      intervalSeconds: ipv4IntervalSeconds,
      ipv4Url: claudeIpv4Endpoint,
    },
    apps: [],
    logs: [],
  };
  private readonly probe: PosixProbe;
  private readonly policies: NetworkPolicies;
  private readonly resolveProxy: (url: string) => Promise<string>;
  constructor(
    probe: PosixProbe,
    policies: NetworkPolicies,
    resolveProxy: (url: string) => Promise<string>,
  ) {
    super();
    this.probe = probe;
    this.policies = policies;
    this.resolveProxy = resolveProxy;
    probe.on("progress", (progress) => {
      if (progress.sourceUrl !== this.data.settings.ipv4Url) return;
      if (progress.step === "attempt") this.snapshot.probe.attempt = progress.attempt;
      if (progress.step === "reconnect") this.pause("正在重试 IPv4 校验");
      this.publish();
    });
  }
  get settings() {
    return this.data.settings;
  }
  get proxy() {
    return this.data.proxy;
  }
  get sessionCount() {
    return this.sessions.size;
  }
  private publish() {
    this.snapshot.rulesLocked = this.data.locked;
    this.snapshot.settings = this.data.settings;
    this.snapshot.ipSource = this.data.settings.ipv4Url;
    this.snapshot.apps = this.data.apps.map((target) => ({
      ...target,
      pathIssue: "",
      isClaudeCode: isPosixCli(target.path),
      launcherPath: launcherPath(target.id),
    }));
    this.snapshot.running = [
      ...new Set([...this.sessions.values()].filter((s) => s.guarded).map((s) => s.appId)),
    ];
    this.snapshot.otherModelRunning = [
      ...new Set([...this.sessions.values()].filter((s) => !s.guarded).map((s) => s.appId)),
    ];
    this.snapshot.networkPolicy = this.policies.kernelPolicy;
    this.policies.observeKernel(this.policies.record.revision);
    this.snapshot.autostart = this.data.autostart;
    this.snapshot.networkAdapterId = this.data.adapterId;
    this.emit("snapshot", this.snapshot);
  }
  private log(message: string, level: "info" | "warning" | "error" = "info") {
    this.snapshot.logs.unshift({ time: new Date().toISOString(), level, message });
    this.snapshot.logs.length = Math.min(this.snapshot.logs.length, 200);
  }
  private async save(next: z.infer<typeof configurationSchema>) {
    if (this.error) throw new Error(this.error);
    await writePrivate(file(), JSON.stringify(configurationSchema.parse(next)));
    this.data = next;
    this.publish();
  }
  async initialize() {
    try {
      const saved = await readOptionalJson(file());
      if (saved !== undefined) this.data = configurationSchema.parse(saved);
    } catch {
      this.error = "配置读取失败，原文件保留。请备份并修复 settings.json 后重启。";
      this.snapshot.reason = this.error;
    }
    try {
      await this.observeNetwork();
    } catch (error) {
      this.pause(error instanceof Error ? error.message : "网络检测失败");
    }
    this.publish();
    this.emit("identity", String(process.getuid?.()));
    if (!this.error) {
      await this.selectProbeRoute();
      void this.check();
    }
    this.monitor = setInterval(
      () =>
        void this.observeNetwork().catch((error) => {
          this.pause(error instanceof Error ? error.message : "网络检测失败");
          this.publish();
        }),
      2000,
    );
  }
  private async observeNetwork() {
    const interfaces = networkInterfaces();
    this.snapshot.networkAdapters = Object.entries(interfaces)
      .filter(([, addresses]) => addresses?.some((a) => !a.internal))
      .map(([name, addresses]) => ({
        id: name,
        name,
        exists: true,
        up: Boolean(addresses?.length),
        ipv4: Boolean(addresses?.some((a) => a.family === "IPv4")),
        error: "",
      }));
    this.snapshot.watchedAdapter = this.snapshot.networkAdapters.find((n) =>
      this.data.adapterId ? n.id === this.data.adapterId : n.up && n.ipv4,
    ) ?? {
      id: this.data.adapterId,
      name: this.data.adapterId || "未找到联网网卡",
      exists: false,
      up: false,
      ipv4: false,
      error: "",
    };
    const route =
      this.data.proxy.mode === "manual"
        ? this.data.proxy.address
        : await this.resolveProxy(this.data.settings.ipv4Url);
    const fingerprint = JSON.stringify([interfaces, route]);
    if (this.network && this.network !== fingerprint) {
      this.pause("网络发生变化，正在复核 IPv4");
      void this.recheck();
    }
    this.network = fingerprint;
    this.publish();
  }
  pause(reason: string) {
    this.snapshot.ready = false;
    this.snapshot.reason = reason;
    this.snapshot.networkIssue = "checking";
    for (const session of this.sessions.values())
      for (const socket of session.sockets) socket.destroy();
  }
  check(): Promise<Snapshot> {
    if (this.checking) return this.checking;
    clearTimeout(this.timer);
    this.checking = this.readIp().finally(() => {
      this.checking = undefined;
      if (this.snapshot.online)
        this.timer = setTimeout(() => void this.check(), this.data.settings.intervalSeconds * 1000);
    });
    return this.checking;
  }
  private async selectProbeRoute() {
    if (this.data.proxy.mode === "manual") await this.probe.useFixedProxy(this.data.proxy.address);
    else await this.probe.useSystemProxy();
  }
  private async recheck() {
    this.epoch++;
    this.probe.invalidate();
    if (this.checking) await this.checking;
    await this.selectProbeRoute();
    return this.check();
  }
  private async readIp() {
    const epoch = this.epoch;
    this.snapshot.checking = true;
    this.snapshot.probe = { round: this.snapshot.probe.round + 1, attempt: 1, phase: "checking" };
    this.publish();
    try {
      const value = await this.probe.check(this.data.settings.ipv4Url);
      if (epoch !== this.epoch) return this.snapshot;
      const before = this.snapshot.ready;
      this.snapshot.currentIp = value.ip;
      this.snapshot.lastChecked = value.checkedAt;
      this.snapshot.adapter = value.adapter;
      const allowed =
        this.snapshot.online &&
        !this.error &&
        this.data.locked &&
        !value.error &&
        this.data.settings.expectedIps.includes(value.ip);
      if (allowed) {
        this.snapshot.ready = true;
        this.snapshot.reason = "IPv4 命中允许列表";
        this.snapshot.networkIssue = "idle";
      } else {
        this.pause(
          this.error ||
            value.error ||
            (!this.data.locked ? "请锁定允许的 IPv4" : "公网 IPv4 未命中允许列表"),
        );
        this.snapshot.networkIssue = value.ip ? "ip_changed" : "ip_unavailable";
      }
      this.snapshot.probe.phase = allowed ? "passed" : "failed";
      if (before !== allowed)
        this.log(
          allowed ? "受管代理连接已恢复" : this.snapshot.reason,
          allowed ? "info" : "warning",
        );
    } finally {
      this.snapshot.checking = false;
      this.publish();
    }
    return this.snapshot;
  }
  async lock(settings: Settings) {
    if (this.data.locked) throw new Error("请先取消锁定");
    this.pause("正在应用允许的 IPv4");
    await this.save({ ...this.data, settings: settingsSchema.parse(settings), locked: true });
    return this.recheck();
  }
  async unlock() {
    this.stopSessions();
    this.pause("IPv4 未锁定");
    await this.save({ ...this.data, locked: false });
    return this.snapshot;
  }
  async add(target: ProtectedApp) {
    const resolved = await executablePath(target.path);
    if (this.data.apps.some((a) => a.path === resolved || a.id === target.id))
      throw new Error("该程序已添加");
    if (!isPosixCli(resolved) && !resolved.includes("/Claude.app/Contents/MacOS/"))
      throw new Error("此开发版的受管启动支持 Claude Code 与 macOS Claude Desktop");
    await this.save({
      ...this.data,
      apps: [...this.data.apps, { ...target, path: resolved, enabled: false, enhanced: false }],
    });
  }
  target(id: string) {
    const target = this.data.apps.find((a) => a.id === id);
    if (!target) throw new Error("程序不存在");
    return target;
  }
  async edit(id: string, name: string, args: string) {
    argumentWords(args);
    this.target(id);
    await this.save({
      ...this.data,
      apps: this.data.apps.map((a) => (a.id === id ? { ...a, name, arguments: args } : a)),
    });
  }
  async protect(id: string, enabled: boolean) {
    this.target(id);
    if (enabled && !this.data.locked) throw new Error("请先锁定 IPv4");
    this.stopSessions(id);
    await this.save({
      ...this.data,
      apps: this.data.apps.map((a) => (a.id === id ? { ...a, enabled } : a)),
    });
  }
  async remove(id: string) {
    this.target(id);
    this.stopSessions(id);
    await this.save({ ...this.data, apps: this.data.apps.filter((a) => a.id !== id) });
  }
  async setAdapter(adapterId: string) {
    await this.save({ ...this.data, adapterId });
    await this.observeNetwork();
  }
  async setAutostart(autostart: boolean) {
    await this.save({ ...this.data, autostart });
    this.snapshot.startup = {
      enabled: autostart,
      state: autostart ? "ready" : "off",
      message: autostart ? "已配置登录启动" : "",
    };
    this.publish();
  }
  observeStartup(enabled: boolean, error = "") {
    const missing = this.data.autostart && !enabled;
    this.snapshot.startup = {
      enabled: enabled || missing,
      state: error || missing ? "error" : enabled ? "ready" : "off",
      message: error || (missing ? "登录启动项未就绪，请重新开启" : ""),
    };
    this.publish();
  }
  async setProxy(proxy: ProxySettings) {
    this.pause("代理来源已变化，正在复核");
    await this.save({ ...this.data, proxy });
    await this.recheck();
  }
  async setScope(id: string, scope: ProtectedApp["apiScope"]) {
    const target = this.target(id);
    if (!isPosixCli(target.path)) throw new Error("仅 Claude Code 会话可设置模型范围");
    this.stopSessions(id);
    await this.save({
      ...this.data,
      apps: this.data.apps.map((a) => (a.id === id ? { ...a, apiScope: scope } : a)),
    });
  }
  async createSession(
    id: string,
    close: () => void,
    provider: "claude" | "other" | "unknown" = "unknown",
  ) {
    const target = this.target(id);
    if (!target.enabled) throw new Error("请先开启受管启动");
    const guarded =
      !isPosixCli(target.path) ||
      target.apiScope === "claude" ||
      (target.apiScope === "auto" && provider !== "other");
    if (guarded) {
      await this.check();
      if (!this.snapshot.ready) throw new Error(this.snapshot.reason);
    }
    const resolved = await executablePath(target.path);
    if (resolved !== target.path) throw new Error("程序入口已更新，请重新添加");
    const sessionId = randomUUID(),
      sockets = new Set<Socket>();
    const server = createServer((client) =>
      acceptHttpProxy(client, {
        sockets,
        allowed: () =>
          guarded &&
          this.snapshot.online &&
          this.data.locked &&
          this.snapshot.ready &&
          this.sessions.has(sessionId) &&
          !this.policies.error,
        connect: async (destination) => {
          const action = this.policies.action(destination);
          if (action === "block") throw new ProxyRequestError(403, "该目标已被拦截策略阻断");
          const upstream =
            this.data.proxy.mode === "manual"
              ? this.data.proxy.address
              : await this.resolveProxy(`https://${destination.host}:${destination.port}`);
          if (action === "direct")
            return this.policies.connect(
              { host: "127.0.0.1", port: 1, protocol: "http" },
              destination,
            );
          if (upstream === "DIRECT") return openDirect(destination);
          const endpoint = upstream.includes("://")
            ? systemProxyEndpoint(
                (upstream.startsWith("socks5:") ? "SOCKS5 " : "PROXY ") + new URL(upstream).host,
              )
            : systemProxyEndpoint(upstream);
          return this.policies.connect(endpoint, destination);
        },
      }),
    );
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("受管代理端口创建失败");
    const release = () => {
      const record = this.sessions.get(sessionId);
      if (!record) return;
      this.sessions.delete(sessionId);
      for (const socket of sockets) socket.destroy();
      server.close();
      this.reservePorts();
      this.publish();
    };
    this.sessions.set(sessionId, {
      appId: id,
      guarded,
      server,
      sockets,
      close: () => {
        release();
        close();
      },
    });
    this.reservePorts();
    this.publish();
    const granted = {
      sessionId,
      target,
      args: argumentWords(target.arguments),
      release,
    };
    return guarded
      ? { ...granted, scope: "guarded" as const, proxy: `http://127.0.0.1:${address.port}` }
      : { ...granted, scope: "other" as const };
  }
  private reservePorts() {
    this.policies.reserve(
      "enhancement",
      [...this.sessions.values()].flatMap((record) => {
        const value = record.server.address();
        return value && typeof value !== "string" ? [value.port] : [];
      }),
    );
  }
  stopSessions(id?: string) {
    for (const record of this.sessions.values()) if (!id || record.appId === id) record.close();
  }
  stop() {
    this.snapshot.online = false;
    clearTimeout(this.timer);
    clearInterval(this.monitor);
    this.stopSessions();
    this.probe.stop();
    this.publish();
  }
}
