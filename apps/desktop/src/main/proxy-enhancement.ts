import { randomUUID } from "node:crypto";
import { readFile, writeFile, rename, mkdir } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";
import path from "node:path";

import { session } from "electron";

import { claudeIpv4Endpoint, egressPolicySchema, proxySettingsSchema } from "@ip-guard/electron";
import type { EgressPolicy, ProxySettings, ProxyEnhancementState } from "@ip-guard/electron";

import { EnhancementExit } from "./enhancement-exit.ts";
import { ForcedProxy } from "./forced-proxy.ts";
import { guardDataDirectory } from "./guard-data.ts";
import { destination, openTunnel, proxyEndpoint, systemProxyEndpoint } from "./proxy-tunnel.ts";
import type { ProxyEndpoint } from "./proxy-tunnel.ts";

const settingsFile = () => path.join(guardDataDirectory(), "proxy-settings.json");
export class ProxyEnhancement {
  onChange: (() => void) | undefined;
  onVerificationChange: (() => void) | undefined;
  readonly exit = new EnhancementExit(() => {
    if (!this.exit.ready) this.setAllowed(false);
    this.onVerificationChange?.();
  });
  private upstream: ProxyEnhancementState = {
    settings: { mode: "system" },
    phase: "idle",
    endpoint: "",
    error: "",
  };
  get state(): ProxyEnhancementState {
    return { ...this.upstream, verification: this.exit.state };
  }
  private servers: Server[] = [];
  private sockets = new Set<Socket>();
  private managedSockets = new Set<Socket>();
  private allowed = false;
  private revision = 0;
  private timer: ReturnType<typeof setInterval> | undefined;
  private refreshing: Promise<void> | undefined;
  private needed = false;
  private holds = 0;
  private approved = false;
  private stopped = false;
  private readonly forced = new ForcedProxy(() => {
    this.disconnect();
    this.upstream = {
      ...this.upstream,
      phase: "unavailable",
      error: "Claude 专用通道已退出，增强连接保持暂停",
    };
    this.onChange?.();
  });
  get routeActive() {
    return Boolean(this.forced.endpoint);
  }
  get routeHeld() {
    return this.holds > 0;
  }
  get needsApproval() {
    return !this.approved;
  }
  approve() {
    this.approved = true;
  }
  async setNeeded(needed: boolean) {
    if (this.needed === needed) return;
    this.needed = needed;
    await this.refresh();
    if (needed && this.approved && !this.routeActive && this.upstream.phase === "ready")
      await this.refresh();
  }
  async acquire() {
    this.approve();
    this.holds++;
    try {
      await this.refresh();
      if (!this.routeActive && this.upstream.phase === "ready") await this.refresh();
      if (!this.routeActive) throw new Error(this.upstream.error || "Claude 专用通道未就绪");
      return async () => {
        this.holds--;
        await this.refresh();
      };
    } catch (error) {
      this.holds--;
      await this.refresh();
      throw error;
    }
  }
  private configurationError = "";
  policy: EgressPolicy | undefined;
  probeAddress = "";
  private readonly resolver = () => session.fromPartition("ip-guard-upstream", { cache: false });
  async initialize() {
    try {
      this.upstream.settings = proxySettingsSchema.parse(
        JSON.parse(await readFile(settingsFile(), "utf8")),
      );
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
        this.configurationError = "通用代理配置读取失败，请重新选择代理来源；原文件保留";
    }
    const probe = await this.listen(false);
    const port = await this.listen(true);
    this.probeAddress = `http://127.0.0.1:${probe}`;
    this.policy = egressPolicySchema.parse({ id: randomUUID(), label: "当前代理", port });
    void this.refresh();
    this.timer = setInterval(() => void this.refresh(), 2000);
  }
  private async sourceEndpoint(): Promise<ProxyEndpoint> {
    if (this.configurationError) throw new Error(this.configurationError);
    const settings = this.upstream.settings;
    let endpoint: ProxyEndpoint;
    if (settings.mode === "manual") endpoint = proxyEndpoint(settings.address);
    else {
      const resolved = await this.resolver().resolveProxy(claudeIpv4Endpoint);
      endpoint =
        resolved.split(";")[0]?.trim() === "DIRECT"
          ? await this.forced.locate()
          : systemProxyEndpoint(resolved);
    }
    if (
      this.servers.some((server) => {
        const address = server.address();
        return (
          address &&
          typeof address !== "string" &&
          address.port === endpoint.port &&
          ["127.0.0.1", "localhost", "::1"].includes(endpoint.host)
        );
      })
    )
      throw new Error("代理地址指向 IP Guard 自身，请选择上游代理端口");
    return endpoint;
  }
  refresh(): Promise<void> {
    if (this.stopped) return Promise.resolve();
    if (this.refreshing) return this.refreshing;
    const work = this.refreshCore();
    this.refreshing = work;
    void work
      .finally(() => {
        if (this.refreshing === work) this.refreshing = undefined;
      })
      .catch(() => undefined);
    return work;
  }
  private async refreshCore() {
    const previous = `${this.upstream.phase}|${this.upstream.endpoint}|${this.upstream.error}`;
    try {
      await this.resolver().forceReloadProxyConfig();
      if (!this.needed && !this.holds) {
        if (this.forced.allocated) {
          this.disconnect();
          await this.forced.stop();
        }
        this.approved = false;
        this.forced.forget();
        const entry = await this.sourceEndpoint();
        if (!["127.0.0.1", "localhost", "::1"].includes(entry.host))
          throw new Error("自动专用路由需指定本机 Xray / sing-box 入口");
        this.upstream = {
          ...this.upstream,
          phase: "ready",
          endpoint: `${entry.protocol}://${entry.host}:${entry.port} · 待确认建立专用通道`,
          error: "",
        };
        return;
      }
      if (!this.approved) throw new Error("请确认启用 Claude 专用路由；现有增强连接保持暂停");
      const source = await this.forced.source(await this.sourceEndpoint());
      if (!this.forced.matches(source)) {
        this.disconnect();
        await this.forced.start(source);
      }
      const endpoint = this.forced.endpoint;
      this.upstream = {
        ...this.upstream,
        phase: "ready",
        endpoint: endpoint
          ? `${endpoint.protocol}://${endpoint.host}:${endpoint.port}`
          : `${source.node.engine} · 已识别当前节点，待开启增强`,
        error: "",
      };
    } catch (error) {
      this.disconnect();
      try {
        await this.forced.stop();
      } catch (cleanupError) {
        console.error("专用通道清理未完成", cleanupError);
      }
      this.upstream = {
        ...this.upstream,
        phase: "unavailable",
        endpoint: "",
        error: error instanceof Error ? error.message : "当前代理不可用",
      };
    } finally {
      if (previous !== `${this.upstream.phase}|${this.upstream.endpoint}|${this.upstream.error}`)
        this.onChange?.();
    }
  }
  async configure(settings: ProxySettings) {
    const next = proxySettingsSchema.parse(settings);
    await mkdir(guardDataDirectory(), { recursive: true });
    const temporary = settingsFile() + ".tmp";
    await writeFile(temporary, JSON.stringify(next), "utf8");
    await rename(temporary, settingsFile());
    this.configurationError = "";
    this.disconnect();
    this.upstream = { settings: next, phase: "idle", endpoint: "", error: "" };
    await this.refresh();
  }
  private async listen(gated: boolean): Promise<number> {
    const server = createServer((socket) => this.accept(socket, gated));
    this.servers.push(server);
    server.on("error", () => {
      this.disconnect();
      this.upstream = { ...this.upstream, phase: "unavailable", error: "本地增强通道发生错误" };
    });
    return new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
        const address = server.address();
        if (!address || typeof address === "string") reject(new Error("增强通道创建失败"));
        else {
          server.off("error", reject);
          resolve(address.port);
        }
      });
    });
  }
  private accept(client: Socket, gated: boolean) {
    if ((gated && !this.allowed) || this.sockets.size >= 512) {
      client.destroy();
      return;
    }
    this.sockets.add(client);
    if (gated) this.managedSockets.add(client);
    const revision = this.revision;
    let buffer = Buffer.alloc(0);
    let upstream: Socket | undefined;
    const close = () => {
      client.destroy();
      upstream?.destroy();
      this.sockets.delete(client);
      this.managedSockets.delete(client);
      if (upstream) {
        this.sockets.delete(upstream);
        this.managedSockets.delete(upstream);
      }
    };
    client.on("error", close);
    client.on("close", close);
    client.setTimeout(10000, close);
    const read = (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      const end = buffer.indexOf("\r\n\r\n");
      if (end < 0) {
        if (buffer.length > 16384) close();
        return;
      }
      if (end > 16384) {
        close();
        return;
      }
      client.off("data", read);
      client.pause();
      void (async () => {
        const lines = buffer.subarray(0, end).toString("latin1").split("\r\n");
        const request = /^([A-Z]+) ([^\s]+) HTTP\/1\.[01]$/.exec(lines[0] ?? "");
        if (!request) throw new Error("代理请求无效");
        const method = request[1],
          url = request[2] ?? "";
        const parsed = method === "CONNECT" ? undefined : new URL(url);
        if (parsed && (parsed.protocol !== "http:" || parsed.username || parsed.password))
          throw new Error("仅支持 HTTP 或 CONNECT 代理请求");
        const target = destination(
          method === "CONNECT" ? url : `${parsed?.hostname}:${parsed?.port || 80}`,
        );
        if (!gated && !["claude.ai", "myip.ipip.net"].includes(target.host))
          throw new Error("检测通道仅用于出口复核");
        const endpoint = this.forced.endpoint;
        if (!endpoint || this.upstream.phase !== "ready") throw new Error("Claude 专用代理未就绪");
        upstream = await openTunnel(endpoint, target);
        this.sockets.add(upstream);
        if (gated) this.managedSockets.add(upstream);
        upstream.on("error", close);
        upstream.on("close", close);
        if (client.destroyed || revision !== this.revision || (gated && !this.allowed))
          throw new Error("连接许可已撤销");
        if (method === "CONNECT") client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        else {
          const headers = lines
            .slice(1)
            .filter((line) => !/^(proxy-connection|proxy-authorization|connection):/i.test(line));
          upstream.write(
            `${method} ${parsed?.pathname}${parsed?.search} HTTP/1.1\r\n${headers.join("\r\n")}\r\nConnection: close\r\n\r\n`,
          );
        }
        if (buffer.length > end + 4) upstream.write(buffer.subarray(end + 4));
        buffer = Buffer.alloc(0);
        client.setTimeout(0);
        upstream.setTimeout(0);
        client.pipe(upstream).pipe(client);
        upstream.resume();
        client.resume();
      })().catch(close);
    };
    client.on("data", read);
  }
  setAllowed(allowed: boolean) {
    this.allowed =
      !this.stopped &&
      allowed &&
      this.routeActive &&
      this.upstream.phase === "ready" &&
      this.exit.ready;
    if (!this.allowed) this.disconnect(false);
  }
  private disconnect(all = true) {
    // Probe retries may continue while managed connections remain paused.
    if (all) {
      this.revision++;
      this.allowed = false;
      this.exit.invalidate();
    }
    for (const socket of all ? this.sockets : this.managedSockets) socket.destroy();
    if (all) this.sockets.clear();
    this.managedSockets.clear();
  }
  async stop() {
    clearInterval(this.timer);
    this.stopped = true;
    this.allowed = false;
    this.disconnect();
    if (this.refreshing) await this.refreshing;
    this.allowed = false;
    this.exit.stop();
    this.disconnect();
    await Promise.all(
      this.servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
    );
    this.servers = [];
    await this.forced.stop();
  }
}
