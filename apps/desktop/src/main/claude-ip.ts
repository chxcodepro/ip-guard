import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";

import { session } from "electron";
import type { Session } from "electron";

import {
  claudeIpv4Endpoint,
  ipv4Attempts,
  ipv4AttemptTimeoutMs,
  ipv4ProbeTimeoutMs,
  publicIPv4Schema,
} from "@ip-guard/electron";

export type ProbeProgress = {
  label: string;
  status: string;
  detail: string;
} & ({ step: "attempt"; attempt: number } | { step: "dns" | "ipv4" | "reconnect" });
export interface ClaudeIPv4Result {
  ip: string;
  error: string;
  checkedAt: string;
  adapter: string;
  status: number;
  ms: number;
}
async function bounded<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) void work.catch(() => undefined);
  signal.throwIfAborted();
  let cancel: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    cancel = () => reject(new Error("Claude 出口检测超时或已取消"));
    signal.addEventListener("abort", cancel, { once: true });
  });
  try {
    return await Promise.race([work, aborted]);
  } finally {
    if (cancel) signal.removeEventListener("abort", cancel);
  }
}
export class ClaudeIPv4 extends EventEmitter<{
  update: [ClaudeIPv4Result];
  progress: [ProbeProgress];
}> {
  private readonly partition: string;
  constructor(partition = "ip-guard-ipv4") {
    super();
    this.partition = partition;
  }
  latest: ClaudeIPv4Result | undefined;
  steps: ProbeProgress[] = [];
  private pending: Promise<ClaudeIPv4Result> | undefined;
  private abort = new AbortController();
  private transport: Session | undefined;
  private route = new AbortController();
  private proxy: string | null | undefined = null;
  private proxyError = "固定出口暂不可用";
  fixedProxyUnavailable(message: string) {
    this.proxy = undefined;
    this.proxyError = message;
    this.route.abort();
    this.route = new AbortController();
  }
  private async selectProxy(proxy: string | null) {
    this.route.abort();
    this.route = new AbortController();
    if (this.pending) await this.pending;
    this.proxy = proxy;
    if (this.transport)
      await this.transport.setProxy(
        proxy === null
          ? { mode: "system" }
          : { mode: "fixed_servers", proxyRules: proxy, proxyBypassRules: "<-loopback>" },
      );
  }
  useFixedProxy(proxy: string) {
    return this.selectProxy(proxy);
  }
  useSystemProxy() {
    return this.selectProxy(null);
  }
  private progress(value: ProbeProgress) {
    const index = this.steps.findIndex((step) => step.step === value.step);
    if (index < 0) this.steps.push(value);
    else this.steps[index] = value;
    this.emit("progress", value);
  }
  check(): Promise<ClaudeIPv4Result> {
    if (this.pending) return this.pending;
    this.steps = [];
    this.pending = this.read()
      .then((result) => {
        this.latest = result;
        this.emit("update", result);
        return result;
      })
      .finally(() => {
        this.pending = undefined;
      });
    return this.pending;
  }
  stop() {
    this.abort.abort();
  }
  private async read(): Promise<ClaudeIPv4Result> {
    const started = performance.now();
    const lifetime = AbortSignal.any([
      this.abort.signal,
      this.route.signal,
      AbortSignal.timeout(ipv4ProbeTimeoutMs - 1000),
    ]);
    let status = 0,
      adapter = "",
      retries = 0;
    try {
      const fresh = !this.transport;
      const transport = (this.transport ??= session.fromPartition(this.partition, {
        cache: false,
      }));
      if (fresh && typeof this.proxy === "string")
        await bounded(
          transport.setProxy({
            mode: "fixed_servers",
            proxyRules: this.proxy,
            proxyBypassRules: "<-loopback>",
          }),
          lifetime,
        );
      while (true) {
        const attempt = new AbortController();
        const signal = AbortSignal.any([lifetime, attempt.signal]);
        const timer = setTimeout(() => attempt.abort(), ipv4AttemptTimeoutMs);
        try {
          signal.throwIfAborted();
          this.progress({
            step: "attempt",
            label: "IPv4 检测",
            status: "running",
            detail: `第 ${retries + 1}/${ipv4Attempts} 次`,
            attempt: retries + 1,
          });
          if (this.proxy === undefined) throw new Error(this.proxyError);
          status = 0;
          await bounded(transport.closeAllConnections(), signal);
          if (retries) {
            await bounded(transport.clearHostResolverCache(), signal);
            await bounded(transport.forceReloadProxyConfig(), signal);
          }
          this.progress({ step: "dns", label: "DNS 解析", status: "running", detail: "claude.ai" });
          const proxy = await bounded(transport.resolveProxy(claudeIpv4Endpoint), signal);
          adapter = this.proxy ? "独立固定节点" : proxy === "DIRECT" ? "系统直连" : "系统代理";
          if (proxy !== "DIRECT")
            this.progress({
              step: "dns",
              label: "DNS 解析",
              status: "info",
              detail: "由系统代理解析",
            });
          else {
            try {
              const host = await bounded(
                transport.resolveHost("claude.ai", { queryType: "A" }),
                signal,
              );
              this.progress({
                step: "dns",
                label: "DNS 解析",
                status: "ok",
                detail: host.endpoints[0]?.address ?? "系统解析",
              });
            } catch (error) {
              signal.throwIfAborted();
              this.progress({
                step: "dns",
                label: "DNS 解析",
                status: "unknown",
                detail: error instanceof Error ? error.message : "未取得解析信息",
              });
            }
          }
          this.progress({
            step: "ipv4",
            label: "Claude AI IPv4",
            status: "running",
            detail: adapter,
          });
          const response = await bounded(
            transport.fetch(claudeIpv4Endpoint, {
              signal,
              cache: "no-store",
              redirect: "manual",
              bypassCustomProtocolHandlers: true,
            }),
            signal,
          );
          status = response.status;
          if (status !== 200) throw new Error(`Claude 出口返回 HTTP ${status}`);
          const reader = response.body?.getReader();
          if (!reader) throw new Error("Claude 出口响应为空");
          const decoder = new TextDecoder();
          let body = "",
            bytes = 0;
          try {
            while (true) {
              const chunk = await bounded(reader.read(), signal);
              if (chunk.done) break;
              bytes += chunk.value.byteLength;
              if (bytes > 32768) throw new Error("Claude 出口响应超过 32 KB");
              body += decoder.decode(chunk.value, { stream: true });
            }
            body += decoder.decode();
          } finally {
            void reader.cancel().catch(() => undefined);
          }
          const ip = /^ip=([^\r\n]+)$/m.exec(body)?.[1]?.trim() ?? "";
          if (!publicIPv4Schema.safeParse(ip).success)
            throw new Error("Claude 出口未返回公网 IPv4，请确认代理提供 IPv4 出口");
          if (retries)
            this.progress({
              step: "reconnect",
              label: "代理/网络",
              status: "ok",
              detail: "连接已恢复",
            });
          this.progress({ step: "ipv4", label: "Claude AI IPv4", status: "ok", detail: ip });
          return {
            ip,
            error: "",
            checkedAt: new Date().toISOString(),
            adapter,
            status,
            ms: Math.round(performance.now() - started),
          };
        } catch (error) {
          if (lifetime.aborted) throw error;
          const detail = attempt.signal.aborted
            ? "单次检测超时（4.5 秒）"
            : error instanceof Error
              ? error.message
              : "未取得公网 IPv4";
          if (retries === ipv4Attempts - 1)
            throw new Error(`${ipv4Attempts} 次检测均未取得公网 IPv4 · ${detail}`);
          retries++;
          this.progress({
            step: "reconnect",
            label: "IPv4 重试",
            status: "running",
            detail: `第 ${retries + 1}/${ipv4Attempts} 次 · 上次未取得公网 IPv4`,
          });
          clearTimeout(timer);
          attempt.abort();
          await delay(retries * 250, undefined, { signal: lifetime });
        } finally {
          clearTimeout(timer);
          attempt.abort();
        }
      }
    } catch (error) {
      if (retries && !this.abort.signal.aborted)
        this.progress({
          step: "reconnect",
          label: "代理/网络",
          status: "error",
          detail: "检测暂不可用",
        });
      const detail = this.abort.signal.aborted
        ? "Claude 出口检测已取消"
        : this.proxy === undefined
          ? this.proxyError
          : lifetime.aborted
            ? "三次 IPv4 检测等待超时，请确认代理/网络已连接后重试"
            : error instanceof Error
              ? error.message
              : "Claude 出口检测失败";
      return {
        ip: "",
        error: detail,
        checkedAt: new Date().toISOString(),
        adapter,
        status,
        ms: Math.round(performance.now() - started),
      };
    }
  }
}
