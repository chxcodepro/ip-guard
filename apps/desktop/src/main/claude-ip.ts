import { EventEmitter } from "node:events";
import { setTimeout as delay } from "node:timers/promises";

import { session } from "electron";
import type { Session } from "electron";

import {
  ipv4Attempts,
  ipv4AttemptTimeoutMs,
  ipv4ProbeTimeoutMs,
  ipv4RetryDelayMs,
  ipv4SourceUrlSchema,
  parseIpv4Response,
} from "@ip-guard/electron";

type ProbeStep = {
  label: string;
  status: string;
  detail: string;
} & ({ step: "attempt"; attempt: number } | { step: "dns" | "ipv4" | "reconnect" });
export type ProbeProgress = ProbeStep & { sourceUrl: string };
export interface ClaudeIPv4Result {
  sourceUrl: string;
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
    cancel = () => reject(new Error("公网 IPv4 检测超时或已取消"));
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
  private readonly results = new Map<string, ClaudeIPv4Result>();
  private readonly progressBySource = new Map<string, ProbeProgress[]>();
  private readonly pending = new Map<string, Promise<ClaudeIPv4Result>>();
  private abort = new AbortController();
  private readonly transports = new Map<string, Session>();
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
    if (this.proxy === proxy) return;
    this.route.abort();
    this.route = new AbortController();
    await Promise.all(this.pending.values());
    this.proxy = proxy;
    for (const transport of this.transports.values())
      await transport.setProxy(
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
  latest(sourceUrl: string) {
    return this.results.get(sourceUrl);
  }
  steps(sourceUrl: string) {
    return this.progressBySource.get(sourceUrl) ?? [];
  }
  private progress(sourceUrl: string, value: ProbeStep) {
    const steps = this.steps(sourceUrl);
    const progress = { ...value, sourceUrl };
    const index = steps.findIndex((step) => step.step === value.step);
    if (index < 0) steps.push(progress);
    else steps[index] = progress;
    this.emit("progress", progress);
  }
  check(input: string): Promise<ClaudeIPv4Result> {
    const sourceUrl = ipv4SourceUrlSchema.parse(input);
    const existing = this.pending.get(sourceUrl);
    if (existing) return existing;
    this.progressBySource.set(sourceUrl, []);
    const pending = this.read(sourceUrl)
      .then((result) => {
        this.results.set(sourceUrl, result);
        this.emit("update", result);
        return result;
      })
      .finally(() => {
        this.pending.delete(sourceUrl);
      });
    this.pending.set(sourceUrl, pending);
    return pending;
  }
  stop() {
    this.abort.abort();
  }
  private async read(sourceUrl: string): Promise<ClaudeIPv4Result> {
    const started = performance.now();
    const progress = (value: ProbeStep) => this.progress(sourceUrl, value);
    const hostname = new URL(sourceUrl).hostname;
    const lifetime = AbortSignal.any([
      this.abort.signal,
      this.route.signal,
      AbortSignal.timeout(ipv4ProbeTimeoutMs - 1000),
    ]);
    let status = 0,
      adapter = "",
      retries = 0;
    try {
      let transport = this.transports.get(sourceUrl);
      const fresh = !transport;
      if (!transport) {
        transport = session.fromPartition(`${this.partition}-${this.transports.size}`, {
          cache: false,
        });
        this.transports.set(sourceUrl, transport);
      }
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
          progress({
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
          progress({ step: "dns", label: "DNS 解析", status: "running", detail: hostname });
          const proxy = await bounded(transport.resolveProxy(sourceUrl), signal);
          adapter = this.proxy ? "受控代理通道" : proxy === "DIRECT" ? "系统直连" : "系统代理";
          if (proxy !== "DIRECT")
            progress({
              step: "dns",
              label: "DNS 解析",
              status: "info",
              detail: "由系统代理解析",
            });
          else {
            try {
              const host = await bounded(
                transport.resolveHost(hostname, { queryType: "A" }),
                signal,
              );
              progress({
                step: "dns",
                label: "DNS 解析",
                status: "ok",
                detail: host.endpoints[0]?.address ?? "系统解析",
              });
            } catch (error) {
              signal.throwIfAborted();
              progress({
                step: "dns",
                label: "DNS 解析",
                status: "unknown",
                detail: error instanceof Error ? error.message : "未取得解析信息",
              });
            }
          }
          progress({
            step: "ipv4",
            label: "公网 IPv4",
            status: "running",
            detail: adapter,
          });
          const response = await bounded(
            transport.fetch(sourceUrl, {
              signal,
              cache: "no-store",
              redirect: "manual",
              bypassCustomProtocolHandlers: true,
            }),
            signal,
          );
          status = response.status;
          if (status !== 200) throw new Error(`IPv4 接口返回 HTTP ${status}`);
          const reader = response.body?.getReader();
          if (!reader) throw new Error("IPv4 接口响应为空");
          const decoder = new TextDecoder();
          let body = "",
            bytes = 0;
          try {
            while (true) {
              const chunk = await bounded(reader.read(), signal);
              if (chunk.done) break;
              bytes += chunk.value.byteLength;
              if (bytes > 32768) throw new Error("IPv4 接口响应超过 32 KB");
              body += decoder.decode(chunk.value, { stream: true });
            }
            body += decoder.decode();
          } finally {
            void reader.cancel().catch(() => undefined);
          }
          const ip = parseIpv4Response(body);
          if (retries)
            progress({
              step: "reconnect",
              label: "代理/网络",
              status: "ok",
              detail: "连接已恢复",
            });
          progress({ step: "ipv4", label: "公网 IPv4", status: "ok", detail: ip });
          return {
            sourceUrl,
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
          progress({
            step: "reconnect",
            label: "IPv4 重试",
            status: "running",
            detail: `第 ${retries + 1}/${ipv4Attempts} 次 · 上次未取得公网 IPv4`,
          });
          clearTimeout(timer);
          attempt.abort();
          await delay(ipv4RetryDelayMs, undefined, { signal: lifetime });
        } finally {
          clearTimeout(timer);
          attempt.abort();
        }
      }
    } catch (error) {
      if (retries && !this.abort.signal.aborted)
        progress({
          step: "reconnect",
          label: "代理/网络",
          status: "error",
          detail: "检测暂不可用",
        });
      const detail = this.abort.signal.aborted
        ? "公网 IPv4 检测已取消"
        : this.proxy === undefined
          ? this.proxyError
          : lifetime.aborted
            ? "三次 IPv4 检测等待超时，请确认代理/网络已连接后重试"
            : error instanceof Error
              ? error.message
              : "公网 IPv4 检测失败";
      return {
        sourceUrl,
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
