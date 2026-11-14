import { setTimeout as delay } from "node:timers/promises";

import { session } from "electron";

import { ipv4Attempts, ipv4AttemptTimeoutMs, publicIPv4Schema } from "@ip-guard/electron";
import type { EnhancementVerification } from "@ip-guard/electron";

export const enhancementExitEndpoint = "https://myip.ipip.net/";
export function domesticExit(text: string): string {
  if (text.length > 4096) throw new Error("出口查询响应过大");
  const match = /当前\s*IP\s*[：:]\s*(\d{1,3}(?:\.\d{1,3}){3})(?=\s|$|[，,])/.exec(text);
  return publicIPv4Schema.parse(match?.[1]);
}
export function exitMatches(ip: string, allowed: readonly string[]) {
  return allowed.includes(publicIPv4Schema.parse(ip));
}
export class EnhancementExit {
  state: EnhancementVerification = {
    phase: "idle",
    checkedAt: "",
    currentIp: "",
    reason: "等待增强出口复核",
  };
  private pending: Promise<boolean> | undefined;
  private abort = new AbortController();
  private generation = 0;
  private key = "";
  private startedAt = 0;
  private stopped = false;
  private readonly changed: () => void;
  constructor(changed: () => void) {
    this.changed = changed;
  }
  get ready() {
    return this.state.phase === "passed" && Date.now() - Date.parse(this.state.checkedAt) < 15000;
  }
  private set(state: EnhancementVerification) {
    this.state = state;
    this.changed();
  }
  invalidate(reason = "网络或代理已变化，等待增强出口复核") {
    this.generation++;
    this.abort.abort();
    this.abort = new AbortController();
    this.key = "";
    this.startedAt = 0;
    if (this.state.phase !== "idle" || this.state.reason !== reason)
      this.set({ phase: "idle", checkedAt: "", currentIp: "", reason });
  }
  check(allowed: readonly string[], proxy: string, force = false): Promise<boolean> {
    if (this.stopped) return Promise.resolve(false);
    const key = `${proxy}|${[...allowed].sort().join(",")}`;
    if (this.pending && key === this.key) return this.pending;
    if (!force && key === this.key && Date.now() - this.startedAt < 5000)
      return Promise.resolve(this.ready);
    if (key !== this.key) this.invalidate();
    const previous = this.pending;
    this.key = key;
    this.startedAt = Date.now();
    const generation = this.generation,
      signal = this.abort.signal;
    const pending = (async () => {
      if (previous) await previous;
      if (generation !== this.generation || this.stopped) return false;
      if (!allowed.length || !proxy) {
        this.set({
          phase: "failed",
          checkedAt: new Date().toISOString(),
          currentIp: "",
          reason: "请先锁定允许地址并准备增强通道",
        });
        return false;
      }
      if (!this.ready && !["blocked", "failed"].includes(this.state.phase))
        this.set({ ...this.state, phase: "checking", reason: "正在复核国内查询出口" });
      const transport = session.fromPartition("ip-guard-enhancement-exit", { cache: false });
      try {
        await transport.setProxy({
          mode: "fixed_servers",
          proxyRules: proxy,
          proxyBypassRules: "<-loopback>",
        });
        for (let attempt = 1; attempt <= ipv4Attempts; attempt++) {
          if (generation !== this.generation || signal.aborted) return false;
          try {
            await transport.closeAllConnections();
            const response = await transport.fetch(enhancementExitEndpoint, {
              cache: "no-store",
              redirect: "error",
              signal: AbortSignal.any([signal, AbortSignal.timeout(ipv4AttemptTimeoutMs)]),
            });
            if (!response.ok || !response.body) throw new Error("出口查询暂未响应");
            const reader = response.body.getReader(),
              decoder = new TextDecoder();
            let text = "",
              bytes = 0;
            try {
              while (true) {
                const item = await reader.read();
                if (item.done) break;
                bytes += item.value.length;
                if (bytes > 4096) throw new Error("出口查询响应过大");
                text += decoder.decode(item.value, { stream: true });
              }
              text += decoder.decode();
            } finally {
              await reader.cancel().catch(() => undefined);
            }
            const ip = domesticExit(text);
            if (generation !== this.generation || signal.aborted) return false;
            const matched = exitMatches(ip, allowed);
            this.set({
              phase: matched ? "passed" : "blocked",
              checkedAt: new Date().toISOString(),
              currentIp: ip,
              reason: matched
                ? "国内查询出口已命中允许列表"
                : "专用出口 IPv4 未命中允许列表，增强连接已暂停；请核对当前节点与允许地址",
            });
            return matched;
          } catch {
            if (generation !== this.generation || signal.aborted) return false;
            this.set({
              phase:
                attempt < ipv4Attempts
                  ? ["blocked", "failed"].includes(this.state.phase)
                    ? this.state.phase
                    : "checking"
                  : "failed",
              checkedAt: new Date().toISOString(),
              currentIp: "",
              reason: `增强出口复核 ${attempt}/${ipv4Attempts} 次未取得 IPv4，增强联网已暂停`,
            });
            if (attempt < ipv4Attempts) await delay(250, undefined, { signal });
          }
        }
      } catch {
        if (generation === this.generation && !signal.aborted)
          this.set({
            phase: "failed",
            checkedAt: new Date().toISOString(),
            currentIp: "",
            reason: "增强出口复核失败，联网保持暂停",
          });
      }
      return false;
    })().finally(() => {
      if (this.pending === pending) this.pending = undefined;
    });
    this.pending = pending;
    return pending;
  }
  stop() {
    this.stopped = true;
    this.invalidate("增强出口复核已停止");
  }
}
