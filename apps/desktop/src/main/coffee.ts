import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import { request } from "node:https";
import { isIP } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { z } from "zod";

import type { CoffeeMetric, CoffeeReport } from "@ip-guard/electron";

import type { ClaudeIPv4, ClaudeIPv4Result } from "#src/main/claude-ip.ts";

const coffeeUrl = "https://ip.net.coffee/claude/";
const base = "https://ip.net.coffee";
const text = z.string().max(500).nullish();
const flag = z.boolean().nullish();
const geoSchema = z.object({
  country: text,
  region: text,
  city: text,
  isp: text,
  country_code: text,
});
const riskSchema = z.object({
  trust_score: z.number().min(0).max(100).nullish(),
  country: text,
  countryCode: text,
  region: text,
  city: text,
  timezone: text,
  asn: z.union([z.string(), z.number()]).nullish(),
  asOrganization: text,
  isResidential: flag,
  isBroadcast: flag,
  is_datacenter: flag,
  is_mobile: flag,
  is_vpn: flag,
  is_proxy: flag,
  is_tor: flag,
  is_crawler: flag,
  is_abuser: flag,
  company_type: text,
  company_name: text,
  datacenter_name: text,
});
const dnsSchema = z.object({
  dns_servers: z.array(z.string().refine((ip) => isIP(ip) !== 0)).max(64),
});
const restricted = new Set(["CN", "HK", "MO", "RU", "KP", "IR", "SY", "CU", "BY", "VE"]);
const metric = (
  id: string,
  label: string,
  value: string,
  status: CoffeeMetric["status"] = "neutral",
  detail = "",
): CoffeeMetric => ({ id, label, value, status, detail });
const unknown = (id: string, label: string, detail = "") =>
  metric(id, label, "未取得结果", "unknown", detail);
const boolean = (
  id: string,
  label: string,
  value: boolean | null | undefined,
  positive = "检测到",
  negative = "未检测到",
) =>
  value == null
    ? unknown(id, label)
    : metric(id, label, value ? positive : negative, value ? "error" : "ok");
const message = (error: unknown) =>
  error instanceof Error ? error.message.slice(0, 200) : "请求失败";

export class CoffeeDiagnostics extends EventEmitter<{ update: [CoffeeReport] }> {
  private readonly claude: ClaudeIPv4;
  private refreshAfterRun = false;
  private collectingIp = "";
  constructor(claude: ClaudeIPv4) {
    super();
    this.claude = claude;
    claude.on("update", (result) => this.applyClaude(result));
  }
  private applyClaude(result: ClaudeIPv4Result) {
    const changed = this.report.claudeIp !== result.ip;
    this.report.claudeIp = result.ip;
    const exits = this.report.groups.find((group) => group.id === "exits");
    if (!exits) return;
    this.item(
      "exits",
      metric(
        "claude",
        "Claude AI 出口",
        result.ip || "获取失败",
        result.ip ? "neutral" : "error",
        result.error ||
          `IPv4 · ${new Date(result.checkedAt).toLocaleTimeString("zh-CN", { hour12: false })}`,
      ),
    );
    this.setAvailability("claude", {
      label: "claude.ai",
      status: result.status,
      ms: result.ms,
      ...(result.error ? { error: result.error } : {}),
    });
    if (changed) {
      this.country = "";
      this.report.claudeTimezone = "";
      for (const group of this.report.groups)
        if (["trust", "security", "location", "dns"].includes(group.id))
          group.items = group.items.map((item) =>
            unknown(item.id, item.label, "等待 Claude 出口重新检测"),
          );
      if (this.report.phase === "complete") this.refresh();
      else if (
        this.report.phase === "running" &&
        this.collectingIp &&
        this.collectingIp !== result.ip
      )
        this.refreshAfterRun = true;
    }
    this.publish();
  }
  report: CoffeeReport = {
    phase: "idle",
    checkedAt: "",
    error: "",
    claudeIp: "",
    claudeTimezone: "",
    groups: [],
  };
  private timer: ReturnType<typeof setInterval> | undefined;
  private abort = new AbortController();
  private stopped = false;
  private country = "";
  private availability = new Map<
    string,
    { label: string; status: number; ms: number; error?: string }
  >();
  start() {
    this.refresh();
    this.timer = setInterval(() => this.refresh(), 300000);
    this.timer.unref();
  }
  stop() {
    this.stopped = true;
    this.abort.abort();
    if (this.timer) clearInterval(this.timer);
  }
  private publish() {
    if (!this.stopped) this.emit("update", this.report);
  }
  private group(id: string, title: string, items: CoffeeMetric[]) {
    const index = this.report.groups.findIndex((group) => group.id === id);
    if (index < 0) this.report.groups.push({ id, title, items });
    else this.report.groups[index] = { id, title, items };
    this.publish();
  }
  private item(groupId: string, item: CoffeeMetric) {
    const group = this.report.groups.find((group) => group.id === groupId);
    if (!group) throw new Error("诊断分组缺失");
    group.items = group.items.map((old) => (old.id === item.id ? item : old));
    this.publish();
  }
  private read(
    url: string,
    timeout = 8000,
    family: 4 | 6 = 4,
  ): Promise<{ status: number; body: string; ms: number }> {
    const started = performance.now();
    return new Promise((resolve, reject) => {
      const req = request(
        url,
        {
          family,
          signal: AbortSignal.any([this.abort.signal, AbortSignal.timeout(timeout)]),
          headers: { "user-agent": "IPGuard/0.2", "cache-control": "no-cache", referer: coffeeUrl },
        },
        (res) => {
          res.setEncoding("utf8");
          let body = "",
            bytes = 0;
          res.on("data", (chunk: string) => {
            body += chunk;
            bytes += Buffer.byteLength(chunk, "utf8");
            if (bytes > 131072) res.destroy(new Error("检测响应超过 128 KB"));
          });
          res.on("error", reject);
          res.on("end", () =>
            resolve({
              status: res.statusCode ?? 0,
              body,
              ms: Math.round(performance.now() - started),
            }),
          );
        },
      );
      req.on("error", reject);
      req.end();
    });
  }
  private async json(url: string): Promise<unknown> {
    const response = await this.read(url, 10000);
    if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
    const parsed: unknown = JSON.parse(response.body);
    return parsed;
  }
  refresh(): CoffeeReport {
    if (this.report.phase === "running" || this.stopped) return this.report;
    this.collectingIp = "";
    this.report = {
      phase: "running",
      checkedAt: "",
      error: "",
      claudeIp: this.claude.latest?.ip ?? "",
      claudeTimezone: "",
      groups: [],
    };
    this.country = "";
    this.availability.clear();
    this.group("exits", "出口 IP", [
      unknown("cn", "国内出口"),
      unknown("cf", "Cloudflare 出口"),
      unknown("claude", "Claude AI 出口"),
    ]);
    this.group("ipv6", "IPv6 检测", [
      unknown("public", "公网 IPv6", "等待 IPv6 请求"),
      unknown("cf", "Cloudflare IPv6"),
      unknown("claude", "Claude IPv6"),
    ]);
    this.group("trust", "信任与地区", [
      unknown("score", "信任分"),
      unknown("support", "Claude 支持地区"),
    ]);
    this.group("location", "IP 属性", [
      unknown("country", "地区"),
      unknown("city", "城市"),
      unknown("type", "IP 属性"),
      unknown("asn", "ASN"),
      unknown("isp", "运营商"),
      unknown("timezone", "IP 时区"),
    ]);
    this.group("security", "安全属性", [
      unknown("vpn", "VPN"),
      unknown("proxy", "代理"),
      unknown("tor", "Tor"),
      unknown("crawler", "机器人"),
      unknown("abuse", "滥用记录"),
    ]);
    this.group("availability", "网络连通", [
      unknown("claude", "claude.ai"),
      unknown("anthropic", "anthropic.com"),
      unknown("service", "Claude 服务状态"),
    ]);
    this.group("dns", "DNS 出口", [unknown("status", "状态")]);
    void this.collect()
      .catch((error: unknown) => {
        this.report.error = message(error);
      })
      .finally(() => {
        this.report.phase = "complete";
        this.report.checkedAt = new Date().toISOString();
        this.publish();
        if (this.refreshAfterRun && !this.stopped) {
          this.refreshAfterRun = false;
          this.refresh();
        }
      });
    return this.report;
  }
  private async trace(id: "cf", url: string) {
    const label = "Cloudflare 出口";
    try {
      const response = await this.read(url);
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
      const ip = /^ip=([^\r\n]+)$/m.exec(response.body)?.[1]?.trim() ?? "";
      if (!isIP(ip)) throw new Error("响应未包含有效 IP");
      this.item("exits", metric(id, label, ip, "neutral"));
      return ip;
    } catch (error) {
      this.item("exits", metric(id, label, "获取失败", "error", message(error)));
      return "";
    }
  }
  private setAvailability(
    id: string,
    sample: { label: string; status: number; ms: number; error?: string },
  ) {
    this.availability.set(id, sample);
    const detail = sample.error ?? `HTTP ${sample.status} · ${sample.ms} ms`;
    if (restricted.has(this.country)) {
      this.item("availability", metric(id, sample.label, "站点提示受限", "error", detail));
      return;
    }
    if (sample.status !== 200 || sample.error) {
      this.item("availability", metric(id, sample.label, "不可访问", "error", detail));
      return;
    }
    this.item(
      "availability",
      metric(
        id,
        sample.label,
        sample.ms < 250 ? "正常" : sample.ms < 500 ? "良好" : "较慢",
        sample.ms < 500 ? "ok" : "warning",
        detail,
      ),
    );
  }
  private async ipv6Probe(id: string, label: string, url: string, trace = false) {
    try {
      const response = await this.read(url, 8000, 6);
      if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
      const ip = trace
        ? (/^ip=([^\r\n]+)$/m.exec(response.body)?.[1]?.trim() ?? "")
        : response.body.trim();
      if (isIP(ip) !== 6) throw new Error("未取得有效 IPv6 地址");
      this.item("ipv6", metric(id, label, ip, "warning", "站点建议核查 IPv6 出口"));
    } catch (error) {
      const code: unknown =
        error !== null && typeof error === "object" && "code" in error ? error.code : undefined;
      const detail =
        code === "ENETUNREACH" || code === "EHOSTUNREACH"
          ? "未发现可用的 IPv6 路由"
          : code === "ENOTFOUND" || code === "ENOENT"
            ? "未取得 IPv6 DNS 记录"
            : error instanceof Error &&
                (error.name === "AbortError" || error.name === "TimeoutError")
              ? "IPv6 请求超时"
              : message(error);
      this.item("ipv6", metric(id, label, "未取得 IPv6", "unknown", detail));
    }
  }
  private async serviceStatus() {
    try {
      const data = z
        .object({
          overall_indicator: z
            .enum(["none", "minor", "major", "critical", "maintenance"])
            .optional(),
        })
        .parse(await this.json(`${base}/claude/status.json`));
      const indicator = data.overall_indicator;
      if (!indicator) {
        this.item("availability", unknown("service", "Claude 服务状态"));
        return;
      }
      const labels = {
        none: "全部服务正常",
        minor: "轻微故障",
        major: "重大故障",
        critical: "严重故障",
        maintenance: "维护中",
      };
      this.item(
        "availability",
        metric(
          "service",
          "Claude 服务状态",
          labels[indicator],
          indicator === "none"
            ? "ok"
            : indicator === "minor" || indicator === "maintenance"
              ? "warning"
              : "error",
        ),
      );
    } catch (error) {
      this.item("availability", unknown("service", "Claude 服务状态", message(error)));
    }
  }
  private async cn() {
    const errors: string[] = [];
    for (const url of ["https://2026.ip138.com/", "https://my.ip.cn/"]) {
      try {
        const response = await this.read(url, 5000);
        if (response.status !== 200) throw new Error(`HTTP ${response.status}`);
        const ip = response.body.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/)?.[0] ?? "";
        if (isIP(ip) !== 4) throw new Error("未返回 IPv4");
        this.item("exits", metric("cn", "国内出口", ip));
        return ip;
      } catch (error) {
        errors.push(message(error));
      }
    }
    this.item("exits", metric("cn", "国内出口", "获取失败", "error", errors.join("；")));
    return "";
  }
  private async geo(id: string, ip: string) {
    if (!ip) return;
    try {
      const geo = geoSchema.parse(await this.json(`${base}/api/geoip/${encodeURIComponent(ip)}`));
      if (id === "claude" && this.report.claudeIp !== ip) return;
      const group = this.report.groups.find((group) => group.id === "exits");
      const item = group?.items.find((item) => item.id === id);
      if (item)
        this.item("exits", {
          ...item,
          detail: [geo.country, geo.region, geo.city, geo.isp].filter(Boolean).join(" · "),
        });
    } catch (error) {
      if (id === "claude" && this.report.claudeIp !== ip) return;
      const item = this.report.groups
        .find((group) => group.id === "exits")
        ?.items.find((item) => item.id === id);
      if (item) this.item("exits", { ...item, detail: `地区信息：${message(error)}` });
    }
  }
  private async risk(ip: string) {
    if (!ip) {
      this.group("trust", "信任与地区", [
        unknown("score", "信任分", "Claude 出口获取失败"),
        unknown("support", "Claude 支持地区"),
      ]);
      return;
    }
    try {
      const data = riskSchema.parse(
        await this.json(`${base}/api/iprisk/${encodeURIComponent(ip)}`),
      );
      if (this.report.claudeIp !== ip) return;
      this.country = (data.countryCode ?? "").toUpperCase();
      this.report.claudeTimezone = data.timezone ?? "";
      const blockedRegion = restricted.has(this.country);
      const score = blockedRegion ? 0 : data.trust_score;
      const grade =
        score == null
          ? ""
          : score >= 95
            ? "极度纯净"
            : score >= 80
              ? "纯净"
              : score >= 50
                ? "良好"
                : score >= 25
                  ? "中性"
                  : "可疑";
      this.group("trust", "信任与地区", [
        score == null
          ? unknown("score", "信任分")
          : metric(
              "score",
              "信任分",
              `${score} / 100 · ${grade}`,
              score >= 80 ? "ok" : score >= 50 ? "info" : score >= 25 ? "warning" : "error",
            ),
        this.country
          ? metric(
              "support",
              "Claude 支持地区",
              blockedRegion ? "站点提示受限" : "站点提示支持",
              blockedRegion ? "error" : "ok",
              this.country,
            )
          : unknown("support", "Claude 支持地区"),
      ]);
      const residential =
        data.isResidential ?? (data.is_datacenter == null ? undefined : !data.is_datacenter);
      const kind = residential == null ? "未知" : residential ? "家庭住宅 IP" : "机房 IP";
      this.group("location", "IP 属性", [
        metric(
          "country",
          "地区",
          [data.country, data.region].filter(Boolean).join(" · ") || "未知",
        ),
        metric("city", "城市", data.city || "未知"),
        metric(
          "type",
          "IP 属性",
          kind,
          residential == null ? "unknown" : residential ? "ok" : "warning",
          [data.company_type, data.isBroadcast ? "广播 IP" : ""].filter(Boolean).join(" · "),
        ),
        metric(
          "asn",
          "ASN",
          data.asn == null ? "未知" : `AS${String(data.asn).replace(/^AS/i, "")}`,
        ),
        metric("isp", "运营商", data.asOrganization || data.company_name || "未知"),
        metric("timezone", "IP 时区", data.timezone || "未知"),
      ]);
      this.group("security", "安全属性", [
        boolean("vpn", "VPN", data.is_vpn),
        boolean("proxy", "代理", data.is_proxy),
        boolean("tor", "Tor", data.is_tor),
        boolean("crawler", "机器人", data.is_crawler),
        boolean("abuse", "滥用记录", data.is_abuser, "有记录", "无记录"),
      ]);
      for (const [id, sample] of this.availability) this.setAvailability(id, sample);
    } catch (error) {
      if (this.report.claudeIp !== ip) return;
      const detail = message(error);
      this.group("trust", "信任与地区", [
        unknown("score", "信任分", detail),
        unknown("support", "Claude 支持地区", detail),
      ]);
      this.group("location", "IP 属性", [unknown("result", "属性查询", detail)]);
      this.group("security", "安全属性", [unknown("result", "安全查询", detail)]);
    }
  }
  private async dns(riskReady: Promise<void>) {
    try {
      const token = randomUUID().replaceAll("-", "");
      await Promise.allSettled(
        [1, 2].map((index) =>
          this.read(`https://${token}-${index}.d.ip.net.coffee/pixel.gif`, 2500),
        ),
      );
      await delay(1500, undefined, { signal: this.abort.signal });
      let ips: string[] = [];
      for (let attempt = 0; attempt < 2; attempt++) {
        const result = dnsSchema.parse(await this.json(`${base}/api/dns/result/${token}`));
        ips = result.dns_servers.slice(0, 8);
        if (ips.length || attempt === 1) break;
        await delay(1500, undefined, { signal: this.abort.signal });
      }
      if (!ips.length) {
        this.group("dns", "DNS 出口", [unknown("status", "状态", "未观测到解析器出口")]);
        return;
      }
      await riskReady;
      const items = await Promise.all(
        ips.map(async (ip, index) => {
          try {
            const geo = geoSchema.parse(
              await this.json(`${base}/api/geoip/${encodeURIComponent(ip)}`),
            );
            const cc = (geo.country_code ?? "").toUpperCase();
            const known = Boolean(this.country && cc);
            const differs = known && cc === "CN" && this.country !== "CN";
            return metric(
              `dns-${index}`,
              "DNS 出口",
              ip,
              differs ? "warning" : known ? "ok" : "unknown",
              [geo.country, geo.isp, differs ? "中国 DNS 与非中国 Claude 出口组合" : ""]
                .filter(Boolean)
                .join(" · "),
            );
          } catch (error) {
            return metric(`dns-${index}`, "DNS 出口", ip, "unknown", message(error));
          }
        }),
      );
      const leaked = items.some((item) => item.status === "warning");
      const complete = items.every((item) => item.status === "ok");
      this.group("dns", "DNS 出口", [
        metric(
          "status",
          "状态",
          leaked ? "可能泄露" : complete ? "未检测到泄露" : "判定信息不完整",
          leaked ? "warning" : complete ? "ok" : "unknown",
          `观测到 ${ips.length} 个解析器`,
        ),
        ...items,
      ]);
    } catch (error) {
      this.group("dns", "DNS 出口", [
        metric("status", "状态", "检测失败", "error", message(error)),
      ]);
    }
  }
  private async collect() {
    const claude = this.claude.check().then((result) => {
      this.collectingIp = result.ip;
      this.applyClaude(result);
      return result.ip;
    });
    const cf = this.trace("cf", "https://1.1.1.1/cdn-cgi/trace");
    const cn = this.cn();
    const risk = claude.then((ip) => this.risk(ip));
    const availability = (async () => {
      try {
        const r = await this.read("https://www.anthropic.com/cdn-cgi/trace");
        this.setAvailability("anthropic", { label: "anthropic.com", status: r.status, ms: r.ms });
      } catch (error) {
        this.setAvailability("anthropic", {
          label: "anthropic.com",
          status: 0,
          ms: 0,
          error: message(error),
        });
      }
    })();
    await Promise.all([
      risk,
      cf.then((ip) => this.geo("cf", ip)),
      cn.then((ip) => this.geo("cn", ip)),
      claude.then((ip) => this.geo("claude", ip)),
      availability,
      this.dns(risk),
      this.serviceStatus(),
      this.ipv6Probe("public", "公网 IPv6", "https://api6.ipify.org"),
      this.ipv6Probe("cf", "Cloudflare IPv6", "https://one.one.one.one/cdn-cgi/trace", true),
      this.ipv6Probe("claude", "Claude IPv6", "https://claude.ai/cdn-cgi/trace", true),
    ]);
  }
}
