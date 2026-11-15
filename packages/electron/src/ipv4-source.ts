import { z } from "zod";

import { publicIPv4Schema } from "./ipv4-policy.ts";

export const claudeIpv4Endpoint = "https://claude.ai/cdn-cgi/trace";
export const ipv4Sources = [
  { label: "Claude AI（默认）", url: claudeIpv4Endpoint },
  { label: "ipify", url: "https://api.ipify.org/?format=json" },
  { label: "IPIP.NET", url: "https://myip.ipip.net/" },
  { label: "icanhazip", url: "https://ipv4.icanhazip.com/" },
  { label: "Amazon Check IP", url: "https://checkip.amazonaws.com/" },
  { label: "Cloudflare", url: "https://1.1.1.1/cdn-cgi/trace" },
  { label: "ident.me", url: "https://v4.ident.me/" },
];

export const ipv4SourceUrlSchema = z
  .string()
  .trim()
  .min(1, "请填写 IPv4 API 网址")
  .max(2048, "IPv4 API 网址过长")
  .refine((value) => {
    try {
      const url = new URL(value);
      if (url.protocol !== "https:" || url.username || url.password || value.includes("#"))
        return false;
      const host = url.hostname.replace(/\.$/u, "");
      if (z.ipv4().safeParse(host).success) return publicIPv4Schema.safeParse(host).success;
      return (
        /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/iu.test(host) &&
        !/\.(?:localhost|local|internal)$/iu.test(host)
      );
    } catch {
      return false;
    }
  }, "请使用公开 HTTPS API 网址，去掉账号、密码或锚点")
  .transform((value) => new URL(value).href);

export function parseIpv4Response(body: string): string {
  const text = body.trim();
  if (publicIPv4Schema.safeParse(text).success) return text;
  let candidates: unknown[] = [];
  if (text.startsWith("{")) {
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch {
      throw new Error("IPv4 接口返回无效 JSON");
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const data = Reflect.get(value, "data");
      for (const object of [value, data])
        if (object && typeof object === "object" && !Array.isArray(object))
          for (const key of ["ip", "ipv4", "query", "ip_address", "ip_addr"])
            candidates.push(Reflect.get(object, key));
    }
  } else {
    candidates = [...text.matchAll(/^ip=([^\r\n]*)$/gmu)].map((match) => match[1]);
    const domestic = /^当前\s*IP\s*[：:]\s*(\d{1,3}(?:\.\d{1,3}){3})(?=\s|$|[，,])/u.exec(text);
    if (domestic) candidates.push(domestic[1]);
  }
  const ips = new Set<string>();
  for (const value of candidates) {
    const parsed = publicIPv4Schema.safeParse(value);
    if (parsed.success) ips.add(parsed.data);
  }
  const [ip] = ips;
  if (ips.size === 1 && ip !== undefined) return ip;
  throw new Error(
    ips.size > 1 ? "接口返回多个不同 IPv4，请选择只返回出口 IP 的 API" : "接口未返回有效公网 IPv4",
  );
}
