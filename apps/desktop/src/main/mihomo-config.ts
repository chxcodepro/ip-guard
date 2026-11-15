import { parseDocument } from "yaml";
import { z } from "zod";

const record = z.record(z.string(), z.unknown());
const proxy = record.and(z.object({ name: z.string().min(1).max(256), type: z.string() }));
const group = z.object({
  name: z.string().min(1).max(256),
  proxies: z.array(z.string()).default([]),
});
export const mihomoProfileSchema = record.and(
  z.object({
    proxies: z.array(proxy).default([]),
    "proxy-groups": z.array(group).default([]),
    "proxy-providers": z.record(z.string(), record).default({}),
  }),
);
export type MihomoProfile = z.infer<typeof mihomoProfileSchema>;
export type MihomoController =
  | { kind: "tcp"; port: number; hosts: ("127.0.0.1" | "::1")[] }
  | { kind: "pipe"; path: string };
export function mihomoController(profile: MihomoProfile): MihomoController {
  const pipe = profile["external-controller-pipe"];
  if (pipe !== undefined && pipe !== "") {
    if (
      typeof pipe !== "string" ||
      pipe.length > 256 ||
      !pipe.toLowerCase().startsWith("\\\\.\\pipe\\") ||
      pipe.length <= 9 ||
      /[\r\n\0]/u.test(pipe)
    )
      throw new Error("Mihomo 控制管道需使用本机命名管道路径。");
    return { kind: "pipe", path: pipe };
  }
  const address = profile["external-controller"];
  if (typeof address !== "string" || !address)
    throw new Error("Mihomo 需启用本机 HTTP 或命名管道控制 API，原配置保持。");
  let url: URL;
  try {
    url = new URL("http://" + (/^:\d+$/u.test(address) ? "127.0.0.1" + address : address));
  } catch {
    throw new Error("Mihomo 本机控制 API 地址无效。");
  }
  const host = url.hostname.replace(/^\[|\]$/gu, ""),
    port = Number(/:(\d+)$/u.exec(address)?.[1]);
  if (
    !["127.0.0.1", "localhost", "0.0.0.0", "::1", "::"].includes(host) ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65535 ||
    url.username ||
    url.password ||
    url.pathname !== "/" ||
    url.search ||
    url.hash
  )
    throw new Error("Mihomo 控制 API 需使用本机回环地址和有效端口。");
  return {
    kind: "tcp",
    port,
    hosts: host === "localhost" ? ["127.0.0.1", "::1"] : [host.includes(":") ? "::1" : "127.0.0.1"],
  };
}
export function mihomoReservedPorts(profile: MihomoProfile): number[] {
  const values = ["mixed-port", "port", "socks-port", "redir-port", "tproxy-port"].map(
    (field) => profile[field],
  );
  if (Array.isArray(profile.listeners))
    for (const listener of profile.listeners) {
      const entry = record.safeParse(listener);
      if (entry.success) values.push(entry.data.port);
    }
  const controller = profile["external-controller"];
  if (typeof controller === "string") values.push(Number(/:(\d+)$/u.exec(controller)?.[1]));
  return [
    ...new Set(
      values.filter(
        (value): value is number =>
          typeof value === "number" && Number.isInteger(value) && value > 0 && value <= 65535,
      ),
    ),
  ];
}
export const mihomoApiSchema = z.object({
  proxies: z.record(
    z.string(),
    z.object({
      type: z.string(),
      now: z.string().optional(),
      "provider-name": z.string().optional(),
    }),
  ),
});
export type MihomoApi = z.infer<typeof mihomoApiSchema>;
export class MihomoGroupRequired extends Error {
  readonly groups: string[];
  constructor(groups: string[], message?: string) {
    super(
      message ??
        (groups.length
          ? "Mihomo 有多个策略组，请在代理设置中选择供 Claude 使用的组。"
          : "Mihomo 未提供可选择的策略组，请在客户端建立普通节点选择组。"),
    );
    this.groups = groups;
  }
}
export function parseMihomoProfile(text: string): MihomoProfile {
  try {
    const doc = parseDocument(text, {
      prettyErrors: false,
      uniqueKeys: true,
      merge: true,
      logLevel: "silent",
    });
    if (doc.errors.length) throw new Error("Invalid YAML");
    const data: unknown = doc.toJS({ maxAliasCount: 100 });
    return mihomoProfileSchema.parse(data);
  } catch {
    throw new Error("Mihomo 配置格式无效或别名展开过多，请检查当前配置。");
  }
}
export function selectMihomoNode(profile: MihomoProfile, api: MihomoApi, selectedGroup?: string) {
  const groups = profile["proxy-groups"]
    .map((item) => item.name)
    .filter((name) => api.proxies[name]?.now);
  if (api.proxies.GLOBAL?.now && profile.mode === "global") groups.unshift("GLOBAL");
  let selected = selectedGroup;
  if (selected && !groups.includes(selected))
    throw new MihomoGroupRequired(groups, "已保存的 Mihomo 代理组不存在，请重新选择。");
  if (!selected) {
    if (profile.mode === "global" && groups.includes("GLOBAL")) selected = "GLOBAL";
    else if (groups.length === 1) selected = groups[0];
    else if (
      !groups.length &&
      !Object.keys(profile["proxy-providers"]).length &&
      profile.proxies.length === 1
    )
      selected = profile.proxies[0]?.name;
    else throw new MihomoGroupRequired(groups);
  }
  const seen = new Set<string>();
  while (selected) {
    if (seen.has(selected)) throw new Error("Mihomo 策略组存在循环，请选择普通代理组。");
    seen.add(selected);
    const entry = api.proxies[selected];
    if (!entry) throw new Error("当前 Mihomo 节点已失效，请刷新策略组。");
    if (["DIRECT", "REJECT", "REJECTDROP", "PASS", "COMPATIBLE"].includes(entry.type.toUpperCase()))
      throw new Error("Mihomo 当前组使用直连或拒绝，请选择远程代理节点。");
    if (entry.type === "LoadBalance")
      throw new Error("Mihomo 负载均衡组会按连接选择出口，请选择固定节点组。");
    if (entry.now) {
      selected = entry.now;
      continue;
    }
    if (["Selector", "URLTest", "Fallback", "LoadBalance"].includes(entry.type))
      throw new Error("当前 Mihomo 组无法确定单个节点，请选择固定节点组。");
    return { name: selected, provider: entry["provider-name"], groups };
  }
  throw new Error("Mihomo 策略组未返回当前节点。");
}
