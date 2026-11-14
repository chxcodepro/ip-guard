import { isIP } from "node:net";
import { domainToASCII } from "node:url";

import { z } from "zod";

const record = z.record(z.string(), z.unknown());
const outboundSchema = record.and(z.object({ tag: z.string().optional() }));
const configSchema = z.object({ outbounds: z.array(outboundSchema).min(1) });
const xrayProtocols = new Set([
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "socks",
  "http",
  "hysteria",
]);
const singProtocols = new Set([
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "socks",
  "http",
  "hysteria2",
  "tuic",
  "anytls",
]);
export type NodeSnapshot = { engine: "xray" | "sing-box"; outbound: Record<string, unknown> };

export function nodeServers(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(nodeServers);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value).flatMap(([key, item]) => {
    if ((key === "address" || key === "server") && typeof item === "string") return [item];
    return nodeServers(item);
  });
}

function validateTree(value: unknown): void {
  if (Array.isArray(value)) {
    for (const item of value) validateTree(item);
  } else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (
        [
          "plugin",
          "plugin_opts",
          "dialerProxy",
          "proxySettings",
          "detour",
          "certificate_path",
          "key_path",
          "certificateFile",
          "keyFile",
        ].includes(key) &&
        item
      )
        throw new Error("该节点包含链式代理、插件或外部文件，请选择独立节点");
      if (["insecure", "allowInsecure"].includes(key) && item === true)
        throw new Error("固定出口要求验证 TLS 证书，请选择证书有效的节点");
      validateTree(item);
    }
  }
}

export function snapshotV2rayNode(input: unknown): NodeSnapshot {
  const { outbounds } = configSchema.parse(input);
  const xray = outbounds.some((entry) => typeof entry.protocol === "string");
  const protocols = xray ? xrayProtocols : singProtocols;
  let selected = outbounds.find((entry) => entry.tag === "proxy");
  if (!selected) {
    const candidates = outbounds.filter((entry) =>
      protocols.has(String(xray ? entry.protocol : entry.type)),
    );
    if (candidates.length !== 1)
      throw new Error("配置中无法确定唯一节点，请先在 v2rayN 选择一个普通节点");
    selected = candidates[0];
  }
  const seen = new Set<string>();
  while (selected && ["selector", "urltest"].includes(String(selected.type))) {
    const children = z.array(z.string()).parse(selected.outbounds);
    if (children.length !== 1 || seen.has(children[0] ?? ""))
      throw new Error("固定出口暂不导入自动选择或多节点组，请选择单个节点");
    const tag = children[0];
    if (!tag) throw new Error("节点组为空");
    seen.add(tag);
    selected = outbounds.find((entry) => entry.tag === tag);
  }
  if (!selected || !protocols.has(String(xray ? selected.protocol : selected.type)))
    throw new Error("当前节点类型暂不支持独立固定出口");
  validateTree(selected);
  const outbound = structuredClone(selected);
  delete outbound.tag;
  delete outbound.domain_resolver;
  delete outbound.domain_strategy;
  return { engine: xray ? "xray" : "sing-box", outbound };
}

export function coreConfiguration(node: NodeSnapshot, port: number): Record<string, unknown> {
  z.number().int().min(1024).max(65535).parse(port);
  if (node.engine === "xray") {
    const stream = record.parse(node.outbound.streamSettings ?? {});
    const sockopt = record.parse(stream.sockopt ?? {});
    const bootstrap = [
      ...new Set(
        nodeServers(node.outbound.settings)
          .filter((value) => !isIP(value))
          .map(domainToASCII)
          .filter(Boolean),
      ),
    ];
    return {
      log: { loglevel: "none" },
      dns: {
        servers: [
          ...(bootstrap.length
            ? [
                {
                  address: "https+local://1.1.1.1/dns-query",
                  domains: bootstrap.map((domain) => `full:${domain}`),
                  skipFallback: true,
                },
              ]
            : []),
          "https://1.1.1.1/dns-query",
        ],
        queryStrategy: "UseIPv4",
        disableFallback: true,
      },
      inbounds: [{ tag: "guard-http", listen: "127.0.0.1", port, protocol: "http", settings: {} }],
      outbounds: [
        {
          ...node.outbound,
          tag: "fixed",
          targetStrategy: "ForceIPv4",
          streamSettings: { ...stream, sockopt: { ...sockopt, domainStrategy: "ForceIPv4" } },
        },
        { tag: "blocked", protocol: "blackhole", settings: {} },
      ],
      routing: {
        rules: [
          { type: "field", ip: ["::/0"], outboundTag: "blocked" },
          { type: "field", inboundTag: ["guard-http"], outboundTag: "fixed" },
        ],
      },
    };
  }
  const remote = z.string().min(1).parse(node.outbound.server);
  return {
    log: { disabled: true },
    dns: {
      servers: [
        { type: "https", tag: "egress-dns", server: "1.1.1.1", detour: "fixed" },
        { type: "https", tag: "bootstrap", server: "1.1.1.1" },
      ],
      final: "egress-dns",
      strategy: "ipv4_only",
    },
    inbounds: [{ type: "http", tag: "guard-http", listen: "127.0.0.1", listen_port: port }],
    outbounds: [
      {
        ...node.outbound,
        tag: "fixed",
        ...(isIP(remote)
          ? {}
          : { domain_resolver: { server: "bootstrap", strategy: "ipv4_only" } }),
      },
    ],
    route: {
      default_domain_resolver: "egress-dns",
      rules: [
        { action: "resolve", strategy: "ipv4_only" },
        { ip_version: 6, action: "reject" },
      ],
      final: "fixed",
    },
  };
}
