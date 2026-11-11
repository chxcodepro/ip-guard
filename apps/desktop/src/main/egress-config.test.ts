import { describe, expect, it } from "vite-plus/test";

import { coreConfiguration, snapshotV2rayNode } from "./egress-config.ts";

describe("fixed node import boundary", () => {
  it("discards v2rayN routing, TUN and direct outbounds", () => {
    const remote = {
      type: "vless",
      tag: "proxy",
      server: "proxy.example",
      server_port: 443,
      uuid: "local-secret",
    };
    const source = {
      inbounds: [{ type: "tun" }],
      outbounds: [remote, { type: "direct", tag: "direct" }],
      route: { final: "direct" },
    };
    const node = snapshotV2rayNode(source);
    remote.server = "changed.example";
    const built = coreConfiguration(node, 18081);
    expect(built).toMatchObject({
      inbounds: [{ type: "http", listen: "127.0.0.1", listen_port: 18081 }],
      outbounds: [{ type: "vless", server: "proxy.example", tag: "fixed" }],
      route: {
        final: "fixed",
        rules: [
          { action: "resolve", strategy: "ipv4_only" },
          { ip_version: 6, action: "reject" },
        ],
      },
    });
    expect(JSON.stringify(built)).not.toContain('"direct"');
  });

  it("forces Xray IPv4 without an AsIs resolution fallback", () => {
    const config = coreConfiguration(
      snapshotV2rayNode({ outbounds: [{ protocol: "vless", tag: "proxy", settings: {} }] }),
      18081,
    );
    expect(config).toMatchObject({
      outbounds: [
        {
          targetStrategy: "ForceIPv4",
          streamSettings: { sockopt: { domainStrategy: "ForceIPv4" } },
        },
        { protocol: "blackhole" },
      ],
    });
  });

  it("bootstraps the proxy host outside the tunnel while resolving targets inside it", () => {
    const config = coreConfiguration(
      snapshotV2rayNode({
        outbounds: [
          {
            protocol: "vless",
            tag: "proxy",
            settings: { vnext: [{ address: "node.example", port: 443 }] },
          },
        ],
      }),
      18081,
    );
    expect(config).toMatchObject({
      dns: {
        servers: [
          {
            address: "https+local://1.1.1.1/dns-query",
            domains: ["full:node.example"],
            skipFallback: true,
          },
          "https://1.1.1.1/dns-query",
        ],
      },
    });
  });

  it.each([
    { outbounds: [{ type: "selector", tag: "proxy", outbounds: ["a", "b"] }] },
    { outbounds: [{ type: "vless", tag: "proxy", tls: { insecure: true } }] },
    {
      outbounds: [
        {
          protocol: "trojan",
          tag: "proxy",
          streamSettings: { tlsSettings: { allowInsecure: true } },
        },
      ],
    },
    { outbounds: [{ type: "vless", tag: "proxy", detour: "direct" }] },
    { outbounds: [{ protocol: "freedom", tag: "proxy" }] },
    { outbounds: [{ type: "shadowsocks", tag: "proxy", plugin: "external.exe" }] },
  ])("rejects automatic switching, bypasses and unverified TLS", (input) => {
    expect(() => snapshotV2rayNode(input)).toThrow();
  });
});
