import { describe, expect, it, vi } from "vite-plus/test";

import { coreConfiguration, snapshotMihomoNode } from "./egress-config.ts";
import { automaticNode, inboundPorts, proxyEngine } from "./forced-proxy.ts";

vi.mock("electron", () => ({ app: { isPackaged: false, getPath: () => "/unused-fixture" } }));
import {
  MihomoGroupRequired,
  mihomoApiSchema,
  mihomoController,
  mihomoReservedPorts,
  parseMihomoProfile,
  selectMihomoNode,
} from "./mihomo-config.ts";

const source = `
mixed-port: 7890
external-controller: 127.0.0.1:9090
secret: fixture-control-secret
proxies:
  - &remote
    name: remote-a
    type: trojan
    server: node.example
    port: 443
    password: fixture-proxy-password
    skip-cert-verify: false
  - <<: *remote
    name: remote-b
proxy-groups:
  - name: AI
    type: select
    proxies: [remote-a, remote-b, DIRECT]
rules: ["GEOIP,CN,DIRECT"]
`;
const api = mihomoApiSchema.parse({
  proxies: {
    AI: { type: "Selector", now: "remote-b" },
    "remote-a": { type: "Trojan" },
    "remote-b": { type: "Trojan" },
    DIRECT: { type: "Direct" },
  },
});
describe("Mihomo private route", () => {
  it("loads YAML aliases and follows the actual current node of a unique group", () => {
    const profile = parseMihomoProfile(source);
    expect(profile.proxies[1]?.password).toBe("fixture-proxy-password");
    expect(selectMihomoNode(profile, api).name).toBe("remote-b");
    expect(proxyEngine("C:\\Proxy\\verge-mihomo.exe")).toBe("mihomo");
    expect(proxyEngine("C:\\Proxy\\mihomo-windows-amd64.exe")).toBe("mihomo");
    expect(proxyEngine("C:\\Proxy\\xray.exe")).toBe("xray");
  });
  it("requests an explicit group rather than guessing among multiple independent policies", () => {
    const profile = parseMihomoProfile(source + "\n");
    profile["proxy-groups"].push({ name: "Other", proxies: ["remote-a"] });
    const choices = mihomoApiSchema.parse({
      proxies: { ...api.proxies, Other: { type: "Selector", now: "remote-a" } },
    });
    expect(() => selectMihomoNode(profile, choices)).toThrow(MihomoGroupRequired);
    expect(() =>
      selectMihomoNode({ ...profile, proxies: profile.proxies.slice(0, 1) }, choices),
    ).toThrow(MihomoGroupRequired);
    expect(selectMihomoNode(profile, choices, "Other").name).toBe("remote-a");
    choices.proxies.AI = { type: "Selector", now: "DIRECT" };
    expect(() => selectMihomoNode(profile, choices, "AI")).toThrow("直连或拒绝");
    expect(() => selectMihomoNode(profile, choices, "Removed")).toThrow("已保存的");
    choices.proxies.AI = { type: "Selector", now: "AI" };
    expect(() => selectMihomoNode(profile, choices, "AI")).toThrow("循环");
    choices.proxies.AI = { type: "LoadBalance", now: "remote-a" };
    expect(() => selectMihomoNode(profile, choices, "AI")).toThrow("负载均衡");
  });
  it("uses only local controllers, including Verge named pipes and IPv6-only localhost", () => {
    const profile = parseMihomoProfile(source);
    expect(mihomoController(profile)).toEqual({ kind: "tcp", port: 9090, hosts: ["127.0.0.1"] });
    for (const address of ["localhost:9090", "[::1]:9090", "0.0.0.0:80", ":9090"]) {
      expect(mihomoController({ ...profile, "external-controller": address }).kind).toBe("tcp");
    }
    expect(mihomoController({ ...profile, "external-controller": "localhost:9090" })).toMatchObject(
      { hosts: ["127.0.0.1", "::1"] },
    );
    const pipe = String.raw`\\.\pipe\verge-mihomo`;
    expect(mihomoController({ ...profile, "external-controller-pipe": pipe })).toEqual({
      kind: "pipe",
      path: pipe,
    });
    for (const address of [
      "example.com:9090",
      "127.0.0.1:0",
      "127.0.0.1:65536",
      "user@127.0.0.1:9090",
      "127.0.0.1:9090/path",
    ])
      expect(() => mihomoController({ ...profile, "external-controller": address })).toThrow();
    for (const path of [String.raw`\\server\pipe\mihomo`, "\\\\.\\pipe\\", "invalid"])
      expect(() => mihomoController({ ...profile, "external-controller-pipe": path })).toThrow();
  });
  it("reserves every declared proxy and controller port against local development exceptions", () => {
    expect(inboundPorts({ outbounds: [] })).toEqual([]);
    const profile = parseMihomoProfile(
      source +
        "\nsocks-port: 7891\nredir-port: 7892\nlisteners:\n - {name: other, type: http, port: 7893}\n",
    );
    expect(mihomoReservedPorts(profile).sort((a, b) => a - b)).toEqual([
      7890, 7891, 7892, 7893, 9090,
    ]);
    expect(
      inboundPorts({
        inbounds: [
          { protocol: "http", port: 10808 },
          { type: "socks", listen_port: 10809 },
        ],
      }),
    ).toEqual([10808, 10809]);
  });
  it("replaces mainland bypass, TUN and controller settings with one private listener and one proxy", () => {
    const profile = parseMihomoProfile(source);
    const selected = profile.proxies[0];
    if (!selected) throw new Error("Fixture proxy missing");
    const node = automaticNode(selected, "mihomo");
    const config = coreConfiguration(node, 18081);
    expect(config).toMatchObject({
      "external-controller": "",
      tun: { enable: false },
      ipv6: false,
      listeners: [{ type: "http", listen: "127.0.0.1", port: 18081, proxy: "fixed" }],
      proxies: [{ name: "fixed", server: "node.example", "ip-version": "ipv4" }],
      rules: ["MATCH,fixed"],
    });
    expect(JSON.stringify(config)).not.toContain("fixture-control-secret");
    expect(JSON.stringify(config)).not.toContain("GEOIP");
    expect(config.dns).toMatchObject({
      nameserver: ["https://1.1.1.1/dns-query#fixed"],
      "proxy-server-nameserver": ["https://1.1.1.1/dns-query#DIRECT"],
    });
  });
  it("rejects chain dependencies, external certificates, invalid TLS flags and local proxy relays", () => {
    const node = {
      name: "test",
      type: "trojan",
      server: "node.example",
      port: 443,
      password: "fixture",
    };
    for (const value of [true, "true", "false"])
      expect(() => snapshotMihomoNode({ ...node, "skip-cert-verify": value })).toThrow();
    expect(() => snapshotMihomoNode({ ...node, "dialer-proxy": "upstream" })).toThrow();
    expect(() => snapshotMihomoNode({ ...node, ca: "private-ca.pem" })).toThrow();
    expect(() => automaticNode({ ...node, server: "127.0.0.1" }, "mihomo")).toThrow("远程节点");
    expect(() => parseMihomoProfile("secret: first\nsecret: second\n")).toThrow("配置格式无效");
  });
});
