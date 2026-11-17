import { describe, expect, it, vi } from "vite-plus/test";

vi.mock("electron", () => ({ app: {} }));
import { coreConfiguration } from "./egress-config.ts";
import { automaticNode, proxyDiscoveryIssue } from "./forced-proxy.ts";

describe("automatic per-program force-proxy route", () => {
  it("distinguishes a starting core and a slow lookup from an invalid configuration", () => {
    expect(
      proxyDiscoveryIssue({ stderr: "IPGUARD_DISCOVERY: Proxy listener is unavailable\r\n" }),
    ).toBe("本机代理端口尚未监听，等待代理核心启动");
    expect(proxyDiscoveryIssue({ killed: true })).toBe("代理核心查询超时，请稍后重试");
    expect(
      proxyDiscoveryIssue({ stderr: "IPGUARD_DISCOVERY: Proxy listener process exited" }),
    ).toBe("代理核心已退出，请稍后重试");
    expect(
      proxyDiscoveryIssue({
        stderr: "IPGUARD_DISCOVERY: One explicit configuration file is required",
      }),
    ).toBe("Xray / sing-box 启动参数缺少唯一配置文件");
  });
  it("discards mainland direct rules and binds the dedicated inbound to the selected proxy", () => {
    const node = automaticNode(
      {
        inbounds: [{ tag: "shared", port: 7890, protocol: "mixed" }],
        outbounds: [
          {
            tag: "proxy",
            protocol: "vless",
            settings: {
              vnext: [{ address: "proxy.example", port: 443, users: [{ id: "fixture-only" }] }],
            },
          },
          { tag: "direct", protocol: "freedom" },
        ],
        routing: {
          rules: [
            { domain: ["geosite:cn"], outboundTag: "direct" },
            { ip: ["geoip:cn"], outboundTag: "direct" },
          ],
        },
      },
      "xray",
    );
    const route = coreConfiguration(node, 19001);
    expect(route).toMatchObject({
      inbounds: [{ tag: "guard-http", listen: "127.0.0.1", port: 19001 }],
      routing: {
        rules: [
          { type: "field", ip: ["::/0"], outboundTag: "blocked" },
          { type: "field", inboundTag: ["guard-http"], outboundTag: "fixed" },
        ],
      },
    });
    expect(JSON.stringify(route)).not.toMatch(/geosite:cn|geoip:cn|freedom|"direct"/);
  });
  it("keeps sing-box forced to its proxy outbound rather than the source split-route final", () => {
    const node = automaticNode(
      {
        outbounds: [
          { tag: "proxy", type: "trojan", server: "proxy.example", server_port: 443 },
          { tag: "direct", type: "direct" },
        ],
        route: { final: "direct" },
      },
      "sing-box",
    );
    expect(coreConfiguration(node, 19001)).toMatchObject({
      route: { final: "fixed" },
      outbounds: [{ tag: "fixed", type: "trojan" }],
    });
  });
  it.each(["127.0.0.1", "192.168.1.1", "10.0.0.1", "localhost", "::1"])(
    "refuses a local node %s that could reapply the original split routing",
    (server) => {
      expect(() =>
        automaticNode(
          { outbounds: [{ tag: "proxy", type: "socks", server, server_port: 7890 }] },
          "sing-box",
        ),
      ).toThrow();
    },
  );
  it("refuses a mismatched core type, ambiguous selectors and a direct outbound", () => {
    expect(() =>
      automaticNode(
        { outbounds: [{ protocol: "vless", settings: { vnext: [{ address: "proxy.example" }] } }] },
        "sing-box",
      ),
    ).toThrow();
    expect(() =>
      automaticNode(
        { outbounds: [{ type: "selector", tag: "proxy", outbounds: ["a", "b"] }] },
        "sing-box",
      ),
    ).toThrow();
    expect(() =>
      automaticNode({ outbounds: [{ type: "direct", tag: "proxy" }] }, "sing-box"),
    ).toThrow();
  });
});
