import { describe, expect, it } from "vite-plus/test";

import { ipv4Sources } from "@ip-guard/electron";

import {
  destination,
  proxyEndpoint,
  systemProxyEndpoint,
  exitProbeTargets,
} from "./proxy-tunnel.ts";

describe("generic proxy boundary", () => {
  it("allows the selected IPv4 source in the probe listener without opening arbitrary targets", () => {
    for (const source of ipv4Sources) {
      const url = new URL(source.url),
        targets = exitProbeTargets(source.url);
      expect(targets.has(url.hostname + ":" + (url.port || 443))).toBe(true);
      expect(targets.has("unselected.example:443")).toBe(false);
      expect(targets.has(url.hostname + ":8080")).toBe(false);
    }
    expect(exitProbeTargets("https://sample.example:8443/ip").has("sample.example:8443")).toBe(
      true,
    );
  });
  it("accepts standard local HTTP and SOCKS5 independently of proxy brand", () => {
    expect(proxyEndpoint("http://127.0.0.1:7890")).toEqual({
      protocol: "http",
      host: "127.0.0.1",
      port: 7890,
    });
    expect(systemProxyEndpoint("SOCKS5 127.0.0.1:1080; DIRECT")).toEqual({
      protocol: "socks5",
      host: "127.0.0.1",
      port: 1080,
    });
    expect(systemProxyEndpoint("PROXY [::1]:8080")).toEqual({
      protocol: "http",
      host: "::1",
      port: 8080,
    });
  });
  it("rejects DIRECT fallback, malformed endpoints and embedded credentials", () => {
    for (const route of [
      "DIRECT",
      "DIRECT; PROXY 127.0.0.1:7890",
      "HTTPS proxy:443",
      "PROXY host:0",
    ])
      expect(() => systemProxyEndpoint(route)).toThrow();
    for (const address of [
      "socks5://127.0.0.1",
      "http://user:secret@host:80",
      "http://host:80/path",
      "file:///proxy",
    ])
      expect(() => proxyEndpoint(address)).toThrow();
  });
  it("retains remote DNS and rejects invalid destinations", () => {
    expect(destination("example.com:443")).toEqual({ host: "example.com", port: 443 });
    expect(destination("api.deepseek.com:443")).toEqual({ host: "api.deepseek.com", port: 443 });
    expect(destination("www.baidu.com:443")).toEqual({ host: "www.baidu.com", port: 443 });
    expect(destination("180.101.49.12:443")).toEqual({ host: "180.101.49.12", port: 443 });
    expect(destination("203.0.113.1:80")).toEqual({ host: "203.0.113.1", port: 80 });
    expect(destination("[::1]:5173")).toEqual({ host: "::1", port: 5173 });
    for (const value of [
      "example.com",
      "example.com:0",
      "name@host:80",
      "host:65536",
      "[2001:db8::1]:443",
      "host:443\r\nInjected",
    ])
      expect(() => destination(value)).toThrow();
  });
});
