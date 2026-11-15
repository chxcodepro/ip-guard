import { describe, expect, it } from "vite-plus/test";

import { settingsSchema } from "./index.ts";
import {
  claudeIpv4Endpoint,
  ipv4Sources,
  ipv4SourceUrlSchema,
  parseIpv4Response,
} from "./ipv4-source.ts";

describe("IPv4 API sources", () => {
  it("retains Claude for deployed settings and accepts each HTTPS preset", () => {
    expect(settingsSchema.parse({ expectedIps: ["8.8.8.8"], intervalSeconds: 5 }).ipv4Url).toBe(
      claudeIpv4Endpoint,
    );
    for (const source of ipv4Sources)
      expect(ipv4SourceUrlSchema.parse(source.url)).toBe(source.url);
    expect(ipv4SourceUrlSchema.parse("https://example.com/api?format=json")).toBe(
      "https://example.com/api?format=json",
    );
  });
  it("rejects insecure, local, credential-bearing and fragmented URLs", () => {
    for (const url of [
      "http://example.com/ip",
      "file:///ip",
      "https://user:pass@example.com/ip",
      "https://127.0.0.1/ip",
      "https://192.168.1.2/ip",
      "https://localhost/ip",
      "https://router.local/ip",
      "https://example.com/ip#secret",
    ])
      expect(ipv4SourceUrlSchema.safeParse(url).success).toBe(false);
  });
  it.each([
    "8.8.8.8\n",
    '{"ip":"8.8.8.8"}',
    '{"query":"8.8.8.8"}',
    '{"data":{"ipv4":"8.8.8.8"}}',
    '{"ip_address":"8.8.8.8"}',
    '{"ip":"8.8.8.8","ipv4":"8.8.8.8"}',
    "fl=sample\nh=1.1.1.1\nip=8.8.8.8\nloc=US\n",
    "当前 IP：8.8.8.8  来自于：测试地区\n",
  ])("reads only the response's public IPv4: %s", (body) => {
    expect(parseIpv4Response(body)).toBe("8.8.8.8");
  });
  it.each([
    "",
    "2001:4860:4860::8888",
    "127.0.0.1",
    '{"ip":"10.0.0.1"}',
    '{"ip":"8.8.8.8","query":"1.1.1.1"}',
    "<html>server: 8.8.8.8</html>",
    'callback({"ip":"8.8.8.8"})',
    "{bad JSON",
  ])("refuses ambiguous or unsupported data: %s", (body) => {
    expect(() => parseIpv4Response(body)).toThrow();
  });
});
