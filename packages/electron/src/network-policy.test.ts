import { describe, expect, it } from "vite-plus/test";

import {
  initialNetworkPolicy,
  localPolicyPorts,
  networkAction,
  networkPolicySchema,
} from "./network-policy.ts";

describe("global TCP policy", () => {
  it("permits only the explicit local development port by default", () => {
    for (const host of [
      "localhost",
      "127.0.0.1",
      "127.0.0.2",
      "127.1",
      "::1",
      "[::1]",
      "app.localhost",
    ])
      expect(networkAction(initialNetworkPolicy, { host, port: 5173 })).toBe("direct");
    expect(networkAction(initialNetworkPolicy, { host: "localhost", port: 7890 })).toBe("block");
    expect(networkAction(initialNetworkPolicy, { host: "api.deepseek.com", port: 443 })).toBe(
      "proxy",
    );
    expect(localPolicyPorts(initialNetworkPolicy)).toEqual([5173]);
  });
  it("matches an exact enabled host and port, without a suffix or port escape", () => {
    const policy = networkPolicySchema.parse({
      rules: [
        {
          id: "2d5a1941-e2ab-4ac6-9057-4729a480f091",
          enabled: true,
          host: "API.Example.com",
          port: 443,
          action: "block",
        },
        {
          id: "5ae45835-7d38-42c7-9f9a-b35575925d07",
          enabled: true,
          host: "192.168.1.8",
          port: 8080,
          action: "direct",
        },
      ],
    });
    expect(networkAction(policy, { host: "api.example.com", port: 443 })).toBe("block");
    expect(networkAction(policy, { host: "api.example.com.evil.test", port: 443 })).toBe("proxy");
    expect(networkAction(policy, { host: "api.example.com", port: 80 })).toBe("proxy");
    expect(networkAction(policy, { host: "192.168.1.8", port: 8080 })).toBe("direct");
    const first = policy.rules[0];
    if (!first) throw new Error("Fixture rule missing");
    policy.rules[0] = { ...first, enabled: false };
    expect(networkAction(policy, { host: "api.example.com", port: 443 })).toBe("proxy");
  });
  it("rejects duplicate aliases, invalid ports and malformed host inputs", () => {
    const base = initialNetworkPolicy.rules[0];
    if (!base) throw new Error("Default local rule missing");
    expect(
      networkPolicySchema.safeParse({
        rules: [base, { ...base, id: crypto.randomUUID(), host: "127.0.0.1" }],
      }).success,
    ).toBe(false);
    for (const host of [
      "http://localhost",
      "host/path",
      "user@host",
      "localhost:5173",
      "999.999.999.999",
      "a b",
    ])
      expect(networkPolicySchema.safeParse({ rules: [{ ...base, host }] }).success).toBe(false);
    for (const port of [0, 65536, 2.5])
      expect(networkPolicySchema.safeParse({ rules: [{ ...base, port }] }).success).toBe(false);
    expect(networkPolicySchema.safeParse({ rules: [{ ...base, action: "proxy" }] }).success).toBe(
      false,
    );
  });
});
