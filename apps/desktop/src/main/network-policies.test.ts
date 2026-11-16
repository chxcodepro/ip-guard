import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { NetworkPolicies } from "./network-policies.ts";

vi.mock("./guard-data.ts", () => ({
  guardDataDirectory: () => {
    const folder = process.env.IPGUARD_POLICY_TEST_DIR;
    if (!folder) throw new Error("Test policy directory missing");
    return folder;
  },
}));

const folders: string[] = [];
afterEach(async () => {
  delete process.env.IPGUARD_POLICY_TEST_DIR;
  for (const folder of folders.splice(0)) {
    if (!folder.startsWith(path.join(tmpdir(), "ipguard-policy-")))
      throw new Error("Unsafe test path");
    await rm(folder, { recursive: true, force: true });
  }
});

describe("saved network policy migration", () => {
  it("turns on default loopback access once and preserves prior rules in a backup", async () => {
    const folder = await mkdtemp(path.join(tmpdir(), "ipguard-policy-"));
    folders.push(folder);
    process.env.IPGUARD_POLICY_TEST_DIR = folder;
    const legacy = {
      revision: crypto.randomUUID(),
      settings: {
        rules: [
          {
            id: crypto.randomUUID(),
            enabled: true,
            host: "localhost",
            port: 5173,
            action: "direct",
          },
        ],
      },
    };
    const file = path.join(folder, "network-policy.json");
    await writeFile(file, JSON.stringify(legacy));
    const policies = new NetworkPolicies();
    await policies.initialize();
    expect(policies.record.settings).toEqual({ ...legacy.settings, loopbackDirect: true });
    expect(policies.record.revision).not.toBe(legacy.revision);
    expect(JSON.parse(await readFile(file, "utf8"))).toEqual(policies.record);
    expect(JSON.parse(await readFile(file + ".bak", "utf8"))).toEqual(legacy);
    const revision = policies.record.revision;
    await policies.initialize();
    expect(policies.record.revision).toBe(revision);
    const malformed = JSON.stringify({
      ...policies.record,
      settings: { ...policies.record.settings, loopbackDirect: "yes" },
    });
    await writeFile(file, malformed);
    const rejected = new NetworkPolicies();
    await rejected.initialize();
    expect(rejected.error).toContain("读取失败");
    expect(await readFile(file, "utf8")).toBe(malformed);
  });
});
