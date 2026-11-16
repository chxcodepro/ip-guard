import { randomUUID } from "node:crypto";
import { readFile, mkdir, writeFile, rename, copyFile } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import {
  initialNetworkPolicy,
  networkAction,
  networkPolicySchema,
  networkRuleSchema,
  localExceptionPorts,
  networkHost,
} from "@ip-guard/electron";
import type { NetworkPolicy, Snapshot, NetworkPolicyState } from "@ip-guard/electron";

import { guardDataDirectory } from "./guard-data.ts";
import { ProxyRequestError } from "./http-proxy.ts";
import { openDirect, openTunnel } from "./proxy-tunnel.ts";
import type { ProxyEndpoint } from "./proxy-tunnel.ts";

const recordSchema = z.object({ revision: z.uuid(), settings: networkPolicySchema });
// Pre-default-loopback records have only rules; retain them through a one-time backed-up migration.
const legacyRecordSchema = z
  .object({
    revision: z.uuid(),
    settings: z.object({ rules: z.array(networkRuleSchema).max(64) }).strict(),
  })
  .strict();
export type NetworkPolicyRecord = z.infer<typeof recordSchema>;
const policyFile = () => path.join(guardDataDirectory(), "network-policy.json");
export class NetworkPolicies {
  record: NetworkPolicyRecord = {
    revision: randomUUID(),
    settings: structuredClone(initialNetworkPolicy),
  };
  private loadError = "";
  applying = false;
  private observedRevision = "";
  observeKernel(revision: string) {
    this.observedRevision = revision;
  }
  get confirmed() {
    return this.observedRevision === this.record.revision;
  }
  fail(message: string) {
    this.loadError = message;
  }
  private reservations = new Map<"enhancement" | "fixed", number[]>();
  get error() {
    if (this.loadError) return this.loadError;
    try {
      this.validate(this.record.settings);
      return "";
    } catch (error) {
      return error instanceof Error ? error.message : "本机规则与代理端口冲突";
    }
  }
  reserve(owner: "enhancement" | "fixed", ports: number[]) {
    this.reservations.set(owner, ports);
  }
  validate(settings: NetworkPolicy) {
    const reserved = new Set([...this.reservations.values()].flat());
    if (localExceptionPorts(settings).some((port) => reserved.has(port)))
      throw new Error("本机端口规则与代理端口冲突，请删除该端口例外。");
  }
  get kernelPolicy() {
    return {
      revision: this.record.revision,
      loopbackDirect: this.error ? false : this.record.settings.loopbackDirect,
      localPorts: this.error ? [] : localExceptionPorts(this.record.settings),
    };
  }
  status(snapshot: Snapshot | undefined, allowed: boolean): NetworkPolicyState {
    const programs =
      snapshot?.apps
        .filter((app) => app.enabled && (app.enhanced || snapshot.egress))
        .map((app) => app.name) ?? [];
    const error =
      this.error ||
      (snapshot?.driver.enabled && !snapshot.driver.ready ? snapshot.driver.error : "") ||
      (snapshot?.online &&
      !this.applying &&
      snapshot.networkPolicy.revision !== this.record.revision
        ? "原生策略与保存记录尚未一致，连接保持暂停，请重新应用。"
        : "");
    return {
      settings: this.record.settings,
      revision: this.record.revision,
      programs,
      error: error || (!snapshot?.online ? "守护尚未连接，等待原生状态确认。" : ""),
      phase: error
        ? "failed"
        : !snapshot?.online
          ? "paused"
          : !programs.length
            ? "inactive"
            : !this.applying &&
                allowed &&
                snapshot?.networkPolicy.revision === this.record.revision &&
                !snapshot.apps.some((app) => app.enabled && app.enhanced && !snapshot.driver.ready)
              ? "active"
              : "paused",
      childProtection: Boolean(snapshot?.driver.ready),
      loopbackDirect: snapshot?.networkPolicy.loopbackDirect ?? false,
      localPorts: snapshot?.driver.localPorts ?? [],
    };
  }
  async initialize() {
    try {
      const raw: unknown = JSON.parse(await readFile(policyFile(), "utf8"));
      const current = recordSchema.safeParse(raw);
      if (current.success) this.record = current.data;
      else {
        const legacy = legacyRecordSchema.parse(raw);
        const migrated = recordSchema.parse({
          revision: randomUUID(),
          settings: { ...legacy.settings, loopbackDirect: true },
        });
        await this.write(migrated);
        this.record = migrated;
      }
    } catch (error) {
      if (error && typeof error === "object" && Reflect.get(error, "code") === "ENOENT") return;
      this.loadError = "拦截策略读取失败，原文件保留；请重新保存有效规则。";
    }
  }
  async write(record: NetworkPolicyRecord, backup = true) {
    await mkdir(guardDataDirectory(), { recursive: true });
    const temporary = policyFile() + ".tmp";
    await writeFile(temporary, JSON.stringify(record), "utf8");
    try {
      if (backup && !this.loadError) await copyFile(policyFile(), policyFile() + ".bak");
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
        throw error;
    }
    await rename(temporary, policyFile());
  }
  commit(record: NetworkPolicyRecord) {
    this.record = record;
    this.loadError = "";
  }
  prepare(settings: NetworkPolicy): NetworkPolicyRecord {
    const parsed = networkPolicySchema.parse(settings);
    this.validate(parsed);
    return { revision: randomUUID(), settings: parsed };
  }
  action(target: { host: string; port: number }) {
    if (this.applying) throw new Error("拦截策略正在应用");
    if (!this.confirmed) throw new Error("策略尚未获得原生确认");
    if (this.error) throw new Error(this.error);
    return networkAction(this.record.settings, target);
  }
  async connect(endpoint: ProxyEndpoint, target: { host: string; port: number }) {
    const action = this.action(target);
    if (action === "block")
      throw new ProxyRequestError(
        403,
        "目标已被全局拦截策略阻断，请在拦截策略中检查该主机和端口。",
      );
    if (action === "direct") {
      if (
        networkHost(target.host) === "localhost" &&
        [...this.reservations.values()].flat().includes(target.port)
      )
        throw new ProxyRequestError(403, "代理端口禁止作为本机直连目标");
      return openDirect({
        ...target,
        host:
          networkHost(target.host) === "localhost" &&
          !/^127(?:\.\d{1,3}){3}$/u.test(target.host) &&
          target.host !== "::1"
            ? "localhost"
            : target.host,
      });
    }
    return openTunnel(endpoint, target);
  }
}
