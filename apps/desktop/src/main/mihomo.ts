import { readFile, stat } from "node:fs/promises";
import { request } from "node:http";
import path from "node:path";

import { z } from "zod";

import {
  mihomoApiSchema,
  mihomoController,
  mihomoReservedPorts,
  parseMihomoProfile,
  selectMihomoNode,
} from "./mihomo-config.ts";
import type { MihomoController, MihomoProfile } from "./mihomo-config.ts";

type Source = { executable: string; config: string; home?: string; pid: number };
export class MihomoResolver {
  groups: string[] = [];
  reservedPorts: number[] = [];
  private cached = new Map<string, { stamp: string; profile: MihomoProfile }>();
  forget() {
    this.cached.clear();
  }
  private async profile(file: string) {
    const info = await stat(file);
    if (!info.isFile() || info.size > 1048576) throw new Error("Mihomo 配置文件无效或超过 1MB。");
    const stamp = `${file}|${info.size}|${info.mtimeMs}`;
    const cached = this.cached.get(file);
    if (stamp === cached?.stamp) return cached.profile;
    const text = await readFile(file, "utf8");
    if (Buffer.byteLength(text, "utf8") > 1048576) throw new Error("Mihomo 配置超过 1MB。");
    const profile = parseMihomoProfile(text);
    if (this.cached.size >= 4 && !this.cached.has(file)) {
      const first = this.cached.keys().next().value;
      if (first) this.cached.delete(first);
    }
    this.cached.set(file, { stamp, profile });
    return profile;
  }
  private async api(
    profile: MihomoProfile,
    apiPath: string,
    owner: (controller: MihomoController) => Promise<void>,
  ): Promise<unknown> {
    const controller = mihomoController(profile);
    try {
      await owner(controller);
    } catch {
      throw new Error("Mihomo 控制 API 的进程归属未通过核对，未发送认证信息。");
    }
    const secret =
      profile.secret === undefined
        ? ""
        : z
            .string()
            .max(4096)
            .regex(/^[^\r\n\0]*$/u)
            .parse(profile.secret);
    return new Promise((resolve, reject) => {
      const signal = AbortSignal.timeout(4000),
        tooLarge = new Error("Mihomo 控制响应超过 1MB。");
      const connect = (index: number) => {
        const req = request(
          {
            ...(controller.kind === "pipe"
              ? { socketPath: controller.path }
              : { hostname: controller.hosts[index], port: controller.port }),
            signal,
            path: apiPath,
            method: "GET",
            headers: secret ? { Authorization: "Bearer " + secret } : {},
          },
          (res) => {
            if (res.statusCode !== 200) {
              res.resume();
              reject(
                new Error(
                  res.statusCode === 401 || res.statusCode === 403
                    ? "Mihomo 控制 API 认证失败，请核对当前配置。"
                    : "Mihomo 控制 API 暂未响应。",
                ),
              );
              return;
            }
            const chunks: Buffer[] = [];
            let size = 0;
            res.on("data", (chunk: Buffer) => {
              size += chunk.length;
              if (size > 1048576) req.destroy(tooLarge);
              else chunks.push(chunk);
            });
            res.on("error", () => reject(new Error("Mihomo 控制响应中断。")));
            res.on("end", () => {
              try {
                const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
                resolve(value);
              } catch {
                reject(new Error("Mihomo 控制 API 未返回有效 JSON。"));
              }
            });
          },
        );
        req.on("error", (error) => {
          // localhost may be bound only on IPv6; retry only a refused loopback connection.
          if (
            controller.kind === "tcp" &&
            index + 1 < controller.hosts.length &&
            !signal.aborted &&
            Reflect.get(error, "code") === "ECONNREFUSED"
          ) {
            connect(index + 1);
            return;
          }
          reject(
            error === tooLarge
              ? tooLarge
              : new Error(
                  signal.aborted
                    ? "Mihomo 控制 API 请求超时。"
                    : "Mihomo 本机控制 API 无法连接，请检查监听地址或命名管道。",
                ),
          );
        });
        req.end();
      };
      connect(0);
    });
  }
  async read(
    source: Source,
    selectedGroup: string | undefined,
    owner: (controller: MihomoController) => Promise<void>,
  ) {
    const profile = await this.profile(source.config);
    this.reservedPorts = mihomoReservedPorts(profile);
    const version = z
      .object({ meta: z.literal(true) })
      .safeParse(await this.api(profile, "/version", owner));
    if (!version.success)
      throw new Error("该进程未提供 Mihomo Meta API，请使用受支持的 Mihomo 核心。");
    const api = mihomoApiSchema.parse(await this.api(profile, "/proxies", owner));
    this.groups = profile["proxy-groups"]
      .map((group) => group.name)
      .filter((name) => api.proxies[name]?.now);
    if (profile.mode === "global" && api.proxies.GLOBAL?.now) this.groups.unshift("GLOBAL");
    const selected = selectMihomoNode(profile, api, selectedGroup);
    let candidates = profile.proxies.filter((proxy) => proxy.name === selected.name);
    if (!candidates.length && selected.provider) {
      const provider = profile["proxy-providers"][selected.provider];
      if (!provider) throw new Error("Mihomo 节点的订阅定义未在当前配置中找到。");
      const override = z.record(z.string(), z.unknown()).parse(provider.override ?? {});
      if (
        Object.keys(override).some(
          (key) => !["additional-prefix", "additional-suffix"].includes(key),
        )
      )
        throw new Error("此订阅包含特殊节点覆盖，暂需使用内联节点或普通订阅缓存。");
      let payload: unknown = provider.payload;
      if (!Array.isArray(payload)) {
        const declared = z.string().min(1).safeParse(provider.path);
        if (!declared.success || (!path.isAbsolute(declared.data) && !source.home))
          throw new Error("订阅节点需明确的本地缓存路径；IP Guard 不额外下载订阅。");
        const file = path.isAbsolute(declared.data)
          ? declared.data
          : path.resolve(source.home ?? "", declared.data);
        if (file.startsWith("\\\\")) throw new Error("Mihomo 订阅缓存须位于本机。");
        payload = (await this.profile(file)).proxies;
      }
      const proxies = z.array(z.record(z.string(), z.unknown())).parse(payload);
      const prefix = z.string().parse(override["additional-prefix"] ?? ""),
        suffix = z.string().parse(override["additional-suffix"] ?? "");
      candidates = proxies
        .filter((proxy) => prefix + String(proxy.name) + suffix === selected.name)
        .map((proxy) => ({ ...proxy, name: selected.name, type: z.string().parse(proxy.type) }));
    }
    if (candidates.length !== 1)
      throw new Error("无法从本地配置或订阅缓存唯一定位当前 Mihomo 节点。");
    const node = candidates[0];
    if (!node) throw new Error("Mihomo 节点为空。");
    return { node, name: selected.name };
  }
}
