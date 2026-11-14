import { execFile, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { copyFile, mkdir, readFile, realpath, rmdir, stat, unlink } from "node:fs/promises";
import { createConnection, createServer, isIP } from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { z } from "zod";

import { publicIPv4Schema } from "@ip-guard/electron";

import { coreConfiguration, snapshotV2rayNode, nodeServers } from "./egress-config.ts";
import type { NodeSnapshot } from "./egress-config.ts";
import { guardDataDirectory } from "./guard-data.ts";
import { nativePath } from "./guardian.ts";
import type { ProxyEndpoint } from "./proxy-tunnel.ts";

const execute = promisify(execFile);
const sourceSchema = z.object({ executable: z.string(), config: z.string() });
const ownerSchema = z.object({ executable: z.string().min(1) });
const inboundsSchema = z.object({
  inbounds: z.array(
    z.object({
      protocol: z.string().optional(),
      type: z.string().optional(),
      port: z.number().int().min(1).max(65535).optional(),
      listen_port: z.number().int().min(1).max(65535).optional(),
    }),
  ),
});
const discovery = String.raw`
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$port=[int]$env:IPGUARD_PROXY_PORT
if($port -eq 0) {
  $own=Join-Path $env:LOCALAPPDATA 'IPGuard\egress\'
  $cores=@(Get-CimInstance Win32_Process -Filter "Name='xray.exe' OR Name='sing-box.exe' OR Name='mihomo.exe' OR Name='clash-meta.exe' OR Name='clash.exe'" | Where-Object {$_.ExecutablePath -and -not $_.ExecutablePath.StartsWith($own,[StringComparison]::OrdinalIgnoreCase)})
  if($cores.Count -ne 1) {throw 'One running proxy core is required without a system proxy port'}
  $process=$cores[0]
} else {
  $ids=@(Get-NetTCPConnection -LocalPort $port -State Listen | Select-Object -ExpandProperty OwningProcess -Unique)
  if($ids.Count -ne 1) { throw 'Proxy listener owner is ambiguous' }
  $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$ids[0])
}
if($env:IPGUARD_EXPECTED_IMAGE) {
  @{executable=$process.ExecutablePath} | ConvertTo-Json -Compress
  exit 0
}
if($process.Name -notin @('xray.exe','sing-box.exe')) { throw 'Unsupported proxy core' }
$matches=[regex]::Matches($process.CommandLine,'(?i)(?:^|\s)(?:-config|--config|-c)(?:=|\s+)(?:"([^"]+)"|(\S+))')
if($matches.Count -ne 1) { throw 'One explicit configuration file is required' }
$argument=if($matches[0].Groups[1].Success){$matches[0].Groups[1].Value}else{$matches[0].Groups[2].Value}
$candidates=@()
if([IO.Path]::IsPathRooted($argument)) {$candidates+= $argument}
else {
  $parent=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$process.ParentProcessId)
  if($parent.Name -eq 'v2rayN.exe' -and $argument -eq 'config.json') {
    $candidates+=Join-Path ([IO.Path]::GetDirectoryName($parent.ExecutablePath)) 'binConfigs\config.json'
  } else { throw 'Relative configuration requires a supported client layout' }
}
$config=@($candidates | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf})
if($config.Count -ne 1) { throw 'Active configuration cannot be resolved' }
@{executable=$process.ExecutablePath;config=[IO.Path]::GetFullPath($config[0])} | ConvertTo-Json -Compress
`;

export type ProxySource = { executable: string; config: string; node: NodeSnapshot; key: string };
export function automaticNode(input: unknown, engine: "xray" | "sing-box") {
  const node = snapshotV2rayNode(input);
  if (node.engine !== engine) throw new Error("代理核心与运行配置的类型不一致");
  const servers = nodeServers(node.outbound);
  if (
    !servers.length ||
    servers.some(
      (server) =>
        server.toLowerCase() === "localhost" ||
        server.toLowerCase().endsWith(".localhost") ||
        (isIP(server) !== 0 && !publicIPv4Schema.safeParse(server).success),
    )
  )
    throw new Error("专用通道需使用远程节点，保留本机或内网转发入口可能再次触发直连分流");
  return node;
}
export class ForcedProxy {
  private metadata: z.infer<typeof sourceSchema> | undefined;
  private metadataPort = 0;
  private discoveredAt = 0;
  private sourceStamp = "";
  private cached: ProxySource | undefined;
  private automaticEntry: ProxyEndpoint | undefined;
  private entryAt = 0;
  private child: ChildProcess | undefined;
  private folder = "";
  private image = "";
  private activeKey = "";
  endpoint: ProxyEndpoint | undefined;
  get allocated() {
    return Boolean(this.child || this.folder);
  }
  forget() {
    this.cached = undefined;
    this.sourceStamp = "";
  }
  async locate(): Promise<ProxyEndpoint> {
    if (this.automaticEntry && performance.now() - this.entryAt < 10000) return this.automaticEntry;
    try {
      const { stdout } = await execute(
        "powershell.exe",
        ["-NoProfile", "-NonInteractive", "-Command", discovery],
        {
          windowsHide: true,
          timeout: 6000,
          maxBuffer: 8192,
          env: { ...process.env, IPGUARD_PROXY_PORT: "0", IPGUARD_EXPECTED_IMAGE: "" },
        },
      );
      const input: unknown = JSON.parse(stdout.replace(/^\uFEFF/, ""));
      const metadata = sourceSchema.parse(input);
      if (!path.isAbsolute(metadata.config) || metadata.config.startsWith("\\\\"))
        throw new Error("Local configuration required");
      const file = await stat(metadata.config);
      if (!file.isFile() || file.size > 1048576) throw new Error("Invalid configuration size");
      const text = await readFile(metadata.config, "utf8");
      if (Buffer.byteLength(text, "utf8") > 1048576) throw new Error("Invalid configuration size");
      const value: unknown = JSON.parse(text);
      const candidates = inboundsSchema
        .parse(value)
        .inbounds.filter((entry) =>
          ["mixed", "http", "socks"].includes(entry.protocol ?? entry.type ?? ""),
        );
      for (const kind of ["mixed", "http", "socks"]) {
        const entries = candidates.filter((entry) => (entry.protocol ?? entry.type) === kind);
        if (entries.length > 1) throw new Error("Ambiguous local proxy inbound");
        const entry = entries[0],
          port = entry?.port ?? entry?.listen_port;
        if (port) {
          this.metadata = metadata;
          this.metadataPort = port;
          this.discoveredAt = performance.now();
          this.entryAt = performance.now();
          return (this.automaticEntry = {
            host: "127.0.0.1",
            port,
            protocol: kind === "socks" ? "socks5" : "http",
          });
        }
      }
      throw new Error("No standard local proxy inbound");
    } catch {
      throw new Error(
        "系统未设置代理入口，且无法唯一识别 TUN 使用的受支持核心；请指定本机代理入口",
      );
    }
  }
  readonly changed: () => void;
  constructor(changed: () => void) {
    this.changed = changed;
  }
  async source(upstream: ProxyEndpoint): Promise<ProxySource> {
    if (!["127.0.0.1", "localhost", "::1"].includes(upstream.host))
      throw new Error("自动专用路由需连接本机 Xray / sing-box 核心；此代理来源尚待适配");
    if (
      !this.metadata ||
      this.metadataPort !== upstream.port ||
      performance.now() - this.discoveredAt > 10000
    ) {
      try {
        const { stdout } = await execute(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", discovery],
          {
            windowsHide: true,
            timeout: 6000,
            maxBuffer: 8192,
            env: {
              ...process.env,
              IPGUARD_PROXY_PORT: String(upstream.port),
              IPGUARD_EXPECTED_IMAGE: "",
            },
          },
        );
        const input: unknown = JSON.parse(stdout.replace(/^\uFEFF/, ""));
        this.metadata = sourceSchema.parse(input);
        this.metadataPort = upstream.port;
        this.discoveredAt = performance.now();
      } catch {
        throw new Error(
          "尚未找到可自动管理的本机 Xray / sing-box 配置，增强保持暂停；其他代理工具需适配专用路由接口",
        );
      }
    }
    const { executable, config } = this.metadata;
    if (![executable, config].every((file) => path.isAbsolute(file) && !file.startsWith("\\\\")))
      throw new Error("代理核心与配置须位于本机绝对路径");
    const engine =
      path.basename(executable).toLowerCase() === "xray.exe"
        ? "xray"
        : path.basename(executable).toLowerCase() === "sing-box.exe"
          ? "sing-box"
          : undefined;
    if (!engine) throw new Error("代理核心类型尚待适配");
    const [file, binary] = await Promise.all([stat(config), stat(executable)]);
    if (!file.isFile() || file.size > 1048576 || !binary.isFile())
      throw new Error("运行配置或核心文件无效");
    const stamp = `${executable}|${config}|${file.size}|${file.mtimeMs}|${binary.size}|${binary.mtimeMs}`;
    if (stamp === this.sourceStamp && this.cached) return this.cached;
    let node: NodeSnapshot;
    try {
      const text = await readFile(config, "utf8");
      if (Buffer.byteLength(text, "utf8") > 1048576) throw new Error("运行配置过大");
      const input: unknown = JSON.parse(text);
      node = automaticNode(input, engine);
    } catch {
      throw new Error(
        "当前节点配置无法安全建立专用路由，请使用独立节点及受支持的 Xray / sing-box 配置",
      );
    }
    this.sourceStamp = stamp;
    // Credentials stay in memory and the existing core's private stdin, never in logs or a new config file.
    return (this.cached = {
      executable,
      config,
      node,
      key: `${executable}|${binary.size}|${binary.mtimeMs}|${JSON.stringify(node)}`,
    });
  }
  matches(source: ProxySource) {
    return Boolean(this.endpoint && this.activeKey === source.key);
  }
  async start(source: ProxySource) {
    if (this.matches(source)) return;
    await this.stop();
    const id = randomUUID(),
      root = path.resolve(guardDataDirectory(), "egress");
    const folder = path.resolve(root, id);
    if (path.dirname(folder) !== root) throw new Error("专用通道目录无效");
    await mkdir(root, { recursive: true });
    await mkdir(folder);
    this.folder = folder;
    this.image = path.join(folder, `${source.node.engine}.exe`);
    try {
      await copyFile(source.executable, this.image, constants.COPYFILE_EXCL);
      const reserve = createServer();
      const port = await new Promise<number>((resolve, reject) => {
        reserve.once("error", reject);
        reserve.listen({ host: "127.0.0.1", port: 0, exclusive: true }, () => {
          const address = reserve.address();
          if (!address || typeof address === "string") reject(new Error("专用通道端口无效"));
          else resolve(address.port);
        });
      });
      await new Promise<void>((resolve, reject) =>
        reserve.close((error) => (error ? reject(error) : resolve())),
      );
      const child = spawn(nativePath(), ["egress-core", id, source.node.engine], {
        windowsHide: true,
        stdio: ["pipe", "ignore", "ignore"],
      });
      this.child = child;
      const failed = () => {
        if (this.child === child) {
          this.endpoint = undefined;
          this.activeKey = "";
          this.changed();
        }
      };
      child.on("error", failed);
      child.on("exit", failed);
      child.stdin?.on("error", failed);
      child.stdin?.write(`${JSON.stringify(coreConfiguration(source.node, port))}\n`);
      for (let attempt = 0; attempt < 50 && child.exitCode === null && !child.killed; attempt++) {
        const listening = await new Promise<boolean>((resolve) => {
          const socket = createConnection({ host: "127.0.0.1", port });
          const finish = (ok: boolean) => {
            socket.destroy();
            resolve(ok);
          };
          socket.setTimeout(100);
          socket.once("connect", () => finish(true));
          socket.once("error", () => finish(false));
          socket.once("timeout", () => finish(false));
        });
        if (listening) {
          try {
            const { stdout } = await execute(
              "powershell.exe",
              ["-NoProfile", "-NonInteractive", "-Command", discovery],
              {
                windowsHide: true,
                timeout: 6000,
                maxBuffer: 8192,
                env: {
                  ...process.env,
                  IPGUARD_PROXY_PORT: String(port),
                  IPGUARD_EXPECTED_IMAGE: this.image,
                },
              },
            );
            const input: unknown = JSON.parse(stdout.replace(/^\uFEFF/, ""));
            const owner = ownerSchema.parse(input);
            const [actual, expected] = await Promise.all([
              realpath(owner.executable),
              realpath(this.image),
            ]);
            if (actual.toLowerCase() !== expected.toLowerCase())
              throw new Error("Dedicated listener owner mismatch");
          } catch {
            throw new Error("Claude 专用端口的进程归属未通过校验，连接保持暂停");
          }
          if (this.child !== child || child.exitCode !== null || child.killed)
            throw new Error("Claude 专用代理核心已退出");
          this.activeKey = source.key;
          this.endpoint = { protocol: "http", host: "127.0.0.1", port };
          return;
        }
        await delay(100);
      }
      throw new Error("Claude 专用代理核心未就绪，增强连接保持暂停");
    } catch (error) {
      await this.stop();
      throw error;
    }
  }
  async stop() {
    this.endpoint = undefined;
    this.activeKey = "";
    const child = this.child;
    this.child = undefined;
    if (child?.pid && child.exitCode === null && child.signalCode === null) {
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          child.kill();
        }, 2500);
        child.once("exit", () => {
          clearTimeout(timer);
          resolve();
        });
        child.once("error", () => {
          clearTimeout(timer);
          resolve();
        });
        child.stdin?.end();
      });
    }
    const image = this.image,
      folder = this.folder;
    this.image = "";
    this.folder = "";
    if (image) {
      try {
        await unlink(image);
      } catch (error) {
        if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
          throw error;
      }
    }
    if (folder) await rmdir(folder);
  }
}
