import { execFile, spawn } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { copyFile, mkdir, readFile, realpath, rm, stat } from "node:fs/promises";
import { createConnection, createServer, isIP } from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { z } from "zod";

import { publicIPv4Schema } from "@ip-guard/electron";

import {
  coreConfiguration,
  snapshotV2rayNode,
  nodeServers,
  snapshotMihomoNode,
} from "./egress-config.ts";
import type { NodeSnapshot } from "./egress-config.ts";
import { guardDataDirectory } from "./guard-data.ts";
import { nativePath } from "./guardian.ts";
import { mihomoReservedPorts, parseMihomoProfile } from "./mihomo-config.ts";
import { MihomoResolver } from "./mihomo.ts";
import type { ProxyEndpoint } from "./proxy-tunnel.ts";

const execute = promisify(execFile);
const discoveryTimeoutMs = 15000;
const sourceSchema = z.object({
  executable: z.string(),
  config: z.string(),
  home: z.string().optional(),
  pid: z.number().int().positive(),
});
const ownerSchema = z.object({ executable: z.string().min(1), pid: z.number().int().positive() });
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
export function inboundPorts(input: unknown): number[] {
  const config = z
    .object({
      inbounds: z.array(z.record(z.string(), z.unknown())).default([]),
    })
    .parse(input);
  return [
    ...new Set(
      config.inbounds
        .flatMap((entry) => [entry.port, entry.listen_port])
        .flatMap((value) => {
          const port = typeof value === "string" && /^\d+$/u.test(value) ? Number(value) : value;
          return typeof port === "number" && Number.isInteger(port) && port > 0 && port <= 65535
            ? [port]
            : [];
        }),
    ),
  ];
}
const discovery = String.raw`
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
trap { [Console]::Error.WriteLine('IPGUARD_DISCOVERY: '+$_.Exception.Message); exit 1 }
$port=[int]$env:IPGUARD_PROXY_PORT
if($env:IPGUARD_CONTROLLER_PIPE) {
  if(-not $env:IPGUARD_CONTROLLER_PIPE.StartsWith('\\.\pipe\',[StringComparison]::OrdinalIgnoreCase)){throw 'Local controller pipe required'}
  Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class IPGuardPipeOwner {
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFile(string name,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetNamedPipeServerProcessId(SafeFileHandle pipe,out uint pid);
  public static uint Read(string path) {
    using(var pipe=CreateFile(path,0xc0000000,0,IntPtr.Zero,3,0,IntPtr.Zero)) {
      if(pipe.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
      uint pid;if(!GetNamedPipeServerProcessId(pipe,out pid)) throw new Win32Exception(Marshal.GetLastWin32Error());return pid;
    }
  }
}
'@
  $id=[IPGuardPipeOwner]::Read($env:IPGUARD_CONTROLLER_PIPE)
  $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$id)
} elseif($port -eq 0) {
  $own=Join-Path $env:LOCALAPPDATA 'IPGuard\egress\'
  $cores=@(Get-CimInstance Win32_Process -Filter "Name='xray.exe' OR Name='sing-box.exe' OR Name LIKE 'mihomo%.exe' OR Name='clash-meta.exe' OR Name='clash.exe' OR Name LIKE 'verge-mihomo%.exe' OR Name='clash.meta.exe'" | Where-Object {$_.ExecutablePath -and -not $_.ExecutablePath.StartsWith($own,[StringComparison]::OrdinalIgnoreCase)})
  if($cores.Count -ne 1) {throw 'One running proxy core is required without a system proxy port'}
  $process=$cores[0]
} else {
  $ids=@(Get-NetTCPConnection -State Listen | Where-Object LocalPort -eq $port | Select-Object -ExpandProperty OwningProcess -Unique)
  if($ids.Count -eq 0) { throw 'Proxy listener is unavailable' }
  if($ids.Count -ne 1) { throw 'Proxy listener owner is ambiguous' }
  $process=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$ids[0])
}
if($env:IPGUARD_EXPECTED_IMAGE) {
  if(-not $process) { throw 'Proxy listener process exited' }
  @{executable=$process.ExecutablePath;pid=[int]$process.ProcessId} | ConvertTo-Json -Compress
  exit 0
}
if(-not $process) { throw 'Proxy listener process exited' }
if($process.Name -match '^(mihomo(?:-.+)?|verge-mihomo(?:-.+)?|clash(?:-meta|\.meta)?)\.exe$') {
  $f=[regex]::Matches($process.CommandLine,'(?i)(?:^|\s)-f(?:=|\s+)(?:"([^"]+)"|(\S+))')
  $d=[regex]::Matches($process.CommandLine,'(?i)(?:^|\s)-d(?:=|\s+)(?:"([^"]+)"|(\S+))')
  if($f.Count -gt 1 -or $d.Count -gt 1) {throw 'Ambiguous Mihomo configuration'}
  $home=if($d.Count -eq 1){if($d[0].Groups[1].Success){$d[0].Groups[1].Value}else{$d[0].Groups[2].Value}}else{''}
  if($home -and $home -notmatch '^[A-Za-z]:[\\/]'){throw 'Mihomo home must be a local absolute path'}
  $file=if($f.Count -eq 1){if($f[0].Groups[1].Success){$f[0].Groups[1].Value}else{$f[0].Groups[2].Value}}elseif($home){Join-Path $home 'config.yaml'}else{throw 'Explicit Mihomo configuration required'}
  if($file -notmatch '^[A-Za-z]:[\\/]'){throw 'Mihomo -f must use a local absolute path; relative files depend on the process working directory'}
  if(-not (Test-Path -LiteralPath $file -PathType Leaf)){throw 'Mihomo configuration missing'}
  @{executable=$process.ExecutablePath;config=[IO.Path]::GetFullPath($file);home=$home;pid=[int]$process.ProcessId}|ConvertTo-Json -Compress
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
@{executable=$process.ExecutablePath;config=[IO.Path]::GetFullPath($config[0]);pid=[int]$process.ProcessId} | ConvertTo-Json -Compress
`;

export function proxyDiscoveryIssue(error: unknown): string {
  if (error && typeof error === "object") {
    if (Reflect.get(error, "killed") === true) return "代理核心查询超时，请稍后重试";
    const stderr = Reflect.get(error, "stderr");
    if (typeof stderr === "string") {
      const reason = /IPGUARD_DISCOVERY: ([^\r\n]+)/u.exec(stderr)?.[1]?.trim();
      if (reason === "Proxy listener is unavailable")
        return "本机代理端口尚未监听，等待代理核心启动";
      if (reason === "Proxy listener process exited") return "代理核心已退出，请稍后重试";
      if (reason === "Proxy listener owner is ambiguous") return "本机代理端口归属不唯一";
      if (reason === "One explicit configuration file is required")
        return "Xray / sing-box 启动参数缺少唯一配置文件";
      if (reason === "Active configuration cannot be resolved") return "代理运行配置文件未找到";
      if (reason === "Relative configuration requires a supported client layout")
        return "代理核心使用了尚未支持的相对配置路径";
      if (reason === "Unsupported proxy core") return "本机代理端口由尚未支持的程序监听";
    }
  }
  return "本机代理进程查询失败，请稍后重试";
}

export class ProxyDiscoveryUnavailable extends Error {
  entry: ProxyEndpoint | undefined;
}

function discoveryFailure(error: unknown): Error {
  const issue = proxyDiscoveryIssue(error);
  if (issue === "代理核心查询超时，请稍后重试" || issue === "本机代理进程查询失败，请稍后重试")
    return new ProxyDiscoveryUnavailable(issue);
  return new Error(issue);
}

export type ProxySource = { executable: string; config: string; node: NodeSnapshot; key: string };
export function proxyEngine(executable: string): NodeSnapshot["engine"] | undefined {
  const name = path.win32
    .basename(path.basename(executable))
    .toLowerCase()
    .replace(/\.exe$/u, "");
  return name === "xray"
    ? "xray"
    : name === "sing-box"
      ? "sing-box"
      : /^(mihomo(?:-.+)?|verge-mihomo(?:-.+)?|clash(?:-meta|\.meta)?)$/u.test(name)
        ? "mihomo"
        : undefined;
}
export function automaticNode(input: unknown, engine: NodeSnapshot["engine"]) {
  const node = engine === "mihomo" ? snapshotMihomoNode(input) : snapshotV2rayNode(input);
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
  private readonly mihomo = new MihomoResolver();
  private controlOwner = { key: "", checkedAt: 0 };
  get core() {
    return this.metadata ? proxyEngine(this.metadata.executable) : undefined;
  }
  get groups() {
    return this.mihomo.groups;
  }
  private declaredPorts: number[] = [];
  get reservedPorts() {
    return this.core === "mihomo" ? this.mihomo.reservedPorts : this.declaredPorts;
  }
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
  private sourceEntry: string | undefined;
  private activeStamp = "";
  endpoint: ProxyEndpoint | undefined;
  get allocated() {
    return Boolean(this.child || this.folder);
  }
  forget() {
    this.mihomo.forget();
    this.cached = undefined;
    this.sourceStamp = "";
  }
  async locate(): Promise<ProxyEndpoint> {
    if (this.automaticEntry && performance.now() - this.entryAt < 10000) return this.automaticEntry;
    try {
      this.checking();
      let stdout: string;
      try {
        ({ stdout } = await execute(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", discovery],
          {
            windowsHide: true,
            timeout: discoveryTimeoutMs,
            maxBuffer: 8192,
            env: {
              ...process.env,
              IPGUARD_PROXY_PORT: "0",
              IPGUARD_EXPECTED_IMAGE: "",
              IPGUARD_CONTROLLER_PIPE: "",
            },
          },
        ));
      } catch (error) {
        throw discoveryFailure(error);
      }
      const input: unknown = JSON.parse(stdout.replace(/^\uFEFF/, ""));
      const metadata = sourceSchema.parse(input);
      if (!path.isAbsolute(metadata.config) || metadata.config.startsWith("\\\\"))
        throw new Error("Local configuration required");
      const file = await stat(metadata.config);
      if (!file.isFile() || file.size > 1048576) throw new Error("Invalid configuration size");
      const text = await readFile(metadata.config, "utf8");
      if (Buffer.byteLength(text, "utf8") > 1048576) throw new Error("Invalid configuration size");
      if (proxyEngine(metadata.executable) === "mihomo") {
        const profile = parseMihomoProfile(text);
        this.mihomo.reservedPorts = mihomoReservedPorts(profile);
        for (const field of ["mixed-port", "port", "socks-port"]) {
          const parsed = z.number().int().min(1).max(65535).safeParse(profile[field]);
          if (parsed.success) {
            this.metadata = metadata;
            this.metadataPort = parsed.data;
            this.discoveredAt = performance.now();
            this.entryAt = performance.now();
            return (this.automaticEntry = {
              host: "127.0.0.1",
              port: parsed.data,
              protocol: field === "socks-port" ? "socks5" : "http",
            });
          }
        }
        throw new Error("Mihomo 需开启标准 HTTP 或 SOCKS 入口");
      }
      const value: unknown = JSON.parse(text);
      this.declaredPorts = inboundPorts(value);
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
    } catch (error) {
      if (error instanceof ProxyDiscoveryUnavailable) throw error;
      throw new Error(
        "系统未设置代理入口，且无法唯一识别 TUN 使用的受支持核心；请指定本机代理入口",
      );
    }
  }
  private readonly changed: (reason: string, firstFailure: boolean) => void;
  private readonly checking: () => void;
  constructor(changed: (reason: string, firstFailure: boolean) => void, checking: () => void) {
    this.changed = changed;
    this.checking = checking;
  }
  async source(upstream: ProxyEndpoint, mihomoGroup?: string): Promise<ProxySource> {
    if (!["127.0.0.1", "localhost", "::1"].includes(upstream.host))
      throw new Error("自动专用路由需连接本机 Xray / sing-box / Mihomo 核心；此代理来源尚待适配");
    if (
      !this.metadata ||
      this.metadataPort !== upstream.port ||
      performance.now() - this.discoveredAt > 10000
    ) {
      this.checking();
      let stdout: string;
      try {
        ({ stdout } = await execute(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", discovery],
          {
            windowsHide: true,
            timeout: discoveryTimeoutMs,
            maxBuffer: 8192,
            env: {
              ...process.env,
              IPGUARD_PROXY_PORT: String(upstream.port),
              IPGUARD_EXPECTED_IMAGE: "",
              IPGUARD_CONTROLLER_PIPE: "",
            },
          },
        ));
      } catch (error) {
        throw discoveryFailure(error);
      }
      const input: unknown = JSON.parse(stdout.replace(/^\uFEFF/, ""));
      this.metadata = sourceSchema.parse(input);
      this.metadataPort = upstream.port;
      this.discoveredAt = performance.now();
    }
    const { executable, config } = this.metadata;
    if (![executable, config].every((file) => path.isAbsolute(file) && !file.startsWith("\\\\")))
      throw new Error("代理核心与配置须位于本机绝对路径");
    const engine = proxyEngine(executable);
    if (!engine) throw new Error("代理核心类型尚待适配");
    const [file, binary] = await Promise.all([stat(config), stat(executable)]);
    if (!file.isFile() || file.size > 1048576 || !binary.isFile())
      throw new Error("运行配置或核心文件无效");
    const stamp = `${executable}|${config}|${file.size}|${file.mtimeMs}|${binary.size}|${binary.mtimeMs}`;
    this.sourceEntry = `${upstream.protocol}://${upstream.host}:${upstream.port}`;
    if (engine !== "mihomo" && stamp === this.sourceStamp && this.cached) return this.cached;
    let node: NodeSnapshot;
    if (engine === "mihomo") {
      const metadata = this.metadata;
      const selected = await this.mihomo.read(metadata, mihomoGroup, async (controller) => {
        const key =
          metadata.pid +
          ":" +
          (controller.kind === "tcp" ? controller.port : controller.path.toLowerCase());
        if (
          key === this.controlOwner.key &&
          performance.now() - this.controlOwner.checkedAt < 10000
        )
          return;
        const { stdout } = await execute(
          "powershell.exe",
          ["-NoProfile", "-NonInteractive", "-Command", discovery],
          {
            windowsHide: true,
            timeout: discoveryTimeoutMs,
            maxBuffer: 8192,
            env: {
              ...process.env,
              IPGUARD_PROXY_PORT: controller.kind === "tcp" ? String(controller.port) : "0",
              IPGUARD_EXPECTED_IMAGE: executable,
              IPGUARD_CONTROLLER_PIPE: controller.kind === "pipe" ? controller.path : "",
            },
          },
        );
        const owner = ownerSchema.parse(JSON.parse(stdout.replace(/^\uFEFF/, "")));
        if (
          owner.pid !== metadata.pid ||
          (await realpath(owner.executable)).toLowerCase() !==
            (await realpath(executable)).toLowerCase()
        )
          throw new Error("Mihomo 控制 API 的进程归属不匹配，未发送认证信息。");
        this.controlOwner = { key, checkedAt: performance.now() };
      });
      node = automaticNode(selected.node, "mihomo");
    } else
      try {
        const text = await readFile(config, "utf8");
        if (Buffer.byteLength(text, "utf8") > 1048576) throw new Error("运行配置过大");
        const input: unknown = JSON.parse(text);
        this.declaredPorts = inboundPorts(input);
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
  async canRetain(upstream: ProxyEndpoint) {
    const child = this.child,
      source = this.cached;
    if (
      !child ||
      child.exitCode !== null ||
      child.signalCode !== null ||
      child.killed ||
      !this.endpoint ||
      !source ||
      source.node.engine === "mihomo" ||
      this.activeKey !== source.key ||
      this.sourceEntry !== `${upstream.protocol}://${upstream.host}:${upstream.port}`
    )
      return false;
    try {
      const [file, binary] = await Promise.all([stat(source.config), stat(source.executable)]);
      if (
        !file.isFile() ||
        file.size > 1048576 ||
        !binary.isFile() ||
        this.activeStamp !==
          `${source.executable}|${source.config}|${file.size}|${file.mtimeMs}|${binary.size}|${binary.mtimeMs}`
      )
        return false;
      const text = await readFile(source.config, "utf8");
      if (Buffer.byteLength(text, "utf8") > 1048576) return false;
      const node = automaticNode(JSON.parse(text), source.node.engine);
      return (
        this.child === child &&
        Boolean(this.endpoint) &&
        JSON.stringify(node) === JSON.stringify(source.node)
      );
    } catch {
      return false;
    }
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
      let reported = false;
      const failed = (reason: string) => {
        if (this.child === child) {
          const firstFailure = !reported;
          this.endpoint = undefined;
          this.activeKey = "";
          reported = true;
          this.changed(reason, firstFailure);
        }
      };
      child.once("error", (error: NodeJS.ErrnoException) =>
        failed(`专用核心启动失败（${error.code ?? "unknown"}）`),
      );
      child.once("exit", (code, signal) =>
        failed(
          `专用核心退出（exit=${code === null ? "null" : `0x${(code >>> 0).toString(16).toUpperCase()}`}，signal=${signal ?? "none"}）`,
        ),
      );
      child.stdin?.once("error", (error: NodeJS.ErrnoException) =>
        failed(`专用核心输入通道中断（${error.code ?? "unknown"}）`),
      );
      child.stdin?.write(`${JSON.stringify(coreConfiguration(source.node, port))}\n`);
      for (
        let attempt = 0;
        attempt < 50 && child.exitCode === null && !child.killed && !reported;
        attempt++
      ) {
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
                timeout: discoveryTimeoutMs,
                maxBuffer: 8192,
                env: {
                  ...process.env,
                  IPGUARD_PROXY_PORT: String(port),
                  IPGUARD_EXPECTED_IMAGE: this.image,
                  IPGUARD_CONTROLLER_PIPE: "",
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
          if (
            this.child !== child ||
            child.exitCode !== null ||
            child.signalCode !== null ||
            child.killed ||
            reported
          )
            throw new Error("Claude 专用代理核心已退出");
          this.activeKey = source.key;
          this.activeStamp = this.sourceStamp;
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
    this.activeStamp = "";
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
    const folder = this.folder;
    if (folder) {
      const root = path.resolve(guardDataDirectory(), "egress");
      if (path.dirname(folder) !== root || !z.uuid().safeParse(path.basename(folder)).success)
        throw new Error("专用通道清理路径无效，目录保留");
      // Mihomo may create cache.db even when selected-node persistence is disabled.
      await rm(folder, { recursive: true, force: true });
    }
    this.image = "";
    this.folder = "";
  }
}
