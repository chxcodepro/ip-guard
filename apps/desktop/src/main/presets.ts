import { execFile } from "node:child_process";
import { open, readFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { app } from "electron";
import { z } from "zod";

import type { AppPreset } from "@ip-guard/electron";

const run = promisify(execFile);
const metadataSchema = z.object({
  shim: z.string(),
  npmPrefix: z.string(),
  npmError: z.string(),
  desktopError: z.string(),
  native: z.array(z.object({ path: z.string(), version: z.string() })),
  desktop: z.array(
    z.object({
      path: z.string(),
      icon: z.string(),
      version: z.string(),
      source: z.enum(["msix", "installer"]),
    }),
  ),
});
const packageSchema = z.object({
  name: z.literal("@anthropic-ai/claude-code"),
  version: z.string(),
  bin: z.union([z.string(), z.object({ claude: z.string() })]),
});
const script = `
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$shim=Get-Command claude.cmd -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$prefix=''; $npmError=''; $desktopError=''; $desktop=@()
$native=@()
$nativePaths=@((Join-Path $env:USERPROFILE '.local\\bin\\claude.exe'))
$nativePaths+=@(Get-Command claude.exe -CommandType Application -All -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source)
foreach($file in $nativePaths | Select-Object -Unique) {
  if((Test-Path -LiteralPath $file -PathType Leaf) -and $file -notmatch '[\\\\/]node_modules[\\\\/]|[\\\\/]WindowsApps[\\\\/]') {
    $native+=@{path=$file;version=[string](Get-Item -LiteralPath $file).VersionInfo.ProductVersion}
  }
}
$npm=Get-Command npm.cmd -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if($npm) {
  try {
    $output=@(& $npm.Source prefix --global 2>$null)
    if($LASTEXITCODE -eq 0 -and $output.Count -gt 0) { $prefix=[string]$output[-1] }
    else { $npmError='npm 全局目录读取失败' }
  } catch { $npmError='npm 全局目录读取失败' }
}
try {
  Get-AppxPackage -Name Claude -ErrorAction Stop | ForEach-Object {
    $p=$_
    (Get-AppxPackageManifest -Package $p.PackageFullName -ErrorAction Stop).Package.Applications.Application | Where-Object { $_.Id -eq 'Claude' } | ForEach-Object {
      $desktop+=@{path=(Join-Path $p.InstallLocation $_.Executable);icon='';version=[string]$p.Version;source='msix'}
    }
  }
} catch { $desktopError='MSIX 安装信息读取失败' }
$keys=@('HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*','HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*')
Get-ItemProperty -Path $keys -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -eq 'Claude' } | ForEach-Object {
  $location=''
  if($_.InstallLocation) { $location=Join-Path $_.InstallLocation 'Claude.exe' }
  $desktop+=@{path=$location;icon=[string]$_.DisplayIcon;version=[string]$_.DisplayVersion;source='installer'}
}
@{shim=$(if($shim){[string]$shim.Source}else{''});npmPrefix=$prefix;npmError=$npmError;desktopError=$desktopError;desktop=@($desktop);native=@($native)} | ConvertTo-Json -Depth 4 -Compress
`;

async function nativeExe(file: string) {
  if (!path.isAbsolute(file) || path.extname(file).toLowerCase() !== ".exe") return false;
  try {
    const handle = await open(file, "r");
    try {
      if (!(await handle.stat()).isFile()) return false;
      const header = Buffer.alloc(2);
      const result = await handle.read(header, 0, 2, 0);
      return result.bytesRead === 2 && header.toString("ascii") === "MZ";
    } finally {
      await handle.close();
    }
  } catch {
    return false;
  }
}
function inside(root: string, file: string) {
  const relative = path.relative(root, file);
  return relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}
async function discover(): Promise<AppPreset[]> {
  let discoveryError = "";
  let metadata: z.infer<typeof metadataSchema> = {
    shim: "",
    npmPrefix: "",
    npmError: "",
    desktopError: "",
    native: [],
    desktop: [],
  };
  try {
    const result = await run(
      path.join(
        process.env.SystemRoot ?? "C:\\Windows",
        "System32/WindowsPowerShell/v1.0/powershell.exe",
      ),
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { windowsHide: true, timeout: 15000, maxBuffer: 262144, encoding: "utf8" },
    );
    const value: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
    metadata = metadataSchema.parse(value);
  } catch {
    discoveryError = "安装信息读取失败，请浏览选择";
    metadata.npmError = "自动定位失败，请浏览选择";
    metadata.desktopError = "安装信息读取失败，请浏览选择";
  }
  let cli: AppPreset = {
    id: "claude-cli",
    name: "Claude Code（npm）",
    path: "",
    version: "",
    status: metadata.npmError ? "error" : "missing",
    message: metadata.npmError || "未找到 npm 原生 EXE",
  };
  const prefixes = [
    metadata.shim ? path.dirname(metadata.shim) : "",
    metadata.npmPrefix,
    path.join(app.getPath("appData"), "npm"),
  ].filter(Boolean);
  const seen = new Set<string>();
  for (const prefix of prefixes) {
    if (seen.has(prefix.toLowerCase())) continue;
    seen.add(prefix.toLowerCase());
    const root = path.join(prefix, "node_modules/@anthropic-ai/claude-code");
    try {
      const value: unknown = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
      const pkg = packageSchema.parse(value);
      const bin = typeof pkg.bin === "string" ? pkg.bin : pkg.bin.claude;
      const exe = path.resolve(root, bin);
      if (inside(root, exe) && (await nativeExe(exe))) {
        cli = { ...cli, path: exe, version: pkg.version, status: "ready", message: "" };
        break;
      }
      cli = {
        ...cli,
        version: pkg.version,
        status: "missing",
        message: "原生 EXE 未就绪，请浏览选择",
      };
    } catch (error) {
      if (error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT")
        continue;
      cli = { ...cli, status: "error", message: "npm 安装包信息读取失败，请浏览选择" };
    }
  }
  let desktop: AppPreset = {
    id: "claude-desktop",
    name: "Claude Desktop",
    path: "",
    version: "",
    status: metadata.desktopError ? "error" : "missing",
    message: metadata.desktopError || "未找到桌面版安装路径",
  };
  for (const candidate of metadata.desktop) {
    const icon =
      candidate.icon.match(/^"([^"]+\.exe)"(?:,\s*-?\d+)?$/i)?.[1] ??
      candidate.icon.match(/^(.*\.exe)(?:,\s*-?\d+)?$/i)?.[1] ??
      "";
    for (const file of [candidate.path, icon]) {
      if (path.basename(file).toLowerCase() === "claude.exe" && (await nativeExe(file))) {
        desktop = {
          ...desktop,
          path: path.resolve(file),
          version: candidate.version,
          status: "ready",
          message: "",
        };
        break;
      }
    }
    if (desktop.status === "ready") break;
  }
  let native: AppPreset = {
    id: "claude-native",
    name: "Claude Code（原生）",
    path: "",
    version: "",
    status: discoveryError ? "error" : "missing",
    message: discoveryError || "未找到独立安装的 claude.exe",
  };
  for (const candidate of metadata.native) {
    if (await nativeExe(candidate.path)) {
      native = {
        ...native,
        path: path.resolve(candidate.path),
        version: candidate.version,
        status: "ready",
        message: "",
      };
      break;
    }
  }
  return [cli, native, desktop];
}
let pending: Promise<AppPreset[]> | undefined;
export function claudePresets(): Promise<AppPreset[]> {
  pending ??= discover().finally(() => {
    pending = undefined;
  });
  return pending;
}
