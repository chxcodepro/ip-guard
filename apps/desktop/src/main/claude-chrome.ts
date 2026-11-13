import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { cp, lstat, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

import { z } from "zod";

import { claudeChromeExtensionId } from "@ip-guard/electron";
import type { ClaudeChromeState } from "@ip-guard/electron";

import { guardDataDirectory } from "./guard-data.ts";

const run = promisify(execFile);
const chromeInfoSchema = z.object({
  product: z.literal("Google Chrome"),
  version: z.string().regex(/^\d+\.\d+\.\d+\.\d+$/),
});
const snapshotSchema = z.object({
  version: chromeInfoSchema.shape.version,
  source: z.string().min(1),
});
const root = () => path.join(guardDataDirectory(), "browser");
const preferencesSchema = z.object({
  extensions: z.object({ settings: z.record(z.string(), z.unknown()).optional() }).optional(),
});
export const claudeChromePath = () => path.join(root(), "Application/chrome.exe");
const snapshotPath = () => path.join(root(), "Application/ip-guard.json");
const missing = (error: unknown) =>
  error !== null && typeof error === "object" && Reflect.get(error, "code") === "ENOENT";
async function exists(file: string) {
  try {
    await stat(file);
    return true;
  } catch (error) {
    if (missing(error)) return false;
    throw error;
  }
}
function owned(name: string) {
  const base = path.resolve(root()),
    result = path.resolve(base, name);
  if (path.dirname(result) !== base) throw new Error("专用浏览器目录无效");
  return result;
}
async function inspect(executable: string) {
  if (!path.isAbsolute(executable) || path.basename(executable).toLowerCase() !== "chrome.exe")
    throw new Error("请选择已安装的 Google Chrome chrome.exe");
  const script =
    "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$v=(Get-Item -LiteralPath $env:IP_GUARD_CHROME_SOURCE).VersionInfo;@{product=$v.ProductName;version=$v.ProductVersion}|ConvertTo-Json -Compress";
  const result = await run(
    path.join(
      process.env.SystemRoot ?? "C:\\Windows",
      "System32/WindowsPowerShell/v1.0/powershell.exe",
    ),
    ["-NoProfile", "-NonInteractive", "-Command", script],
    {
      windowsHide: true,
      timeout: 10000,
      maxBuffer: 4096,
      encoding: "utf8",
      env: { ...process.env, IP_GUARD_CHROME_SOURCE: executable },
    },
  );
  const input: unknown = JSON.parse(result.stdout.trim().replace(/^\uFEFF/, ""));
  const parsed = chromeInfoSchema.safeParse(input);
  if (!parsed.success) throw new Error("请选择正式版 Google Chrome 的程序文件");
  return parsed.data;
}
export async function installedChromePath() {
  for (const base of [
    process.env.ProgramFiles,
    process.env["ProgramFiles(x86)"],
    process.env.LOCALAPPDATA,
  ]) {
    if (!base) continue;
    const file = path.join(base, "Google/Chrome/Application/chrome.exe");
    if (await exists(file)) return file;
  }
  return "";
}
let sourceInfo: { path: string; version: string; until: number } | undefined;
export async function claudeChromeStatus(): Promise<ClaudeChromeState> {
  const state: ClaudeChromeState = {
    prepared: false,
    path: claudeChromePath(),
    version: "",
    sourceVersion: "",
    extensionInstalled: false,
    error: "",
  };
  try {
    if (!(await exists(snapshotPath())) || !(await exists(state.path))) return state;
    const input: unknown = JSON.parse(await readFile(snapshotPath(), "utf8"));
    const snapshot = snapshotSchema.parse(input);
    state.prepared = true;
    state.version = snapshot.version;
    if (!sourceInfo || sourceInfo.path !== snapshot.source || sourceInfo.until < Date.now()) {
      try {
        const info = await inspect(snapshot.source);
        sourceInfo = { path: snapshot.source, version: info.version, until: Date.now() + 60000 };
      } catch {
        sourceInfo = { path: snapshot.source, version: "", until: Date.now() + 60000 };
      }
    }
    state.sourceVersion = sourceInfo.version;
    for (const filename of ["Secure Preferences", "Preferences"]) {
      try {
        const input: unknown = JSON.parse(
          await readFile(path.join(root(), "User Data/Default", filename), "utf8"),
        );
        const preferences = preferencesSchema.parse(input);
        const registration = preferences.extensions?.settings?.[claudeChromeExtensionId];
        if (registration !== undefined) {
          z.record(z.string(), z.unknown()).parse(registration);
          state.extensionInstalled = true;
          state.error = "";
          break;
        }
      } catch (error) {
        if (!missing(error)) state.error = "Claude 插件安装状态读取失败";
      }
    }
  } catch {
    state.error = "专用 Chrome 信息读取失败，请重新准备浏览器";
  }
  return state;
}
export async function prepareClaudeChrome(source: string) {
  if ((await lstat(source)).isSymbolicLink())
    throw new Error("请选择 Chrome 程序原文件，避免影响原浏览器");
  const info = await inspect(source);
  const current = await claudeChromeStatus();
  if (current.prepared && info.version.localeCompare(current.version, "en", { numeric: true }) < 0)
    throw new Error("原 Chrome 版本较旧，已保留较新的专用浏览器");
  if (current.prepared && current.version === info.version && sourceInfo?.path === source) {
    sourceInfo = { path: source, version: info.version, until: Date.now() + 60000 };
    return { ...current, sourceVersion: info.version };
  }
  const stage = owned(`Application.tmp-${randomUUID()}`),
    destination = owned("Application"),
    backup = owned("Application.previous");
  await mkdir(root(), { recursive: true });
  if ((await lstat(root())).isSymbolicLink())
    throw new Error("专用浏览器目录包含外部链接，请检查目录");
  for (const file of [destination, backup])
    if ((await exists(file)) && (await lstat(file)).isSymbolicLink())
      throw new Error("专用浏览器目录包含外部链接，已保留原文件");
  if (!(await exists(destination)) && (await exists(backup))) await rename(backup, destination);
  await mkdir(stage);
  try {
    const application = path.dirname(source);
    await cp(source, path.join(stage, "chrome.exe"), { errorOnExist: true, force: false });
    await cp(path.join(application, info.version), path.join(stage, info.version), {
      recursive: true,
      errorOnExist: true,
      force: false,
      filter: async (file) => {
        if ((await lstat(file)).isSymbolicLink())
          throw new Error("Chrome 程序目录包含外部链接，请重新安装 Chrome");
        return true;
      },
    });
    const copied = await inspect(path.join(stage, "chrome.exe"));
    if (copied.version !== info.version)
      throw new Error("Chrome 正在更新，请稍后重新准备专用浏览器");
    await writeFile(
      path.join(stage, "ip-guard.json"),
      JSON.stringify({ version: info.version, source }),
      { flag: "wx" },
    );
    if (await exists(destination)) {
      await rm(backup, { recursive: true, force: true });
      await rename(destination, backup);
    }
    await rename(stage, destination);
    await rm(backup, { recursive: true, force: true });
    sourceInfo = { path: source, version: info.version, until: Date.now() + 60000 };
    return await claudeChromeStatus();
  } catch (error) {
    if (!(await exists(destination)) && (await exists(backup))) await rename(backup, destination);
    throw error;
  } finally {
    await rm(stage, { recursive: true, force: true });
  }
}
