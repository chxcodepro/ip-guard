import { spawn } from "node:child_process";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";

import { dialog } from "electron";
import type { BrowserWindow } from "electron";
import { z } from "zod";

import {
  browserExtensionId,
  extensionVersionSchema,
  isNewerExtensionVersion,
  nativeVersion,
} from "@ip-guard/electron";

const preferencesSchema = z.object({
  extensions: z.object({ settings: z.record(z.string(), z.unknown()).optional() }).optional(),
});
const entrySchema = z.object({
  state: z.number().optional(),
  manifest: z
    .object({
      version: z.string().optional(),
      permissions: z.array(z.string()).optional(),
      optional_permissions: z.array(z.string()).optional(),
    })
    .optional(),
});
export function hasLegacyBrowserGuard(input: unknown) {
  const preferences = preferencesSchema.parse(input);
  const entry = preferences.extensions?.settings?.[browserExtensionId];
  if (entry === undefined) return false;
  const parsed = entrySchema.parse(entry);
  if (parsed.state === 0) return false;
  const permissions = [
    ...(parsed.manifest?.permissions ?? []),
    ...(parsed.manifest?.optional_permissions ?? []),
  ];
  if (permissions.some((permission) => ["proxy", "privacy", "management"].includes(permission)))
    return true;
  const version = parsed.manifest?.version;
  if (!extensionVersionSchema.safeParse(version).success) return false;
  return (
    isNewerExtensionVersion("0.12.0", version ?? "") ||
    // Local control prototypes used higher numbers before the public 0.12.0 release.
    (isNewerExtensionVersion(version ?? "", nativeVersion) &&
      isNewerExtensionVersion("0.14.0", version ?? ""))
  );
}
function missing(error: unknown) {
  return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT";
}

// Old browser-wide proxy and official-extension controls require a clean web-only upgrade.
export async function notifyBrowserRecovery(window: BrowserWindow) {
  if (!process.env.LOCALAPPDATA) return;
  const profiles: string[] = [];
  const executables: { name: string; file: string }[] = [];
  for (const browser of [
    { name: "Chrome", folder: "Google/Chrome", image: "chrome.exe" },
    { name: "Edge", folder: "Microsoft/Edge", image: "msedge.exe" },
  ]) {
    const root = path.join(process.env.LOCALAPPDATA, browser.folder, "User Data");
    try {
      for (const profile of await readdir(root, { withFileTypes: true })) {
        if (!profile.isDirectory() || !/^(Default|Profile \d+|Guest Profile)$/.test(profile.name))
          continue;
        for (const file of ["Secure Preferences", "Preferences"]) {
          try {
            const input: unknown = JSON.parse(
              await readFile(path.join(root, profile.name, file), "utf8"),
            );
            if (hasLegacyBrowserGuard(input)) {
              profiles.push(`${browser.name} · ${profile.name}`);
              break;
            }
          } catch (error) {
            if (!missing(error))
              console.error("旧浏览器扩展登记读取失败", browser.name, profile.name, error);
          }
        }
      }
    } catch (error) {
      if (!missing(error)) console.error("旧浏览器资料读取失败", browser.name, error);
    }
    for (const base of [
      process.env.ProgramFiles,
      process.env["ProgramFiles(x86)"],
      process.env.LOCALAPPDATA,
    ]) {
      if (!base) continue;
      const file = path.join(base, browser.folder, "Application", browser.image);
      try {
        if ((await stat(file)).isFile()) {
          executables.push({ name: browser.name, file });
          break;
        }
      } catch (error) {
        if (!missing(error)) console.error("浏览器管理入口读取失败", browser.name, error);
      }
    }
  }
  if (!profiles.length || window.isDestroyed()) return;
  const answer = await dialog.showMessageBox(window, {
    type: "info",
    title: "更新 Claude 网页扩展",
    message: "请移除旧 IP Guard 扩展，再加载新版网页扩展",
    detail: `${profiles.join("\n")}\n\n先移除旧 IP Guard 扩展以释放旧版代理与 WebRTC 限制，再从新版安装目录加载网页扩展。新版仅保护 claude.ai。保留官方 Claude 插件；如果它此前被暂停，请重新启用。自定义浏览器资料也请检查。`,
    buttons: ["稍后处理", ...executables.map((browser) => `打开 ${browser.name} 扩展管理`)],
    defaultId: executables.length ? 1 : 0,
    cancelId: 0,
  });
  const selected = executables[answer.response - 1];
  if (!selected) return;
  await new Promise<void>((resolve, reject) => {
    const child = spawn(
      selected.file,
      [selected.name === "Edge" ? "edge://extensions/" : "chrome://extensions/"],
      { detached: true, windowsHide: true, stdio: "ignore" },
    );
    child.once("error", reject);
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}
