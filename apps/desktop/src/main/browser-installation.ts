import { readFile, readdir } from "node:fs/promises";
import path from "node:path";

import { z } from "zod";

import { browserExtensionId } from "@ip-guard/electron";

const preferencesSchema = z.object({
  extensions: z.object({ settings: z.record(z.string(), z.unknown()).optional() }).optional(),
});
const entrySchema = z.object({ state: z.number().optional(), path: z.string().optional() });
function missing(error: unknown) {
  return error !== null && typeof error === "object" && "code" in error && error.code === "ENOENT";
}
export async function browserInstallations() {
  const installedBrowsers: ("Chrome" | "Edge")[] = [];
  const errors: string[] = [];
  const local = process.env.LOCALAPPDATA;
  if (!local) return { installedBrowsers, error: "Windows 用户目录不可用" };
  for (const browser of [
    { name: "Chrome", folder: "Google/Chrome/User Data" },
    { name: "Edge", folder: "Microsoft/Edge/User Data" },
  ] as const) {
    const root = path.join(local, browser.folder);
    let installed = false;
    try {
      const profiles = (await readdir(root, { withFileTypes: true })).filter(
        (item) => item.isDirectory() && /^(Default|Profile \d+|Guest Profile)$/.test(item.name),
      );
      for (const profile of profiles)
        for (const filename of ["Secure Preferences", "Preferences"]) {
          try {
            const source: unknown = JSON.parse(
              await readFile(path.join(root, profile.name, filename), "utf8"),
            );
            const data = preferencesSchema.parse(source);
            const entry = data.extensions?.settings?.[browserExtensionId];
            if (entry !== undefined && entrySchema.safeParse(entry).success) installed = true;
          } catch (error) {
            if (!missing(error)) errors.push(`${browser.name} 扩展信息读取失败`);
          }
        }
      if (installed) installedBrowsers.push(browser.name);
    } catch (error) {
      if (!missing(error)) errors.push(`${browser.name} 用户目录读取失败`);
    }
  }
  return { installedBrowsers, error: [...new Set(errors)].join("；") };
}
