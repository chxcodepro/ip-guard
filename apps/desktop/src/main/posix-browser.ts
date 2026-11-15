import os from "node:os";
import path from "node:path";

import { browserExtensionId, browserHostName } from "@ip-guard/electron";

import {
  posixBrowserSocketPath,
  posixDataDirectory,
  readOptionalJson,
  writeLauncher,
  writePrivate,
} from "./posix-platform.ts";

export async function setupPosixBrowser(executable: string, helper: string) {
  const host = path.join(posixDataDirectory(), "native-host");
  await writeLauncher(host, executable, helper, [posixBrowserSocketPath()]);
  const base =
    process.platform === "darwin"
      ? path.join(os.homedir(), "Library/Application Support")
      : process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config");
  const folders =
    process.platform === "darwin"
      ? ["Google/Chrome", "Microsoft Edge"]
      : ["google-chrome", "microsoft-edge"];
  const manifest = {
    name: browserHostName,
    description: "IP Guard browser bridge",
    path: host,
    type: "stdio",
    allowed_origins: [`chrome-extension://${browserExtensionId}/`],
  };
  for (const folder of folders) {
    const file = path.join(base, folder, "NativeMessagingHosts", browserHostName + ".json");
    const existing = await readOptionalJson(file);
    if (existing && typeof existing === "object" && Reflect.get(existing, "path") !== host)
      throw new Error("此浏览器已有不同的 IP Guard 通信入口，请先检查原配置");
    await writePrivate(file, JSON.stringify(manifest));
  }
}
