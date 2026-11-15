import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { z } from "zod";

const settingsSchema = z.record(z.string(), z.unknown());
export async function sessionArguments(
  args: string[],
  cwd: string,
  env: NodeJS.ProcessEnv,
  cli: boolean,
) {
  if (!cli) return { args, cleanup: async () => {} };
  const result: string[] = [],
    sources: string[] = [];
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (value === undefined) continue;
    if (value === "--settings") {
      const next = args[++index];
      if (!next) throw new Error("--settings 缺少配置值");
      sources.push(next);
    } else if (value.startsWith("--settings=")) sources.push(value.slice(11));
    else result.push(value);
  }
  if (sources.length > 1) throw new Error("请合并为一个 --settings 配置后再启动");
  let current: Record<string, unknown> = {};
  const source = sources[0];
  if (source) {
    let text = source;
    if (!source.trimStart().startsWith("{")) {
      const file = path.resolve(cwd, source),
        info = await stat(file);
      if (!info.isFile() || info.size > 1048576) throw new Error("会话配置文件无效或超过 1MB");
      text = await readFile(file, "utf8");
    }
    try {
      current = settingsSchema.parse(JSON.parse(text));
    } catch {
      throw new Error("--settings 配置格式无效");
    }
  }
  const existing = settingsSchema.parse(current.env ?? {});
  const keys = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
  ];
  const proxy = Object.fromEntries(keys.map((key) => [key, env[key] ?? ""]));
  const directory = await mkdtemp(path.join(os.tmpdir(), "ipguard-session-"));
  try {
    const file = path.join(directory, "settings.json");
    await writeFile(file, JSON.stringify({ ...current, env: { ...existing, ...proxy } }), {
      mode: 0o600,
    });
    return {
      args: [...result, "--settings", file],
      cleanup: () => rm(directory, { recursive: true, force: true }),
    };
  } catch (error) {
    await rm(directory, { recursive: true, force: true });
    throw error;
  }
}
