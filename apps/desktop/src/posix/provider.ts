import { readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export type ProviderHint = "claude" | "other" | "unknown";
export function modelHint(model: string): ProviderHint {
  if (/claude|^(?:sonnet|opus|haiku)(?:\[.*\])?$/iu.test(model)) return "claude";
  if (/deepseek|^gpt-|^o[134]-|gemini|qwen|kimi|^glm-/iu.test(model)) return "other";
  return "unknown";
}
export async function providerHint(
  args: string[],
  cwd: string,
  environment: NodeJS.ProcessEnv,
): Promise<ProviderHint> {
  let env: Record<string, unknown> = {},
    model = "";
  const files = [
    path.join(environment.CLAUDE_CONFIG_DIR || path.join(os.homedir(), ".claude"), "settings.json"),
    path.join(cwd, ".claude/settings.json"),
    path.join(cwd, ".claude/settings.local.json"),
  ];
  const flags = args.filter((arg) => arg.startsWith("--setting-sources"));
  if (flags.length) return "unknown";
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    const next = args[index + 1];
    if (value === "--settings" && next) {
      files.push(path.resolve(cwd, next));
      index++;
    } else if (value?.startsWith("--settings=")) files.push(path.resolve(cwd, value.slice(11)));
  }
  for (const file of files) {
    try {
      const info = await stat(file);
      if (!info.isFile() || info.size > 1048576) return "unknown";
      const value: unknown = JSON.parse(await readFile(file, "utf8"));
      if (value && typeof value === "object") {
        const settingEnv = Reflect.get(value, "env");
        if (settingEnv && typeof settingEnv === "object" && !Array.isArray(settingEnv))
          env = { ...env, ...settingEnv };
        const settingModel = Reflect.get(value, "model");
        if (typeof settingModel === "string") model = settingModel;
      }
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
        return "unknown";
    }
  }
  env = { ...env, ...environment };
  if (typeof env.ANTHROPIC_MODEL === "string") model = env.ANTHROPIC_MODEL;
  for (let index = 0; index < args.length; index++) {
    const value = args[index];
    if (value === "--model" && args[index + 1]) model = args[++index] ?? model;
    else if (value?.startsWith("--model=")) model = value.slice(8);
  }
  const hint = modelHint(model);
  if (/claude/iu.test(model)) return "claude";
  try {
    if (
      typeof env.ANTHROPIC_BASE_URL === "string" &&
      new URL(env.ANTHROPIC_BASE_URL).hostname === "api.deepseek.com"
    )
      return "other";
  } catch {
    return "unknown";
  }
  return hint;
}
