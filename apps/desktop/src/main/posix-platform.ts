import { execFile } from "node:child_process";
import { constants } from "node:fs";
import {
  access,
  chmod,
  mkdir,
  readFile,
  realpath,
  rename,
  unlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
export const posixDataDirectory = () =>
  process.platform === "darwin"
    ? path.join(os.homedir(), "Library/Application Support/IPGuard")
    : path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "ip-guard");
export const posixSocketPath = () =>
  path.join(os.tmpdir(), `ipguard-${process.getuid?.()}`, "control.sock");
export const posixBrowserSocketPath = () =>
  path.join(path.dirname(posixSocketPath()), "browser.sock");
export const shellArgument = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
export function argumentWords(text: string): string[] {
  const words: string[] = [];
  let word = "",
    quote = "",
    escaped = false,
    present = false;
  for (const char of text) {
    if (escaped) {
      word += char;
      escaped = false;
      present = true;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      escaped = true;
      present = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = "";
      else word += char;
      present = true;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      present = true;
      continue;
    }
    if (/\s/u.test(char)) {
      if (present) words.push(word);
      word = "";
      present = false;
    } else {
      word += char;
      present = true;
    }
  }
  if (quote || escaped) throw new Error("启动参数中的引号或转义未闭合");
  if (present) words.push(word);
  return words;
}
export async function executablePath(input: string): Promise<string> {
  let file = path.resolve(input);
  if (process.platform === "darwin" && file.endsWith(".app")) {
    await access(file);
    const { stdout } = await execute(
      "/usr/bin/plutil",
      ["-extract", "CFBundleExecutable", "raw", "-o", "-", path.join(file, "Contents/Info.plist")],
      { timeout: 5000 },
    );
    const name = stdout.trim();
    if (!name || path.basename(name) !== name) throw new Error("应用入口无效");
    file = path.join(file, "Contents/MacOS", name);
  }
  file = await realpath(file);
  await access(file, constants.X_OK);
  return file;
}
export const isPosixCli = (file: string) =>
  /(?:^|\/)claude(?:-code)?$/u.test(file) ||
  file.includes("@anthropic-ai/claude-code/") ||
  file.includes("/.local/share/claude/versions/");
export async function posixPresets() {
  const candidates = [
    {
      id: "claude-native" as const,
      name: "Claude Code（原生）",
      files: [path.join(os.homedir(), ".local/bin/claude")],
    },
    {
      id: "claude-cli" as const,
      name: "Claude Code（npm）",
      files: (process.env.PATH || "")
        .split(path.delimiter)
        .filter(Boolean)
        .map((dir) => path.join(dir, "claude")),
    },
    {
      id: "claude-desktop" as const,
      name: "Claude Desktop",
      files:
        process.platform === "darwin"
          ? ["/Applications/Claude.app", path.join(os.homedir(), "Applications/Claude.app")]
          : [],
    },
  ];
  return Promise.all(
    candidates.map(async (item) => {
      for (const candidate of item.files) {
        try {
          return {
            id: item.id,
            name: item.name,
            path: await executablePath(candidate),
            version: "",
            status: "ready" as const,
            message: "",
          };
        } catch (error) {
          if (
            !error ||
            typeof error !== "object" ||
            !["ENOENT", "EACCES"].includes(String(Reflect.get(error, "code")))
          )
            throw error;
        }
      }
      return {
        id: item.id,
        name: item.name,
        path: "",
        version: "",
        status: "missing" as const,
        message:
          item.id === "claude-desktop" && process.platform === "linux"
            ? "此平台暂无官方 Claude Desktop 安装入口"
            : "未找到安装入口",
      };
    }),
  );
}
export async function writePrivate(file: string, content: string) {
  await mkdir(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = file + ".tmp";
  await writeFile(temporary, content, { mode: 0o600 });
  await rename(temporary, file);
}
export async function posixAutostart(enabled: boolean, executable: string) {
  if (process.platform === "darwin") throw new Error("macOS 登录启动由应用登录项管理");
  const file = path.join(
    process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"),
    "autostart/ip-guard.desktop",
  );
  if (enabled) {
    if (/[\r\n\0]/u.test(executable)) throw new Error("启动路径无效");
    const quoted =
      '"' +
      executable
        .replaceAll("\\", "\\\\")
        .replaceAll('"', '\\"')
        .replaceAll("`", "\\`")
        .replaceAll("$", "\\$")
        .replaceAll("%", "%%") +
      '"';
    await writePrivate(
      file,
      `[Desktop Entry]\nType=Application\nName=IP Guard\nExec=${quoted} --background\nTerminal=false\nX-GNOME-Autostart-enabled=true\n`,
    );
  } else
    try {
      await unlink(file);
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
        throw error;
    }
}
export async function writeLauncher(
  file: string,
  executable: string,
  script: string,
  args: string[],
) {
  await writePrivate(
    file,
    `#!/bin/sh\nexport ELECTRON_RUN_AS_NODE=1\nexec ${[executable, script, ...args].map(shellArgument).join(" ")} "$@"\n`,
  );
  await chmod(file, 0o700);
}
export async function readOptionalJson(file: string): Promise<unknown> {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (error && typeof error === "object" && Reflect.get(error, "code") === "ENOENT")
      return undefined;
    throw error;
  }
}
