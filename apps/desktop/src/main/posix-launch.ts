import { spawn } from "node:child_process";
import { chmod, lstat, mkdir, readdir, unlink } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server } from "node:net";
import path from "node:path";
import { createInterface } from "node:readline";

import { launchRequestSchema } from "../posix/protocol.ts";
import type { PosixGuard } from "./posix-guard.ts";
import {
  isPosixCli,
  posixDataDirectory,
  posixSocketPath,
  posixBrowserSocketPath,
  writeLauncher,
} from "./posix-platform.ts";

export const launcherPath = (id: string) =>
  path.join(
    posixDataDirectory(),
    "launchers",
    id + (process.platform === "darwin" ? ".command" : ".sh"),
  );
export async function preparePosixBroker(
  guard: PosixGuard,
  executable: string,
  client: string,
  endpoint?: string,
): Promise<Server> {
  const socket = endpoint ?? posixSocketPath(),
    folder = path.dirname(socket);
  await mkdir(folder, { recursive: true, mode: 0o700 });
  const info = await lstat(folder);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid?.())
    throw new Error("受管启动目录归属无效");
  await chmod(folder, 0o700);
  for (const stale of endpoint ? [socket] : [socket, posixBrowserSocketPath()])
    try {
      const previous = await lstat(stale);
      if (!previous.isSocket() || previous.uid !== process.getuid?.())
        throw new Error("受管启动通信路径已被其他文件占用");
      await unlink(stale);
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ENOENT")
        throw error;
    }
  const server = createServer((connection) => {
    let received = false,
      release: (() => void) | undefined;
    let size = 0;
    connection.on("data", (chunk) => {
      size += chunk.length;
      if (size > 65536) connection.destroy();
    });
    connection.on("error", () => connection.destroy());
    connection.on("close", () => release?.());
    createInterface({ input: connection }).on("line", (line) => {
      if (received) {
        connection.destroy();
        return;
      }
      received = true;
      void (async () => {
        try {
          const request = launchRequestSchema.parse(JSON.parse(line));
          if (!path.isAbsolute(request.cwd)) throw new Error("工作目录无效");
          const record = await guard.createSession(request.id, () => connection.destroy());
          release = record.release;
          if (connection.destroyed) {
            release();
            return;
          }
          connection.write(
            JSON.stringify({
              type: "launch",
              path: record.target.path,
              args: [...record.args, ...request.args],
              proxy: record.proxy,
              cli: isPosixCli(record.target.path),
            }) + "\n",
          );
        } catch (error) {
          connection.end(
            JSON.stringify({
              type: "error",
              message: error instanceof Error ? error.message : "启动失败",
            }) + "\n",
          );
        }
      })();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socket, resolve);
  });
  await chmod(socket, 0o600);
  await refreshLaunchers(guard, executable, client);
  return server;
}
export async function refreshLaunchers(guard: PosixGuard, executable: string, client: string) {
  const folder = path.join(posixDataDirectory(), "launchers");
  await mkdir(folder, { recursive: true, mode: 0o700 });
  const known = new Set(guard.snapshot.apps.map((a) => path.basename(launcherPath(a.id))));
  for (const name of await readdir(folder))
    if (/^[a-f0-9-]{36}\.(?:sh|command)$/u.test(name) && !known.has(name))
      await unlink(path.join(folder, name));
  for (const target of guard.snapshot.apps)
    await writeLauncher(launcherPath(target.id), executable, client, [
      posixSocketPath(),
      target.id,
      "--",
    ]);
}
export async function openPosixTerminal(id: string) {
  const file = launcherPath(id);
  if (process.platform === "darwin") {
    await new Promise<void>((resolve, reject) => {
      const child = spawn("/usr/bin/open", ["-a", "Terminal", file], { stdio: "ignore" });
      child.once("error", reject);
      child.once("exit", (code) =>
        code === 0 ? resolve() : reject(new Error("请在终端执行受管启动命令")),
      );
    });
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const child = spawn("x-terminal-emulator", ["-e", file], { stdio: "ignore", detached: true });
    child.once("error", () => reject(new Error("请先安装终端程序，或在原终端执行受管启动命令")));
    child.once("spawn", () => {
      child.unref();
      resolve();
    });
  });
}
