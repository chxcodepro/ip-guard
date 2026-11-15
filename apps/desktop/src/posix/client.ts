import { spawn } from "node:child_process";
import { createConnection } from "node:net";
import { createInterface } from "node:readline";

import { shellArgument } from "../main/posix-platform.ts";
import { launchReplySchema, launchRequestSchema, proxyEnvironment } from "./protocol.ts";
import { providerHint } from "./provider.ts";
import { sessionArguments } from "./settings.ts";

const [socketPath, id, ...extra] = process.argv.slice(2);
const request = launchRequestSchema.parse({
  id,
  cwd: process.cwd(),
  args: extra[0] === "--" ? extra.slice(1) : extra,
});
if (!socketPath) throw new Error("IP Guard 启动入口缺少通信路径");
const connection = createConnection(socketPath);
let child: ReturnType<typeof spawn> | undefined,
  finished = false,
  timer: ReturnType<typeof setTimeout> | undefined;
const stop = () => {
  if (child?.pid && child.exitCode === null) {
    try {
      process.kill(-child.pid, "SIGTERM");
    } catch (error) {
      if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ESRCH")
        throw error;
    }
    timer = setTimeout(() => {
      if (child?.pid && child.exitCode === null)
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch (error) {
          if (!error || typeof error !== "object" || Reflect.get(error, "code") !== "ESRCH")
            throw error;
        }
    }, 3000);
  }
};
connection.once(
  "connect",
  () =>
    void providerHint(request.args, request.cwd, process.env)
      .then((provider) => connection.write(JSON.stringify({ ...request, provider }) + "\n"))
      .catch(() => connection.destroy()),
);
connection.on("error", () => {
  console.error("IP Guard 尚未运行，请先打开桌面程序。");
  process.exitCode = 1;
  stop();
});
connection.on("close", () => {
  if (!finished) stop();
});
createInterface({ input: connection }).on("line", (line) => {
  void (async () => {
    const message = launchReplySchema.parse(JSON.parse(line));
    if (message.type === "error") {
      console.error(message.message);
      process.exitCode = 1;
      connection.end();
      return;
    }
    if (child) throw new Error("重复的启动许可");
    const proxy = message.scope === "guarded" ? message.proxy : undefined;
    const env = proxy ? { ...process.env, ...proxyEnvironment(proxy) } : process.env;
    const settings = await sessionArguments(
      message.args,
      request.cwd,
      env,
      message.cli && Boolean(proxy),
    );
    let executable = message.path,
      args = settings.args;
    if (!message.cli && proxy)
      args = [
        ...args.filter(
          (arg) => !arg.startsWith("--proxy-server=") && !arg.startsWith("--proxy-bypass-list="),
        ),
        "--proxy-server=" + proxy,
        "--proxy-bypass-list=<-loopback>",
      ];
    if (message.cli && process.stdin.isTTY) {
      executable = "/usr/bin/script";
      args =
        process.platform === "darwin"
          ? ["-q", "/dev/null", message.path, ...args]
          : ["-q", "-e", "-c", [message.path, ...args].map(shellArgument).join(" "), "/dev/null"];
    }
    // The owned process group also owns the pseudo-terminal; closing it sends HUP to its foreground child.
    child = spawn(executable, args, { cwd: request.cwd, env, detached: true, stdio: "inherit" });
    child.once("error", (error) => {
      console.error(error.message);
      finished = true;
      connection.end();
      process.exitCode = 1;
      void settings.cleanup();
    });
    child.once("exit", (code) => {
      finished = true;
      clearTimeout(timer);
      connection.end();
      process.exitCode = code ?? 1;
      void settings.cleanup();
    });
  })().catch((error) => {
    console.error(error instanceof Error ? error.message : "受管启动失败");
    process.exitCode = 1;
    connection.end();
  });
});
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"] as const) process.on(signal, stop);
