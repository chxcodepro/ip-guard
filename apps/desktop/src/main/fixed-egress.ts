import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { app, safeStorage } from "electron";
import { z } from "zod";

import type { EgressPolicy, EgressState } from "@ip-guard/electron";
import { egressPolicySchema } from "@ip-guard/electron";

import type { ClaudeIPv4 } from "./claude-ip.ts";
import { coreConfiguration, snapshotV2rayNode } from "./egress-config.ts";
import type { NodeSnapshot } from "./egress-config.ts";
import { nativePath } from "./guardian.ts";

const profileSchema = z.object({
  id: z.uuid(),
  label: z.string().min(1).max(100),
  engine: z.enum(["xray", "sing-box"]),
  outbound: z.record(z.string(), z.unknown()),
});
type Profile = z.infer<typeof profileSchema>;
const directory = () =>
  path.join(process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"), "IPGuard");
const profileDirectory = (id: string) => {
  const root = path.resolve(directory(), "egress");
  const folder = path.resolve(root, z.uuid().parse(id));
  if (path.dirname(folder) !== root) throw new Error("节点目录无效");
  return folder;
};

function listen(server: Server, port: number): Promise<number> {
  return new Promise((resolve, reject) => {
    const fail = (error: Error) => reject(error);
    server.once("error", fail);
    server.listen({ host: "127.0.0.1", port, exclusive: true }, () => {
      server.off("error", fail);
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("固定代理端口创建失败"));
      else resolve(address.port);
    });
  });
}

export class FixedEgress {
  private readonly claude: ClaudeIPv4;
  state: EgressState = { profile: null, phase: "disabled", error: "" };
  private profile: Profile | undefined;
  private child: ReturnType<typeof spawn> | undefined;
  private server: Server | undefined;
  private sockets = new Set<Socket>();
  private allowed = false;
  private stopping = false;
  private initialized: Promise<void> | undefined;

  constructor(claude: ClaudeIPv4) {
    this.claude = claude;
  }

  initialize(): Promise<void> {
    return (this.initialized ??= this.restore());
  }

  private async restore() {
    try {
      const source: unknown = JSON.parse(
        await readFile(path.join(directory(), "settings.json"), "utf8"),
      );
      const policy = z.object({ egress: egressPolicySchema.nullish() }).parse(source).egress;
      if (policy) await this.start(policy);
    } catch (error) {
      if (error && typeof error === "object" && Reflect.get(error, "code") === "ENOENT") return;
      this.fail("固定出口配置读取或启动失败，请在防护设置中重新导入节点");
    }
  }

  async importCurrent(executable: string, label: string) {
    if (this.state.phase !== "disabled") throw new Error("请先取消锁定并关闭固定出口");
    if (path.basename(executable).toLowerCase() !== "v2rayn.exe")
      throw new Error("请选择 v2rayN.exe");
    const root = path.dirname(executable);
    const source = path.join(root, "binConfigs/config.json");
    if ((await stat(source)).size > 1048576) throw new Error("v2rayN 配置超过 1 MB");
    let node: NodeSnapshot;
    try {
      node = snapshotV2rayNode(JSON.parse(await readFile(source, "utf8")));
    } catch (error) {
      if (error instanceof z.ZodError || error instanceof SyntaxError)
        throw new Error("v2rayN 当前配置格式不受支持，请先选择单个普通节点");
      throw error;
    }
    if (!(await safeStorage.isAsyncEncryptionAvailable()))
      throw new Error("Windows 凭据加密暂不可用，未保存节点");
    const id = randomUUID();
    const profile: Profile = { id, label, ...node };
    const folder = profileDirectory(id);
    await mkdir(folder, { recursive: true });
    try {
      const binary = node.engine === "xray" ? "bin/xray/xray.exe" : "bin/sing_box/sing-box.exe";
      await copyFile(path.join(root, binary), path.join(folder, `${node.engine}.exe`));
      const sealed = await safeStorage.encryptStringAsync(JSON.stringify(profile));
      await writeFile(path.join(folder, "profile.bin.tmp"), sealed, { flag: "wx" });
      await rename(path.join(folder, "profile.bin.tmp"), path.join(folder, "profile.bin"));
    } catch {
      await rm(folder, { recursive: true, force: true });
      throw new Error("节点或独立核心保存失败，请确认 v2rayN 安装完整");
    }
    this.profile = profile;
    this.state = { profile: { id, label, engine: node.engine }, phase: "disabled", error: "" };
  }

  private async load(id: string) {
    if (!(await safeStorage.isAsyncEncryptionAvailable()))
      throw new Error("Windows 凭据加密暂不可用");
    const sealed = await readFile(path.join(profileDirectory(id), "profile.bin"));
    if (sealed.length > 2097152) throw new Error("节点文件过大");
    const decrypted = await safeStorage.decryptStringAsync(sealed);
    const input: unknown = JSON.parse(decrypted.result);
    const profile = profileSchema.parse(input);
    if (profile.id !== id) throw new Error("节点身份不匹配");
    const node = snapshotV2rayNode({ outbounds: [{ ...profile.outbound, tag: "proxy" }] });
    if (node.engine !== profile.engine) throw new Error("节点核心不匹配");
    if (decrypted.shouldReEncrypt) {
      const file = path.join(profileDirectory(id), "profile.bin");
      await writeFile(`${file}.tmp`, await safeStorage.encryptStringAsync(decrypted.result));
      await rename(`${file}.tmp`, file);
    }
    this.profile = { ...profile, ...node };
    this.state.profile = { id, label: profile.label, engine: profile.engine };
    return this.profile;
  }

  async prepare(): Promise<EgressPolicy> {
    if (!this.profile) throw new Error("请先从 v2rayN 导入一个固定节点");
    await this.closeResources();
    return this.start({ id: this.profile.id, label: this.profile.label, port: 0 });
  }

  async retry(policy: EgressPolicy) {
    await this.closeResources();
    await this.start(policy);
  }

  fail(message: string) {
    this.setAllowed(false);
    this.state = { ...this.state, phase: "failed", error: message };
    this.claude.fixedProxyUnavailable(message);
  }

  private async start(policy: EgressPolicy): Promise<EgressPolicy> {
    this.stopping = false;
    this.state = { ...this.state, phase: "starting", error: "" };
    this.claude.fixedProxyUnavailable("固定出口正在启动");
    try {
      const profile = await this.load(policy.id);
      const reserve = createServer();
      const backendPort = await listen(reserve, 0);
      await new Promise<void>((resolve, reject) =>
        reserve.close((error) => (error ? reject(error) : resolve())),
      );
      const child = spawn(nativePath(), ["egress-core", profile.id, profile.engine], {
        windowsHide: true,
        stdio: ["pipe", "ignore", "ignore"],
      });
      this.child = child;
      child.on("error", () => {
        if (this.child === child && !this.stopping) this.fail("固定出口核心启动失败，已保持断网");
      });
      child.on("exit", () => {
        if (this.child === child && !this.stopping)
          this.fail("固定出口核心已退出，已保持断网；请重启通道");
      });
      child.stdin?.on("error", () => {
        if (this.child === child && !this.stopping) this.fail("固定出口核心连接中断，已保持断网");
      });
      child.stdin?.write(`${JSON.stringify(coreConfiguration(profile, backendPort))}\n`);
      let listening = false;
      for (let attempt = 0; attempt < 50 && child.exitCode === null && !child.killed; attempt++) {
        listening = await new Promise<boolean>((resolve) => {
          const socket = createConnection({ host: "127.0.0.1", port: backendPort });
          socket.setTimeout(100);
          const finish = (ok: boolean) => {
            socket.destroy();
            resolve(ok);
          };
          socket.once("connect", () => finish(true));
          socket.once("error", () => finish(false));
          socket.once("timeout", () => finish(false));
        });
        if (listening) break;
        await delay(100);
      }
      if (!listening || this.state.phase === "failed") throw new Error("固定出口核心未能就绪");
      const server = createServer((client) => {
        if (!this.allowed || this.state.phase !== "ready") {
          client.destroy();
          return;
        }
        const upstream = createConnection({ host: "127.0.0.1", port: backendPort });
        this.sockets.add(client);
        this.sockets.add(upstream);
        const close = () => {
          client.destroy();
          upstream.destroy();
          this.sockets.delete(client);
          this.sockets.delete(upstream);
        };
        client.on("error", close);
        upstream.on("error", close);
        client.on("close", close);
        upstream.on("close", close);
        client.pipe(upstream).pipe(client);
      });
      this.server = server;
      const port = await listen(server, policy.port);
      server.on("error", () => this.fail("固定出口代理异常，已保持断网"));
      await this.claude.useFixedProxy(`http://127.0.0.1:${backendPort}`);
      this.state = { ...this.state, phase: "ready", error: "" };
      return { id: policy.id, label: policy.label, port };
    } catch {
      this.fail("固定出口启动失败，请检查节点和核心版本，当前保持断网");
      await this.closeResources();
      throw new Error(this.state.error);
    }
  }

  setAllowed(allowed: boolean) {
    this.allowed = allowed && this.state.phase === "ready";
    if (!this.allowed) {
      for (const socket of this.sockets) socket.destroy();
      this.sockets.clear();
    }
  }

  private async closeResources() {
    this.stopping = true;
    this.setAllowed(false);
    const server = this.server;
    this.server = undefined;
    if (server?.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
    const child = this.child;
    this.child = undefined;
    if (child && child.exitCode === null && child.signalCode === null) {
      child.stdin?.end();
      await Promise.race([
        new Promise<void>((resolve) => child.once("exit", () => resolve())),
        delay(3000),
      ]);
      if (child.exitCode === null && child.signalCode === null) child.kill();
    }
  }

  async disable() {
    await this.closeResources();
    await this.claude.useSystemProxy();
    this.state = { ...this.state, phase: "disabled", error: "" };
  }

  async stop() {
    await this.closeResources();
  }
}
