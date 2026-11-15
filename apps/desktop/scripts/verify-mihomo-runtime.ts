import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createServer as httpServer, request } from "node:http";
import type { RequestListener } from "node:http";
import { createConnection, createServer } from "node:net";
import type { Server, Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { nativeVersion } from "@ip-guard/electron";

import { coreConfiguration, snapshotMihomoNode } from "../src/main/egress-config.ts";
import { MihomoResolver } from "../src/main/mihomo.ts";

if (process.env.GITHUB_ACTIONS !== "true" || process.env.RUNNER_ENVIRONMENT !== "github-hosted")
  throw new Error("Runtime verification requires an isolated GitHub-hosted runner.");
const binary = process.env.IPGUARD_MIHOMO;
assert(binary, "Official Mihomo binary is required");
const desktop = path.resolve(import.meta.dirname, ".."),
  temporary = await mkdtemp(path.join(os.tmpdir(), "ipguard-mihomo-")),
  sockets = new Set<Socket>(),
  servers: Server[] = [];
async function listen(server: Server, pipe?: string) {
  servers.push(server);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  const ready = once(server, "listening");
  if (pipe) server.listen(pipe);
  else server.listen(0, "127.0.0.1");
  await ready;
  const address = server.address();
  if (typeof address === "string") return 0;
  assert(address);
  return address.port;
}
async function unusedPort() {
  const server = createServer(),
    port = await listen(server);
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}
try {
  // A loopback HTTP proxy stands in for the remote provider; the real Mihomo and Native run unchanged.
  const forwarded: string[] = [];
  const remote = httpServer();
  remote.on("connect", (req, socket) => {
    forwarded.push(req.url ?? "");
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    let received = "";
    socket.on("data", (data) => {
      received += data.toString();
      if (received.includes("\r\n\r\n"))
        socket.end("HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nvia-private");
    });
  });
  const remotePort = await listen(remote);
  let selected = "remote-a";
  let apiError = "";
  const control: RequestListener = (req, res) => {
    if (req.method !== "GET" || req.headers.authorization !== "Bearer isolated-fixture") {
      apiError = "Controller request contract failed";
      res.writeHead(403).end();
      return;
    }
    res.setHeader("Content-Type", "application/json");
    res.end(
      JSON.stringify(
        req.url === "/version"
          ? { meta: true }
          : {
              proxies: {
                AI: { type: "Selector", now: selected },
                "remote-a": { type: "Http" },
                "remote-b": { type: "Http" },
              },
            },
      ),
    );
  };
  const api = httpServer(control);
  const controllerPort = await listen(api);
  const file = path.join(temporary, "profile.yaml");
  const profile = {
    "external-controller": "127.0.0.1:" + controllerPort,
    secret: "isolated-fixture",
    proxies: ["remote-a", "remote-b"].map((name) => ({
      name,
      type: "http",
      server: "127.0.0.1",
      port: remotePort,
    })),
    "proxy-groups": [{ name: "AI", type: "select", proxies: ["remote-a", "remote-b"] }],
  };
  await writeFile(file, JSON.stringify(profile));
  const resolver = new MihomoResolver();
  const source = { executable: binary, config: file, pid: process.pid };
  let ownerChecks = 0;
  const owner = async () => {
    ownerChecks++;
  };
  const first = await resolver.read(source, undefined, owner);
  assert.equal(first.name, "remote-a");
  selected = "remote-b";
  assert.equal((await resolver.read(source, undefined, owner)).name, "remote-b");
  const pipe = String.raw`\\.\pipe\ipguard-mihomo-ci-` + crypto.randomUUID();
  const piped = httpServer(control);
  await listen(piped, pipe);
  await writeFile(file, JSON.stringify({ ...profile, "external-controller-pipe": pipe }));
  assert.equal(
    (
      await resolver.read(source, undefined, async (controller) => {
        assert.deepEqual(controller, { kind: "pipe", path: pipe });
        ownerChecks++;
      })
    ).name,
    "remote-b",
  );
  assert.equal(apiError, "");
  assert.equal(ownerChecks, 6);
  console.log("PASS controller GET/authentication, live group changes and Windows named pipe");

  const id = crypto.randomUUID();
  assert(process.env.LOCALAPPDATA);
  const root = path.resolve(process.env.LOCALAPPDATA, "IPGuard/egress"),
    folder = path.join(root, id);
  assert.equal(path.dirname(folder), root);
  await mkdir(folder, { recursive: true });
  const native = path.join(desktop, "dist/native", nativeVersion, "IpGuard.Native.exe");
  const image = path.join(folder, "mihomo.exe");
  await copyFile(binary, image);
  const port = await unusedPort();
  const child = spawn(native, ["egress-core", id, "mihomo"], {
    stdio: ["pipe", "ignore", "pipe"],
    windowsHide: true,
  });
  const exited = once(child, "exit");
  void exited.catch(() => undefined);
  let stderr = "";
  child.stderr.on("data", (data) => {
    stderr += data.toString();
  });
  child.stdin.on("error", () => {
    stderr += "Native configuration pipe closed.";
  });
  try {
    child.stdin.write(
      JSON.stringify(coreConfiguration(snapshotMihomoNode(first.node), port)) + "\n",
    );
    let ready = false;
    for (let i = 0; i < 80 && child.exitCode === null; i++) {
      ready = await new Promise<boolean>((resolve) => {
        const socket = createConnection({ host: "127.0.0.1", port });
        socket.once("connect", () => {
          socket.destroy();
          resolve(true);
        });
        socket.once("error", () => resolve(false));
      });
      if (ready) break;
      await delay(100);
    }
    assert(ready, "Private Mihomo did not listen: " + stderr);
    const response = await new Promise<string>((resolve, reject) => {
      const req = request(
        { host: "127.0.0.1", port, path: "http://198.51.100.10/isolated", agent: false },
        (res) => {
          let text = "";
          res.on("data", (chunk) => (text += chunk.toString()));
          res.on("end", () => resolve(text));
          res.on("error", reject);
        },
      );
      req.setTimeout(10000, () => req.destroy(new Error("Fixture forwarding timed out")));
      req.on("error", reject);
      req.end();
    });
    assert.equal(response, "via-private");
    assert.deepEqual(forwarded, ["198.51.100.10:80"]);
    console.log("PASS real Native -> private Mihomo -> proxy fixture -> HTTP response");
  } finally {
    child.stdin.end();
    try {
      await Promise.race([
        exited,
        delay(6000).then(() => {
          throw new Error("Private Native did not exit");
        }),
      ]);
    } finally {
      if (child.exitCode === null) {
        child.kill();
        await exited;
      }
      await rm(folder, { recursive: true, force: true });
    }
  }
  await assert.rejects(
    new Promise<void>((resolve, reject) => {
      const socket = createConnection({ host: "127.0.0.1", port });
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.destroy();
        resolve();
      });
    }),
    "Private proxy stayed listening after Native exit",
  );
  console.log("PASS closing Native stdin terminates the private core and releases its listener");
} finally {
  for (const socket of sockets) socket.destroy();
  await Promise.all(
    servers
      .filter((s) => s.listening)
      .map((s) => new Promise<void>((resolve) => s.close(() => resolve()))),
  );
  await rm(temporary, { recursive: true, force: true });
}
