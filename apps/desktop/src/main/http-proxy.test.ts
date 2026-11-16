import { createServer as createHttpServer } from "node:http";
import { createConnection, createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { afterEach, describe, expect, it, vi } from "vite-plus/test";

import { networkPolicySchema } from "@ip-guard/electron";

import { acceptHttpProxy } from "./http-proxy.ts";
import { NetworkPolicies } from "./network-policies.ts";

// Only Electron's host metadata is replaced; sockets, routing and the local HTTP services run for real.
vi.mock("electron", () => ({ app: { getPath: () => "/unused-local-fixture" } }));

const servers: Server[] = [],
  sockets = new Set<Socket>();
async function listen(server: Server): Promise<number> {
  servers.push(server);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Local fixture did not bind");
  return address.port;
}
afterEach(async () => {
  for (const socket of sockets) socket.destroy();
  for (const server of servers.splice(0))
    if (server.listening) await new Promise<void>((resolve) => server.close(() => resolve()));
});
function policies(port: number) {
  const policy = new NetworkPolicies(),
    revision = crypto.randomUUID();
  policy.commit({
    revision,
    settings: networkPolicySchema.parse({
      loopbackDirect: false,
      rules: [
        { id: crypto.randomUUID(), enabled: true, host: "localhost", port, action: "direct" },
      ],
    }),
  });
  policy.observeKernel(revision);
  return policy;
}
async function exchange(port: number, request: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const client = createConnection({ host: "127.0.0.1", port });
    let text = "";
    sockets.add(client);
    client.setTimeout(3000, () => {
      client.destroy();
      reject(new Error("Local fixture timed out"));
    });
    client.on("error", reject);
    client.on("data", (data) => (text += data.toString()));
    client.on("close", () => {
      sockets.delete(client);
      resolve(text);
    });
    client.once("connect", () => client.write(request));
  });
}
describe("policy HTTP gateway", () => {
  it("opens a local development server on this machine, rather than asking the remote proxy", async () => {
    const body = "local-development:" + "x".repeat(262144);
    const local = await listen(createHttpServer((_request, response) => response.end(body)));
    let forwarded = 0;
    const upstream = await listen(
      createServer((socket) => {
        forwarded++;
        socket.destroy();
      }),
    );
    const policy = policies(local);
    const gate = await listen(
      createServer((client) =>
        acceptHttpProxy(client, {
          sockets,
          allowed: () => policy.confirmed,
          connect: (target) =>
            policy.connect({ protocol: "http", host: "127.0.0.1", port: upstream }, target),
        }),
      ),
    );
    const response = await exchange(
      gate,
      `GET http://localhost:${local}/preview HTTP/1.1\r\nHost: localhost:${local}\r\n\r\n`,
    );
    expect(response).toContain("200 OK");
    expect(response.endsWith(body)).toBe(true);
    expect(forwarded).toBe(0);
    const blocked = await exchange(
      gate,
      `GET http://localhost:${upstream}/ HTTP/1.1\r\nHost: localhost:${upstream}\r\n\r\n`,
    );
    expect(blocked).toContain("403 Request Failed");
    expect(forwarded).toBe(0);
  });
  it("retains a development WebSocket upgrade and its bidirectional bytes", async () => {
    const server = createHttpServer();
    let connection = "";
    server.on("upgrade", (request, socket) => {
      connection = request.headers.connection ?? "";
      socket.write(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
      );
      socket.on("data", (data) => socket.write(data));
    });
    const local = await listen(server),
      policy = policies(local);
    const gate = await listen(
      createServer((client) =>
        acceptHttpProxy(client, {
          sockets,
          allowed: () => policy.confirmed,
          connect: (target) =>
            policy.connect({ protocol: "http", host: "127.0.0.1", port: 1 }, target),
        }),
      ),
    );
    const response = await new Promise<string>((resolve, reject) => {
      const client = createConnection({ host: "127.0.0.1", port: gate });
      let text = "",
        sent = false;
      sockets.add(client);
      client.on("error", reject);
      client.setTimeout(3000, () => {
        client.destroy();
        reject(new Error("WebSocket fixture timed out"));
      });
      client.once("connect", () =>
        client.write(
          `GET http://localhost:${local}/hmr HTTP/1.1\r\nHost: localhost:${local}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n`,
        ),
      );
      client.on("data", (data) => {
        text += data.toString();
        if (!sent && text.includes("\r\n\r\n")) {
          sent = true;
          client.write("hmr-fixture-bytes");
        }
        if (text.includes("hmr-fixture-bytes")) {
          client.destroy();
          resolve(text);
        }
      });
    });
    expect(response).toContain("101 Switching Protocols");
    expect(connection.toLowerCase()).toBe("upgrade");
  });
  it("continues to tunnel ordinary public targets through the configured proxy", async () => {
    let target = "";
    const upstream = await listen(
      createServer((socket) => {
        let data = "",
          connected = false;
        socket.on("data", (chunk) => {
          data += chunk.toString();
          if (!data.includes("\r\n\r\n")) return;
          if (!connected) {
            target = data.split("\r\n")[0] ?? "";
            data = "";
            connected = true;
            socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
          } else
            socket.end("HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\nproxied");
        });
      }),
    );
    const policy = policies(5173);
    const gate = await listen(
      createServer((client) =>
        acceptHttpProxy(client, {
          sockets,
          allowed: () => policy.confirmed,
          connect: (request) =>
            policy.connect({ protocol: "http", host: "127.0.0.1", port: upstream }, request),
        }),
      ),
    );
    const response = await exchange(
      gate,
      "GET http://api.example.test/resource HTTP/1.1\r\nHost: api.example.test\r\n\r\n",
    );
    expect(target).toBe("CONNECT api.example.test:80 HTTP/1.1");
    expect(response).toContain("proxied");
  });
  it("rejects a local exception that points at a known proxy port", () => {
    const policy = policies(5173);
    policy.reserve("enhancement", [5173]);
    expect(() => policy.prepare(policy.record.settings)).toThrow("代理端口冲突");
  });
});
