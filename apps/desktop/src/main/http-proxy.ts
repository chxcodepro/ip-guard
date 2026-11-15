import type { Socket } from "node:net";

import { destination } from "./proxy-tunnel.ts";

export class ProxyRequestError extends Error {
  readonly status: 400 | 403;
  constructor(status: 400 | 403, message: string) {
    super(message);
    this.status = status;
  }
}

export function acceptHttpProxy(
  client: Socket,
  options: {
    allowed: () => boolean;
    connect: (target: { host: string; port: number }) => Promise<Socket>;
    sockets: Set<Socket>;
    managed?: Set<Socket>;
  },
) {
  if (!options.allowed() || options.sockets.size >= 512) {
    client.destroy();
    return;
  }
  options.sockets.add(client);
  options.managed?.add(client);
  let buffer = Buffer.alloc(0),
    upstream: Socket | undefined;
  let established = false;
  let replyingError = false;
  const close = () => {
    client.destroy();
    upstream?.destroy();
    options.sockets.delete(client);
    options.managed?.delete(client);
    if (upstream) {
      options.sockets.delete(upstream);
      options.managed?.delete(upstream);
    }
  };
  client.on("error", close);
  client.on("close", close);
  client.setTimeout(10000, close);
  const read = (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    const end = buffer.indexOf("\r\n\r\n");
    if (end < 0) {
      if (buffer.length > 16384) close();
      return;
    }
    if (end > 16384) {
      close();
      return;
    }
    client.off("data", read);
    client.pause();
    void (async () => {
      const lines = buffer.subarray(0, end).toString("latin1").split("\r\n");
      const request = /^([A-Z]+) ([^\s]+) HTTP\/1\.[01]$/u.exec(lines[0] ?? "");
      if (!request) throw new Error("代理请求无效");
      const method = request[1],
        url = request[2] ?? "";
      const parsed = method === "CONNECT" ? undefined : new URL(url);
      if (
        parsed &&
        (!["http:", "ws:"].includes(parsed.protocol) ||
          parsed.username ||
          parsed.password ||
          parsed.hash)
      )
        throw new Error("代理请求地址无效");
      const target = destination(
        method === "CONNECT" ? url : `${parsed?.hostname}:${parsed?.port || 80}`,
      );
      upstream = await options.connect(target);
      options.sockets.add(upstream);
      options.managed?.add(upstream);
      upstream.on("error", () => {
        if (!replyingError) close();
      });
      upstream.on("close", () => {
        if (upstream) {
          options.sockets.delete(upstream);
          options.managed?.delete(upstream);
        }
        // pipe() must flush the client's buffered response before closing a normal upstream EOF.
        if (!upstream?.readableEnded && !replyingError) close();
      });
      if (client.destroyed || !options.allowed()) throw new Error("连接许可已撤销");
      if (method === "CONNECT") {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        established = true;
      } else {
        const upgrade =
          lines.some((line) => /^upgrade:\s*websocket\s*$/iu.test(line)) &&
          lines.some((line) => /^connection:\s*.*\bupgrade\b/iu.test(line));
        const headers = lines
          .slice(1)
          .filter((line) => !/^(proxy-connection|proxy-authorization|connection):/iu.test(line));
        upstream.write(
          `${method} ${parsed?.pathname}${parsed?.search} HTTP/1.1\r\n${headers.join("\r\n")}\r\nConnection: ${upgrade ? "Upgrade" : "close"}\r\n\r\n`,
        );
      }
      if (buffer.length > end + 4) upstream.write(buffer.subarray(end + 4));
      buffer = Buffer.alloc(0);
      client.setTimeout(0);
      upstream.setTimeout(0);
      client.pipe(upstream).pipe(client);
      upstream.resume();
      client.resume();
    })().catch((error: unknown) => {
      if (established || client.destroyed) {
        close();
        return;
      }
      const status = error instanceof ProxyRequestError ? error.status : 502;
      replyingError = true;
      const body = Buffer.from(
        "IP Guard：" +
          (error instanceof ProxyRequestError
            ? error.message
            : "目标服务暂不可用，请检查本机服务或代理通道。"),
      );
      upstream?.destroy();
      client.end(
        "HTTP/1.1 " +
          status +
          " Request Failed\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: " +
          body.length +
          "\r\nConnection: close\r\n\r\n" +
          body.toString("utf8"),
        close,
      );
    });
  };
  client.on("data", read);
}
