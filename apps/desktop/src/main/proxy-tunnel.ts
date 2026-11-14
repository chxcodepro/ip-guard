import { createConnection, isIP } from "node:net";
import type { Socket } from "node:net";

import { SocksClient } from "socks";

export type ProxyEndpoint = { protocol: "http" | "socks5"; host: string; port: number };
export function proxyEndpoint(address: string): ProxyEndpoint {
  const url = new URL(address);
  if (
    !["http:", "socks5:"].includes(url.protocol) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !["", "/"].includes(url.pathname)
  )
    throw new Error("代理地址须使用 HTTP 或 SOCKS5，认证代理请通过本地代理工具接入");
  const port = Number(url.port || (url.protocol === "http:" ? 80 : 0));
  if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535)
    throw new Error("代理地址或端口无效");
  return {
    protocol: url.protocol === "http:" ? "http" : "socks5",
    host: url.hostname.replace(/^\[|\]$/g, ""),
    port,
  };
}
export function systemProxyEndpoint(resolved: string): ProxyEndpoint {
  const first = resolved.split(";")[0]?.trim() ?? "";
  const match = /^(PROXY|SOCKS5|SOCKS)\s+(\[[^\]]+\]|[^\s:]+):(\d+)$/i.exec(first);
  if (!match)
    throw new Error(
      "当前网络未提供 HTTP / SOCKS5 代理端口；请开启代理工具的系统代理或填写代理地址",
    );
  return proxyEndpoint(
    `${match[1]?.toUpperCase() === "PROXY" ? "http" : "socks5"}://${match[2]}:${match[3]}`,
  );
}
export function destination(authority: string): { host: string; port: number } {
  if (!/^[^\s\\/@?#]+:\d+$/.test(authority)) throw new Error("代理目标无效");
  const url = new URL(`http://${authority}`);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const port = Number(authority.slice(authority.lastIndexOf(":") + 1));
  if (!host || port < 1 || port > 65535 || !Number.isInteger(port) || host.length > 253)
    throw new Error("代理目标无效");
  if (isIP(host) === 6) throw new Error("增强通道仅支持 IPv4 与远程域名解析");
  return { host, port };
}
export async function openTunnel(
  proxy: ProxyEndpoint,
  target: { host: string; port: number },
): Promise<Socket> {
  if (proxy.protocol === "socks5") {
    const result = await SocksClient.createConnection({
      command: "connect",
      proxy: { host: proxy.host, port: proxy.port, type: 5 },
      destination: target,
      timeout: 8000,
    });
    return result.socket;
  }
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: proxy.host, port: proxy.port });
    let header = Buffer.alloc(0);
    const fail = (error: Error) => {
      socket.destroy();
      reject(error);
    };
    const data = (chunk: Buffer) => {
      header = Buffer.concat([header, chunk]);
      const end = header.indexOf("\r\n\r\n");
      if (end < 0) {
        if (header.length > 16384) fail(new Error("代理响应过大"));
        return;
      }
      if (!/^HTTP\/1\.[01] 200(?: |\r)/.test(header.subarray(0, end).toString("latin1"))) {
        fail(new Error("上游代理拒绝连接，请检查端口和认证"));
        return;
      }
      socket.pause();
      socket.off("data", data);
      socket.off("error", fail);
      socket.setTimeout(0);
      socket.off("timeout", timeout);
      if (header.length > end + 4) socket.unshift(header.subarray(end + 4));
      resolve(socket);
    };
    const timeout = () => fail(new Error("上游代理连接超时"));
    socket.on("error", fail);
    socket.on("data", data);
    socket.setTimeout(8000, timeout);
    socket.once("connect", () => {
      const authority = `${target.host}:${target.port}`;
      socket.write(
        `CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\nConnection: keep-alive\r\n\r\n`,
      );
    });
  });
}
