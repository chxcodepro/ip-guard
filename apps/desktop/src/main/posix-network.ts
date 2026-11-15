import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { promisify } from "node:util";

type Interfaces = ReturnType<typeof networkInterfaces>;
export function macAdapters(text: string, interfaces: Interfaces) {
  const entries = [...text.matchAll(/^(\S+): flags=[^<]*<([^>]*)>/gmu)];
  return entries.flatMap((entry, index) => {
    const name = entry[1],
      flags = entry[2];
    if (!name || name === "lo0" || !flags) return [];
    const block = text.slice(entry.index, entries[index + 1]?.index ?? text.length),
      status = /\bstatus:\s*(active|inactive)/u.exec(block)?.[1];
    const addresses = interfaces[name];
    return [
      {
        id: name,
        name,
        exists: true,
        up:
          flags.split(",").includes("UP") &&
          (status ? status === "active" : Boolean(addresses?.length)),
        ipv4: Boolean(addresses?.some((a) => a.family === "IPv4")),
        error: "",
      },
    ];
  });
}
export async function readPosixNetwork() {
  const interfaces = networkInterfaces();
  if (process.platform === "darwin") {
    const { stdout } = await promisify(execFile)("/sbin/ifconfig", ["-a"], {
      timeout: 4000,
      maxBuffer: 262144,
    });
    return { interfaces, adapters: macAdapters(stdout, interfaces) };
  }
  const names = await readdir("/sys/class/net");
  const adapters = await Promise.all(
    names
      .filter((name) => name !== "lo")
      .map(async (name) => {
        let state = "",
          error = "",
          exists = true;
        try {
          state = (await readFile("/sys/class/net/" + name + "/operstate", "utf8")).trim();
        } catch (cause) {
          exists = !(cause && typeof cause === "object" && Reflect.get(cause, "code") === "ENOENT");
          error = exists ? "网卡状态读取失败" : "网卡已移除";
        }
        const addresses = interfaces[name];
        return {
          id: name,
          name,
          exists,
          up: state === "up" || (state === "unknown" && Boolean(addresses?.length)),
          ipv4: Boolean(addresses?.some((a) => a.family === "IPv4")),
          error,
        };
      }),
  );
  return { interfaces, adapters };
}
