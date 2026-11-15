import { createConnection } from "node:net";
import { createInterface } from "node:readline";

import { z } from "zod";

import {
  browserExtensionId,
  browserStateSchema,
  nativeVersion,
  extensionVersionSchema,
} from "@ip-guard/electron";

const [socketPath, origin] = process.argv.slice(2);
if (!socketPath || origin !== `chrome-extension://${browserExtensionId}/`) process.exit(1);
const initial = z.object({
  action: z.literal("watch"),
  protocol: z.literal(1),
  extensionVersion: z.union([z.literal(""), extensionVersionSchema]),
});
let input = Buffer.alloc(0),
  started = false;
let connection: ReturnType<typeof createConnection> | undefined;
let heartbeat: ReturnType<typeof setTimeout> | undefined;
function send(value: unknown) {
  const data = Buffer.from(JSON.stringify(value));
  if (data.length > 16384) throw new Error("Native message exceeds limit");
  const header = Buffer.alloc(4);
  header.writeUInt32LE(data.length);
  process.stdout.write(Buffer.concat([header, data]));
}
const offline = () => {
  clearTimeout(heartbeat);
  connection?.destroy();
  send({
    protocol: 1,
    appVersion: nativeVersion,
    phase: "offline",
    currentIp: "",
    expectedIps: [],
    checkedAt: "",
    reason: "请运行 IP Guard",
  });
  process.stdin.destroy();
  process.exitCode = 1;
};
process.stdin.on("data", (chunk: Buffer) => {
  try {
    if (started) throw new Error("Unexpected native request");
    input = Buffer.concat([input, chunk]);
    if (input.length > 16388) throw new Error("Native request exceeds limit");
    if (input.length < 4) return;
    const length = input.readUInt32LE();
    if (length < 1 || length > 16384) throw new Error("Invalid native length");
    if (input.length < 4 + length) return;
    if (input.length !== 4 + length) throw new Error("Unexpected native bytes");
    const request = initial.parse(JSON.parse(input.subarray(4).toString("utf8")));
    started = true;
    input = Buffer.alloc(0);
    connection = createConnection(socketPath);
    connection.once("connect", () =>
      connection?.write(JSON.stringify({ extensionVersion: request.extensionVersion }) + "\n"),
    );
    connection.once("error", offline);
    connection.once("close", () => process.stdin.destroy());
    const lines = createInterface({ input: connection });
    lines.on("line", (line) => {
      try {
        const state = browserStateSchema.parse(JSON.parse(line));
        send(state);
        clearTimeout(heartbeat);
        heartbeat = setTimeout(offline, 3000);
      } catch {
        offline();
      }
    });
    heartbeat = setTimeout(offline, 3000);
  } catch {
    offline();
  }
});
process.stdin.on("end", () => {
  clearTimeout(heartbeat);
  connection?.destroy();
});
process.stdout.on("error", () => {
  clearTimeout(heartbeat);
  connection?.destroy();
  process.stdin.destroy();
});
