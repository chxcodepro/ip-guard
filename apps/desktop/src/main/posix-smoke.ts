import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";

import { browserExtensionId, browserStateSchema, nativeVersion } from "@ip-guard/electron";

import { posixBrowserSocketPath } from "./posix-platform.ts";

export async function verifyNativeBridge(executable: string, helper: string) {
  assert.equal(process.env.GITHUB_ACTIONS, "true");
  const child = spawn(
    executable,
    [helper, posixBrowserSocketPath(), `chrome-extension://${browserExtensionId}/`],
    { env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" }, stdio: ["pipe", "pipe", "pipe"] },
  );
  const exited = once(child, "exit");
  void exited.catch(() => undefined);
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk.toString()));
  try {
    const state = await new Promise<ReturnType<typeof browserStateSchema.parse>>(
      (resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error("Native bridge did not reply: " + stderr)),
          5000,
        );
        let data = Buffer.alloc(0);
        const finish = () => clearTimeout(timer);
        child.once("error", (error) => {
          finish();
          reject(error);
        });
        child.stdout.on("data", (chunk) => {
          data = Buffer.concat([data, chunk]);
          if (data.length < 4) return;
          const length = data.readUInt32LE();
          if (length > 16384) {
            finish();
            reject(new Error("Native reply too large"));
            return;
          }
          if (data.length < 4 + length) return;
          finish();
          try {
            resolve(
              browserStateSchema.parse(JSON.parse(data.subarray(4, 4 + length).toString("utf8"))),
            );
          } catch (error) {
            reject(error);
          }
        });
        const request = Buffer.from(
          JSON.stringify({ action: "watch", protocol: 1, extensionVersion: nativeVersion }),
        );
        const header = Buffer.alloc(4);
        header.writeUInt32LE(request.length);
        child.stdin.write(Buffer.concat([header, request]));
      },
    );
    assert.equal(state.phase, "unlocked");
    child.stdin.end();
    const timer = setTimeout(() => child.kill(), 5000);
    try {
      const [code] = await exited;
      assert.equal(code, 0, stderr);
    } finally {
      clearTimeout(timer);
    }
    return { nativeMessaging: "passed", phase: state.phase };
  } finally {
    if (child.exitCode === null) child.kill();
  }
}
