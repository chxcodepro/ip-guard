import { describe, expect, it } from "vite-plus/test";

import { updateFailure } from "./update-error.ts";

describe("updater failures", () => {
  it("recognizes the observed wrapped 504 instead of reporting a missing release", () => {
    const error = new Error(
      'Cannot parse releases feed: Error: Unable to find latest version on GitHub: HttpError: 504 "method: GET url: https://github.com/example/app/releases/latest"',
    );
    expect(updateFailure(error)).toEqual({
      retryable: true,
      message: "GitHub 连接超时（HTTP 504），请稍后重试。",
    });
  });
  it("retries temporary connections and server failures", () => {
    for (const error of [
      new Error("net::ERR_NETWORK_CHANGED"),
      new Error("net::ERR_PROXY_CONNECTION_FAILED"),
      Object.assign(new Error("bad gateway"), { statusCode: 502 }),
    ])
      expect(updateFailure(error).retryable).toBe(true);
    expect(updateFailure(new Error("Request timed out")).message).toContain("连接超时");
  });
  it("keeps metadata, permission, certificate and integrity failures explicit", () => {
    for (const error of [
      new Error("ERR_CERT_AUTHORITY_INVALID"),
      Object.assign(new Error("denied"), { statusCode: 403 }),
      new Error("ERR_UPDATER_CHECKSUM_MISMATCH"),
      new Error("ERR_UPDATER_CHANNEL_FILE_NOT_FOUND: HttpError: 404"),
    ])
      expect(updateFailure(error).retryable).toBe(false);
    expect(
      updateFailure(new Error("ERR_UPDATER_CHANNEL_FILE_NOT_FOUND: HttpError: 404")).message,
    ).toContain("发布文件尚未就绪");
  });
});
