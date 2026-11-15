import path from "node:path";

import { app } from "electron";

import { posixDataDirectory } from "./posix-platform.ts";

export const guardDataDirectory = () =>
  process.platform === "win32"
    ? path.join(
        process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"),
        "IPGuard",
      )
    : posixDataDirectory();
