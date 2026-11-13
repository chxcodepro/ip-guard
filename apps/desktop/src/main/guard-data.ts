import path from "node:path";

import { app } from "electron";

export const guardDataDirectory = () =>
  path.join(process.env.LOCALAPPDATA ?? path.join(app.getPath("home"), "AppData/Local"), "IPGuard");
