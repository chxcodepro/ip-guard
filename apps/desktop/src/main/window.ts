import { BrowserWindow, shell } from "electron";

import { isExternalUrl, isTrustedUrl } from "#src/main/renderer-route.ts";

const openOutside = (target: string) => {
  if (isExternalUrl(target)) {
    void shell.openExternal(target);
  }
};

export const createMainWindow = ({
  devOrigin,
  preload,
  url,
  background = false,
}: {
  devOrigin: string | null;
  preload: string;
  url: string;
  background?: boolean;
}) => {
  const win = new BrowserWindow({
    height: 840,
    minHeight: 640,
    minWidth: 760,
    title: "IP Guard",
    backgroundColor: "#f6f7f8",
    autoHideMenuBar: true,
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      preload,
      sandbox: true,
      webviewTag: false,
    },
    width: 1180,
  });

  win.once("ready-to-show", () => {
    if (!background) win.show();
  });

  win.webContents.setWindowOpenHandler((details) => {
    openOutside(details.url);

    return { action: "deny" };
  });
  win.webContents.on("will-navigate", (event, target) => {
    if (!isTrustedUrl(target, devOrigin)) {
      event.preventDefault();
      openOutside(target);
    }
  });

  void win.loadURL(url);

  return win;
};
