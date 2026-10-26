import { contextBridge, ipcRenderer } from "electron";

import type { DesktopApi } from "@ip-guard/electron";
import {
  commandSchema,
  coffeeReportSchema,
  desktopBridgeGlobal,
  desktopChannels,
  replySchema,
  snapshotSchema,
  updateStateSchema,
} from "@ip-guard/electron";

const desktop: DesktopApi = {
  invoke: async (command) =>
    replySchema.parse(
      await ipcRenderer.invoke(desktopChannels.invoke, commandSchema.parse(command)),
    ),
  subscribe: (listener) => {
    const receive = (_event: Electron.IpcRendererEvent, value: unknown) => {
      const result = snapshotSchema.safeParse(value);
      if (result.success) listener(result.data);
    };
    ipcRenderer.on(desktopChannels.update, receive);
    return () => ipcRenderer.removeListener(desktopChannels.update, receive);
  },
  subscribeCoffee: (listener) => {
    const receive = (_event: Electron.IpcRendererEvent, value: unknown) => {
      const result = coffeeReportSchema.safeParse(value);
      if (result.success) listener(result.data);
    };
    ipcRenderer.on(desktopChannels.coffee, receive);
    return () => ipcRenderer.removeListener(desktopChannels.coffee, receive);
  },
  subscribeAppUpdate: (listener) => {
    const receive = (_event: Electron.IpcRendererEvent, value: unknown) => {
      const result = updateStateSchema.safeParse(value);
      if (result.success) listener(result.data);
    };
    ipcRenderer.on(desktopChannels.appUpdate, receive);
    return () => ipcRenderer.removeListener(desktopChannels.appUpdate, receive);
  },
};

contextBridge.exposeInMainWorld(desktopBridgeGlobal, desktop);
