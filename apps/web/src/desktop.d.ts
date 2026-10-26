import type { DesktopApi } from "@ip-guard/electron";

declare global {
  interface Window {
    desktop?: DesktopApi;
  }
}
