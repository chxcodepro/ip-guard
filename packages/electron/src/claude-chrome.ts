import { z } from "zod";

export const claudeChromeExtensionId = "fcoeoabgfenejglbffodgkkbkcdhcgfn";
export const claudeChromeStoreUrl = `https://chromewebstore.google.com/detail/claude/${claudeChromeExtensionId}`;
export const isClaudeChromePath = (value: string) =>
  /[\\/]IPGuard[\\/]browser[\\/]Application[\\/]chrome\.exe$/i.test(value);
export const claudeChromeStateSchema = z.object({
  prepared: z.boolean(),
  path: z.string(),
  version: z.string(),
  sourceVersion: z.string(),
  extensionInstalled: z.boolean(),
  error: z.string(),
});
export type ClaudeChromeState = z.infer<typeof claudeChromeStateSchema>;
