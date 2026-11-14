import { z } from "zod";

export const commandProtectionSchema = z.object({
  installed: z.boolean(),
  loaded: z.boolean(),
  enabled: z.boolean(),
  ready: z.boolean(),
  supported: z.boolean(),
  phase: z.enum(["not_installed", "disabled", "starting", "ready", "failed"]),
  error: z.string(),
  version: z.string(),
});
export type CommandProtection = z.infer<typeof commandProtectionSchema>;
export const initialCommandProtection: CommandProtection = {
  installed: false, loaded: false, enabled: false, ready: false, supported: false,
  phase: "not_installed", error: "", version: "Fort 3.20.9 / ABI 65",
};
