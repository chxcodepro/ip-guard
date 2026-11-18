import { z } from "zod";

export const commandProtectionSchema = z.object({
  installed: z.boolean(),
  loaded: z.boolean(),
  enabled: z.boolean(),
  ready: z.boolean(),
  supported: z.boolean(),
  hvci: z.boolean(),
  rebootRequired: z.boolean(),
  phase: z.enum(["not_installed", "disabled", "starting", "ready", "failed"]),
  error: z.string(),
  version: z.string(),
  localPorts: z.array(z.number().int().min(1).max(65535)),
});
export type CommandProtection = z.infer<typeof commandProtectionSchema>;
export const initialCommandProtection: CommandProtection = {
  installed: false,
  loaded: false,
  enabled: false,
  ready: false,
  supported: false,
  hvci: false,
  rebootRequired: false,
  phase: "not_installed",
  error: "",
  version: "Fort 3.20.9 / ABI 65",
  localPorts: [],
};
