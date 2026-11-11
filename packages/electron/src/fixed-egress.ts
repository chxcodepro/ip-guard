import { z } from "zod";

export const egressPolicySchema = z.object({
  id: z.uuid(),
  label: z.string().min(1).max(100),
  port: z.number().int().min(1024).max(65535),
});
export type EgressPolicy = z.infer<typeof egressPolicySchema>;
export const egressStateSchema = z.object({
  profile: z
    .object({ id: z.uuid(), label: z.string(), engine: z.enum(["xray", "sing-box"]) })
    .nullable(),
  phase: z.enum(["disabled", "starting", "ready", "failed"]),
  error: z.string(),
});
export type EgressState = z.infer<typeof egressStateSchema>;
