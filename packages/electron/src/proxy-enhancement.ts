import { z } from "zod";

export const proxyAddressSchema = z
  .string()
  .trim()
  .max(2048)
  .refine((value) => {
    try {
      const url = new URL(value);
      return (
        ["http:", "socks5:"].includes(url.protocol) &&
        Boolean(url.hostname) &&
        Boolean(url.port || url.protocol === "http:") &&
        !url.username &&
        !url.password &&
        !url.search &&
        !url.hash &&
        (url.pathname === "" || url.pathname === "/")
      );
    } catch {
      return false;
    }
  }, "填写 HTTP / SOCKS5 代理地址，例如 http://127.0.0.1:7890");
export const proxySettingsSchema = z.discriminatedUnion("mode", [
  z.object({ mode: z.literal("system") }),
  z.object({ mode: z.literal("manual"), address: proxyAddressSchema }),
]);
export type ProxySettings = z.infer<typeof proxySettingsSchema>;
export const enhancementVerificationSchema = z.object({
  phase: z.enum(["idle", "checking", "passed", "blocked", "failed"]),
  checkedAt: z.string(),
  currentIp: z.string(),
  reason: z.string(),
});
export type EnhancementVerification = z.infer<typeof enhancementVerificationSchema>;
export const proxyEnhancementStateSchema = z.object({
  settings: proxySettingsSchema,
  phase: z.enum(["idle", "ready", "unavailable"]),
  endpoint: z.string(),
  error: z.string(),
  verification: enhancementVerificationSchema.optional(),
});
export type ProxyEnhancementState = z.infer<typeof proxyEnhancementStateSchema>;
