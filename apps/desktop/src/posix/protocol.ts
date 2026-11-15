import { z } from "zod";

export const launchRequestSchema = z
  .object({
    id: z.uuid(),
    cwd: z.string().min(1).max(4096),
    args: z.array(z.string().max(4096)).max(128),
    provider: z.enum(["claude", "other", "unknown"]).default("unknown"),
  })
  .strict();
const launch = z.object({
  type: z.literal("launch"),
  path: z.string().min(1),
  args: z.array(z.string()),
  cli: z.boolean(),
});
export const launchReplySchema = z.union([
  z.object({ type: z.literal("error"), message: z.string() }),
  launch.extend({ scope: z.literal("guarded"), proxy: z.string().url() }),
  launch.extend({ scope: z.literal("other") }),
]);
export const proxyEnvironment = (proxy: string) => ({
  HTTP_PROXY: proxy,
  HTTPS_PROXY: proxy,
  ALL_PROXY: proxy,
  NO_PROXY: "",
  http_proxy: proxy,
  https_proxy: proxy,
  all_proxy: proxy,
  no_proxy: "",
});
