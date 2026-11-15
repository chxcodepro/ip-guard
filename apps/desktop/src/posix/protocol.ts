import { z } from "zod";

export const launchRequestSchema = z
  .object({
    id: z.uuid(),
    cwd: z.string().min(1).max(4096),
    args: z.array(z.string().max(4096)).max(128),
  })
  .strict();
export const launchReplySchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("error"), message: z.string() }),
  z.object({
    type: z.literal("launch"),
    path: z.string().min(1),
    args: z.array(z.string()),
    proxy: z.string().url(),
    cli: z.boolean(),
  }),
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
