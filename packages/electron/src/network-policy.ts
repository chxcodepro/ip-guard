import { z } from "zod";

export function networkHost(value: string): string {
  let host = value
    .trim()
    .toLowerCase()
    .replace(/^\[|\]$/gu, "")
    .replace(/\.$/u, "");
  if (!host.includes(":")) {
    try {
      host = new URL("http://" + host).hostname;
    } catch {
      return "";
    }
  }
  return ["localhost", "0.0.0.0", "::1"].includes(host) ||
    host.endsWith(".localhost") ||
    /^127(?:\.\d{1,3}){3}$/u.test(host)
    ? "localhost"
    : host;
}
const hostSchema = z
  .string()
  .trim()
  .min(1, "填写目标主机")
  .max(253)
  .refine(
    (value) =>
      !/[\s\\/@?#]/u.test(value) &&
      ((!value.includes("[") && !value.includes("]") && !value.includes(":")) ||
        ["::1", "[::1]"].includes(value)),
    "目标主机不含协议、路径、账号或端口",
  )
  .transform(networkHost)
  .refine(
    (host) =>
      host === "localhost" ||
      z.ipv4().safeParse(host).success ||
      /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/u.test(host),
    "填写域名、IPv4 或 localhost，不含协议、路径和端口",
  );
export const networkRuleSchema = z
  .object({
    id: z.uuid(),
    enabled: z.boolean(),
    host: hostSchema,
    port: z.number().int().min(1).max(65535),
    action: z.enum(["proxy", "direct", "block"]),
  })
  .refine(
    (rule) => rule.host !== "localhost" || rule.action !== "proxy",
    "本机服务请选择直连或阻断",
  );
export const networkPolicySchema = z
  .object({ rules: z.array(networkRuleSchema).max(64, "最多设置 64 条例外") })
  .superRefine((policy, context) => {
    const keys = new Set<string>();
    const ids = new Set<string>();
    policy.rules.forEach((rule, index) => {
      const key = `${rule.host}:${rule.port}`;
      if (keys.has(key))
        context.addIssue({
          code: "custom",
          path: ["rules", index, "host"],
          message: "同一目标端口只保留一条规则",
        });
      keys.add(key);
      if (ids.has(rule.id))
        context.addIssue({
          code: "custom",
          path: ["rules", index, "id"],
          message: "规则标识重复，请删除重复项后重建",
        });
      ids.add(rule.id);
    });
  });
export type NetworkPolicy = z.infer<typeof networkPolicySchema>;
export type NetworkRule = z.infer<typeof networkRuleSchema>;
export const initialNetworkPolicy: NetworkPolicy = {
  rules: [
    {
      id: "b0c7e969-e7e6-470f-9628-d9b82d8cc0ee",
      enabled: true,
      host: "localhost",
      port: 5173,
      action: "direct",
    },
  ],
};
export function networkAction(
  policy: NetworkPolicy,
  target: { host: string; port: number },
): NetworkRule["action"] {
  const host = networkHost(target.host);
  return (
    policy.rules.find((rule) => rule.enabled && rule.host === host && rule.port === target.port)
      ?.action ?? (host === "localhost" ? "block" : "proxy")
  );
}
export function localPolicyPorts(policy: NetworkPolicy): number[] {
  return policy.rules
    .filter((rule) => rule.enabled && rule.host === "localhost" && rule.action === "direct")
    .map((rule) => rule.port)
    .sort((a, b) => a - b);
}
export const networkPolicyStateSchema = z.object({
  settings: networkPolicySchema,
  revision: z.uuid(),
  phase: z.enum(["active", "paused", "inactive", "failed"]),
  programs: z.array(z.string()),
  error: z.string(),
  childProtection: z.boolean(),
  localPorts: z.array(z.number().int().min(1).max(65535)),
});
export type NetworkPolicyState = z.infer<typeof networkPolicyStateSchema>;
export const kernelNetworkPolicySchema = z.object({
  revision: z.uuid(),
  localPorts: z.array(z.number().int().min(1).max(65535)).max(64),
});
export type KernelNetworkPolicy = z.infer<typeof kernelNetworkPolicySchema>;
