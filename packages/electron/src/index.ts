import { z } from "zod";

import { proxyEnhancementStateSchema, proxySettingsSchema } from "./proxy-enhancement.ts";
export { proxyAddressSchema, proxySettingsSchema } from "./proxy-enhancement.ts";
export type {
  ProxySettings,
  ProxyEnhancementState,
  EnhancementVerification,
} from "./proxy-enhancement.ts";

import { commandProtectionSchema } from "./command-protection.ts";
export { commandProtectionSchema, initialCommandProtection } from "./command-protection.ts";
export type { CommandProtection } from "./command-protection.ts";

import { extensionVersionSchema } from "./extension-version.ts";
import { egressPolicySchema, egressStateSchema } from "./fixed-egress.ts";
import { allowedIpsSchema, ipv4Attempts } from "./ipv4-policy.ts";
export { egressPolicySchema } from "./fixed-egress.ts";
export type { EgressPolicy, EgressState } from "./fixed-egress.ts";
export {
  ipv4Attempts,
  ipv4AttemptTimeoutMs,
  ipv4ProbeTimeoutMs,
  maxAllowedIps,
  publicIPv4Schema,
} from "./ipv4-policy.ts";
export { formatIPText } from "./ip-display.ts";
export { programProtectionStatus } from "./program-protection-status.ts";
export { extensionVersionSchema, isNewerExtensionVersion } from "./extension-version.ts";
export { claudeDesktopFamilies, isClaudeDesktopPath } from "./claude-desktop.ts";

export const nativeVersion = "0.12.1";
export const nativeProtocol = 18;
export const browserExtensionId = "blmgamidelconfabgilaacbkokomegep";
export const browserHostName = "com.ipguard.browser";
export const browserStateSchema = z
  .object({
    protocol: z.literal(1),
    appVersion: z.string(),
    latestExtensionVersion: extensionVersionSchema.optional(),
    phase: z.enum(["allowed", "blocked", "offline", "unlocked", "checking"]),
    currentIp: z.union([z.literal(""), z.ipv4()]),
    expectedIps: allowedIpsSchema.optional(),
    // Released protocol-1 extensions and hosts still exchange a single address.
    expectedIp: z.union([z.literal(""), z.ipv4()]).optional(),
    checkedAt: z.string(),
    reason: z.string(),
  })
  .refine((value) => value.expectedIps !== undefined || value.expectedIp !== undefined)
  .transform(({ expectedIp, expectedIps, ...value }) => ({
    ...value,
    expectedIps: expectedIps ?? (expectedIp ? [expectedIp] : []),
  }))
  .refine(
    (value) =>
      value.phase !== "allowed" ||
      (value.currentIp !== "" && value.expectedIps.includes(value.currentIp)),
    { message: "Invalid IPv4 permission" },
  );
export type BrowserState = z.infer<typeof browserStateSchema>;
export const extensionStatusSchema = z.object({
  phase: z.enum(["running", "installed", "missing", "unknown"]),
  installedBrowsers: z.array(z.enum(["Chrome", "Edge"])),
  outdatedBrowsers: z.array(z.enum(["Chrome", "Edge"])),
  outdatedConnections: z.number().int().nonnegative(),
  latestVersion: extensionVersionSchema,
  connections: z.number().int().nonnegative(),
  error: z.string(),
});
export type ExtensionStatus = z.infer<typeof extensionStatusSchema>;
export const claudeIpv4Endpoint = "https://claude.ai/cdn-cgi/trace";

export const desktopBridgeGlobal = "desktop";
export const rendererHost = "app.localhost";
export const rendererOrigin = `https://${rendererHost}`;
export const desktopChannels = {
  invoke: "guard:invoke",
  update: "guard:update",
  coffee: "coffee:update",
  appUpdate: "app:update",
} as const;
export const coffeeMetricSchema = z.object({
  id: z.string(),
  label: z.string(),
  value: z.string(),
  detail: z.string(),
  status: z.enum(["neutral", "ok", "info", "warning", "error", "unknown"]),
});
export const coffeeReportSchema = z.object({
  phase: z.enum(["idle", "running", "complete"]),
  checkedAt: z.string(),
  error: z.string(),
  claudeIp: z.string(),
  claudeTimezone: z.string(),
  groups: z.array(
    z.object({ id: z.string(), title: z.string(), items: z.array(coffeeMetricSchema) }),
  ),
});
export type CoffeeMetric = z.infer<typeof coffeeMetricSchema>;
export type CoffeeReport = z.infer<typeof coffeeReportSchema>;
export const appPresetSchema = z.object({
  id: z.enum(["claude-cli", "claude-native", "claude-desktop"]),
  name: z.string(),
  path: z.string(),
  version: z.string(),
  status: z.enum(["ready", "missing", "error"]),
  message: z.string(),
});
export type AppPreset = z.infer<typeof appPresetSchema>;
export const claudeStateSchema = z.object({
  phase: z.enum(["running", "stopped", "unknown"]),
  count: z.number().int().nonnegative(),
  canStop: z.boolean(),
  message: z.string(),
  checkedAt: z.string(),
});
export type ClaudeState = z.infer<typeof claudeStateSchema>;
export const updateStateSchema = z.object({
  phase: z.enum([
    "unconfigured",
    "idle",
    "checking",
    "available",
    "current",
    "downloading",
    "downloaded",
    "installing",
    "error",
  ]),
  currentVersion: z.string(),
  latestVersion: z.string(),
  progress: z.number().min(0).max(100),
  checkedAt: z.string(),
  message: z.string(),
  repository: z.string(),
});
export type UpdateState = z.infer<typeof updateStateSchema>;
export const ipv4Schema = z.ipv4();
export const ipv6Schema = z.ipv6();
export const settingsSchema = z.object({
  expectedIps: allowedIpsSchema.refine((ips) => ips.length > 0, "请至少填写一个公网 IPv4"),
  intervalSeconds: z.number().int().min(1).max(60),
});
export const appSchema = z.object({
  id: z.uuid(),
  name: z.string().min(1).max(100),
  path: z.string().min(4).max(1024),
  arguments: z.string().max(4096),
  apiScope: z.enum(["auto", "claude", "other"]).default("auto"),
  enhanced: z.boolean().default(false),
  enabled: z.boolean(),
});
export const logSchema = z.object({
  time: z.string(),
  level: z.enum(["info", "warning", "error"]),
  message: z.string(),
});
export const adapterSchema = z.object({
  id: z.string(),
  name: z.string(),
  exists: z.boolean(),
  up: z.boolean(),
  ipv4: z.boolean(),
  error: z.string(),
});
export const probeStateSchema = z.object({
  round: z.number().int().nonnegative(),
  attempt: z.number().int().min(0).max(ipv4Attempts),
  phase: z.enum(["idle", "checking", "passed", "failed"]),
});
export type ProbeState = z.infer<typeof probeStateSchema>;
export const startupStatusSchema = z.object({
  enabled: z.boolean(),
  state: z.enum(["unknown", "off", "waiting", "running", "ready", "error"]),
  message: z.string(),
});
export const initialStartupStatus = {
  enabled: false,
  state: "unknown",
  message: "等待检查启动项",
} as const;
export const snapshotSchema = z.object({
  enhancementReady: z.boolean().default(false),
  enhancementReason: z.string().default("等待增强出口复核"),
  enhancementPhase: z.enum(["idle", "checking", "passed", "blocked", "failed"]).default("idle"),
  driver: commandProtectionSchema,
  commandBlockId: z.string(),
  commandBlockReason: z.string(),
  commandBlockAppId: z.string(),
  egress: egressPolicySchema.nullable(),
  online: z.boolean(),
  admin: z.boolean(),
  ready: z.boolean(),
  checking: z.boolean(),
  probe: probeStateSchema,
  networkIssue: z.enum(["idle", "checking", "ip_changed", "ip_unavailable", "enforcement_failed"]),
  nativeVersion: z.literal(nativeVersion),
  ipSource: z.literal(claudeIpv4Endpoint),
  currentIp: z.string(),
  adapter: z.string(),
  lastChecked: z.string(),
  reason: z.string(),
  detection: z.string(),
  running: z.array(z.string()),
  otherModelRunning: z.array(z.string()),
  autostart: z.boolean(),
  startup: startupStatusSchema,
  rulesLocked: z.boolean(),
  networkAdapters: z.array(adapterSchema),
  watchedAdapter: adapterSchema,
  networkAdapterId: z.string(),
  settings: z.object({
    expectedIps: allowedIpsSchema,
    intervalSeconds: z.number().int().min(1).max(60),
  }),
  apps: z.array(appSchema.extend({ pathIssue: z.string(), isClaudeCode: z.boolean() })),
  logs: z.array(logSchema),
});
export const commandSchema = z.discriminatedUnion("action", [
  z.object({ action: z.literal("extension:setup") }),
  z.object({ action: z.literal("extension:status") }),
  z.object({ action: z.literal("proxy:status") }),
  z.object({ action: z.literal("proxy:configure"), settings: proxySettingsSchema }),
  z.object({ action: z.literal("enhance"), id: z.uuid(), enabled: z.boolean() }),
  z.object({ action: z.literal("kernel:install") }),
  z.object({ action: z.literal("kernel:repair") }),
  z.object({ action: z.literal("kernel:rescue") }),
  z.object({ action: z.literal("egress:status") }),
  z.object({ action: z.literal("egress:disable") }),
  z.object({ action: z.literal("egress:retry") }),
  z.object({ action: z.literal("status") }),
  z.object({ action: z.literal("check") }),
  z.object({ action: z.literal("lock"), settings: settingsSchema }),
  z.object({ action: z.literal("unlock") }),
  z.object({ action: z.literal("add"), app: appSchema }),
  z.object({
    action: z.literal("edit"),
    id: z.uuid(),
    name: z.string().min(1).max(100),
    arguments: z.string().max(4096),
  }),
  z.object({ action: z.literal("protect"), id: z.uuid(), enabled: z.boolean() }),
  z.object({ action: z.literal("remove"), id: z.uuid() }),
  z.object({ action: z.literal("start"), id: z.uuid() }),
  z.object({ action: z.literal("stop"), id: z.uuid() }),
  z.object({ action: z.literal("autostart"), enabled: z.boolean() }),
  z.object({ action: z.literal("pick") }),
  z.object({ action: z.literal("presets") }),
  z.object({ action: z.literal("desktop:relocate"), id: z.uuid() }),
  z.object({ action: z.literal("adapter:set"), adapterId: z.string().max(256) }),
  z.object({ action: z.literal("ip:current") }),
  z.object({ action: z.literal("claude:status") }),
  z.object({ action: z.literal("claude:stop") }),
  z.object({ action: z.literal("logs") }),
  z.object({ action: z.literal("elevate") }),
  z.object({ action: z.literal("restart") }),
  z.object({ action: z.literal("coffee:status") }),
  z.object({ action: z.literal("coffee:refresh") }),
  z.object({ action: z.literal("update:status") }),
  z.object({ action: z.literal("update:check") }),
  z.object({ action: z.literal("update:download") }),
  z.object({ action: z.literal("update:install") }),
  z.object({ action: z.literal("update:releases") }),
]);
export type Settings = z.infer<typeof settingsSchema>;
export type ProtectedApp = z.infer<typeof appSchema>;
export type Snapshot = z.infer<typeof snapshotSchema>;
export type Command = z.infer<typeof commandSchema>;
export const replySchema = z.object({
  extension: extensionStatusSchema.optional(),
  proxyEnhancement: proxyEnhancementStateSchema.optional(),
  egress: egressStateSchema.optional(),
  snapshot: snapshotSchema.optional(),
  selectedPath: z.string().optional(),
  cancelled: z.boolean().optional(),
  diagnostics: coffeeReportSchema.optional(),
  presets: z.array(appPresetSchema).optional(),
  ipv4: ipv4Schema.optional(),
  claude: claudeStateSchema.optional(),
  appUpdate: updateStateSchema.optional(),
});
export type Reply = z.infer<typeof replySchema>;
export interface DesktopApi {
  invoke: (command: Command) => Promise<Reply>;
  subscribe: (listener: (snapshot: Snapshot) => void) => () => void;
  subscribeCoffee: (listener: (report: CoffeeReport) => void) => () => void;
  subscribeAppUpdate: (listener: (report: UpdateState) => void) => () => void;
}
