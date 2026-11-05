import { z } from "zod";

export const ipv4AttemptTimeoutMs = 4500;
export const ipv4Attempts = 3;
export const ipv4ProbeTimeoutMs = 16000;
export const maxAllowedIps = 32;
export const publicIPv4Schema = z.ipv4().refine((value) => {
  const [a, b, c] = value.split(".").map(Number);
  return !(
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a !== undefined && a >= 224) ||
    (a === 100 && b !== undefined && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b !== undefined && b >= 16 && b <= 31) ||
    (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)))) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113)
  );
});
export const allowedIpsSchema = z
  .array(publicIPv4Schema)
  .max(maxAllowedIps)
  .refine((ips) => new Set(ips).size === ips.length, "允许地址有重复项");
