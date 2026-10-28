import { z } from "zod";

export const extensionVersionSchema = z
  .string()
  .regex(/^\d{1,5}(?:\.\d{1,5}){1,3}$/)
  .refine((value) => value.split(".").every((part) => Number(part) <= 65535));

export function isNewerExtensionVersion(candidate: string, current: string): boolean {
  if (
    !extensionVersionSchema.safeParse(candidate).success ||
    !extensionVersionSchema.safeParse(current).success
  )
    return false;
  const next = candidate.split(".").map(Number);
  const installed = current.split(".").map(Number);
  for (let index = 0; index < 4; index++) {
    const difference = (next[index] ?? 0) - (installed[index] ?? 0);
    if (difference) return difference > 0;
  }
  return false;
}
