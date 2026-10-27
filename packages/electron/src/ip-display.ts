import { z } from "zod";

const ipv4 = z.ipv4();
const ipv6 = z.ipv6();
const hideV6 = (value: string) => `${value.split(":").slice(0, 2).join(":")}:••••:••••`;
export function formatIPText(value: string, visible = false) {
  if (visible) return value;
  return value
    .replace(/[0-9a-fA-F:.]*:[0-9a-fA-F:.]+/g, (candidate) => {
      if (ipv6.safeParse(candidate).success) return hideV6(candidate);
      if (candidate.startsWith(":") && ipv6.safeParse(candidate.slice(1)).success)
        return `:${hideV6(candidate.slice(1))}`;
      return candidate;
    })
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, (candidate) =>
      ipv4.safeParse(candidate).success
        ? `${candidate.split(".").slice(0, 2).join(".")}.•••.•••`
        : candidate,
    );
}
