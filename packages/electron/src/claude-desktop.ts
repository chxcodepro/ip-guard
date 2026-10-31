export const claudeDesktopFamilies = [
  "Claude_pzs8sxrjxfjjc",
  "AnthropicPBC.Claude_fnn82j28hfe8t",
] as const;

export function isClaudeDesktopPath(value: string): boolean {
  if (!/[\\/]Claude\.exe$/i.test(value)) return false;
  return value.split(/[\\/]/).some((segment) => {
    const parts = segment.split("_");
    return (
      parts.length === 5 &&
      /^\d+\.\d+\.\d+\.\d+$/.test(parts[1] ?? "") &&
      claudeDesktopFamilies.some(
        (family) => family.toLowerCase() === `${parts[0]}_${parts[4]}`.toLowerCase(),
      )
    );
  });
}
