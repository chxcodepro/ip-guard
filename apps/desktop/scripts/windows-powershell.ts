export function windowsPowerShellEnvironment() {
  // Let Windows PowerShell build its own paths instead of importing PowerShell 7 modules.
  return Object.fromEntries(
    Object.entries(process.env).filter(([name]) => name.toUpperCase() !== "PSMODULEPATH"),
  );
}
