await import("./build-assets.ts");
if (process.platform === "win32") {
  await import("./prepare-fort.ts");
  await import("./build-native.ts");
}
