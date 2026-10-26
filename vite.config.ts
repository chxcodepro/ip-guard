import { defineConfig } from "vite-plus";

const generatedFiles = ["**/routeTree.gen.ts"];

const vendoredFiles = ["packages/ui/src/components/**"];

export default defineConfig({
  fmt: {
    ignorePatterns: [...generatedFiles],
    proseWrap: "preserve",
    sortImports: {
      customGroups: [
        {
          elementNamePattern: ["@ip-guard/**"],
          groupName: "workspace",
        },
      ],
      groups: [
        "builtin",
        "external",
        "workspace",
        ["internal", "subpath"],
        ["parent", "sibling", "index"],
        "style",
        "unknown",
      ],
      ignoreCase: true,
      newlinesBetween: true,
      order: "asc",
    },
  },
  lint: {
    extends: [],
    ignorePatterns: [...generatedFiles, ...vendoredFiles],
    jsPlugins: [{ name: "vite-plus", specifier: "vite-plus/oxlint-plugin" }],
    options: { typeAware: true, typeCheck: true },
    rules: {
      "vite-plus/prefer-vite-plus-imports": "error",
    },
  },
  staged: {
    "*": "vp check --fix",
  },
  test: {
    passWithNoTests: true,
    projects: [
      {
        test: {
          include: ["apps/desktop/src/**/*.test.ts", "packages/*/src/**/*.test.ts"],
          name: "unit",
        },
      },
    ],
  },
});
