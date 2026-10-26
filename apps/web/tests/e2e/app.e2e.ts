import { expect, test } from "@playwright/test";
import type { Page } from "@playwright/test";

const visit = async (page: Page, path: string) => {
  await page.goto(path, { waitUntil: "networkidle" });
};

test("the home page shows the IPv4 guard setup", async ({ page }) => {
  await visit(page, "/");

  await expect(page.getByRole("heading", { name: "防护总览", exact: true })).toBeVisible();
  await expect(page.getByLabel("允许的公网 IPv4")).toBeVisible();
  await expect(page.getByRole("button", { name: "锁定", exact: true })).toBeDisabled();
  await expect(page.getByText("还没有添加程序")).toBeVisible();
});

test("the dark theme survives a reload", async ({ page }) => {
  await visit(page, "/");

  await page.getByRole("button", { name: "深色", exact: true }).click();
  await expect(page.locator("html")).toHaveClass(/\bdark\b/u);

  await page.reload({ waitUntil: "networkidle" });
  await expect(page.locator("html")).toHaveClass(/\bdark\b/u);
});
