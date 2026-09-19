import { expect, test } from '@playwright/test';

test('production page enforces CSP with no third-party runtime requests', async ({ page }) => {
  const requestedUrls: string[] = [];
  const browserErrors: string[] = [];

  page.on('request', (request) => requestedUrls.push(request.url()));
  page.on('pageerror', (error) => browserErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') browserErrors.push(message.text());
  });

  await page.addInitScript(() => {
    const violations: string[] = [];
    Object.defineProperty(globalThis, '__cspViolations', {
      value: violations,
      configurable: false,
    });
    document.addEventListener('securitypolicyviolation', (event) => {
      violations.push(
        [event.effectiveDirective, event.blockedURI, event.sourceFile].filter(Boolean).join(' | '),
      );
    });
  });

  await page.goto('.');
  await expect(page.getByRole('heading', { name: 'ML-KEM', level: 1 })).toBeVisible();

  const policy = await page
    .locator('meta[http-equiv="Content-Security-Policy"]')
    .getAttribute('content');
  expect(policy).toContain("default-src 'none'");
  expect(policy).toContain("script-src 'self'");
  expect(policy).toContain("style-src 'self'");
  expect(policy).toContain("connect-src 'none'");
  expect(policy).not.toContain('unsafe-inline');
  expect(policy).not.toContain('unsafe-eval');

  await expect(page.locator('script:not([src]), style, [style]')).toHaveCount(0);

  const pageOrigin = new URL(page.url()).origin;
  const thirdPartyRequests = requestedUrls.filter((url) => {
    const parsed = new URL(url);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.origin !== pageOrigin;
  });
  expect(thirdPartyRequests).toEqual([]);

  const violations = await page.evaluate(
    () => (globalThis as typeof globalThis & { __cspViolations: string[] }).__cspViolations,
  );
  expect(violations).toEqual([]);
  expect(browserErrors).toEqual([]);
});
