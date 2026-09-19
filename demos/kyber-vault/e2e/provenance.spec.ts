import { expect, test } from '@playwright/test';

test('standards claims expose provenance, freshness, and the Kyber boundary', async ({ page }) => {
  await page.goto('.');
  await page.locator('#tab-params').click();

  const deployment = page.locator('.provenance-card');
  await expect(deployment).toContainText('Final standard');
  await expect(deployment).toContainText('Pre-standard lineage');
  await expect(deployment).toContainText('mlkem768x25519-sha256');
  await expect(deployment).toContainText('Names are not interchangeable');
  await expect(deployment.getByRole('link', { name: 'OpenSSH 9.9 release notes' })).toHaveAttribute(
    'href',
    'https://www.openssh.com/releasenotes.html#9.9',
  );
  await expect(deployment.getByRole('link', { name: "Apple's PQ3 design" })).toHaveAttribute(
    'href',
    'https://security.apple.com/blog/imessage-pq3/',
  );
  await expect(deployment.getByRole('link', { name: 'Signal PQXDH specification' })).toHaveAttribute(
    'href',
    'https://signal.org/docs/specifications/pqxdh/',
  );

  const sources = page.locator('.source-status');
  await expect(sources.locator('time')).toHaveAttribute('datetime', '2026-09-19');
  await expect(sources).toContainText('September 19, 2026');
  await expect(sources).toContainText('Open errata notice');
  await expect(sources).toContainText('November 17, 2025');
  await expect(sources.getByRole('link', { name: /NIST FIPS 203/ })).toHaveAttribute(
    'href',
    'https://csrc.nist.gov/pubs/fips/203/final',
  );
  await expect(sources.getByRole('link', { name: /Pinned NIST ACVP/ })).toHaveAttribute(
    'href',
    /975de31eb83d87039ec88934fdc47d8c312b892d/,
  );
});
