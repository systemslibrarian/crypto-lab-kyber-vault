import { readFileSync } from 'node:fs';

interface LockedPackage {
  version?: string;
  integrity?: string;
}

interface PackageLock {
  packages?: Record<string, LockedPackage>;
}

const packageLock = JSON.parse(
  readFileSync(new URL('./package-lock.json', import.meta.url), 'utf8'),
) as PackageLock;
const nobleLock = packageLock.packages?.['node_modules/@noble/post-quantum'];

if (!nobleLock?.version || !nobleLock.integrity) {
  throw new Error('package-lock.json is missing the pinned @noble/post-quantum release receipt');
}

export const lockedImplementation = Object.freeze({
  version: nobleLock.version,
  integrity: nobleLock.integrity,
});
