import { readFileSync } from 'node:fs';

const workflow = readFileSync(new URL('../.github/workflows/deploy.yml', import.meta.url), 'utf8');
const externalUses = workflow
  .split('\n')
  .map((line) => line.trim())
  .filter((line) => /^-?\s*uses:\s+/.test(line))
  .map((line) => line.replace(/^-\s*/, ''))
  .filter((line) => !line.startsWith('uses: ./'));
const unpinned = externalUses.filter(
  (line) => !/@[0-9a-f]{40}(?:\s|$)/i.test(line),
);

if (externalUses.length === 0) {
  throw new Error('no external GitHub Actions found to verify');
}
if (unpinned.length > 0) {
  throw new Error(`GitHub Actions must use immutable 40-character SHAs:\n${unpinned.join('\n')}`);
}

console.log(`verified ${externalUses.length} immutable GitHub Action references`);
