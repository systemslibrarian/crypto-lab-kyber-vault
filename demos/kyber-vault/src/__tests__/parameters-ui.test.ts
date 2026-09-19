// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('../main');
});

describe('parameter-set decision UI', () => {
  it('starts with the balanced ML-KEM-768 profile selected', () => {
    const choice = document.querySelector('.parameter-choice');
    expect(choice?.textContent).toContain('ML-KEM-768');
    expect(choice?.textContent).toContain('NIST category 3');
    expect(choice?.textContent).toContain('Balanced general-purpose profile');

    const selected = Array.from(document.querySelectorAll<HTMLButtonElement>('[data-variant]')).filter(
      (button) => button.getAttribute('aria-pressed') === 'true',
    );
    expect(selected).toHaveLength(1);
    expect(selected[0]?.textContent).toBe('ML-KEM-768');
  });

  it('updates guidance and artifact sizes when the learner changes profile', () => {
    const cases = [
      { id: 'ml-kem-512', label: 'ML-KEM-512', category: 1, publicKey: 800, ciphertext: 768 },
      { id: 'ml-kem-768', label: 'ML-KEM-768', category: 3, publicKey: 1184, ciphertext: 1088 },
      { id: 'ml-kem-1024', label: 'ML-KEM-1024', category: 5, publicKey: 1568, ciphertext: 1568 },
    ] as const;

    for (const profile of cases) {
      document.querySelector<HTMLButtonElement>(`[data-variant="${profile.id}"]`)?.click();
      const choice = document.querySelector('.parameter-choice');
      expect(choice?.textContent).toContain(profile.label);
      expect(choice?.textContent).toContain(`NIST category ${profile.category}`);
      expect(choice?.textContent).toContain(`Public key ${profile.publicKey} B`);
      expect(choice?.textContent).toContain(`Ciphertext ${profile.ciphertext} B`);
    }
  });
});
