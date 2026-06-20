// @vitest-environment happy-dom
import { beforeAll, describe, expect, it } from 'vitest';

// Mount the real app once, then assert the accessibility contract holds.
// This guards the ARIA/semantic structure against regressions.
beforeAll(async () => {
  document.body.innerHTML = '<div id="app"></div>';
  await import('../main');
});

describe('accessibility structure', () => {
  it('exposes a labelled tablist with one tab per section', () => {
    const tablist = document.querySelector('[role="tablist"]');
    expect(tablist).not.toBeNull();
    expect(tablist?.getAttribute('aria-label')).toBeTruthy();
    expect(document.querySelectorAll('[role="tab"]').length).toBe(5);
  });

  it('uses a roving tabindex: exactly one selected, focusable tab', () => {
    const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
    const selected = tabs.filter((t) => t.getAttribute('aria-selected') === 'true');
    const focusable = tabs.filter((t) => t.getAttribute('tabindex') === '0');
    expect(selected.length).toBe(1);
    expect(focusable.length).toBe(1);
    expect(selected[0]).toBe(focusable[0]);
  });

  it('wires every tab to a labelled tabpanel via aria-controls', () => {
    for (const tab of document.querySelectorAll('[role="tab"]')) {
      const panel = document.getElementById(tab.getAttribute('aria-controls') ?? '');
      expect(panel, `panel for ${tab.id}`).not.toBeNull();
      expect(panel?.getAttribute('role')).toBe('tabpanel');
      expect(panel?.getAttribute('aria-labelledby')).toBe(tab.id);
    }
  });

  it('gives every button an accessible name', () => {
    for (const button of document.querySelectorAll('button')) {
      const name = (button.textContent ?? '').trim() || button.getAttribute('aria-label');
      expect(name, button.outerHTML).toBeTruthy();
    }
  });

  it('labels non-text visualizations and the icon-only theme toggle', () => {
    expect(document.querySelector('#theme-toggle')?.getAttribute('aria-label')).toBeTruthy();
    for (const img of document.querySelectorAll('[role="img"]')) {
      expect(img.getAttribute('aria-label'), img.outerHTML).toBeTruthy();
    }
  });

  it('keeps inactive tabpanels out of the accessibility tree', () => {
    const panels = Array.from(document.querySelectorAll('[role="tabpanel"]'));
    const visible = panels.filter((p) => !p.hasAttribute('hidden'));
    expect(visible.length).toBe(1);
  });
});
