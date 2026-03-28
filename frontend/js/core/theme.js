/* =============================================================
   frontend/js/core/theme.js
   Global theme selection and toggle controls.

   Accessibility concept:
   Themes are not only about aesthetics. They affect contrast,
   readability, glare, and comfort in different environments.
   Persisting the choice respects user preference across sessions.
   ============================================================= */

const Theme = {
  KEY: 'pg_theme',

  getPreferredTheme() {
    const saved = localStorage.getItem(this.KEY);
    if (saved === 'light' || saved === 'dark') return saved;
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
  },

  apply(theme) {
    const resolved = theme === 'light' ? 'light' : 'dark';
    document.documentElement.dataset.theme = resolved;
    localStorage.setItem(this.KEY, resolved);
    this.syncButtons();
    return resolved;
  },

  toggle() {
    return this.apply(this.current() === 'dark' ? 'light' : 'dark');
  },

  current() {
    return document.documentElement.dataset.theme || this.getPreferredTheme();
  },

  buttonLabel() {
    return this.current() === 'dark' ? 'Light theme' : 'Dark theme';
  },

  buttonIcon() {
    return this.current() === 'dark' ? 'L' : 'D';
  },

  syncButtons() {
    const label = this.buttonLabel();
    const icon = this.buttonIcon();

    document.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      btn.setAttribute('aria-label', label);
      btn.setAttribute('title', label);
      const iconEl = btn.querySelector('[data-theme-icon]');
      const textEl = btn.querySelector('[data-theme-text]');
      if (iconEl) iconEl.textContent = icon;
      if (textEl) textEl.textContent = btn.dataset.themeText === 'full' ? label : 'Theme';
    });
  },

  ensureFloatingToggle() {
    // On public/auth pages there is no shared topbar yet, so we
    // mount a small floating control instead of duplicating markup
    // across every page.
    if (document.querySelector('.topbar')) return;
    if (document.querySelector('[data-theme-floating]')) return;

    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'app-icon-btn theme-fab';
    btn.dataset.themeToggle = '1';
    btn.dataset.themeFloating = '1';
    btn.innerHTML = '<span data-theme-icon></span>';
    btn.addEventListener('click', () => Theme.toggle());
    document.body.appendChild(btn);
    this.syncButtons();
  },

  init() {
    this.apply(this.getPreferredTheme());
    this.ensureFloatingToggle();
  },
};

Theme.apply(Theme.getPreferredTheme());

document.addEventListener('DOMContentLoaded', () => {
  Theme.init();
});
