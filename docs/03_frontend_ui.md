# Frontend UI Structure

This project uses plain HTML, CSS, and JavaScript served by Flask.

## Frontend Theory Map

This UI is useful for learning because it shows several frontend concepts without hiding them behind a framework:

- Shared shell architecture:
  a common navbar is rendered across protected pages
- Design tokens:
  colors, spacing, radii, and layout values live in shared CSS variables
- Role-based UI:
  the same app shell can expose different capabilities depending on user role
- Progressive enhancement:
  the browser improves the experience, but core security decisions still live on the backend

## Where To Edit The Main Shell

- Shared navbar and role-aware navigation:
  [frontend/js/core/app-shell.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/core/app-shell.js)
- Theme selection and light/dark toggle:
  [frontend/js/core/theme.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/core/theme.js)
- Shared layout rules for navbar, main content, dropdowns, and responsive behavior:
  [frontend/css/layout.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/layout.css)
- Theme variable overrides:
  [frontend/css/themes.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/themes.css)
- Base design tokens:
  [frontend/css/variables.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/variables.css)

## Where To Edit Shared Components

- Buttons, cards, tables, badges, modals:
  [frontend/css/components.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/components.css)
- Base typography, form controls, utility classes:
  [frontend/css/base.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/base.css)
- Page-specific shared styles:
  [frontend/css/pages.css](/home/shwn/Desktop/Active_projects/phishguard/frontend/css/pages.css)

## Where To Edit Page Logic

- Dashboard:
  [frontend/js/dashboard.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/dashboard.js)
- Analyzer:
  [frontend/js/analyzer.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/analyzer.js)
- Shared auth/session behavior:
  [frontend/js/auth.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/auth.js)
- Shared API client:
  [frontend/js/api.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/api.js)
- Shared helpers:
  [frontend/js/utils.js](/home/shwn/Desktop/Active_projects/phishguard/frontend/js/utils.js)

## Navigation Model

Primary navigation is the same for all logged-in users:

- Dashboard
- Analyze
- History
- Chat

Operations are shown in a dropdown for elevated roles:

- Analyst and admin:
  Alerts, Quarantine, Reports, ML Dashboard, System Status
- Admin only:
  User Admin

## Theme Model

The app now uses CSS variables for themes.

- Dark theme is the default product theme.
- Light theme is available through the theme toggle.
- The selected theme is saved in `localStorage` using the `pg_theme` key.

## Practical Editing Tips

- If you want to change colors globally, start in `variables.css` and `themes.css`.
- If you want to change navbar structure or role visibility, edit `app-shell.js`.
- If you want to change spacing, header rhythm, or content width, edit `layout.css`.
- If a page looks different from the rest, search that page for inline `<style>` blocks and `style=` attributes first.

## Suggested Long-Term Cleanup

To make the frontend even easier to teach and hand off later:

- keep reducing page-local inline styles
- move repeated table/card/header patterns into shared CSS classes
- centralize more page bootstrapping patterns in shared JS helpers
- keep using token-based theming rather than page-specific color overrides
