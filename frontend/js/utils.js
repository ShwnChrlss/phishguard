/* =============================================================
   frontend/js/utils.js
   Toast, formatting, DOM helpers — used by every page.

   Engineering concept:
   Small utility layers help avoid duplication, but they should
   stay boring and predictable. This file is deliberately kept
   framework-free so learners can see the underlying DOM work.
   ============================================================= */

const Utils = {

  // ── TOAST NOTIFICATIONS ──────────────────────────────────
  toast(msg, isError = false) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.className = 'show' + (isError ? ' error' : '');
    clearTimeout(el._t);
    el._t = setTimeout(() => { el.className = ''; }, 3500);
  },

  // ── ESCAPING (XSS PREVENTION) ─────────────────────────────
  // CONCEPT: XSS (Cross-Site Scripting)
  // If we insert user data directly into HTML like:
  //   el.innerHTML = userInput
  // An attacker could inject: <script>stealCookies()</script>
  // esc() converts < > & " to harmless HTML entities.
  // Always use esc() before inserting any server data into HTML.
  esc(str) {
    if (str == null) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },

  // ── DATE FORMATTING ───────────────────────────────────────
  fmtDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleString([], {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit'
    });
  },

  fmtDateLong(iso) {
    if (!iso) return '—';
    return new Date(iso).toLocaleString();
  },

  // ── COLOUR HELPERS ────────────────────────────────────────
  scoreColor(score) {
    if (score >= 80) return 'var(--danger)';
    if (score >= 60) return 'var(--warn)';
    if (score >= 40) return '#ff8c00';
    return 'var(--safe)';
  },

  // ── HTML COMPONENT BUILDERS ───────────────────────────────
  // These return HTML strings for repeated UI fragments.
  // Reuse matters here for consistency: the same risk score
  // should look the same on dashboard, reports, and admin pages.
  riskBadge(isPhishing) {
    return isPhishing
      ? '<span class="risk-badge phishing">🚨 Phishing</span>'
      : '<span class="risk-badge safe">✅ Safe</span>';
  },

  riskMeter(score) {
    const color = this.scoreColor(score);
    return `
      <div class="risk-meter" style="min-width:110px;">
        <div class="risk-bar-wrap" style="width:70px;">
          <div class="risk-bar animate" style="width:${score}%;background:${color};"></div>
        </div>
        <span class="risk-num" style="color:${color};">${score}</span>
      </div>`;
  },

  severityBadge(sev) {
    return `<span class="severity-badge ${Utils.esc(sev)}">${Utils.esc(sev)}</span>`;
  },

  statusPill(status) {
    return `<span class="status-pill ${Utils.esc(status)}">${Utils.esc(status)}</span>`;
  },

  // ── DOM HELPERS ───────────────────────────────────────────
  // Shorthand for document.getElementById
  el(id) {
    return document.getElementById(id);
  },

  // Show a loading spinner inside a container
  showLoading(id, cols = 6) {
    const el = document.getElementById(id);
    if (!el) return;
    // If it's a tbody, wrap in a row
    if (el.tagName === 'TBODY') {
      el.innerHTML = `<tr><td colspan="${cols}"><div class="loading"><div class="spinner"></div>Loading...</div></td></tr>`;
    } else {
      el.innerHTML = `<div class="loading"><div class="spinner"></div>Loading...</div>`;
    }
  },

  showEmpty(id, msg = 'No data found.', cols = 6) {
    const el = document.getElementById(id);
    if (!el) return;
    if (el.tagName === 'TBODY') {
      el.innerHTML = `<tr><td colspan="${cols}"><div class="empty">${msg}</div></td></tr>`;
    } else {
      el.innerHTML = `<div class="empty">${msg}</div>`;
    }
  },

  // ── TOPBAR SETUP ──────────────────────────────────────────
  // Call on every protected page to populate the topbar.
  // In a component framework this would likely live in a shared
  // layout component; in vanilla JS we do the same job manually.
  setupTopbar() {
    const user = Auth.getUser();
    if (!user) return;
    const nameEl = document.getElementById('topbar-username');
    if (nameEl) nameEl.textContent = user.username;

    const roleEl = document.getElementById('topbar-role');
    if (roleEl) roleEl.textContent = (user.role || 'user').toUpperCase();

    this.applyRoleVisibility();
  },

  // ── NAV VISIBILITY ───────────────────────────────────────
  // Normal users should only see general navigation plus
  // their own scan history. Analyst/admin users can see
  // operational pages, and only admins can manage users.
  applyRoleVisibility() {
    if (window.AppShell && document.querySelector('[data-shell-nav="primary"]')) {
      return;
    }

    const isLoggedIn = Auth.isLoggedIn();
    const isAnalyst  = Auth.isAnalyst();
    const isAdmin    = Auth.isAdmin();

    const analystOnly = new Set([
      '/alerts',
      '/quarantine',
      '/reports',
      '/ml-dashboard',
      '/status',
    ]);
    const adminOnly = new Set(['/users']);
    const allUsers = new Set(['/history']);

    document.querySelectorAll('.nav-item').forEach((el) => {
      const href = (el.getAttribute('href') || '').split('?')[0];
      let visible = true;

      if (adminOnly.has(href)) {
        visible = isAdmin;
      } else if (analystOnly.has(href)) {
        visible = isAnalyst;
      } else if (allUsers.has(href)) {
        visible = isLoggedIn;
      }

      el.style.display = visible ? '' : 'none';
      el.classList.toggle('hidden', !visible);
    });

    document.querySelectorAll('.nav-section').forEach((section) => {
      const items = Array.from(section.querySelectorAll('.nav-item'));
      const hasVisibleItem = items.some((item) => item.style.display !== 'none');
      const label = section.querySelector('.nav-label');

      if (label) {
        if (!label.dataset.originalLabel) {
          label.dataset.originalLabel = label.textContent;
        }
        if (section.classList.contains('admin-only') && !isAnalyst) {
          label.textContent = 'Activity';
        } else {
          label.textContent = label.dataset.originalLabel;
        }
      }

      section.style.display = hasVisibleItem ? '' : 'none';
      section.classList.toggle('hidden', !hasVisibleItem);
    });
  },

  // ── ACTIVE NAV ITEM ───────────────────────────────────────
  // Highlights the current page's nav link
  setActiveNav(pageId) {
    document.querySelectorAll('.nav-item, .app-nav-link, .app-dropdown-link, .app-mobile-link, .app-dropdown-toggle').forEach(el => {
      el.classList.toggle('active', el.dataset.page === pageId);
    });
  },
};

// ── Timestamp formatting ──────────────────────────────────────
// All backend timestamps are stored in UTC.
// This converts them to the user's local timezone automatically.
// Timezone concept:
// Storing UTC in the database prevents "whose local time was
// this?" bugs. Localising only at the display layer is a common
// production practice for distributed systems.
// new Date("2026-03-05T08:00:00") → "3/5/2026, 11:00:00 AM" (EAT)
//
// Usage: Utils.formatTime(scan.scanned_at)
// Output examples:
//   "Today at 11:32 AM"
//   "Yesterday at 3:15 PM"
//   "Mar 3, 2026 at 9:00 AM"

Utils.formatTime = function(utcString) {
  if (!utcString) return '—';

  const date  = new Date(utcString);
  const now   = new Date();
  const diffMs = now - date;
  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays  = Math.floor(diffMs / 86400000);

  // Just now
  if (diffMins < 1)   return 'Just now';
  if (diffMins < 60)  return `${diffMins}m ago`;
  if (diffHours < 24) return `Today at ${date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`;
  if (diffDays === 1) return `Yesterday at ${date.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})}`;

  // Older — show full local date
  return date.toLocaleString([], {
    month:  'short',
    day:    'numeric',
    year:   'numeric',
    hour:   '2-digit',
    minute: '2-digit',
  });
};

// Short version — just date, no time
Utils.formatDate = function(utcString) {
  if (!utcString) return '—';
  return new Date(utcString).toLocaleDateString([], {
    month: 'short', day: 'numeric', year: 'numeric'
  });
};
