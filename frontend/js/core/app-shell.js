/* =============================================================
   frontend/js/core/app-shell.js
   Shared navigation shell for all protected pages.

   Frontend architecture concept:
   In component frameworks, this would be a shared layout
   component. In vanilla JS, we build the same abstraction by
   rendering one topbar template into every protected page.
   ============================================================= */

const AppShell = {
  // Information architecture concept:
  // Primary navigation is task-oriented and shared by everyone.
  // Operations links are role-gated because they expose broader
  // organisational data and administrative actions.
  primaryNav: [
    { id: 'dashboard', href: '/dashboard', label: 'Dashboard' },
    { id: 'analyzer', href: '/detect', label: 'Analyze' },
    { id: 'history', href: '/history', label: 'History' },
    { id: 'chatbot', href: '/chat', label: 'Chat' },
  ],

  opsNav: [
    { id: 'admin_alerts', href: '/alerts', label: 'Alerts', minRole: 'analyst' },
    { id: 'quarantine', href: '/quarantine', label: 'Quarantine', minRole: 'analyst' },
    { id: 'reports', href: '/reports', label: 'Reports', minRole: 'analyst' },
    { id: 'ml_dashboard', href: '/ml-dashboard', label: 'ML Dashboard', minRole: 'analyst' },
    { id: 'status', href: '/status', label: 'System Status', minRole: 'analyst' },
    { id: 'admin_users', href: '/users', label: 'User Admin', minRole: 'admin' },
  ],

  roleRank(role) {
    return { user: 1, analyst: 2, admin: 3 }[role] || 0;
  },

  canAccess(item, role) {
    return this.roleRank(role) >= this.roleRank(item.minRole || 'user');
  },

  getPageId() {
    return document.body?.dataset.page || '';
  },

  allowedOps(role) {
    return this.opsNav.filter((item) => this.canAccess(item, role));
  },

  getStatusMarkup(topbar) {
    const current = topbar.querySelector('.topbar-status');
    if (current) return current.outerHTML;

    const legacy = topbar.querySelector('.model-status');
    if (!legacy) return '';

    const clone = legacy.cloneNode(true);
    clone.className = 'topbar-status';
    return clone.outerHTML;
  },

  buildNavLink(item, currentPage, extraClass = 'app-nav-link') {
    const active = currentPage === item.id ? ' active' : '';
    return `
      <a class="${extraClass}${active}" href="${item.href}" data-page="${item.id}">
        <span>${item.label}</span>
      </a>`;
  },

  buildDropdown(role, currentPage) {
    const opsItems = this.allowedOps(role);
    if (!opsItems.length) return '';

    const active = opsItems.some((item) => item.id === currentPage) ? ' active' : '';
    const links = opsItems.map((item) => `
      <a class="app-dropdown-link${currentPage === item.id ? ' active' : ''}" href="${item.href}" data-page="${item.id}">
        <span>${item.label}</span>
        <span class="app-dropdown-meta">${item.minRole}</span>
      </a>`).join('');

    return `
      <div class="app-dropdown" data-shell-dropdown="ops">
        <button class="app-dropdown-toggle${active}" type="button" aria-expanded="false" aria-haspopup="menu">
          <span>Ops</span>
        </button>
        <div class="app-dropdown-menu">
          ${links}
        </div>
      </div>`;
  },

  buildMobile(role, currentPage) {
    const primary = this.primaryNav.map((item) => this.buildNavLink(item, currentPage, 'app-mobile-link')).join('');
    const opsItems = this.allowedOps(role);
    const ops = opsItems.length
      ? `
        <div class="app-mobile-group">
          <div class="app-mobile-label">Operations</div>
          ${opsItems.map((item) => this.buildNavLink(item, currentPage, 'app-mobile-link')).join('')}
        </div>`
      : '';

    return `
      <div class="app-mobile-panel" id="app-mobile-panel">
        <div class="app-mobile-group">
          <div class="app-mobile-label">Navigate</div>
          ${primary}
        </div>
        ${ops}
      </div>`;
  },

  closeTransientUi() {
    document.querySelectorAll('.app-dropdown.open, .app-user.open').forEach((node) => {
      node.classList.remove('open');
      const trigger = node.querySelector('button[aria-expanded]');
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
    });
    const mobile = document.getElementById('app-mobile-panel');
    if (mobile) mobile.classList.remove('open');
    const mobileToggle = document.getElementById('app-mobile-toggle');
    if (mobileToggle) mobileToggle.setAttribute('aria-expanded', 'false');
  },

  bindInteractions(topbar) {
    // Event delegation pattern would also work here, but direct
    // binding keeps the logic easier to read for learners.
    topbar.querySelectorAll('[data-shell-dropdown]').forEach((wrapper) => {
      const toggle = wrapper.querySelector('button');
      if (!toggle) return;
      toggle.addEventListener('click', (event) => {
        event.stopPropagation();
        const wasOpen = wrapper.classList.contains('open');
        this.closeTransientUi();
        wrapper.classList.toggle('open', !wasOpen);
        toggle.setAttribute('aria-expanded', String(!wasOpen));
      });
    });

    const mobileToggle = topbar.querySelector('#app-mobile-toggle');
    const mobilePanel = topbar.querySelector('#app-mobile-panel');
    if (mobileToggle && mobilePanel) {
      mobileToggle.addEventListener('click', (event) => {
        event.stopPropagation();
        const wasOpen = mobilePanel.classList.contains('open');
        this.closeTransientUi();
        mobilePanel.classList.toggle('open', !wasOpen);
        mobileToggle.setAttribute('aria-expanded', String(!wasOpen));
      });
    }

    topbar.querySelectorAll('[data-theme-toggle]').forEach((btn) => {
      btn.addEventListener('click', () => Theme.toggle());
    });

    document.addEventListener('click', (event) => {
      if (!event.target.closest('.app-dropdown') && !event.target.closest('.app-user')) {
        this.closeTransientUi();
      }
    });

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') this.closeTransientUi();
    });
  },

  render() {
    const topbar = document.querySelector('.topbar');
    if (!topbar || topbar.dataset.shellReady === '1') return;

    const user = typeof Auth !== 'undefined' ? Auth.getUser() : null;
    const role = user?.role || 'user';
    const page = this.getPageId();
    const statusMarkup = this.getStatusMarkup(topbar);
    const preservedExtras = Array.from(topbar.querySelectorAll('[data-shell-preserve]'))
      .map((node) => node.outerHTML)
      .join('');

    const primaryNav = this.primaryNav.map((item) => this.buildNavLink(item, page)).join('');
    const dropdown = this.buildDropdown(role, page);
    const mobilePanel = this.buildMobile(role, page);
    const roleLabel = role.toUpperCase();
    const displayName = user?.username || user?.email || 'Guest';

    topbar.innerHTML = `
      <div class="topbar-shell">
        <a class="topbar-logo" href="/dashboard">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7L12 2z"></path>
            <path d="M9 12l2 2 4-4" stroke-linecap="round" stroke-linejoin="round"></path>
          </svg>
          Phish<span>Guard</span>
        </a>

        <nav class="app-nav" data-shell-nav="primary">
          ${primaryNav}
          ${dropdown}
        </nav>

        ${statusMarkup}

        <button class="app-mobile-toggle" id="app-mobile-toggle" type="button" aria-label="Open navigation" aria-controls="app-mobile-panel" aria-expanded="false">
          <span>Nav</span>
        </button>

        <div class="topbar-right">
          <span class="alert-badge hidden" id="alert-count">0</span>
          ${preservedExtras}
          <button class="app-icon-btn" type="button" data-theme-toggle="1">
            <span data-theme-icon></span>
          </button>
          <div class="app-user" data-shell-dropdown="user">
            <button class="user-badge" type="button" aria-expanded="false" aria-haspopup="menu">
              <span class="user-badge-copy"><b id="topbar-username">${displayName}</b></span>
              <span class="role-pill" id="topbar-role">${roleLabel}</span>
            </button>
            <div class="app-user-menu">
              <button class="app-user-action" type="button" data-theme-toggle="1" data-theme-text="full">
                <span>Theme</span>
                <span class="app-user-meta"><span data-theme-icon></span> <span data-theme-text></span></span>
              </button>
              <button class="app-user-action" type="button" onclick="Auth.logout()">
                <span>Log out</span>
                <span class="app-user-meta">Secure exit</span>
              </button>
            </div>
          </div>
        </div>

        ${mobilePanel}
      </div>`;

    topbar.dataset.shellReady = '1';
    this.bindInteractions(topbar);
    Theme.syncButtons();
  },

  init() {
    if (!document.body?.dataset.page) return;
    if (typeof Auth !== 'undefined' && !Auth.isLoggedIn()) return;
    this.render();
  },
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => AppShell.init(), { once: true });
} else {
  AppShell.init();
}
