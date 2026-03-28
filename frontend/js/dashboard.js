/* =============================================================
   frontend/js/dashboard.js — Dashboard page logic

   UX architecture concept:
   This page supports two personas with one screen:
   - admin/analyst users get operational metrics
   - regular users get a personal activity view
   That is a lightweight example of role-based UI composition.
   ============================================================= */

async function initDashboard() {
  Utils.setupTopbar();
  Utils.setActiveNav('dashboard');
  await loadDashboard();
}

function setDashboardMode(mode) {
  const badge = Utils.el('alert-count');

  if (mode === 'personal') {
    // Least privilege in the UI:
    // regular users still get value from the page without seeing
    // controls that imply access to operations data they do not have.
    Utils.el('model-status').textContent       = 'PERSONAL VIEW';
    Utils.el('stat-queue-label').textContent   = 'Review Queue';
    Utils.el('stat-queue-sub').textContent     = 'Analyst/Admin only';
    Utils.el('recent-alerts-title').textContent = 'Security Feed';
    if (badge) badge.classList.add('hidden');
    return;
  }

  Utils.el('model-status').textContent        = 'MODEL ONLINE';
  Utils.el('stat-queue-label').textContent    = 'Pending Alerts';
  Utils.el('recent-alerts-title').textContent = 'Active Alerts';
}

async function loadDashboard() {
  Utils.el('dash-time').textContent = 'Updated: ' + new Date().toLocaleTimeString();

  const { ok, data } = await API.getDashboard();

  if (!ok) {
    // Progressive enhancement:
    // try the richer admin endpoint first, then gracefully fall
    // back to a personal view rather than failing the whole page.
    await loadPersonalDashboard();
    return;
  }

  setDashboardMode('admin');

  const s = data.data.stats;
  Utils.el('stat-total').textContent    = s.total_scans;
  Utils.el('stat-phishing').textContent = s.total_phishing;
  Utils.el('stat-safe').textContent     = s.total_safe;
  Utils.el('stat-alerts').textContent   = s.pending_alerts;
  Utils.el('stat-rate').textContent     = s.detection_rate + '% detection rate';
  Utils.el('stat-queue-sub').textContent = s.critical_alerts + ' critical';

  // Alert badge
  const badge = Utils.el('alert-count');
  if (badge) {
    if (s.pending_alerts > 0) {
      badge.textContent = s.pending_alerts;
      badge.classList.remove('hidden');
    } else {
      badge.classList.add('hidden');
    }
  }

  // Charts
  if (s.total_scans > 0) {
    Charts.donut('chart-donut', s.total_phishing, s.total_safe);
  }

  renderRecentScans(data.data.recent_scans);
  renderRecentAlerts(data.data.recent_alerts);
}

async function loadPersonalDashboard() {
  setDashboardMode('personal');

  const { ok, data } = await API.getScanHistory(1, 10);
  if (!ok) return;

  const scans    = data.data.scans || [];
  const phishing = scans.filter(s => s.is_phishing).length;
  const total    = data.data.total;

  Utils.el('stat-total').textContent    = total;
  Utils.el('stat-phishing').textContent = phishing;
  Utils.el('stat-safe').textContent     = total - phishing;
  Utils.el('stat-alerts').textContent   = 'Locked';
  Utils.el('stat-rate').textContent     = total > 0
    ? Math.round((phishing / total) * 100) + '% flagged in your recent scans'
    : 'No scans yet';

  if (phishing + (total - phishing) > 0) {
    Charts.donut('chart-donut', phishing, total - phishing);
  }

  renderRecentScans(scans);
  const alertsEl = Utils.el('recent-alerts');
  if (alertsEl) {
    alertsEl.innerHTML = `
      <div class="empty">
        Team alerts, quarantine review, and reports are available to analyst/admin accounts.
      </div>`;
  }
}

function renderRecentScans(scans) {
  const el = Utils.el('recent-scans');
  if (!el) return;

  if (!scans || !scans.length) {
    el.innerHTML = '<div class="empty">No scans yet — try the Analyzer page.</div>';
    return;
  }

  el.innerHTML = scans.map(s => `
    <div style="display:flex;align-items:center;gap:1rem;padding:0.75rem 1.25rem;border-bottom:1px solid var(--border);">
      <div style="flex:1;min-width:0;">
        <div class="truncate text-sm" style="color:var(--text);max-width:260px;">${Utils.esc(s.email_preview || 'No preview')}</div>
        <div class="text-xs text-dim text-mono" style="margin-top:2px;">${Utils.fmtDate(s.scanned_at)}</div>
      </div>
      ${Utils.riskBadge(s.is_phishing)}
      <span style="font-family:var(--font-mono);font-size:0.7rem;font-weight:700;color:${Utils.scoreColor(s.risk_score)};">${s.risk_score}</span>
    </div>
  `).join('');
}

function renderRecentAlerts(alerts) {
  const el = Utils.el('recent-alerts');
  if (!el) return;

  if (!alerts || !alerts.length) {
    el.innerHTML = '<div class="empty">No active alerts.</div>';
    return;
  }

  el.innerHTML = alerts.map(a => `
    <div style="padding:0.9rem 1.25rem;border-bottom:1px solid var(--border);">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.3rem;">
        ${Utils.severityBadge(a.severity)}
        <span class="text-xs text-dim text-mono">${Utils.fmtDate(a.created_at)}</span>
      </div>
      <div class="text-sm" style="color:var(--text);">${Utils.esc(a.title)}</div>
      <div class="text-xs text-dim text-mono" style="margin-top:3px;">${Utils.esc((a.message || '').slice(0, 90))}...</div>
    </div>
  `).join('');
}

window.addEventListener('DOMContentLoaded', initDashboard);
