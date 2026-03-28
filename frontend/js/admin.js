/* =============================================================
   frontend/js/admin.js — Admin pages: alerts, scans, users

   Operations concept:
   Admin pages are read-heavy incident-response views. The main
   frontend job here is to turn raw API records into scannable
   operational tables with status, severity, and timing cues.
   ============================================================= */

// ── ALERTS ────────────────────────────────────────────────────
// These actions mirror a simple incident lifecycle:
// pending -> acknowledged -> resolved
async function loadAlerts() {
  Utils.showLoading('alerts-tbody', 8);
  const { ok, data } = await API.getAlerts();

  if (!ok || !data.data?.alerts?.length) {
    Utils.showEmpty('alerts-tbody', 'No alerts found.', 8);
    return;
  }

  Utils.el('alerts-tbody').innerHTML = data.data.alerts.map(a => `
    <tr>
      <td class="text-mono text-dim">#${a.id}</td>
      <td>${Utils.severityBadge(a.severity)}</td>
      <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${Utils.esc(a.title)}</td>
      <td style="color:${Utils.scoreColor(a.risk_score)};font-family:var(--font-mono);font-weight:700;">${a.risk_score}</td>
      <td class="text-dim text-mono">${Utils.esc(a.target_email || '—')}</td>
      <td>${Utils.statusPill(a.status)}</td>
      <td class="text-dim text-mono">${Utils.fmtDate(a.created_at)}</td>
      <td>
        ${a.status === 'pending'
          ? `<button class="btn btn-secondary btn-sm" onclick="ackAlert(${a.id})">ACK</button>`
          : ''}
        ${a.status !== 'resolved'
          ? `<button class="btn btn-ghost btn-sm" style="margin-left:4px;" onclick="resolveAlert(${a.id})">RESOLVE</button>`
          : '<span class="text-muted text-xs text-mono">resolved</span>'}
      </td>
    </tr>
  `).join('');
}

async function ackAlert(id) {
  const { ok } = await API.acknowledgeAlert(id);
  if (ok) { Utils.toast('Alert acknowledged.'); loadAlerts(); }
  else Utils.toast('Failed.', true);
}

async function resolveAlert(id) {
  const { ok } = await API.resolveAlert(id, 'Resolved via dashboard');
  if (ok) { Utils.toast('Alert resolved.'); loadAlerts(); }
  else Utils.toast('Failed.', true);
}

// ── ALL SCANS ─────────────────────────────────────────────────
async function loadAdminScans() {
  Utils.showLoading('admin-scans-tbody', 8);
  const filter = Utils.el('scan-filter')?.value || '';
  const { ok, data } = await API.getScans(1, filter);

  if (!ok || !data.data?.scans?.length) {
    Utils.showEmpty('admin-scans-tbody', 'No scans found.', 8);
    return;
  }

  Utils.el('admin-scans-tbody').innerHTML = data.data.scans.map(s => `
    <tr>
      <td class="text-mono text-dim">#${s.id}</td>
      <td><div class="truncate" style="max-width:200px;">${Utils.esc(s.email_preview || '—')}</div></td>
      <td class="text-dim text-mono">${Utils.esc(s.email_sender || '—')}</td>
      <td>${Utils.riskBadge(s.is_phishing)}</td>
      <td>${Utils.riskMeter(s.risk_score)}</td>
      <td>${Utils.statusPill(s.status)}</td>
      <td class="text-dim text-mono">${s.user_id || 'anon'}</td>
      <td class="text-dim text-mono">${Utils.fmtDate(s.scanned_at)}</td>
    </tr>
  `).join('');
}

// ── USERS ─────────────────────────────────────────────────────
// User management is intentionally display-first here. The app
// avoids inline mutation controls in the listing until the data
// model and permissions are stable.
async function loadUsers() {
  Utils.showLoading('users-tbody', 7);
  const { ok, data } = await API.getUsers();

  if (!ok || !data.data?.users?.length) {
    Utils.showEmpty('users-tbody', 'No users found.', 7);
    return;
  }

  Utils.el('users-tbody').innerHTML = data.data.users.map(u => `
    <tr>
      <td class="text-mono text-dim">#${u.id}</td>
      <td class="text-mono text-white">${Utils.esc(u.username)}</td>
      <td class="text-dim text-mono">${Utils.esc(u.email || '—')}</td>
      <td>${Utils.severityBadge(u.role === 'admin' ? 'critical' : u.role === 'analyst' ? 'medium' : 'low')} <span class="text-mono text-sm">${Utils.esc(u.role)}</span></td>
      <td class="text-dim">${Utils.esc(u.department || '—')}</td>
      <td style="color:${u.is_active ? 'var(--safe)' : 'var(--danger)'}; font-family:var(--font-mono); font-size:0.7rem;">
        ${u.is_active ? '● Active' : '○ Inactive'}
      </td>
      <td class="text-dim text-mono">${u.last_login ? Utils.fmtDate(u.last_login) : 'Never'}</td>
    </tr>
  `).join('');
}

// ── QUARANTINE ────────────────────────────────────────────────
async function loadQuarantine() {
  Utils.showLoading('quarantine-tbody', 7);
  const { ok, data } = await API.getScans(1, 'true', 'quarantined');

  if (!ok || !data.data?.scans?.length) {
    Utils.showEmpty('quarantine-tbody', 'Quarantine is empty.', 7);
    return;
  }

  Utils.el('quarantine-tbody').innerHTML = data.data.scans.map(s => `
    <tr>
      <td class="text-mono text-dim">#${s.id}</td>
      <td><div class="truncate" style="max-width:220px;">${Utils.esc(s.email_preview || '—')}</div></td>
      <td class="text-dim text-mono">${Utils.esc(s.email_sender || '—')}</td>
      <td style="color:${Utils.scoreColor(s.risk_score)};font-family:var(--font-mono);font-weight:700;">${s.risk_score}/100</td>
      <td class="text-dim text-mono">${Utils.fmtDate(s.scanned_at)}</td>
      <td class="text-dim text-mono">${s.user_id || 'anon'}</td>
      <td>${Utils.statusPill(s.status)}</td>
    </tr>
  `).join('');
}
