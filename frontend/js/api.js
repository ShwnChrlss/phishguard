/* =============================================================
   frontend/js/api.js
   All fetch() calls to the backend API in one place.

   CONCEPT: Centralising API calls
   Instead of writing fetch() in every JS file, all HTTP calls
   live here. If the base URL changes, you change it once.
   Every other file imports from api.js.

   USAGE (from any other JS file):
     const data = await API.login("admin", "pass123")
     const data = await API.detect("URGENT: click now...")
     const data = await API.getDashboard()
   ============================================================= */

// Dynamically use whatever host the page was loaded from.
// This means localhost:5000 for you, and 192.168.100.8:5000
// for anyone else on the network — no hardcoding needed.
const BASE = `${window.location.protocol}//${window.location.host}/api`;

// ── CORE HTTP HELPER ─────────────────────────────────────────
// Every API call goes through this function.
// It automatically:
//   - Adds Content-Type: application/json header
//   - Adds Authorization: Bearer <token> header if logged in
//   - Parses the JSON response
//   - Returns { ok, status, data } consistently
async function http(method, path, body = null) {
  const token = Auth.getToken();
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const opts = { method, headers };
  if (body) opts.body = JSON.stringify(body);

  try {
    const res  = await fetch(BASE + path, opts);
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  } catch (e) {
    console.error('API error:', e);
    return { ok: false, status: 0, data: { message: 'Network error — is the server running?' } };
  }
}

// ── AUTH ENDPOINTS ───────────────────────────────────────────
const API = {

  login(username, password) {
    return http('POST', '/auth/login', { username, password });
  },

  register(username, email, password, department) {
    return http('POST', '/auth/register', { username, email, password, department });
  },

  getMe() {
    return http('GET', '/auth/me');
  },

  logout() {
    return http('POST', '/auth/logout');
  },

  // ── DETECTION ──────────────────────────────────────────────
  detect(emailText, subject = null, sender = null) {
    return http('POST', '/detect', {
      email_text:    emailText,
      email_subject: subject || undefined,
      email_sender:  sender  || undefined,
    });
  },

  getScanHistory(page = 1, limit = 20) {
    return http('GET', `/scans/history?page=${page}&limit=${limit}`);
  },

  // ── CHAT ───────────────────────────────────────────────────
  chat(message) {
    return http('POST', '/chat', { message });
  },

  // ── ADMIN ──────────────────────────────────────────────────
  getDashboard() {
    return http('GET', '/admin/dashboard');
  },

  getScans(page = 1, isPhishing = '', status = '') {
    let url = `/admin/scans?page=${page}`;
    if (isPhishing !== '') url += `&is_phishing=${isPhishing}`;
    if (status)            url += `&status=${status}`;
    return http('GET', url);
  },

  getScan(id) {
    return http('GET', `/admin/scans/${id}`);
  },

  getAlerts(status = '') {
    const url = status ? `/admin/alerts?status=${status}` : '/admin/alerts';
    return http('GET', url);
  },

  acknowledgeAlert(id) {
    return http('POST', `/admin/alerts/${id}/acknowledge`);
  },

  resolveAlert(id, note = '') {
    return http('POST', `/admin/alerts/${id}/resolve`, { note });
  },

  getUsers() {
    return http('GET', '/admin/users');
  },

  createUser(data) {
    return http('POST', '/admin/users', data);
  },

  updateUser(id, data) {
    return http('PATCH', `/admin/users/${id}`, data);
  },
};

// ── USER MANAGEMENT ───────────────────────────────────────────
// These are called from admin_users.html

const updateUser       = (id, data)  => http(`/admin/users/${id}`, "PATCH",  data);
const deactivateUser   = (id)        => http(`/admin/users/${id}/deactivate`, "POST");
const reactivateUser   = (id)        => http(`/admin/users/${id}/reactivate`, "POST");
const deleteUser       = (id)        => http(`/admin/users/${id}`, "DELETE");
const adminCreateUser  = (data)      => http(`/admin/users`, "POST", data);
