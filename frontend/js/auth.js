/* =============================================================
   frontend/js/auth.js
   Login, logout, token storage and session management.

   CONCEPT: JWT token validation client-side
   The backend signs tokens with an expiry timestamp (exp).
   We decode the token payload on the client to check if it
   has expired BEFORE making an API call. This avoids a
   round-trip to the server just to get a 401 back.

   JWT structure: header.payload.signature
   Each part is base64url encoded. We decode the payload
   (middle part) to read exp, user_id, role.

   SECURITY NOTE: We trust the exp field for UX purposes only.
   The backend ALWAYS re-validates the signature on every
   request. A client cannot fake a valid token.
   ============================================================= */

const Auth = {

  TOKEN_KEY: 'pg_token',
  USER_KEY:  'pg_user',

  // ── STORE ────────────────────────────────────────────────
  setSession(token, user) {
    localStorage.setItem(this.TOKEN_KEY, token);
    localStorage.setItem(this.USER_KEY, JSON.stringify(user));
  },

  clearSession() {
    localStorage.removeItem(this.TOKEN_KEY);
    localStorage.removeItem(this.USER_KEY);
  },

  // ── GETTERS ──────────────────────────────────────────────
  getToken() {
    return localStorage.getItem(this.TOKEN_KEY) || '';
  },

  getUser() {
    try {
      return JSON.parse(localStorage.getItem(this.USER_KEY) || 'null');
    } catch {
      return null;
    }
  },

  // ── TOKEN EXPIRY CHECK ───────────────────────────────────
  // Decode the JWT payload (middle section) without a library.
  // JWT payload is base64url encoded JSON.
  // base64url differs from base64: uses - and _ instead of + and /
  //
  // CONCEPT: Why decode client-side?
  // If we only check localStorage for a token's existence,
  // a token from 3 days ago (expired) would keep the user
  // "logged in" until they make an API call and get a 401.
  // Decoding client-side lets us catch this immediately on
  // page load and redirect to login before anything breaks.
  _decodePayload(token) {
    try {
      // JWT = "header.payload.signature" — we want the middle part
      const base64url = token.split('.')[1];
      if (!base64url) return null;

      // Convert base64url → base64 → decode → parse JSON
      const base64 = base64url
        .replace(/-/g, '+')   // base64url uses - instead of +
        .replace(/_/g, '/');  // base64url uses _ instead of /

      const json = atob(base64);  // browser built-in base64 decode
      return JSON.parse(json);
    } catch {
      return null;
    }
  },

  isTokenExpired(token) {
    const payload = this._decodePayload(token);
    if (!payload || !payload.exp) return true;

    // exp is a Unix timestamp in seconds
    // Date.now() is milliseconds — divide by 1000 to compare
    const nowSeconds = Math.floor(Date.now() / 1000);

    // Add a 30-second buffer — if token expires in under 30s,
    // treat it as expired now to avoid mid-session failures
    return payload.exp < (nowSeconds + 30);
  },

  isLoggedIn() {
    const token = this.getToken();
    if (!token) return false;

    // Check expiry — if expired, clean up and return false
    if (this.isTokenExpired(token)) {
      this.clearSession();
      return false;
    }
    return true;
  },

  isAdmin() {
    const u = this.getUser();
    return u?.role === 'admin';
  },

  isAnalyst() {
    const u = this.getUser();
    return u?.role === 'admin' || u?.role === 'analyst';
  },

  // ── GUARDS ───────────────────────────────────────────────
  // Call at the top of every protected page.
  requireAuth() {
    if (!this.isLoggedIn()) {
      window.location.href = '/login';
      return false;
    }
    return true;
  },

  requireAdmin() {
    if (!this.requireAuth()) return false;
    if (!this.isAdmin()) {
      window.location.href = '/dashboard';
      return false;
    }
    return true;
  },

  requireAnalyst() {
    if (!this.requireAuth()) return false;
    if (!this.isAnalyst()) {
      window.location.href = '/dashboard';
      return false;
    }
    return true;
  },

  // ── LOGIN / REGISTER / LOGOUT ────────────────────────────
  async login(username, password) {
    const { ok, data } = await API.login(username, password);
    if (ok) {
      this.setSession(data.data.token, data.data.user);
      return { ok: true, user: data.data.user };
    }
    return { ok: false, message: data.message };
  },

  async register(username, email, password, department) {
    const { ok, data } = await API.register(username, email, password, department);
    if (ok) {
      this.setSession(data.data.token, data.data.user);
      return { ok: true, user: data.data.user };
    }
    return { ok: false, message: data.message };
  },

  async logout() {
    await API.logout().catch(() => {});
    this.clearSession();
    window.location.href = '/login';
  },
};
