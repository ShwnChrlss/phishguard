/* =============================================================
   frontend/js/analyzer.js — Email analysis page logic
   ============================================================= */

window.addEventListener('DOMContentLoaded', () => {
  Utils.setupTopbar();
  Utils.setActiveNav('analyzer');
  document.getElementById('chat-input')?.addEventListener('keydown', e => {
    if (e.key === 'Enter') doDetect();
  });
});

async function doDetect() {
  const body    = Utils.el('det-body').value.trim();
  const subject = Utils.el('det-subject').value.trim();
  const sender  = Utils.el('det-sender').value.trim();

  if (!body) { Utils.toast('Email body is required.', true); return; }

  const btn = Utils.el('detect-btn');
  btn.disabled = true;
  btn.innerHTML = '<div class="spinner"></div> Analysing...';

  const { ok, data } = await API.detect(body, subject || null, sender || null);

  btn.disabled = false;
  btn.innerHTML = '🔍 Analyse Email';

  if (!ok) {
    Utils.toast(data.message || 'Detection failed.', true);
    return;
  }

  renderResult(data.data);

  if (!data.data.model_ready) {
    Utils.toast('⚠ Model not trained yet — run train_model.py first.', true);
  }
}

function renderResult(r) {
  const el = Utils.el('detect-result');
  el.classList.add('visible');

  // Verdict
  const vEl = Utils.el('result-verdict');
  vEl.textContent = r.is_phishing ? 'PHISHING' : 'SAFE';
  vEl.className   = 'verdict-text ' + (r.is_phishing ? 'phishing' : 'safe');

  // Score
  const scoreEl = Utils.el('result-score');
  scoreEl.textContent = r.risk_score + '/100';
  scoreEl.style.color = Utils.scoreColor(r.risk_score);

  // Bar
  setTimeout(() => {
    const bar = Utils.el('result-bar');
    if (bar) {
      bar.style.width      = r.risk_score + '%';
      bar.style.background = Utils.scoreColor(r.risk_score);
    }
  }, 50);

  Utils.el('result-conf').textContent   = (r.confidence * 100).toFixed(1) + '%';
  Utils.el('result-status').textContent = r.status || '—';
  Utils.el('result-alert').textContent  = r.alert_created ? '✅ Yes' : 'No';
  Utils.el('result-id').textContent     = '#' + r.scan_id;

  // Explanations
  const exEl = Utils.el('result-explanations');
  if (r.explanation && r.explanation.length) {
    exEl.innerHTML = r.explanation.map(e => {
      const cls = e.startsWith('🚨') ? 'danger' : e.startsWith('⚠') ? 'warn' : 'ok';
      return `<div class="explanation-item ${cls}">${Utils.esc(e)}</div>`;
    }).join('');
  } else {
    exEl.innerHTML = '<div class="explanation-item ok">✅ No major phishing indicators detected.</div>';
  }

  el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function clearForm() {
  Utils.el('det-body').value    = '';
  Utils.el('det-subject').value = '';
  Utils.el('det-sender').value  = '';
  Utils.el('detect-result').classList.remove('visible');
}