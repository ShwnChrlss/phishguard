/* =============================================================
   frontend/js/analyzer.js — Email analysis page logic

   Security workflow concept:
   The analyzer page is a thin orchestration layer.
   It gathers user input, calls the backend, and renders the
   result. The actual detection logic stays on the server so
   users cannot tamper with the scoring rules in the browser.
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
  // UX concept: optimistic feedback
  // Disabling the button and showing progress helps prevent
  // duplicate submissions and communicates that work is happening.
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
  // Explainability concept:
  // security tools need to justify their verdicts so users can
  // learn from them and analysts can review them critically.
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

// =============================================================
//  TAB SWITCHING
//  CONCEPT: Tab UI pattern
//  Two panes exist in the DOM at all times.
//  Switching tabs just toggles display:none on each pane
//  and updates the active class on the buttons.
//  No page reload, no routing — pure DOM manipulation.
// =============================================================
function switchTab(tab) {
  // Update button styles
  Utils.el('tab-paste').classList.toggle('active',  tab === 'paste');
  Utils.el('tab-upload').classList.toggle('active', tab === 'upload');

  // Show/hide panes
  Utils.el('pane-paste').style.display  = tab === 'paste'  ? 'block' : 'none';
  Utils.el('pane-upload').style.display = tab === 'upload' ? 'block' : 'none';

  // Clear result panel when switching tabs
  Utils.el('detect-result').classList.remove('visible');
}

// =============================================================
//  DRAG AND DROP
//  CONCEPT: HTML5 Drag and Drop API
//  dragover — fires continuously while file is held over zone
//             must call preventDefault() to allow drop
//  dragleave — fires when file leaves the zone
//  drop     — fires when file is released over the zone
//             event.dataTransfer.files contains the dropped files
// =============================================================
function handleDragOver(e) {
  e.preventDefault();                              // required to allow drop
  e.stopPropagation();
  Utils.el('drop-zone').classList.add('dragover'); // visual feedback
}

function handleDragLeave(e) {
  e.preventDefault();
  Utils.el('drop-zone').classList.remove('dragover');
}

function handleDrop(e) {
  e.preventDefault();
  e.stopPropagation();
  Utils.el('drop-zone').classList.remove('dragover');

  const files = e.dataTransfer.files;
  if (files.length > 0) {
    setFile(files[0]);
  }
}

// Triggered by clicking the drop zone → hidden <input type="file">
function handleFileSelect(e) {
  const files = e.target.files;
  if (files.length > 0) {
    setFile(files[0]);
  }
}

// =============================================================
//  FILE SELECTION
//  Validates the file client-side before sending:
//  - extension must be .eml
//  - size must be under 5MB
//  Then shows the file preview and enables the analyse button.
// =============================================================
let _selectedFile = null;

function setFile(file) {
  // Client-side validation — first line of defence
  const ext = file.name.split('.').pop().toLowerCase();
  if (ext !== 'eml') {
    Utils.toast('Invalid file type. Only .eml files are accepted.', true);
    return;
  }

  const sizeMB = file.size / (1024 * 1024);
  if (sizeMB > 5) {
    Utils.toast(`File too large (${sizeMB.toFixed(1)}MB). Maximum is 5MB.`, true);
    return;
  }

  _selectedFile = file;

  // Show preview
  Utils.el('file-name').textContent = file.name;
  Utils.el('file-size').textContent = sizeMB < 0.1
    ? `${(file.size / 1024).toFixed(1)} KB`
    : `${sizeMB.toFixed(2)} MB`;

  Utils.el('file-preview').style.display = 'block';
  Utils.el('drop-zone').style.display    = 'none';
  Utils.el('upload-btn').disabled        = false;
}

function clearFile() {
  _selectedFile = null;
  Utils.el('eml-file-input').value        = '';
  Utils.el('file-preview').style.display  = 'none';
  Utils.el('drop-zone').style.display     = 'block';
  Utils.el('upload-btn').disabled         = true;
  Utils.el('detect-result').classList.remove('visible');
}

// =============================================================
//  EML UPLOAD AND DETECTION
//  CONCEPT: FormData API
//  Unlike JSON (which sends text), file uploads need
//  multipart/form-data encoding. FormData builds this
//  automatically — we just append the file and fetch it.
//
//  The browser sets Content-Type to multipart/form-data
//  with the correct boundary automatically when using FormData.
//  Never set Content-Type manually for file uploads.
// =============================================================
async function doUpload() {
  if (!_selectedFile) {
    Utils.toast('Please select a .eml file first.', true);
    return;
  }

  const btn = Utils.el('upload-btn');
  btn.disabled  = true;
  btn.innerHTML = '<div class="spinner"></div> Analysing...';

  try {
    // CONCEPT: FormData
    // Wraps the file in multipart/form-data encoding
    // Flask reads it with request.files['file']
    const formData = new FormData();
    formData.append('file', _selectedFile);

    const token = Auth.getToken();
    const res   = await fetch('/api/detect/upload', {
      method:  'POST',
      headers: { 'Authorization': `Bearer ${token}` },
      // NOTE: Do NOT set Content-Type here — browser sets it
      // automatically with the correct multipart boundary
      body: formData,
    });

    const data = await res.json();

    if (data.status === 'success') {
      // Merge parsed_email fields into result so renderResult()
      // can show sender/subject from the parsed file
      const result = {
        ...data.data,
      };
      renderResult(result);
    } else {
      Utils.toast(data.message || 'Upload failed.', true);
    }

  } catch (err) {
    Utils.toast('Connection error. Is the server running?', true);
  } finally {
    btn.disabled  = false;
    btn.innerHTML = '🔍 Analyse .eml File';
  }
}
