/* =============================================================
   frontend/js/chatbot.js — Security awareness chat page
   ============================================================= */

window.addEventListener('DOMContentLoaded', () => {
  Utils.setupTopbar();
  Utils.setActiveNav('chatbot');
  Utils.el('chat-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendMessage();
  });
  appendMessage('bot',
    '👋 Hi! I\'m PhishGuard\'s security awareness assistant.\n\n' +
    'Ask me about phishing, how to spot suspicious emails, password security, or 2FA.\n\n' +
    'Try: "What is phishing?" or "How do I check a link safely?"'
  );
});

async function sendMessage() {
  const input = Utils.el('chat-input');
  const msg   = input.value.trim();
  if (!msg) return;

  input.value = '';
  appendMessage('user', msg);

  const { ok, data } = await API.chat(msg);

  if (ok) {
    appendMessage('bot', data.data.reply);
  } else {
    appendMessage('bot', '⚠ Could not reach the assistant. Is the server running?');
  }
}

function appendMessage(role, text) {
  const msgs = Utils.el('chat-messages');
  const div  = document.createElement('div');
  div.className   = 'chat-msg ' + role;
  div.textContent = text;
  msgs.appendChild(div);
  msgs.scrollTop  = msgs.scrollHeight;
}