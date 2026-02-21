// fagents-comms web UI — extracted from inline template
// CONFIG is set by a small inline <script> before this file loads:
//   CONFIG = { channel, lastCount, agents }

const channel = document.getElementById('channel');
channel.scrollTop = channel.scrollHeight;
const CHANNEL = CONFIG.channel;
let lastCount = CONFIG.lastCount;

// Guard against sidebar reflows resetting channel scroll position
function preserveScroll(fn) {
  return async function() {
    const top = channel.scrollTop;
    try { await fn(); } catch(e) {}
    if (Math.abs(channel.scrollTop - top) > 5) channel.scrollTop = top;
  };
}

const COLORS = {
  'Freeturtle': {bg:'#1a3a2a',border:'#2ecc71',name:'#2ecc71'},
  'FTW': {bg:'#1a3a2a',border:'#2ecc71',name:'#2ecc71'},
  'FTF': {bg:'#12302a',border:'#58d68d',name:'#58d68d'},
  'FTL': {bg:'#152a2e',border:'#1abc9c',name:'#1abc9c'},
  'Juho': {bg:'#1a2a3a',border:'#3498db',name:'#3498db'},
  'Freeclaw': {bg:'#2a1a3a',border:'#9b59b6',name:'#9b59b6'},
  'YOBOT': {bg:'#2a1f14',border:'#e67e22',name:'#e67e22'},
  'sirbot': {bg:'#2a1418',border:'#e74c3c',name:'#e74c3c'},
  'System': {bg:'#2a2a1a',border:'#f1c40f',name:'#f1c40f'},
};
const DEFAULT_C = {bg:'#2a2a2a',border:'#95a5a6',name:'#95a5a6'};
const _autoCache = {};

function autoColor(name) {
  if (COLORS[name]) return COLORS[name];
  if (_autoCache[name]) return _autoCache[name];
  // Simple hash from name string (matches Python: md5 first 8 hex chars mod 360)
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = ((hash << 5) - hash + name.charCodeAt(i)) | 0;
  }
  // Use same approach as Python but with JS hash — we need md5 match.
  // Simpler: compute a stable hash mod 360 for hue.
  // To match Python exactly we'd need md5, but consistency across
  // server/client matters more than matching. Use djb2 hash.
  const h = ((hash % 360) + 360) % 360;
  const border = hslToHex(h, 65, 55);
  const bg = hslToHex(h, 30, 12);
  _autoCache[name] = {bg, border, name: border};
  return _autoCache[name];
}

function hslToHex(h, s, l) {
  s /= 100; l /= 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs((h / 60) % 2 - 1));
  const m = l - c / 2;
  let r, g, b;
  if (h < 60) { r=c; g=x; b=0; }
  else if (h < 120) { r=x; g=c; b=0; }
  else if (h < 180) { r=0; g=c; b=x; }
  else if (h < 240) { r=0; g=x; b=c; }
  else if (h < 300) { r=x; g=0; b=c; }
  else { r=c; g=0; b=x; }
  const toHex = v => Math.round((v + m) * 255).toString(16).padStart(2, '0');
  return '#' + toHex(r) + toHex(g) + toHex(b);
}

function esc(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// Reply state
let replyToSender = '';
let replyToText = '';
function setReply(sender, text) {
  replyToSender = sender;
  replyToText = text;
  document.getElementById('replySender').textContent = sender;
  const snippet = text.length > 100 ? text.substring(0, 100) + '...' : text;
  document.getElementById('replySnippet').textContent = snippet;
  document.getElementById('replyBar').classList.add('active');
  document.getElementById('messageInput').focus();
}
function clearReply() {
  replyToSender = '';
  replyToText = '';
  document.getElementById('replyBar').classList.remove('active');
}

function renderMsg(m) {
  const c = autoColor(m.sender);
  let raw = m.message || '';
  let quoteHtml = '';
  let bodyLines = [];
  const lines = raw.split('\n');
  let inQuote = true;
  for (const line of lines) {
    if (inQuote && line.startsWith('> ')) {
      const qtext = line.substring(2);
      const senderMatch = qtext.match(/^@(\S+?):\s*(.*)/);
      if (senderMatch) {
        quoteHtml += '<blockquote><span class="quote-sender">@' + esc(senderMatch[1]) + ':</span> ' + esc(senderMatch[2]) + '</blockquote>';
      } else {
        quoteHtml += '<blockquote>' + esc(qtext) + '</blockquote>';
      }
    } else {
      inQuote = false;
      bodyLines.push(line);
    }
  }
  let t = esc(bodyLines.join('\n'));
  t = t.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  t = t.replace(/`(.+?)`/g, '<code>$1</code>');
  t = t.replace(/!\[([^\]]*)\]\(([^)]+)\)/g, '<img src="$2" alt="$1" style="max-width:400px;max-height:300px;border-radius:6px;margin:4px 0;cursor:pointer" onclick="window.open(this.src)">');
  t = t.replace(/(?<!src=")(https?:\/\/\S+)/g, '<a href="$1" style="color:#3498db" target="_blank">$1</a>');
  t = t.replace(/@(\w+)/g, function(match, name) {
    if ((CONFIG.agents || []).indexOf(name) >= 0) {
      const mc = autoColor(name);
      return '<span class="mention" style="color:'+mc.name+';background:'+mc.bg+';padding:0 3px;border-radius:3px;font-weight:bold">@'+esc(name)+'</span>';
    }
    return match;
  });
  t = t.replace(/\n/g, '<br>');
  if (quoteHtml) t = t.replace(/^(<br>)+/, '');
  const plainText = bodyLines.join('\n').trim().substring(0, 200);
  const safeSender = esc(m.sender).replace(/"/g, '&quot;');
  const safeText = esc(plainText).replace(/"/g, '&quot;');
  return '<div class="msg" style="background:'+c.bg+';border-left:3px solid '+c.border+'">'
    + '<div class="meta"><span class="sender" style="color:'+c.name+'">'+esc(m.sender)+'</span>'
    + '<span class="time">'+esc(m.ts)+'</span></div>'
    + '<div class="text">'+quoteHtml+t+'</div>'
    + '<div class="msg-actions"><button class="reply-btn" data-reply-sender="'+safeSender+'" data-reply-text="'+safeText+'" onclick="setReply(this.dataset.replySender,this.dataset.replyText)">&#8617; Reply</button></div></div>';
}

async function poll() {
  try {
    const r = await fetch('/api/channels/' + CHANNEL + '/messages?count_only=1');
    if (!r.ok) return;
    const d = await r.json();
    if (d.count > lastCount) {
      const r2 = await fetch('/api/channels/' + CHANNEL + '/messages?since=' + lastCount);
      if (!r2.ok) return;
      const d2 = await r2.json();
      const wasAtBottom = channel.scrollTop + channel.clientHeight >= channel.scrollHeight - 30;
      for (const m of (d2.messages || [])) {
        channel.insertAdjacentHTML('beforeend', renderMsg(m));
      }
      lastCount = d.count;
      if (wasAtBottom) channel.scrollTop = channel.scrollHeight;
      markRead();
    }
  } catch(e) {}
}
setInterval(poll, 3000);

// Mark current channel as read (on load + after displaying new messages)
function markRead() {
  fetch('/api/channels/' + CHANNEL + '/read', {method:'PUT',headers:{'Content-Type':'application/json'},body:'{}'});
}
markRead();
async function pollUnread() {
  try {
    const r = await fetch('/api/channels');
    if (!r.ok) return;
    const chs = await r.json();
    const items = document.querySelectorAll('#channelList a.ch-item');
    for (const item of items) {
      const name = item.dataset.channel;
      const ch = chs.find(c => c.name === name);
      if (!ch) continue;
      // Update message count
      const countEl = item.querySelector('.ch-count');
      if (countEl) countEl.textContent = ch.message_count;
      // Unread badge
      let badge = item.querySelector('.ch-unread');
      if (ch.unread > 0 && ch.name !== CHANNEL) {
        if (!badge) {
          badge = document.createElement('span');
          badge.className = 'ch-unread';
          item.appendChild(badge);
        }
        badge.textContent = ch.unread;
      } else if (badge) {
        badge.remove();
      }
    }
  } catch(e) {}
}
preserveScroll(pollUnread)();
setInterval(preserveScroll(pollUnread), 10000);

async function sendMessage() {
  let msg = document.getElementById('messageInput').value.trim();
  if (!msg) return;
  if (replyToSender) {
    const snippet = replyToText.length > 100 ? replyToText.substring(0, 100) + '...' : replyToText;
    msg = '> @' + replyToSender + ': ' + snippet.replace(/\n/g, ' ') + '\n\n' + msg;
  }
  const status = document.getElementById('status');
  try {
    const r = await fetch('/api/channels/' + CHANNEL + '/messages', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({message: msg})
    });
    if (r.ok) {
      document.getElementById('messageInput').value = '';
      status.textContent = '';
      clearReply();
      await poll();
      markRead();
    } else {
      status.textContent = 'Error: ' + await r.text();
    }
  } catch(e) { status.textContent = 'Failed to send'; }
}

const msgInput = document.getElementById('messageInput');
msgInput.focus();

// @mention autocomplete
(function() {
  const agents = CONFIG.agents || [];
  if (!agents.length) return;
  const ac = document.createElement('div');
  ac.id = 'mentionAC';
  ac.style.cssText = 'display:none;position:absolute;background:#1e1e2e;border:1px solid #444;border-radius:4px;z-index:100;max-height:150px;overflow-y:auto;font-size:13px';
  msgInput.parentElement.style.position = 'relative';
  msgInput.parentElement.appendChild(ac);
  let acStart = -1;

  msgInput.addEventListener('input', function() {
    const v = this.value, pos = this.selectionStart;
    // Find @ before cursor
    let at = -1;
    for (let i = pos - 1; i >= 0; i--) {
      if (v[i] === '@') { at = i; break; }
      if (v[i] === ' ' || v[i] === '\n') break;
    }
    if (at < 0) { ac.style.display = 'none'; return; }
    const partial = v.substring(at + 1, pos).toLowerCase();
    const matches = agents.filter(a => a.toLowerCase().startsWith(partial));
    if (!matches.length) { ac.style.display = 'none'; return; }
    acStart = at;
    ac.innerHTML = matches.map(a => {
      const c = autoColor(a);
      return '<div class="ac-item" data-name="'+esc(a)+'" style="padding:4px 8px;cursor:pointer;color:'+c.name+'" onmousedown="acPick(this)">@'+esc(a)+'</div>';
    }).join('');
    ac.style.display = 'block';
    ac.style.bottom = (msgInput.offsetHeight + 4) + 'px';
    ac.style.left = '0';
  });

  msgInput.addEventListener('keydown', function(e) {
    if (ac.style.display === 'none') return;
    const items = ac.querySelectorAll('.ac-item');
    let sel = ac.querySelector('.ac-item.sel');
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      let idx = sel ? Array.from(items).indexOf(sel) : -1;
      if (sel) sel.classList.remove('sel');
      idx = e.key === 'ArrowDown' ? (idx + 1) % items.length : (idx - 1 + items.length) % items.length;
      items[idx].classList.add('sel');
      items[idx].style.background = '#333';
      if (sel) sel.style.background = '';
    } else if (e.key === 'Tab' || e.key === 'Enter') {
      if (sel) { e.preventDefault(); acPick(sel); }
      else if (items.length === 1) { e.preventDefault(); acPick(items[0]); }
    } else if (e.key === 'Escape') {
      ac.style.display = 'none';
    }
  });

  window.acPick = function(el) {
    const name = el.dataset.name;
    const v = msgInput.value;
    msgInput.value = v.substring(0, acStart) + '@' + name + ' ' + v.substring(msgInput.selectionStart);
    msgInput.selectionStart = msgInput.selectionEnd = acStart + name.length + 2;
    ac.style.display = 'none';
    msgInput.focus();
  };
})();

// Channel sidebar drag-and-drop reordering (persisted in localStorage)
(function() {
  const list = document.getElementById('channelList');
  if (!list) return;
  const items = Array.from(list.querySelectorAll('a.ch-item'));
  if (items.length < 2) return;

  // Apply saved order on load
  const key = 'fagent-ch-order';
  const saved = JSON.parse(localStorage.getItem(key) || '[]');
  if (saved.length) {
    const byName = {};
    items.forEach(t => { byName[t.dataset.channel] = t; });
    const placed = new Set();
    saved.forEach(name => {
      if (byName[name]) { list.appendChild(byName[name]); placed.add(name); }
    });
    items.forEach(t => {
      if (!placed.has(t.dataset.channel)) list.appendChild(t);
    });
  }

  // Make items draggable
  let dragItem = null;
  items.forEach(item => {
    item.draggable = true;
    item.addEventListener('dragstart', function(e) {
      dragItem = this;
      this.style.opacity = '0.4';
      e.dataTransfer.effectAllowed = 'move';
    });
    item.addEventListener('dragend', function() {
      this.style.opacity = '';
      dragItem = null;
      list.querySelectorAll('a.ch-item').forEach(t => t.style.borderTop = '');
    });
    item.addEventListener('dragover', function(e) {
      if (!dragItem || dragItem === this) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      this.style.borderTop = '2px solid #58a6ff';
    });
    item.addEventListener('dragleave', function() {
      this.style.borderTop = '';
    });
    item.addEventListener('drop', function(e) {
      e.preventDefault();
      this.style.borderTop = '';
      if (!dragItem || dragItem === this) return;
      list.insertBefore(dragItem, this);
      const order = Array.from(list.querySelectorAll('a.ch-item')).map(t => t.dataset.channel);
      localStorage.setItem(key, JSON.stringify(order));
      // Persist to server
      fetch('/api/preferences/channel-order', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({order})
      });
    });
  });
})();

// Activity feed live polling
const TYPE_COLORS = {
  'thought': '#8b949e', 'tool': '#2ea043', 'heartbeat': '#d29922',
  'wakeup': '#3498db', 'compaction': '#da3633',
};
const urlToken = new URLSearchParams(window.location.search).get('token') || '';
const tokenQ = urlToken ? '?token=' + encodeURIComponent(urlToken) : '';
const tokenA = urlToken ? '&token=' + encodeURIComponent(urlToken) : '';
let lastActivityTs = '';
const activityUrl = '/api/activity?tail=50' + tokenA;
async function pollActivity() {
  try {
    const r = await fetch(activityUrl, {credentials: 'same-origin'});
    if (!r.ok) return;
    const events = await r.json();
    if (events.length === 0) return;
    const newestTs = events[events.length - 1].ts || '';
    if (newestTs === lastActivityTs) return;
    lastActivityTs = newestTs;
    const feed = document.getElementById('activityFeed');
    let html = '';
    let prevAgent = null;
    for (const ev of events) {
      const agent = ev.agent || '?';
      const ac = autoColor(agent).border;
      const tc = TYPE_COLORS[ev.type] || '#8b949e';
      const ts = (ev.ts || '').substring(11, 16) || ev.ts || '';
      const sum = (ev.summary || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      const det = (ev.detail || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
      if (prevAgent && agent !== prevAgent) html += '<div class="act-sep"></div>';
      prevAgent = agent;
      html += '<div class="act-item" data-agent="' + agent + '" style="border-left:3px solid ' + ac + '">';
      html += '<span class="act-ts">' + ts + '</span>';
      html += '<span class="act-agent" style="color:' + ac + '">' + agent + '</span>';
      html += '<span class="act-type" style="color:' + tc + '">' + (ev.type || 'event') + '</span>';
      html += '<span class="act-summary">' + sum + '</span>';
      if (det) html += '<span class="act-detail">' + det + '</span>';
      html += '</div>';
    }
    const newHtml = html || '<div class="agent-empty">No activity yet</div>';
    if (feed.innerHTML !== newHtml) {
      feed.innerHTML = newHtml;
      feed.scrollTop = feed.scrollHeight;
      filterFollowed();
    }
  } catch(e) {}
}
setInterval(preserveScroll(pollActivity), 3000);
preserveScroll(pollActivity)();

// Channel creation
function newChannel() {
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:1000';
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;width:320px;font-size:13px;color:#c9d1d9';
  modal.innerHTML = '<div style="font-weight:600;color:#e6edf3;margin-bottom:12px">New Channel</div>'
    + '<input id="ncName" type="text" placeholder="Channel name (spaces become hyphens)" style="width:100%;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-family:inherit;font-size:13px;margin-bottom:10px">'
    + '<input id="ncDesc" type="text" placeholder="Description (optional, max 200 chars)" maxlength="200" style="width:100%;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-family:inherit;font-size:13px;margin-bottom:10px">'
    + '<div style="font-size:12px;color:#8b949e;margin-bottom:6px">Agent access (check to grant):</div>'
    + '<div id="ncAgents"></div>'
    + '<div style="display:flex;gap:8px;margin-top:14px;justify-content:flex-end">'
    + '<button id="ncCancel" style="background:none;border:1px solid #30363d;color:#c9d1d9;border-radius:6px;padding:6px 14px;cursor:pointer;font-family:inherit;font-size:13px">Cancel</button>'
    + '<button id="ncCreate" style="background:#238636;color:#fff;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;font-family:inherit;font-size:13px;font-weight:600">Create</button>'
    + '</div>';
  overlay.appendChild(modal);
  document.body.appendChild(overlay);
  fetch('/api/agents/list' + tokenQ)
    .then(r => r.json()).then(agents => {
      const div = document.getElementById('ncAgents');
      agents.forEach(a => {
        const lbl = document.createElement('label');
        lbl.style.cssText = 'display:block;margin-bottom:3px;cursor:pointer;font-size:12px';
        lbl.innerHTML = '<input type="checkbox" class="ncAgent" value="' + a + '" style="margin-right:6px">' + a;
        div.appendChild(lbl);
      });
    });
  document.getElementById('ncName').focus();
  document.getElementById('ncCancel').addEventListener('click', () => overlay.remove());
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
  document.getElementById('ncCreate').addEventListener('click', () => {
    const name = document.getElementById('ncName').value.trim().replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
    if (!name) { alert('Invalid channel name'); return; }
    const allow = [];
    document.querySelectorAll('.ncAgent:checked').forEach(cb => allow.push(cb.value));
    const description = (document.getElementById('ncDesc').value || '').trim();
    const payload = {name, allow};
    if (description) payload.description = description;
    fetch('/api/channels', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(payload)
    }).then(r => {
      if (r.ok) {
        overlay.remove();
        window.location.href = '/?channel=' + name + tokenA;
      } else r.text().then(t => alert('Error: ' + t));
    });
  });
}

// Channel rename
function renameChannel() {
  const newName = prompt('Rename #' + CHANNEL + ' to:', CHANNEL);
  if (!newName || newName.trim() === CHANNEL) return;
  const clean = newName.trim().replace(/\s+/g, '-').replace(/[^a-zA-Z0-9_-]/g, '').toLowerCase();
  if (!clean) { alert('Invalid channel name'); return; }
  fetch('/api/channels/' + CHANNEL + '/rename', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({name: clean})
  }).then(r => {
    if (r.ok) r.json().then(d => {
      window.location.href = '/?channel=' + d.new_name + tokenA;
    });
    else r.text().then(t => alert('Error: ' + t));
  });
}

// Channel deletion
function deleteChannel() {
  if (!confirm('Delete #' + CHANNEL + '? This removes all messages permanently.')) return;
  fetch('/api/channels/' + CHANNEL, {
    method: 'DELETE'
  }).then(r => {
    if (r.ok) window.location.href = '/?channel=general' + tokenA;
    else r.text().then(t => alert('Error: ' + t));
  });
}

// Search
function toggleSearch() {
  const sb = document.getElementById('searchBar');
  sb.style.display = sb.style.display === 'none' ? 'block' : 'none';
  if (sb.style.display === 'block') document.getElementById('searchInput').focus();
}
function closeSearch() {
  document.getElementById('searchBar').style.display = 'none';
  document.getElementById('searchResults').innerHTML = '';
  document.getElementById('searchInput').value = '';
}
async function searchMessages() {
  const q = document.getElementById('searchInput').value.trim();
  if (!q) return;
  const r = await fetch('/api/search?q=' + encodeURIComponent(q) + '&limit=20');
  if (!r.ok) return;
  const d = await r.json();
  const div = document.getElementById('searchResults');
  if (!d.results.length) { div.innerHTML = '<div style="color:#8b949e;padding:4px">No results</div>'; return; }
  div.innerHTML = d.results.map(m => {
    const c = autoColor(m.sender);
    return '<div style="padding:3px 0;border-bottom:1px solid #21262d">'
      + '<a href="/?channel=' + m.channel + tokenA + '" style="color:#58a6ff;font-size:11px">#' + esc(m.channel) + '</a> '
      + '<span style="color:' + c.name + ';font-size:11px">' + esc(m.sender) + '</span> '
      + '<span style="color:#8b949e;font-size:10px">' + esc(m.ts) + '</span><br>'
      + '<span style="color:#c9d1d9;font-size:12px">' + esc(m.message.substring(0, 150)) + '</span></div>';
  }).join('');
}

// Channel ACL editor
function editAccess() {
  const editor = document.getElementById('aclEditor');
  if (editor.style.display === 'block') { editor.style.display = 'none'; return; }
  editor.style.display = 'block';
  const tok = tokenQ;
  Promise.all([
    fetch('/api/agents/list' + tok).then(r => r.json()),
    fetch('/api/channels/' + CHANNEL + '/acl' + tok).then(r => r.json())
  ]).then(([agents, acl]) => {
    const allow = acl.allow || [];
    const isOpen = allow.includes('*');
    const div = document.getElementById('aclAgents');
    div.innerHTML = '<label style="display:block;margin-bottom:4px;cursor:pointer;color:#8b949e;font-size:11px">' +
      '<input type="checkbox" id="aclWild"' + (isOpen ? ' checked' : '') +
      ' onchange="toggleWild()" style="margin-right:4px"> Everyone (open)</label>' +
      agents.map(a =>
        '<label style="display:block;margin-bottom:2px;cursor:pointer;font-size:11px;color:#c9d1d9">' +
        '<input type="checkbox" class="aclAgent" value="' + a + '"' +
        (isOpen || allow.includes(a) ? ' checked' : '') +
        ' style="margin-right:4px"> ' + a + '</label>'
      ).join('');
    toggleWild();
  });
}
function toggleWild() {
  const wild = document.getElementById('aclWild').checked;
  document.querySelectorAll('.aclAgent').forEach(cb => { if (wild) cb.checked = true; cb.disabled = wild; });
}
function saveAccess() {
  const wild = document.getElementById('aclWild').checked;
  let allow;
  if (wild) { allow = ['*']; }
  else {
    allow = [];
    document.querySelectorAll('.aclAgent:checked').forEach(cb => allow.push(cb.value));
  }
  fetch('/api/channels/' + CHANNEL + '/acl', {
    method: 'PUT',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({allow})
  }).then(r => r.json()).then(d => {
    if (d.ok) { location.reload(); }
    else { document.getElementById('aclStatus').textContent = 'Error'; }
  });
}

// Agent health polling — compact sidebar panels
let lastAgentSnap = '';

function renderCompactPanel(name, h) {
  const en = esc(name);
  let pct = 0, dotColor = '#484f58';
  if (h) {
    pct = h.context_pct || 0;
    const ageSecs = h.reported_at ? Math.floor(Date.now() / 1000 - h.reported_at) : null;
    if (ageSecs !== null && ageSecs < 300) dotColor = '#2ecc71';
    else if (ageSecs !== null && ageSecs < 3600) dotColor = '#f1c40f';
  }
  let barClass = 'ctx-critical';
  if (pct < 40) barClass = 'ctx-healthy';
  else if (pct < 70) barClass = 'ctx-warming';
  else if (pct < 90) barClass = 'ctx-heavy';
  return '<div style="display:flex;align-items:center;gap:6px;padding:3px 8px;font-size:11px">'
    + '<span style="flex:1;white-space:nowrap"><span style="color:' + dotColor + ';font-size:8px;margin-right:4px">&#9679;</span>' + en + '</span>'
    + '<div class="ctx-bar" style="width:50px"><div class="ctx-fill ' + barClass + '" style="width:' + pct + '%"></div></div>'
    + '<span style="color:#8b949e;width:28px;text-align:right">' + pct + '%</span>'
    + '</div>';
}

async function pollAgentHealth() {
  try {
    const tok = tokenQ;
    const [listResp, healthResp] = await Promise.all([
      fetch('/api/agents/list' + tok),
      fetch('/api/agents' + tok)
    ]);
    if (!listResp.ok || !healthResp.ok) return;
    const names = await listResp.json();
    const health = await healthResp.json();
    const snap = JSON.stringify(names.map(n => {
      const h = health[n];
      if (!h) return {n, off: true};
      const ageSecs = h.reported_at ? Math.floor(Date.now() / 1000 - h.reported_at) : null;
      const ageBucket = ageSecs === null ? null : ageSecs < 300 ? 'on' : ageSecs < 3600 ? 'warm' : 'off';
      return {n, pct: h.context_pct||0, ab: ageBucket};
    }));
    if (snap === lastAgentSnap) return;
    lastAgentSnap = snap;
    const container = document.getElementById('agentPanels');
    if (!container) return;
    if (names.length === 0) {
      container.innerHTML = '<div class="agent-empty">No agents registered</div>';
      return;
    }
    let html = '';
    for (const name of names) {
      html += renderCompactPanel(name, health[name]);
    }
    html += '<div style="padding:6px 8px;font-size:11px"><a href="/agents" style="color:#58a6ff;text-decoration:none">Manage agents &rarr;</a></div>';
    container.innerHTML = html;
  } catch(e) {}
}
setInterval(preserveScroll(pollAgentHealth), 5000);
preserveScroll(pollAgentHealth)();

// ── File upload ──────────────────────────────────────────────────
async function uploadFile(file) {
  const status = document.getElementById('status');
  if (file.size > 10 * 1024 * 1024) {
    if (status) status.textContent = 'File too large (max 10MB)';
    return;
  }
  if (status) status.textContent = 'Uploading ' + file.name + '...';
  const form = new FormData();
  form.append('file', file);
  try {
    const resp = await fetch('/api/upload', {method: 'POST', body: form});
    const data = await resp.json();
    if (data.ok) {
      const input = document.getElementById('messageInput');
      const isImage = /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(data.filename);
      const md = isImage
        ? '![' + data.filename + '](' + data.url + ')'
        : '[' + data.filename + '](' + data.url + ')';
      input.value = input.value ? input.value + ' ' + md : md;
      input.focus();
      if (status) status.textContent = 'Uploaded ' + data.filename;
      setTimeout(() => { if (status) status.textContent = ''; }, 3000);
    } else {
      if (status) status.textContent = 'Upload failed';
    }
  } catch(e) {
    if (status) status.textContent = 'Upload error: ' + e.message;
  }
}

// Attach button click
function attachFile() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = 'image/*,.pdf,.txt,.md,.json';
  input.onchange = () => { if (input.files[0]) uploadFile(input.files[0]); };
  input.click();
}

// Drag and drop on chat area
channel.addEventListener('dragover', e => { e.preventDefault(); channel.style.outline = '2px dashed #3498db'; });
channel.addEventListener('dragleave', () => { channel.style.outline = ''; });
channel.addEventListener('drop', e => {
  e.preventDefault();
  channel.style.outline = '';
  if (e.dataTransfer.files.length) uploadFile(e.dataTransfer.files[0]);
});

// Paste image from clipboard
document.getElementById('messageInput').addEventListener('paste', e => {
  const items = e.clipboardData && e.clipboardData.items;
  if (!items) return;
  for (const item of items) {
    if (item.type.startsWith('image/')) {
      e.preventDefault();
      const file = item.getAsFile();
      if (file) uploadFile(file);
      return;
    }
  }
});

// ── Activity follow editor (mirrors channel members editor pattern) ──
function filterFollowed() {
  const pills = document.querySelectorAll('#activityPicker .ch-member');
  if (pills.length > 0) {
    const followed = new Set();
    pills.forEach(p => followed.add(p.textContent.trim()));
    document.querySelectorAll('.act-item').forEach(el => {
      el.style.display = followed.has(el.dataset.agent) ? '' : 'none';
    });
    // Hide separators between hidden items (ghost lines)
    document.querySelectorAll('.act-sep').forEach(sep => {
      const prev = sep.previousElementSibling;
      const next = sep.nextElementSibling;
      const prevVisible = prev && prev.classList.contains('act-item') && prev.style.display !== 'none';
      const nextVisible = next && next.classList.contains('act-item') && next.style.display !== 'none';
      sep.style.display = (prevVisible && nextVisible) ? '' : 'none';
    });
  }
}
filterFollowed();

function editFollow() {
  const editor = document.getElementById('followEditor');
  if (editor.style.display === 'block') { editor.style.display = 'none'; return; }
  editor.style.display = 'block';
  const current = new Set();
  document.querySelectorAll('#activityPicker .ch-member').forEach(p => current.add(p.textContent.trim()));
  const agents = CONFIG.agents || [];
  const div = document.getElementById('followAgents');
  div.innerHTML = agents.map(a =>
    '<label style="display:block;margin-bottom:2px;cursor:pointer;font-size:11px;color:#c9d1d9">' +
    '<input type="checkbox" class="followAgent" value="' + a + '"' +
    (current.has(a) || current.size === 0 ? ' checked' : '') +
    ' style="margin-right:4px"> ' + a + '</label>'
  ).join('');
}

function saveFollow() {
  const follow = [];
  document.querySelectorAll('.followAgent:checked').forEach(cb => follow.push(cb.value));
  fetch('/api/agents/' + encodeURIComponent(CONFIG.me) + '/config', {
    method: 'PUT', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({activity_follow: follow})
  }).then(r => r.json()).then(d => {
    if (d.ok) location.reload();
    else document.getElementById('followStatus').textContent = 'Error';
  });
}
