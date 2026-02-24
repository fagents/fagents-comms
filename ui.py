"""fagents-comms Web UI rendering.

All HTML/CSS/JS template generation lives here, extracted from server.py
for readability. Pure functions — no global state access. Server passes
data in, gets HTML strings back.
"""

import hashlib
import html
import json
import re
import time


# ── Color schemes ─────────────────────────────────────────────────────

SENDER_COLORS = {
    "Freeturtle": {"bg": "#1a3a2a", "border": "#2ecc71", "name": "#2ecc71"},
    "FTW": {"bg": "#1a3a2a", "border": "#2ecc71", "name": "#2ecc71"},
    "FTF": {"bg": "#12302a", "border": "#58d68d", "name": "#58d68d"},
    "FTL": {"bg": "#152a2e", "border": "#1abc9c", "name": "#1abc9c"},
    "Juho": {"bg": "#1a2a3a", "border": "#3498db", "name": "#3498db"},
    "Freeclaw": {"bg": "#2a1a3a", "border": "#9b59b6", "name": "#9b59b6"},
    "YOBOT": {"bg": "#2a1f14", "border": "#e67e22", "name": "#e67e22"},
    "sirbot": {"bg": "#2a1418", "border": "#e74c3c", "name": "#e74c3c"},
    "System": {"bg": "#2a2a1a", "border": "#f1c40f", "name": "#f1c40f"},
}
DEFAULT_COLOR = {"bg": "#2a2a2a", "border": "#95a5a6", "name": "#95a5a6"}

# Auto-generated colors for agents not in SENDER_COLORS.
# Deterministic: same name always gets the same color.
_AUTO_COLOR_CACHE = {}

def _color_for_sender(name):
    """Return color dict for a sender. Uses hardcoded colors if available,
    otherwise generates a deterministic color from the name hash."""
    if name in SENDER_COLORS:
        return SENDER_COLORS[name]
    if name in _AUTO_COLOR_CACHE:
        return _AUTO_COLOR_CACHE[name]
    # Generate hue from name hash (0-360) using djb2 — matches app.js autoColor()
    raw = 0
    for ch in name:
        raw = (((raw << 5) - raw) + ord(ch)) & 0xFFFFFFFF
    # Sign-extend to match JS 32-bit signed int behavior
    if raw >= 0x80000000:
        raw -= 0x100000000
    h = ((raw % 360) + 360) % 360
    # Accent color in HSL → hex
    # Use S=65%, L=55% for the border/name (vivid but readable on dark bg)
    border = _hsl_to_hex(h, 65, 55)
    # Background: same hue, very dark and desaturated
    bg = _hsl_to_hex(h, 30, 12)
    color = {"bg": bg, "border": border, "name": border}
    _AUTO_COLOR_CACHE[name] = color
    return color


def _hsl_to_hex(h, s, l):
    """Convert HSL (h: 0-360, s: 0-100, l: 0-100) to hex color string."""
    s /= 100
    l /= 100
    c = (1 - abs(2 * l - 1)) * s
    x = c * (1 - abs((h / 60) % 2 - 1))
    m = l - c / 2
    if h < 60:
        r, g, b = c, x, 0
    elif h < 120:
        r, g, b = x, c, 0
    elif h < 180:
        r, g, b = 0, c, x
    elif h < 240:
        r, g, b = 0, x, c
    elif h < 300:
        r, g, b = x, 0, c
    else:
        r, g, b = c, 0, x
    r, g, b = int((r + m) * 255), int((g + m) * 255), int((b + m) * 255)
    return f"#{r:02x}{g:02x}{b:02x}"

ACTIVITY_TYPE_STYLES = {
    "thought": {"border": "#8b949e", "label": "thought"},
    "tool": {"border": "#2ea043", "label": "tool"},
    "heartbeat": {"border": "#d29922", "label": "heartbeat"},
    "wakeup": {"border": "#3498db", "label": "wakeup"},
    "compaction": {"border": "#da3633", "label": "compaction"},
}
ACTIVITY_DEFAULT_STYLE = {"border": "#8b949e", "label": "event"}


# ── Render functions ──────────────────────────────────────────────────

def _render_quote_line(line):
    """Render a single > quote line as HTML blockquote."""
    qtext = line[2:]  # strip "> "
    m = re.match(r"^@(\S+?):\s*(.*)", qtext)
    if m:
        return (f'<blockquote><span class="quote-sender">@{html.escape(m.group(1))}:'
                f'</span> {html.escape(m.group(2))}</blockquote>')
    return f'<blockquote>{html.escape(qtext)}</blockquote>'


def _render_markdown(text):
    """Convert simple markdown (bold, code, links, images) to HTML."""
    out = html.escape(text)
    out = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"`(.+?)`", r'<code>\1</code>', out)
    # Images: ![alt](url) → inline <img>
    out = re.sub(
        r"!\[([^\]]*)\]\(([^)]+)\)",
        r'<img src="\2" alt="\1" style="max-width:400px;max-height:300px;border-radius:6px;margin:4px 0;cursor:pointer" onclick="window.open(this.src)">',
        out,
    )
    # Links: bare URLs (but not already in src= from images above)
    out = re.sub(
        r'(?<!src=")(https?://\S+)',
        r'<a href="\1" style="color:#3498db" target="_blank">\1</a>',
        out,
    )
    return out.replace("\n", "<br>")


def _split_quotes(text):
    """Split message text into (quote_html, body_lines) for quote/reply rendering."""
    lines = text.split("\n")
    quote_html = ""
    body_lines = []
    in_quote = True
    for line in lines:
        if in_quote and line.startswith("> "):
            quote_html += _render_quote_line(line)
        else:
            in_quote = False
            body_lines.append(line)
    return quote_html, body_lines


def render_messages_html(messages, agent_profiles=None):
    profiles = agent_profiles or {}
    parts = []
    for msg in messages:
        sender = msg["sender"]
        ts = msg["ts"]
        text = msg["message"]
        colors = _color_for_sender(sender)
        prof = profiles.get(sender, {})
        sender_type = prof.get("type", "ai")
        type_indicator = ' <span style="font-size:11px;vertical-align:middle" title="hooman">&#128100;</span>' if sender_type == "human" else ' <span style="font-size:11px;vertical-align:middle" title="ai">&#129302;</span>'

        quote_html, body_lines = _split_quotes(text)
        body = _render_markdown("\n".join(body_lines))
        if quote_html:
            body = re.sub(r"^(<br>)+", "", body)

        plain_text = "\n".join(body_lines).strip()

        parts.append(
            f'<div class="msg" style="background:{colors["bg"]};'
            f'border-left:3px solid {colors["border"]}">'
            f'<div class="meta">'
            f'<span class="sender" style="color:{colors["name"]}">'
            f'{html.escape(sender)}{type_indicator}</span>'
            f'<span class="time">{html.escape(ts)}</span>'
            f'</div>'
            f'<div class="text">{quote_html}{body}</div>'
            f'<div class="msg-actions">'
            f'<button class="reply-btn" data-reply-sender="{html.escape(sender)}"'
            f' data-reply-text="{html.escape(plain_text[:200])}"'
            f' onclick="setReply(this.dataset.replySender,this.dataset.replyText)">'
            f'&#8617; Reply</button>'
            f'</div>'
            f'</div>'
        )
    return "\n".join(parts)


def render_agent_panels_html(agent_names, agent_health):
    """Render agent status panels for ALL registered agents.

    agent_names: sorted list of all registered agent names (from tokens.json)
    agent_health: {name: {context_pct, tokens, ...}} — may be empty or partial
    """
    if not agent_names:
        return '<div class="agent-empty">No agents registered</div>'
    panels = []
    for name in agent_names:
        ename = html.escape(name)
        h = agent_health.get(name)
        age_secs = int(time.time() - h["reported_at"]) if h and "reported_at" in h else None
        online = age_secs is not None and age_secs < 300
        if h:
            pct = h.get("context_pct", 0)
            bar_class = next(
                (cls for thresh, cls in [(40, "ctx-healthy"), (70, "ctx-warming"), (90, "ctx-heavy")]
                 if pct < thresh),
                "ctx-critical"
            )
            tokens_k = h.get("tokens", 0) // 1000
            status = h.get("status", "unknown")
            last_tool = html.escape(h.get("last_tool", "—"))
            age = f"{age_secs}s ago" if age_secs is not None and age_secs < 60 else f"{age_secs // 60}m ago" if age_secs is not None else ""
            health_rows = f"""<div class="agent-row">
            <span class="ctx-label">ctx:</span>
            <div class="ctx-bar"><div class="ctx-fill {bar_class}" style="width:{pct}%"></div></div>
            <span class="ctx-value">{pct}%</span>
          </div>
          <div class="agent-row"><span class="ctx-label">~{tokens_k}k tok</span></div>
          <div class="agent-row"><span class="ctx-label">last: {last_tool}</span></div>
          <div class="agent-row"><span class="ctx-label">{status} {age}</span></div>"""
        else:
            health_rows = '<div class="agent-row"><span class="ctx-label" style="color:#484f58">offline — no health data</span></div>'
        dot_color = "#2ecc71" if online else "#484f58"
        dot = f'<span style="color:{dot_color};font-size:8px;margin-right:4px">&#9679;</span>'
        panels.append(f'''<div class="agent-panel">
          <div class="agent-name" style="display:flex;justify-content:space-between;align-items:center">{dot}{ename} <button onclick="deleteAgent('{ename}')" style="background:none;border:none;color:#da3633;cursor:pointer;font-size:9px;font-family:inherit" title="Remove agent">&times;</button></div>
          {health_rows}
          <div class="agent-row"><button onclick="toggleConfig('{ename}')" id="cfgBtn-{ename}" style="background:none;border:none;color:#d29922;cursor:pointer;font-size:10px;font-family:inherit;padding:0">config</button></div>
          <div id="config-{ename}" style="display:none;padding:2px 0"></div>
        </div>''')
    return "\n".join(panels)


def render_compact_agent_panels_html(agent_names, agent_health, agent_profiles=None):
    """Render simplified agent list for chat sidebar — name + type + context/role."""
    if not agent_names:
        return '<div class="agent-empty">No agents registered</div>'
    profiles = agent_profiles or {}
    panels = []
    for name in agent_names:
        ename = html.escape(name)
        h = agent_health.get(name)
        prof = profiles.get(name, {})
        agent_type = prof.get("type", "ai")
        is_human = agent_type == "human"
        if h:
            pct = h.get("context_pct", 0)
            age_secs = int(time.time() - h["reported_at"]) if "reported_at" in h else None
            online = age_secs is not None and age_secs < 300
            dot_color = "#2ecc71" if online else "#f1c40f" if (age_secs is not None and age_secs < 3600) else "#484f58"
        else:
            pct = 0
            dot_color = "#484f58"
        type_icon = '<span style="font-size:11px;vertical-align:middle;margin-right:2px" title="hooman">&#128100;</span>' if is_human else '<span style="font-size:11px;vertical-align:middle;margin-right:2px" title="ai">&#129302;</span>'
        dot = f'<span style="color:{dot_color};font-size:8px;margin-right:4px">&#9679;</span>'
        if is_human:
            detail = "hooman"
            panels.append(
                f'<div style="display:flex;align-items:center;gap:6px;padding:3px 8px;font-size:11px">'
                f'<span style="flex:1;white-space:nowrap">{dot}{type_icon}{ename}</span>'
                f'<span style="color:#3498db;font-size:10px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100px">{detail}</span>'
                f'</div>'
            )
        else:
            bar_class = next(
                (cls for thresh, cls in [(40, "ctx-healthy"), (70, "ctx-warming"), (90, "ctx-heavy")]
                 if pct < thresh),
                "ctx-critical"
            )
            panels.append(
                f'<div style="display:flex;align-items:center;gap:6px;padding:3px 8px;font-size:11px">'
                f'<span style="flex:1;white-space:nowrap">{dot}{ename}</span>'
                f'<div class="ctx-bar" style="width:50px"><div class="ctx-fill {bar_class}" style="width:{pct}%"></div></div>'
                f'<span style="color:#8b949e;width:28px;text-align:right">{pct}%</span>'
                f'</div>'
            )
    panels.append(
        '<div style="padding:6px 8px;font-size:11px">'
        '<a href="/agents" style="color:#58a6ff;text-decoration:none">Manage agents &rarr;</a>'
        '</div>'
    )
    return "\n".join(panels)


def _render_follow_pills(agent_names, activity_follow):
    """Render followed agents as member-style pills. Shows all if no follow list."""
    followed = activity_follow if activity_follow else agent_names
    if not followed:
        return '<span style="color:#484f58">All agents</span>'
    return "".join(
        f'<span class="ch-member" style="color:{_color_for_sender(a)["name"]}">'
        f'{html.escape(a)}</span>'
        for a in sorted(followed) if a in agent_names
    ) or '<span style="color:#484f58">All agents</span>'


def render_activity_html(agent_activity):
    """Render combined activity feed. agent_activity: {name: [events]}"""
    all_events = []
    for agent_name, events in agent_activity.items():
        for ev in events:
            all_events.append({**ev, "agent": agent_name})
    all_events.sort(key=lambda e: e.get("ts", ""))
    all_events = all_events[-50:]

    if not all_events:
        return '<div class="agent-empty">No activity yet</div>'

    parts = []
    prev_agent = None
    for ev in all_events:
        etype = ev.get("type", "event")
        style = ACTIVITY_TYPE_STYLES.get(etype, ACTIVITY_DEFAULT_STYLE)
        agent_raw = ev.get("agent", "?")
        agent = html.escape(agent_raw)
        summary = html.escape(ev.get("summary", ""))
        detail = html.escape(ev.get("detail", ""))
        ts = ev.get("ts", "")
        ts_short = ts[11:16] if len(ts) >= 16 else ts
        detail_html = f'<span class="act-detail">{detail}</span>' if detail else ""
        agent_colors = _color_for_sender(agent_raw)
        agent_color = agent_colors["name"]
        if prev_agent is not None and agent_raw != prev_agent:
            parts.append('<div class="act-sep"></div>')
        prev_agent = agent_raw
        parts.append(
            f'<div class="act-item" style="border-left:3px solid {agent_color}">'
            f'<span class="act-ts">{html.escape(ts_short)}</span>'
            f'<span class="act-agent" style="color:{agent_color}">{agent}</span>'
            f'<span class="act-type" style="color:{style["border"]}">{style["label"]}</span>'
            f'<span class="act-summary">{summary}</span>'
            f'{detail_html}'
            f'</div>'
        )
    return "\n".join(parts)


# ── Full page ─────────────────────────────────────────────────────────

def agents_page_html(agent_names, agent_health, agent_activity, current_agent=None):
    """Render the agent management page.

    Args:
        agent_names: Sorted list of registered agent names
        agent_health: {agent_name: health_dict}
        agent_activity: {agent_name: [event_dicts]}
        current_agent: Authenticated agent name
    """
    agent_html = render_agent_panels_html(agent_names, agent_health)
    sender_label = html.escape(current_agent or "Unknown")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fagents-comms — agents</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: #0d1117; color: #c9d1d9;
    display: flex; flex-direction: column; height: 100vh;
  }}
  .nav {{
    background: #161b22; border-bottom: 1px solid #30363d;
    padding: 8px 16px; display: flex; align-items: center; gap: 16px;
    flex-shrink: 0;
  }}
  .nav a {{
    color: #8b949e; text-decoration: none; font-size: 13px; font-weight: 600;
    padding: 4px 8px; border-radius: 4px;
  }}
  .nav a:hover {{ color: #e6edf3; background: #21262d; }}
  .nav a.active {{ color: #e6edf3; background: #21262d; }}
  .nav .nav-title {{ font-size: 14px; font-weight: 600; color: #e6edf3; margin-right: 8px; }}
  .agents-container {{
    flex: 1; overflow-y: auto; padding: 16px;
    display: grid; grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
    gap: 12px; align-content: start;
  }}
  .agent-card {{
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 12px 16px;
  }}
  .agent-card-header {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 8px;
  }}
  .agent-card-name {{ font-weight: 700; font-size: 14px; color: #e6edf3; }}
  .agent-card-status {{ font-size: 11px; padding: 2px 8px; border-radius: 10px; }}
  .status-online {{ background: #1a3a2a; color: #2ecc71; }}
  .status-asleep {{ background: #1a2a3a; color: #58a6ff; }}
  .status-offline {{ background: #2a2a2a; color: #8b949e; }}
  .agent-card-meta {{ font-size: 11px; color: #8b949e; display: flex; gap: 16px; }}
  .agent-card-section {{
    margin-top: 8px; border-top: 1px solid #21262d; padding-top: 8px;
  }}
  .agent-card-section-title {{
    font-size: 11px; font-weight: 600; color: #8b949e; margin-bottom: 4px;
    display: flex; justify-content: space-between; align-items: center;
  }}
  .text-preview {{
    background: #0d1117; border: 1px solid #21262d; border-radius: 4px;
    padding: 6px 8px; font-size: 11px; line-height: 1.5;
    white-space: pre-wrap; color: #8b949e; max-height: 120px; overflow: hidden;
    cursor: pointer; position: relative;
  }}
  .text-preview:hover {{ border-color: #484f58; }}
  .text-preview::after {{
    content: ''; position: absolute; bottom: 0; left: 0; right: 0;
    height: 20px; background: linear-gradient(transparent, #0d1117);
  }}
  .modal-overlay {{
    position: fixed; inset: 0; background: rgba(0,0,0,0.7);
    display: flex; align-items: center; justify-content: center; z-index: 1000;
  }}
  .modal-content {{
    background: #161b22; border: 1px solid #30363d; border-radius: 8px;
    width: 90vw; max-width: 800px; max-height: 85vh; display: flex; flex-direction: column;
  }}
  .modal-header {{
    display: flex; justify-content: space-between; align-items: center;
    padding: 12px 16px; border-bottom: 1px solid #30363d;
  }}
  .modal-header h3 {{ font-size: 14px; color: #e6edf3; }}
  .modal-close {{
    background: none; border: none; color: #8b949e; font-size: 18px;
    cursor: pointer; font-family: inherit;
  }}
  .modal-close:hover {{ color: #e6edf3; }}
  .modal-body {{
    padding: 16px; overflow-y: auto; font-size: 12px; line-height: 1.6;
    white-space: pre-wrap; color: #c9d1d9;
  }}
  .soul-memory-content {{
    background: #0d1117; border: 1px solid #30363d; border-radius: 6px;
    padding: 16px; font-size: 12px; line-height: 1.6;
    white-space: pre-wrap; max-height: 70vh; overflow-y: auto;
  }}
  .config-form {{ display: flex; flex-direction: column; gap: 12px; max-width: 400px; }}
  .config-field {{ display: flex; flex-direction: column; gap: 4px; }}
  .config-field label {{ font-size: 11px; font-weight: 600; color: #8b949e; }}
  .config-field input, .config-field select {{
    background: #0d1117; border: 1px solid #30363d; border-radius: 4px;
    padding: 6px 8px; color: #c9d1d9; font-family: inherit; font-size: 13px;
  }}
  .config-field input:focus, .config-field select:focus {{
    outline: none; border-color: #3498db;
  }}
  .config-save {{
    background: #238636; color: white; border: none; border-radius: 4px;
    padding: 8px 16px; font-weight: 600; cursor: pointer; font-family: inherit;
    font-size: 13px; width: fit-content;
  }}
  .config-save:hover {{ background: #2ea043; }}
  .config-save:disabled {{ background: #21262d; color: #484f58; cursor: not-allowed; }}
  .config-msg {{ font-size: 11px; margin-top: 4px; }}
  .config-msg.ok {{ color: #2ecc71; }}
  .config-msg.err {{ color: #da3633; }}
</style>
</head>
<body>
<div class="nav">
  <span class="nav-title">fagents-comms</span>
  <a href="/">Chat</a>
  <a href="/agents" class="active">Agents</a>
</div>
<div class="agents-container" id="agentList">
  <div class="agent-empty">Loading agents...</div>
</div>
<div id="textModal"></div>
<script>
const CURRENT_AGENT = '{sender_label}';

async function api(path, opts) {{
  const r = await fetch(path, opts);
  return r.json();
}}

function escHtml(s) {{
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}}

function showModal(title, text, diff) {{
  const m = document.getElementById('textModal');
  const body = diff ? renderWithDiff(text, diff) : `<div class="modal-body">${{escHtml(text)}}</div>`;
  m.innerHTML = `<div class="modal-overlay" onclick="if(event.target===this)closeModal()">
    <div class="modal-content">
      <div class="modal-header"><h3>${{escHtml(title)}}</h3><button class="modal-close" onclick="closeModal()">&times;</button></div>
      ${{body}}
    </div></div>`;
}}
function renderWithDiff(text, diff) {{
  const hunks = [];
  const dl = diff.split('\\n');
  let hunk = null;
  for (const line of dl) {{
    const m = line.match(/^@@ -\\d+(?:,\\d+)? \\+(\\d+)(?:,\\d+)? @@/);
    if (m) {{ hunk = {{ s: parseInt(m[1]), e: [] }}; hunks.push(hunk); continue; }}
    if (!hunk || line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) hunk.e.push({{ t: 'a', x: line.slice(1) }});
    else if (line.startsWith('-')) hunk.e.push({{ t: 'd', x: line.slice(1) }});
    else hunk.e.push({{ t: 'c', x: line.startsWith(' ') ? line.slice(1) : line }});
  }}
  const added = new Set();
  const removed = {{}};
  for (const h of hunks) {{
    let n = h.s - 1;
    let pending = [];
    for (const e of h.e) {{
      if (e.t === 'd') {{ pending.push(e.x); }}
      else if (e.t === 'a') {{
        if (pending.length) {{ removed[n] = (removed[n] || []).concat(pending); pending = []; }}
        added.add(n); n++;
      }} else {{
        if (pending.length) {{ removed[n] = (removed[n] || []).concat(pending); pending = []; }}
        n++;
      }}
    }}
    if (pending.length) {{ removed[n] = (removed[n] || []).concat(pending); }}
  }}
  const ml = text.split('\\n');
  const out = [];
  for (let i = 0; i < ml.length; i++) {{
    if (removed[i]) {{
      for (const r of removed[i]) out.push(`<span style="background:rgba(248,81,73,0.15);display:inline-block;width:100%;margin:0 -12px;padding:0 12px">${{escHtml(r)}}</span>`);
    }}
    if (added.has(i)) {{
      out.push(`<span style="background:rgba(63,185,80,0.15);display:inline-block;width:100%;margin:0 -12px;padding:0 12px">${{escHtml(ml[i])}}</span>`);
    }} else {{
      out.push(escHtml(ml[i]));
    }}
  }}
  if (removed[ml.length]) {{
    for (const r of removed[ml.length]) out.push(`<span style="background:rgba(248,81,73,0.15);display:inline-block;width:100%;margin:0 -12px;padding:0 12px">${{escHtml(r)}}</span>`);
  }}
  return `<div class="modal-body">${{out.join('\\n')}}</div>`;
}}
function closeModal() {{ document.getElementById('textModal').innerHTML = ''; }}

function preview(text, lines) {{
  if (!text || text === '(not available)') return '<span style="color:#484f58;font-size:11px">Not available</span>';
  const cut = text.split('\\n').slice(0, lines).join('\\n');
  return `<div class="text-preview">${{escHtml(cut)}}</div>`;
}}

async function loadAgents() {{
  const [names, health] = await Promise.all([
    api('/api/agents/list'),
    api('/api/agents')
  ]);
  const container = document.getElementById('agentList');
  if (!names.length) {{
    container.innerHTML = '<div class="agent-empty">No agents registered</div>';
    return;
  }}
  // Fetch configs + subscriptions + profiles for all agents in parallel
  const configs = {{}};
  const subs = {{}};
  const profiles = {{}};
  await Promise.all(names.map(async name => {{
    try {{ const c = await api(`/api/agents/${{name}}/config`); configs[name] = c.config || {{}}; }}
    catch(e) {{ configs[name] = {{}}; }}
    try {{ const s = await api(`/api/agents/${{name}}/channels`); subs[name] = s.channels || []; }}
    catch(e) {{ subs[name] = []; }}
    try {{ const p = await api(`/api/agents/${{name}}/profile`); profiles[name] = p.profile || {{}}; }}
    catch(e) {{ profiles[name] = {{}}; }}
  }}));
  container.innerHTML = names.map(name => {{
    const h = health[name] || {{}};
    const cfg = configs[name] || {{}};
    const now = Date.now() / 1000;
    const age = h.reported_at ? now - h.reported_at : Infinity;
    let statusCls, statusTxt;
    if (age < 300) {{ statusCls = 'status-online'; statusTxt = 'online'; }}
    else if (age < 3600) {{ statusCls = 'status-asleep'; statusTxt = 'asleep'; }}
    else {{ statusCls = 'status-offline'; statusTxt = 'offline'; }}
    const pct = h.context_pct != null ? h.context_pct : 0;
    let barCls = 'ctx-critical';
    if (pct < 40) barCls = 'ctx-healthy';
    else if (pct < 70) barCls = 'ctx-warming';
    else if (pct < 90) barCls = 'ctx-heavy';
    const host = h.host || '—';
    const status = h.status || '—';
    const lastTool = h.last_tool || '—';
    const tokensK = h.tokens ? Math.floor(h.tokens / 1000) + 'k' : '—';
    const since = h.reported_at ? new Date(h.reported_at * 1000).toLocaleTimeString() : '—';
    let seenColor = '#484f58';  // default grey
    if (h.reported_at) {{
      if (age < 120) seenColor = '#3fb950';       // green — active
      else if (age < 600) seenColor = '#58a6ff';   // blue — recent
      else if (age < 3600) seenColor = '#8b949e';  // grey — asleep
      // else stays dark grey — offline
    }}
    const hasHealth = h.reported_at != null;
    const soul = h.soul_text || '';
    const memory = h.memory_text || '';
    const en = escHtml(name);
    const prof = profiles[name] || {{}};
    const agentType = prof.type || h.type || 'ai';
    const isHuman = agentType === 'human';
    const typeBadge = isHuman
      ? '<span style="background:#1a2a3a;color:#3498db;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:600">hooman</span>'
      : '<span style="background:#1a3a2a;color:#2ecc71;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:600">ai</span>';
    if (isHuman) return `<div class="agent-card" id="card-${{en}}" style="border-color:#1a3a5a">
      <div class="agent-card-header">
        <span class="agent-card-name">${{en}} ${{typeBadge}}</span>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>SOUL</span></div>
        <textarea id="hoomanSoul-${{en}}" style="width:100%;min-height:120px;background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:6px;padding:8px;font-size:11px;font-family:inherit;resize:vertical">${{escHtml(prof.soul || '# ' + name + '\\n\\n# About me\\n\\n# Here\\'s how I can help')}}</textarea>
        <button onclick="saveHoomanSoul('${{en}}')" style="background:#238636;color:#fff;border:none;border-radius:6px;padding:4px 12px;font-size:11px;cursor:pointer;margin-top:4px">Save</button>
        <span id="hoomanSoulStatus-${{en}}" style="font-size:10px;color:#3fb950;margin-left:8px;display:none">Saved</span>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>Channels</span></div>
        <div id="subsList-${{en}}" style="display:flex;gap:6px;flex-wrap:wrap;font-size:11px;margin-top:2px">
          ${{(subs[name] || []).length ? (subs[name] || []).map(ch => `<span style="background:#21262d;color:#c9d1d9;padding:1px 6px;border-radius:3px">${{escHtml(ch)}}</span>`).join('') : '<span style="color:#484f58">none</span>'}}
        </div>
        <button onclick="editSubs('${{en}}')" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit;margin-top:4px">Edit channels</button>
        <div id="subsEditor-${{en}}" style="display:none"></div>
      </div>
    </div>`;
    return `<div class="agent-card" id="card-${{en}}">
      <div class="agent-card-header">
        <span class="agent-card-name">${{en}} ${{typeBadge}}</span>
        <span class="agent-card-status ${{statusCls}}" id="badge-${{en}}">${{statusTxt}}</span>
      </div>
      <div id="health-${{en}}">
      ${{hasHealth ? `<div style="display:flex;align-items:center;gap:8px;margin:6px 0">
        <div class="ctx-bar" style="flex:1;height:10px"><div class="ctx-fill ${{barCls}}" style="width:${{pct}}%" id="ctxFill-${{en}}"></div></div>
        <span style="color:#c9d1d9;font-size:12px;font-weight:600;min-width:70px;text-align:right" id="ctxLabel-${{en}}">${{pct}}% ${{barCls.replace('ctx-','').toUpperCase()}}</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:2px 16px;font-size:11px;margin:4px 0">
        <span><span style="color:#484f58">Tokens</span> <span style="color:#c9d1d9" id="tokens-${{en}}">${{tokensK}}</span></span>
        <span id="seen-${{en}}" style="color:${{seenColor}}"><span style="color:#484f58">Seen</span> ${{since}}</span>
        <span><span style="color:#484f58">Status</span> <span style="color:#c9d1d9" id="status-${{en}}">${{escHtml(status)}}</span></span>
        <span><span style="color:#484f58">Tool</span> <span style="color:#c9d1d9" id="tool-${{en}}">${{escHtml(lastTool)}}</span></span>
        ${{host && host !== '—' ? `<span><span style="color:#484f58">Host</span> <span style="color:#c9d1d9">${{host}}</span></span>` : ''}}
      </div>` : `<div style="font-size:11px;color:#484f58;margin:6px 0">No health data</div>`}}
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>SOUL</span></div>
        <div onclick="showModal('${{en}} — SOUL', agentData['${{en}}'].soul, agentData['${{en}}'].soul_diff)">${{preview(soul, 6)}}</div>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>MEMORY</span></div>
        <div onclick="showModal('${{en}} — MEMORY', agentData['${{en}}'].memory, agentData['${{en}}'].memory_diff)">${{preview(memory, 6)}}</div>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>Channels</span></div>
        <div id="subsList-${{en}}" style="display:flex;gap:6px;flex-wrap:wrap;font-size:11px;margin-top:2px">
          ${{(subs[name] || []).length ? (subs[name] || []).map(ch => `<span style="background:#21262d;color:#c9d1d9;padding:1px 6px;border-radius:3px">${{escHtml(ch)}}</span>`).join('') : '<span style="color:#484f58">none</span>'}}
        </div>
        <button onclick="editSubs('${{en}}')" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit;margin-top:4px">Edit channels</button>
        <div id="subsEditor-${{en}}" style="display:none"></div>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>Config</span></div>
        <div style="display:flex;gap:12px;flex-wrap:wrap;font-size:11px;color:#c9d1d9;margin-top:2px">
          <span>wake: <strong>${{escHtml(cfg.wake_mode || 'mentions')}}</strong></span>
          <span>poll: <strong>${{cfg.poll_interval || 1}}s</strong></span>
          <span>max_turns: <strong>${{cfg.max_turns || 200}}</strong></span>
          <span>heartbeat: <strong>${{cfg.heartbeat_interval || 15000}}s</strong></span>
        </div>
        <button onclick="editConfig('${{en}}')" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit;margin-top:4px">Edit config</button>
        <div id="cfgEditor-${{en}}" style="display:none"></div>
      </div>
      <div class="agent-card-section">
        <div class="agent-card-section-title"><span>Profile</span></div>
        <button onclick="editProfile('${{en}}')" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit">Edit profile</button>
        <div id="profileEditor-${{en}}" style="display:none"></div>
      </div>
    </div>`;
  }}).join('');
}}

// Store full text data for modal access
const agentData = {{}};

async function loadAgentData() {{
  const [names, health] = await Promise.all([
    api('/api/agents/list'),
    api('/api/agents')
  ]);
  names.forEach(name => {{
    const h = health[name] || {{}};
    agentData[name] = {{
      soul: h.soul_text || '(not available)',
      memory: h.memory_text || '(not available)',
      memory_diff: h.memory_diff || null,
      soul_diff: h.soul_diff || null
    }};
  }});
}}

async function saveHoomanSoul(name) {{
  const text = document.getElementById('hoomanSoul-' + name).value;
  const resp = await fetch('/api/agents/' + name + '/profile', {{
    method: 'PUT', headers: {{'Authorization': 'Bearer ' + CONFIG.token, 'Content-Type': 'application/json'}},
    body: JSON.stringify({{soul: text}})
  }});
  if (resp.ok) {{
    const el = document.getElementById('hoomanSoulStatus-' + name);
    el.style.display = 'inline'; setTimeout(() => el.style.display = 'none', 2000);
  }}
}}

function editConfig(name) {{
  const ed = document.getElementById('cfgEditor-' + name);
  if (ed.style.display === 'block') {{ ed.style.display = 'none'; return; }}
  ed.style.display = 'block';
  api(`/api/agents/${{name}}/config`).then(data => {{
    const cfg = data.config || {{}};
    ed.innerHTML = `<div class="config-form" style="margin-top:8px">
      <div class="config-field"><label>wake_mode</label>
        <select id="cfg-${{name}}-wake_mode">
          <option value="mentions" ${{cfg.wake_mode === 'mentions' ? 'selected' : ''}}>mentions</option>
          <option value="channel" ${{cfg.wake_mode === 'channel' ? 'selected' : ''}}>channel</option>
        </select></div>
      <div class="config-field"><label>poll_interval (s)</label>
        <input type="number" id="cfg-${{name}}-poll_interval" value="${{cfg.poll_interval || 1}}" min="1"></div>
      <div class="config-field"><label>max_turns</label>
        <input type="number" id="cfg-${{name}}-max_turns" value="${{cfg.max_turns || 200}}" min="1"></div>
      <div class="config-field"><label>heartbeat_interval (s)</label>
        <input type="number" id="cfg-${{name}}-heartbeat_interval" value="${{cfg.heartbeat_interval || 15000}}" min="60"></div>
      <div style="display:flex;gap:8px;align-items:center">
        <button class="config-save" onclick="saveConfig('${{name}}')">Save</button>
        <span class="config-msg" id="cfgMsg-${{name}}"></span>
      </div>
    </div>`;
  }});
}}

async function saveConfig(name) {{
  const msg = document.getElementById('cfgMsg-' + name);
  msg.textContent = '';
  try {{
    const data = {{
      wake_mode: document.getElementById('cfg-' + name + '-wake_mode').value,
      poll_interval: parseInt(document.getElementById('cfg-' + name + '-poll_interval').value),
      max_turns: parseInt(document.getElementById('cfg-' + name + '-max_turns').value),
      heartbeat_interval: parseInt(document.getElementById('cfg-' + name + '-heartbeat_interval').value),
    }};
    const r = await fetch(`/api/agents/${{name}}/config`, {{
      method: 'PUT',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(data)
    }});
    const j = await r.json();
    if (j.ok) {{ msg.className = 'config-msg ok'; msg.textContent = 'Saved'; location.reload(); }}
    else {{ msg.className = 'config-msg err'; msg.textContent = j.error || 'Failed'; }}
  }} catch(e) {{ msg.className = 'config-msg err'; msg.textContent = e.message; }}
}}

async function editSubs(name) {{
  const ed = document.getElementById('subsEditor-' + name);
  if (ed.style.display === 'block') {{ ed.style.display = 'none'; return; }}
  ed.style.display = 'block';
  ed.innerHTML = '<span style="font-size:11px;color:#484f58">Loading...</span>';
  const [chData, subData] = await Promise.all([
    api('/api/channels'),
    api(`/api/agents/${{name}}/channels`)
  ]);
  const allCh = (chData || []).map(c => c.name);
  const current = new Set(subData.channels || []);
  ed.innerHTML = `<div style="margin-top:8px;max-height:200px;overflow-y:auto">
    ${{allCh.map(ch => `<label style="display:block;font-size:11px;padding:2px 0;cursor:pointer;color:#c9d1d9">
      <input type="checkbox" class="sub-${{name}}" value="${{escHtml(ch)}}" ${{current.has(ch) ? 'checked' : ''}}
        style="margin-right:6px;vertical-align:middle"> ${{escHtml(ch)}}
    </label>`).join('')}}
  </div>
  <div style="display:flex;gap:8px;align-items:center;margin-top:6px">
    <button class="config-save" onclick="saveSubs('${{name}}')">Save</button>
    <span class="config-msg" id="subsMsg-${{name}}"></span>
  </div>`;
}}

async function saveSubs(name) {{
  const msg = document.getElementById('subsMsg-' + name);
  msg.textContent = '';
  try {{
    const boxes = document.querySelectorAll('.sub-' + name + ':checked');
    const channels = Array.from(boxes).map(b => b.value);
    const r = await fetch(`/api/agents/${{name}}/channels`, {{
      method: 'PUT',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{ channels }})
    }});
    const j = await r.json();
    if (j.ok) {{
      msg.className = 'config-msg ok';
      msg.textContent = j.rejected && j.rejected.length ? 'Saved (some rejected: ' + j.rejected.join(', ') + ')' : 'Saved';
      const list = document.getElementById('subsList-' + name);
      if (list) {{
        list.innerHTML = j.channels.length
          ? j.channels.map(ch => `<span style="background:#21262d;color:#c9d1d9;padding:1px 6px;border-radius:3px;font-size:11px">${{escHtml(ch)}}</span>`).join('')
          : '<span style="color:#484f58">none</span>';
      }}
    }} else {{ msg.className = 'config-msg err'; msg.textContent = j.error || 'Failed'; }}
  }} catch(e) {{ msg.className = 'config-msg err'; msg.textContent = e.message; }}
}}

async function editProfile(name) {{
  const ed = document.getElementById('profileEditor-' + name);
  if (!ed) return;
  if (ed.style.display === 'block') {{ ed.style.display = 'none'; return; }}
  ed.style.display = 'block';
  const data = await api(`/api/agents/${{name}}/profile`);
  const p = data.profile || {{}};
  ed.innerHTML = `<div class="config-form" style="margin-top:8px">
    <div class="config-field"><label>type</label>
      <select id="prof-${{name}}-type">
        <option value="ai" ${{p.type === 'ai' ? 'selected' : ''}}>ai</option>
        <option value="human" ${{p.type === 'human' ? 'selected' : ''}}>hooman</option>
      </select></div>
    <div class="config-field"><label>display_name</label>
      <input type="text" id="prof-${{name}}-display_name" value="${{escHtml(p.display_name || '')}}" maxlength="50"></div>
    <div class="config-field"><label>role</label>
      <input type="text" id="prof-${{name}}-role" value="${{escHtml(p.role || '')}}" maxlength="100"></div>
    <div class="config-field"><label>bio</label>
      <textarea id="prof-${{name}}-bio" rows="3" maxlength="500" style="background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:6px 8px;color:#c9d1d9;font-family:inherit;font-size:13px;resize:vertical">${{escHtml(p.bio || '')}}</textarea></div>
    <div class="config-field"><label>status</label>
      <input type="text" id="prof-${{name}}-status" value="${{escHtml(p.status || '')}}" maxlength="200" placeholder="e.g. Available, Back at 9am"></div>
    <div style="display:flex;gap:8px;align-items:center">
      <button class="config-save" onclick="saveProfile('${{name}}')">Save</button>
      <span class="config-msg" id="profMsg-${{name}}"></span>
    </div>
  </div>`;
}}

async function saveProfile(name) {{
  const msg = document.getElementById('profMsg-' + name);
  msg.textContent = '';
  try {{
    const data = {{
      type: document.getElementById('prof-' + name + '-type').value,
      display_name: document.getElementById('prof-' + name + '-display_name').value,
      role: document.getElementById('prof-' + name + '-role').value,
      bio: document.getElementById('prof-' + name + '-bio').value,
      status: document.getElementById('prof-' + name + '-status').value,
    }};
    const r = await fetch(`/api/agents/${{name}}/profile`, {{
      method: 'PUT',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(data)
    }});
    const j = await r.json();
    if (j.ok) {{ msg.className = 'config-msg ok'; msg.textContent = 'Saved'; setTimeout(() => location.reload(), 500); }}
    else {{ msg.className = 'config-msg err'; msg.textContent = 'Failed (can only edit own profile)'; }}
  }} catch(e) {{ msg.className = 'config-msg err'; msg.textContent = e.message; }}
}}

loadAgentData().then(() => loadAgents());

// Auto-refresh health data every 5 seconds (in-place, no DOM rebuild)
setInterval(async () => {{
  try {{
    const health = await api('/api/agents');
    for (const [name, h] of Object.entries(health)) {{
      const en = escHtml(name);
      const now = Date.now() / 1000;
      const age = h.reported_at ? now - h.reported_at : Infinity;
      // Update badge
      const badge = document.getElementById('badge-' + en);
      if (badge) {{
        if (age < 300) {{ badge.className = 'agent-card-status status-online'; badge.textContent = 'online'; }}
        else if (age < 3600) {{ badge.className = 'agent-card-status status-asleep'; badge.textContent = 'asleep'; }}
        else {{ badge.className = 'agent-card-status status-offline'; badge.textContent = 'offline'; }}
      }}
      if (!h.reported_at) continue;
      // Context bar
      const pct = h.context_pct != null ? h.context_pct : 0;
      let barCls = 'ctx-critical';
      if (pct < 40) barCls = 'ctx-healthy';
      else if (pct < 70) barCls = 'ctx-warming';
      else if (pct < 90) barCls = 'ctx-heavy';
      const fill = document.getElementById('ctxFill-' + en);
      if (fill) {{ fill.style.width = pct + '%'; fill.className = 'ctx-fill ' + barCls; }}
      const lbl = document.getElementById('ctxLabel-' + en);
      if (lbl) lbl.textContent = pct + '% ' + barCls.replace('ctx-','').toUpperCase();
      // Tokens
      const tok = document.getElementById('tokens-' + en);
      if (tok) tok.textContent = h.tokens ? Math.floor(h.tokens / 1000) + 'k' : '—';
      // Last seen
      const seen = document.getElementById('seen-' + en);
      if (seen) {{
        let seenColor = '#484f58';
        if (age < 120) seenColor = '#3fb950';
        else if (age < 600) seenColor = '#58a6ff';
        else if (age < 3600) seenColor = '#8b949e';
        seen.style.color = seenColor;
        const since = new Date(h.reported_at * 1000).toLocaleTimeString();
        seen.innerHTML = '<span style="color:#484f58">Seen</span> ' + since;
      }}
      // Status + Tool
      const st = document.getElementById('status-' + en);
      if (st) st.textContent = h.status || '—';
      const tl = document.getElementById('tool-' + en);
      if (tl) tl.textContent = h.last_tool || '—';
      // Update soul/memory data for modals
      if (h.soul_text) agentData[name] = agentData[name] || {{}};
      if (h.soul_text && agentData[name]) agentData[name].soul = h.soul_text;
      if (h.memory_text && agentData[name]) agentData[name].memory = h.memory_text;
      if (h.memory_diff && agentData[name]) agentData[name].memory_diff = h.memory_diff;
      if (h.soul_diff && agentData[name]) agentData[name].soul_diff = h.soul_diff;
      // If card had "No health data", rebuild it
      const hDiv = document.getElementById('health-' + en);
      if (hDiv && hDiv.querySelector('div[style*="color:#484f58"]')) {{
        loadAgentData().then(() => loadAgents());
        return;
      }}
    }}
  }} catch(e) {{}}
}}, 5000);
</script>
</body>
</html>"""


def page_html(channel_name, messages, channels_list, agent_names,
              agent_health, agent_activity, channel_acl=None,
              current_agent=None, channel_description="",
              total_count=None, activity_follow=None,
              agent_profiles=None):
    """Render the full web UI page.

    Args:
        channel_name: Current channel name
        messages: List of message dicts
        channels_list: List of {name, message_count} dicts
        agent_names: Sorted list of registered agent names
        agent_health: {agent_name: health_dict}
        agent_activity: {agent_name: [event_dicts]}
        channel_acl: Optional ACL dict with 'allow' list for current channel
        current_agent: Authenticated agent name (shown as sender identity)
        total_count: Total message count in channel (may differ from len(messages) due to truncation)
        agent_profiles: {agent_name: profile_dict} for type-aware rendering
    """
    msg_html = render_messages_html(messages, agent_profiles)
    agent_html = render_compact_agent_panels_html(agent_names, agent_health, agent_profiles)
    activity_html = render_activity_html(agent_activity)
    count = total_count if total_count is not None else len(messages)
    agent_types_json = json.dumps({n: (agent_profiles or {}).get(n, {}).get("type", "ai") for n in agent_names})

    # Channel list for left sidebar
    ch_items = []
    for ch in channels_list:
        active = "ch-active" if ch["name"] == channel_name else ""
        ch_items.append(
            f'<a class="ch-item {active}" href="/?channel={ch["name"]}" data-channel="{html.escape(ch["name"])}">'
            f'<span class="ch-hash">#</span>'
            f'<span class="ch-name">{html.escape(ch["name"])}</span>'
            f'<span class="ch-count">{ch["message_count"]}</span>'
            f'</a>'
        )
    ch_list_html = "\n".join(ch_items) if ch_items else '<div class="ch-empty">No channels</div>'

    # Channel members bar
    allow_list = (channel_acl or {}).get("allow", ["*"])
    if "*" in allow_list:
        members_html = '<span class="ch-member">All agents</span>'
    else:
        members_html = "".join(
            f'<span class="ch-member" style="color:{_color_for_sender(a)["name"]}">'
            f'{html.escape(a)}</span>'
            for a in sorted(allow_list)
        )

    # Sender identity label (determined by auth token)
    sender_label = html.escape(current_agent or "Unknown")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fagents-comms — {html.escape(channel_name)}</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
    background: #0d1117; color: #c9d1d9;
    display: flex; flex-direction: column; height: 100vh;
  }}
  .header {{
    background: #161b22; border-bottom: 1px solid #30363d;
    padding: 8px 16px; display: flex; justify-content: space-between;
    align-items: center; flex-shrink: 0; gap: 8px;
  }}
  .header h1 {{ font-size: 14px; font-weight: 600; color: #e6edf3; }}
  .main {{ flex: 1; display: flex; overflow: hidden; }}
  .ch-sidebar {{
    width: 260px; background: #0d1117; border-right: 1px solid #30363d;
    display: flex; flex-direction: column; flex-shrink: 0; overflow: hidden;
  }}
  .ch-sidebar-title {{
    font-size: 11px; font-weight: 600; color: #8b949e;
    padding: 8px 12px 4px; display: flex; justify-content: space-between; align-items: center;
  }}
  .ch-list {{ flex: 1; overflow-y: auto; padding: 2px 0; }}
  .ch-item {{
    display: flex; align-items: center; gap: 4px;
    padding: 5px 12px; font-size: 13px; color: #8b949e;
    text-decoration: none; font-family: inherit; border-left: 3px solid transparent;
    cursor: pointer;
  }}
  .ch-item:hover {{ color: #c9d1d9; background: #161b22; }}
  .ch-item.ch-active {{ color: #e6edf3; background: #161b22; border-left-color: #3498db; }}
  .ch-hash {{ color: #484f58; font-weight: 600; flex-shrink: 0; }}
  .ch-name {{ flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .ch-count {{ font-size: 10px; color: #484f58; flex-shrink: 0; }}
  .ch-empty {{ color: #484f58; font-size: 11px; padding: 8px 12px; }}
  .ch-unread {{
    background: #da3633; color: white; border-radius: 8px;
    padding: 0 5px; font-size: 10px; font-weight: bold; flex-shrink: 0;
  }}
  .chat-col {{ flex: 1; display: flex; flex-direction: column; min-width: 0; }}
  .sidebar {{
    width: 280px; border-left: 1px solid #30363d;
    display: flex; flex-direction: column; flex-shrink: 0;
    overflow-y: auto; padding: 8px;
  }}
  .sidebar-title {{
    font-size: 12px; font-weight: 600; color: #8b949e;
    padding: 4px 8px; margin-bottom: 4px;
  }}
  .agent-panel {{
    background: #161b22; border: 1px solid #30363d; border-radius: 6px;
    padding: 8px 12px; margin-bottom: 8px; font-size: 11px;
  }}
  .agent-name {{ font-weight: 700; color: #e6edf3; margin-bottom: 4px; }}
  .agent-row {{ display: flex; gap: 6px; align-items: center; margin: 2px 0; }}
  .agent-empty {{ color: #484f58; font-size: 11px; padding: 8px; }}
  .ch-members {{
    display: flex; gap: 6px; align-items: center; padding: 4px 16px;
    background: #161b22; border-bottom: 1px solid #30363d; font-size: 11px;
    flex-shrink: 0;
  }}
  .ch-members-label {{ color: #484f58; }}
  .ch-member {{
    color: #8b949e; background: #21262d; border-radius: 10px;
    padding: 1px 8px; font-weight: 600;
  }}
  .channel {{ flex: 1; overflow-y: auto; padding: 12px 16px; }}
  .msg {{
    margin: 4px 0; padding: 8px 12px; border-radius: 6px;
    font-size: 13px; line-height: 1.5;
  }}
  .meta {{ display: flex; justify-content: space-between; margin-bottom: 2px; }}
  .sender {{ font-weight: 700; font-size: 12px; }}
  .time {{ font-size: 11px; color: #8b949e; }}
  .text {{ word-wrap: break-word; }}
  .text code {{
    background: #1f2937; padding: 1px 5px; border-radius: 3px; font-size: 12px;
  }}
  .text strong {{ color: #e6edf3; }}
  .text blockquote {{
    border-left: 3px solid #484f58; margin: 4px 0 6px 0; padding: 2px 8px;
    color: #8b949e; font-size: 12px; background: rgba(255,255,255,0.03);
    border-radius: 0 4px 4px 0;
  }}
  .text blockquote .quote-sender {{ color: #3498db; font-weight: 600; }}
  .msg-actions {{
    display: flex; justify-content: flex-end; margin-top: 4px;
  }}
  .msg .reply-btn {{
    font-size: 11px; color: #8b949e; cursor: pointer;
    background: none; border: 1px solid #30363d; border-radius: 4px;
    font-family: inherit; padding: 2px 8px;
  }}
  .msg .reply-btn:hover {{ color: #e6edf3; border-color: #484f58; background: rgba(255,255,255,0.04); }}
  .reply-bar {{
    display: none; background: #161b22; border: 1px solid #30363d;
    border-radius: 6px; padding: 4px 10px; margin-bottom: 6px;
    font-size: 12px; color: #8b949e; align-items: center; gap: 8px;
    max-width: 900px; margin-left: auto; margin-right: auto;
  }}
  .reply-bar.active {{ display: flex; }}
  .reply-bar .reply-text {{ flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .reply-bar .reply-sender {{ color: #3498db; font-weight: 600; }}
  .reply-bar .reply-cancel {{
    background: none; border: none; color: #da3633; cursor: pointer;
    font-size: 14px; font-family: inherit; padding: 0 4px;
  }}
  .reply-bar .reply-cancel:hover {{ color: #f85149; }}
  .send-bar {{
    background: #161b22; border-top: 1px solid #30363d;
    padding: 8px 16px; flex-shrink: 0;
  }}
  .send-form {{
    display: flex; gap: 6px; align-items: center; max-width: 900px; margin: 0 auto;
  }}
  .send-form input[type="text"] {{
    background: #0d1117; color: #c9d1d9; border: 1px solid #30363d;
    border-radius: 6px; padding: 6px 10px; font-family: inherit; font-size: 13px;
  }}
  .sender-label {{
    color: #8b949e; font-size: 12px; white-space: nowrap;
  }}
  .send-form input[type="text"] {{ flex: 1; outline: none; }}
  .send-form input[type="text"]:focus {{ border-color: #3498db; }}
  .send-form button {{
    background: #238636; color: #fff; border: none; border-radius: 6px;
    padding: 6px 14px; font-family: inherit; font-size: 13px;
    font-weight: 600; cursor: pointer;
  }}
  .send-form button:hover {{ background: #2ea043; }}
  .status {{ font-size: 11px; color: #8b949e; padding: 2px 0; text-align: center; }}
  a {{ text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .ctx-label {{ color: #8b949e; }}
  .ctx-value {{ color: #c9d1d9; font-weight: 600; }}
  .ctx-bar {{
    width: 60px; height: 8px; background: #21262d;
    border-radius: 4px; overflow: hidden;
  }}
  .ctx-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; }}
  .ctx-healthy {{ background: #2ea043; }}
  .ctx-warming {{ background: #d29922; }}
  .ctx-heavy {{ background: #da3633; }}
  .ctx-critical {{ background: #f85149; animation: pulse 1s infinite; }}
  @keyframes pulse {{ 50% {{ opacity: 0.5; }} }}
  .act-item {{
    padding: 3px 8px; font-size: 11px; margin: 1px 0;
    border-radius: 3px; display: flex; gap: 4px;
    align-items: baseline; flex-wrap: wrap;
  }}
  .act-ts {{ color: #484f58; flex-shrink: 0; }}
  .act-agent {{ color: #8b949e; font-weight: 600; flex-shrink: 0; }}
  .act-summary {{ color: #c9d1d9; }}
  .act-detail {{ color: #8b949e; font-size: 10px; width: 100%; padding-left: 36px; }}
  .act-type {{ font-size: 10px; font-weight: 600; flex-shrink: 0; }}
  .act-sep {{ height: 1px; background: #30363d; margin: 4px 0; }}
  .activity-feed {{ flex: 1; overflow-y: auto; }}
  .sidebar-panel {{ display: none; flex: 1; overflow-y: auto; flex-direction: column; }}
  .sidebar-panel.active {{ display: flex; }}
</style>
</head>
<body>
<div class="nav" style="background:#161b22;border-bottom:1px solid #30363d;padding:8px 16px;display:flex;align-items:center;gap:16px;flex-shrink:0">
  <span style="font-size:14px;font-weight:600;color:#e6edf3;margin-right:8px">fagents-comms</span>
  <a href="/" style="color:#e6edf3;text-decoration:none;font-size:13px;font-weight:600;padding:4px 8px;border-radius:4px;background:#21262d">Chat</a>
  <a href="/agents" style="color:#8b949e;text-decoration:none;font-size:13px;font-weight:600;padding:4px 8px;border-radius:4px">Agents</a>
</div>
<div class="header">
  <h1><button onclick="toggleSearch()" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:12px;font-family:inherit;vertical-align:middle" title="Search messages">&#128269;</button></h1>
  <span style="font-size:11px;color:#8b949e">{count} msgs in #{html.escape(channel_name)}{'' if channel_name == 'general' else ' <button onclick="renameChannel()" style="background:none;border:1px solid #58a6ff;color:#58a6ff;border-radius:4px;padding:1px 6px;font-size:10px;cursor:pointer;font-family:inherit;margin-left:8px" title="Rename this channel">Rename</button> <button onclick="deleteChannel()" style="background:none;border:1px solid #da3633;color:#da3633;border-radius:4px;padding:1px 6px;font-size:10px;cursor:pointer;font-family:inherit" title="Delete this channel">Delete</button>'}</span>
</div>
<div id="searchBar" style="display:none;padding:4px 8px;background:#161b22;border-bottom:1px solid #30363d">
  <input type="text" id="searchInput" placeholder="Search messages..." autocomplete="off" onkeydown="if(event.key==='Enter')searchMessages()" style="background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:4px 8px;font-size:12px;width:300px;font-family:inherit">
  <button onclick="searchMessages()" style="background:#238636;color:white;border:none;border-radius:4px;padding:4px 8px;font-size:12px;cursor:pointer;font-family:inherit;margin-left:4px">Search</button>
  <button onclick="closeSearch()" style="background:none;color:#8b949e;border:none;cursor:pointer;font-size:14px;margin-left:4px">&times;</button>
  <div id="searchResults" style="max-height:200px;overflow-y:auto;margin-top:4px;font-size:12px"></div>
</div>
<div class="main">
  <div class="ch-sidebar">
    <div class="ch-sidebar-title">Channels <button onclick="newChannel()" style="background:#238636;color:#fff;border:none;border-radius:4px;padding:2px 6px;font-size:12px;cursor:pointer;font-family:inherit" title="New channel">+</button></div>
    <div class="ch-list" id="channelList">{ch_list_html}</div>
  </div>
  <div class="chat-col">
    <div class="ch-members"><span class="ch-members-label">Members:</span> {members_html} <button onclick="editAccess()" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit;margin-left:6px">Edit</button>{f' <span style="color:#8b949e;margin-left:8px;font-style:italic">{html.escape(channel_description)}</span>' if channel_description else ''}</div>
    <div id="aclEditor" style="display:none;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px;margin:4px 0;font-size:11px">
      <div style="font-weight:600;color:#e6edf3;margin-bottom:4px">Channel Access</div>
      <div id="aclAgents"></div>
      <div style="margin-top:6px;display:flex;gap:6px">
        <button onclick="saveAccess()" style="background:#238636;color:#fff;border:none;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit">Save</button>
        <button onclick="document.getElementById('aclEditor').style.display='none'" style="background:none;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit">Cancel</button>
        <span id="aclStatus" style="color:#8b949e;font-size:10px;align-self:center"></span>
      </div>
    </div>
    <div class="channel" id="channel">{msg_html}</div>
    <div class="send-bar">
      <div class="reply-bar" id="replyBar">
        <span class="reply-text">Replying to <span class="reply-sender" id="replySender"></span>: <span id="replySnippet"></span></span>
        <button class="reply-cancel" onclick="clearReply()" title="Cancel reply">&times;</button>
      </div>
      <div class="send-form" id="sendForm">
        <span class="sender-label">{sender_label}</span>
        <input type="text" name="message" id="messageInput"
               placeholder="Type a message..." autocomplete="off"
               onkeydown="if(event.key==='Enter')sendMessage()">
        <button type="button" onclick="attachFile()" style="background:#21262d;color:#8b949e;border:1px solid #30363d;border-radius:6px;padding:6px 10px;font-size:13px;cursor:pointer;font-family:inherit" title="Attach file">&#128206;</button>
        <button type="button" onclick="sendMessage()">Send</button>
      </div>
      <div class="status" id="status"></div>
    </div>
  </div>
  <div class="sidebar">
    <div class="sidebar-title">Agents</div>
    <div id="agentPanels">{agent_html}</div>
    <div class="sidebar-panel active" id="tab-activity" style="display:flex">
      <div id="activityPicker" style="display:flex;gap:6px;align-items:center;padding:4px 0;margin-bottom:4px;font-size:11px;flex-wrap:wrap">
        <span class="ch-members-label">Following:</span>
        {_render_follow_pills(agent_names, activity_follow)}
        <button onclick="editFollow()" style="background:none;border:none;color:#58a6ff;cursor:pointer;font-size:10px;font-family:inherit;margin-left:6px">Edit</button>
      </div>
      <div id="followEditor" style="display:none;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:8px;margin:0 0 4px;font-size:11px">
        <div style="font-weight:600;color:#e6edf3;margin-bottom:4px">Activity Follow</div>
        <div id="followAgents"></div>
        <div style="margin-top:6px;display:flex;gap:6px">
          <button onclick="saveFollow()" style="background:#238636;color:#fff;border:none;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit">Save</button>
          <button onclick="document.getElementById('followEditor').style.display='none'" style="background:none;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:3px 8px;font-size:11px;cursor:pointer;font-family:inherit">Cancel</button>
          <span id="followStatus" style="color:#8b949e;font-size:10px;align-self:center"></span>
        </div>
      </div>
      <div class="activity-feed" id="activityFeed">{activity_html}</div>
    </div>
  </div>
</div>
<script>const CONFIG = {{channel: '{channel_name}', lastCount: {count}, agents: {json.dumps(agent_names)}, me: '{sender_label}', agentTypes: {agent_types_json} }};</script>
<script src="/static/app.js"></script>
</body>
</html>"""
