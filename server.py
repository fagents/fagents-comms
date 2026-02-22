#!/usr/bin/env python3
"""fagents-comms server — multi-agent chat with flat-file channels.

Binds to 127.0.0.1 only. Access remotely via SSH tunnel.
Per-agent auth tokens. Channels as flat log files.

Usage:
    python3 server.py                        # start on port 9753
    python3 server.py --port 8080            # custom port
    python3 server.py add-agent <name>       # add agent, print token
    python3 server.py list-agents            # show registered agents
"""

import hashlib
import http.server
import json
import os
import re
import secrets
import subprocess
import socketserver
import sys
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
CHANNELS_DIR = SCRIPT_DIR / "channels"
TOKENS_FILE = SCRIPT_DIR / "tokens.json"
CHANNELS_ACL_FILE = SCRIPT_DIR / "channels.json"
SUBSCRIPTIONS_FILE = SCRIPT_DIR / "subscriptions.json"
AGENT_CONFIG_FILE = SCRIPT_DIR / "agent_config.json"
AGENT_HEALTH_FILE = SCRIPT_DIR / "agent_health.json"
CHANNEL_ORDER_FILE = SCRIPT_DIR / "channel_order.json"
READ_MARKERS_FILE = SCRIPT_DIR / "read_markers.json"
DEFAULT_PORT = 9753
BIND_ADDR = "127.0.0.1"
MAX_MESSAGE_LEN = 10000
MAX_MESSAGES_RESPONSE = 500
UPLOADS_DIR = SCRIPT_DIR / "uploads"
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB

# Server timezone — derived from system, used for since_minutes filtering
SERVER_TZ = datetime.now().astimezone().tzinfo

# Server start time for uptime calculation
_SERVER_START_TIME = time.time()

# Agent health store: {agent_name: {context_pct, tokens, status, ...}} — persisted to disk
# Initialized after _load_json is defined (see below)
AGENT_HEALTH = {}

# In-memory activity store: {agent_name: [events]} — ring buffer, last MAX_ACTIVITY each
MAX_ACTIVITY = 100
AGENT_ACTIVITY = {}  # {agent_name: [{"ts": ..., "type": ..., "summary": ..., "detail"?: ...}]}

# Read markers: {agent_name: {channel_name: last_read_msg_count}} — persisted to disk
AGENT_READ_MARKERS = {}

# ── JSON file I/O ──────────────────────────────────────────────────

def _load_json(path):
    """Load a JSON file, returning {} on missing or corrupt."""
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"WARNING: failed to load {path}: {type(e).__name__}: {e}")
        return {}


def _save_json(path, data, mode=None):
    """Write data as indented JSON. Optional chmod after write."""
    path.write_text(json.dumps(data, indent=2) + "\n")
    if mode is not None:
        path.chmod(mode)


# Load persisted health data now that _load_json is defined
AGENT_HEALTH.update(_load_json(AGENT_HEALTH_FILE))

# ── Token management ────────────────────────────────────────────────

_TOKENS_CACHE = None  # in-memory cache, invalidated on save


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def load_tokens():
    """Load tokens.json → {hash: agent_name}.
    Cached in memory; invalidated by save_tokens()."""
    global _TOKENS_CACHE
    if _TOKENS_CACHE is None:
        _TOKENS_CACHE = _load_json(TOKENS_FILE)
    return _TOKENS_CACHE


def save_tokens(tokens):
    global _TOKENS_CACHE
    _save_json(TOKENS_FILE, tokens, mode=0o600)
    _TOKENS_CACHE = tokens


def resolve_agent_name(name):
    """Resolve agent name case-insensitively against known agents from tokens.json.
    Returns canonical name if found, otherwise returns input unchanged."""
    tokens = load_tokens()
    known = set(tokens.values())
    name_lower = name.lower()
    for k in known:
        if k.lower() == name_lower:
            return k
    return name


def add_agent(name):
    """Create token for agent. Returns raw token."""
    tokens = load_tokens()
    # Check name not taken
    if name in tokens.values():
        print(f"Agent '{name}' already exists.", file=sys.stderr)
        # Generate new token anyway (rotation)
        old_hash = [h for h, n in tokens.items() if n == name][0]
        del tokens[old_hash]
    raw_token = secrets.token_urlsafe(32)
    tokens[_hash_token(raw_token)] = name
    save_tokens(tokens)
    return raw_token


def resolve_token(raw_token):
    """Return agent name for token, or None."""
    tokens = load_tokens()
    h = _hash_token(raw_token)
    return tokens.get(h)


# ── Channel ACL ────────────────────────────────────────────────────

_ACL_CACHE = None  # in-memory cache, invalidated on save


def load_channels_acl():
    """Load channels.json → {channel_name: {"allow": [...]}}.
    Cached in memory; invalidated by save_channels_acl()."""
    global _ACL_CACHE
    if _ACL_CACHE is None:
        _ACL_CACHE = _load_json(CHANNELS_ACL_FILE)
    return _ACL_CACHE


def save_channels_acl(acl):
    global _ACL_CACHE
    _save_json(CHANNELS_ACL_FILE, acl)
    _ACL_CACHE = acl


def agent_can_access(channel_name, agent_name):
    """Check if agent has access to channel. No ACL file or no entry = open."""
    acl = load_channels_acl()
    entry = acl.get(channel_name)
    if entry is None:
        return True  # no ACL entry = open (backwards compat)
    allow = entry.get("allow", [])
    return "*" in allow or agent_name in allow


def list_accessible_channels(agent_name):
    """Return channel list filtered to those the agent can access."""
    return [c for c in list_channels() if agent_can_access(c["name"], agent_name)]


def filter_mentions(messages, agent_name):
    """Filter messages to those mentioning or replying to agent_name."""
    mention = f"@{agent_name}"
    reply_prefix = f"> @{agent_name}:"
    return [m for m in messages
            if mention in m.get("message", "")
            or m.get("message", "").startswith(reply_prefix)]


# ── Agent channel subscriptions ────────────────────────────────────

def load_subscriptions():
    """Load subscriptions.json → {agent_name: [channel, ...]}."""
    return _load_json(SUBSCRIPTIONS_FILE)


def save_subscriptions(subs):
    _save_json(SUBSCRIPTIONS_FILE, subs)


# ── Agent config ────────────────────────────────────────────────────────

AGENT_CONFIG_DEFAULTS = {
    "wake_mode": "mentions",
    "poll_interval": 1,
    "max_turns": 200,
    "heartbeat_interval": 15000,
    "activity_follow": [],
}


def load_agent_config():
    """Load agent_config.json -> {agent_name: {key: value, ...}}."""
    return _load_json(AGENT_CONFIG_FILE)


def save_agent_config(config):
    _save_json(AGENT_CONFIG_FILE, config)


# ── Channel order preferences ─────────────────────────────────────

def load_channel_order():
    """Load channel_order.json → {agent_name: [channel_name, ...]}."""
    return _load_json(CHANNEL_ORDER_FILE)


def save_channel_order(order):
    _save_json(CHANNEL_ORDER_FILE, order)


def sort_channels_for_agent(channels, agent_name):
    """Sort channel list by agent's saved order. Unsorted channels go at the end alphabetically."""
    order = load_channel_order().get(agent_name, [])
    if not order:
        channels.sort(key=lambda c: c["name"])
        return channels
    order_map = {name: i for i, name in enumerate(order)}
    max_idx = len(order)
    channels.sort(key=lambda c: (order_map.get(c["name"], max_idx), c["name"]))
    return channels


# ── Read markers persistence ──────────────────────────────────────

def load_read_markers():
    """Load read_markers.json → {agent_name: {channel_name: count}}."""
    return _load_json(READ_MARKERS_FILE)


def save_read_markers(markers):
    _save_json(READ_MARKERS_FILE, markers)


# Initialize from disk on import
AGENT_READ_MARKERS.update(load_read_markers())


# ── Channel log operations ──────────────────────────────────────────

LINE_RE = re.compile(
    r"^\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2} \w+)\] \[([^\]]+)\] (.+)$"
)


def ensure_channels_dir():
    CHANNELS_DIR.mkdir(exist_ok=True)


# ── Message count cache (avoids re-reading entire log files) ──
_MSG_COUNT_CACHE = {}  # channel_name -> count

def count_messages(channel_name):
    """Return message count for a channel, using cache when available."""
    if channel_name in _MSG_COUNT_CACHE:
        return _MSG_COUNT_CACHE[channel_name]
    log_file = CHANNELS_DIR / f"{channel_name}.log"
    if not log_file.exists():
        return 0
    count = sum(1 for line in log_file.read_text().splitlines()
                if LINE_RE.match(line))
    _MSG_COUNT_CACHE[channel_name] = count
    return count


def list_channels():
    """Return list of {name, message_count} for all channels."""
    ensure_channels_dir()
    channels = []
    for f in sorted(CHANNELS_DIR.glob("*.log")):
        name = f.stem
        channels.append({"name": name, "message_count": count_messages(name)})
    return channels


def read_channel(name, since=0, since_minutes=None):
    """Read messages from channel. Returns (messages_list, total_count).

    since: skip first N messages (index-based)
    since_minutes: only return messages from the last N minutes (time-based, overrides since)
    """
    log_file = CHANNELS_DIR / f"{name}.log"
    if not log_file.exists():
        return [], 0
    messages = []
    with open(log_file) as f:
        for line in f:
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if m:
                messages.append({
                    "ts": m.group(1),
                    "sender": m.group(2),
                    "message": m.group(3),
                    "channel": name,
                })
            elif messages:
                # Continuation line
                messages[-1]["message"] += "\n" + line
    total = len(messages)
    if since_minutes is not None:
        local_tz = SERVER_TZ
        cutoff = datetime.now(local_tz) - timedelta(minutes=since_minutes)
        filtered = []
        for msg in messages:
            try:
                ts_str = msg["ts"].rsplit(" ", 1)[0]  # "2026-02-12 14:53"
                msg_time = datetime.strptime(ts_str, "%Y-%m-%d %H:%M").replace(tzinfo=local_tz)
                if msg_time >= cutoff:
                    filtered.append(msg)
            except (ValueError, KeyError):
                filtered.append(msg)  # include unparseable messages
        return filtered[:MAX_MESSAGES_RESPONSE], total
    if since > 0:
        return messages[since:since + MAX_MESSAGES_RESPONSE], total
    return messages[-MAX_MESSAGES_RESPONSE:], total


def write_message(channel_name, sender, message, msg_type="chat"):
    """Append message to channel log. Creates channel if needed."""
    ensure_channels_dir()
    # Sanitize: strip control chars except newline
    message = re.sub(r"[\x00-\x09\x0b-\x1f\x7f]", "", message)
    # Timestamp with system timezone
    now = datetime.now().astimezone()
    tz_name = now.strftime("%Z") or "UTC"
    ts = now.strftime("%Y-%m-%d %H:%M") + " " + tz_name
    line = f"[{ts}] [{sender}] {message}\n"
    log_file = CHANNELS_DIR / f"{channel_name}.log"
    with open(log_file, "a") as f:
        f.write(line)
    # Update count cache — ensure initialized before incrementing
    if channel_name not in _MSG_COUNT_CACHE:
        # count_messages reads from disk (which now includes the line we just wrote)
        _MSG_COUNT_CACHE[channel_name] = count_messages(channel_name)
    else:
        _MSG_COUNT_CACHE[channel_name] += 1
    return {"ts": ts, "sender": sender, "message": message,
            "channel": channel_name, "type": msg_type}


# ── Web UI (rendering in ui.py) ────────────────────────────────────
from ui import page_html, agents_page_html


# ── Path helpers ────────────────────────────────────────────────────

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")


def sanitize_name(raw):
    """Strip unsafe chars from a channel/agent name."""
    return _SAFE_NAME_RE.sub("", raw)


def path_param(path, index=3):
    """Extract and sanitize a path segment (default: /api/foo/{param}/...).
    Returns the sanitized string, or empty string if invalid."""
    parts = path.split("/")
    if index >= len(parts):
        return ""
    return sanitize_name(parts[index])


# ── Git log ────────────────────────────────────────────────────────

# ── HTTP Handler ────────────────────────────────────────────────────

class CommsHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress access logs

    def _cookie_name(self):
        """Port-specific cookie name so multiple servers on 127.0.0.1 don't collide."""
        port = self.server.server_address[1]
        return f"comms_token_{port}"

    def get_token(self):
        """Extract raw token from Authorization header or cookie."""
        # Bearer token
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        # Cookie (port-specific name to avoid collision across servers)
        cookie_name = self._cookie_name()
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith(f"{cookie_name}="):
                return part.split("=", 1)[1]
        # Query param (for browser initial auth)
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)
        if "token" in params:
            return params["token"][0]
        return None

    def set_token_cookie(self, raw_token):
        cookie_name = self._cookie_name()
        self.send_header(
            "Set-Cookie",
            f"{cookie_name}={raw_token}; HttpOnly; SameSite=Strict; Path=/",
        )

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_text(self, text, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def require_auth(self):
        """Authenticate request. Returns (agent, raw_token) or sends 401 and returns (None, None)."""
        raw_token = self.get_token()
        agent = resolve_token(raw_token) if raw_token else None
        if not agent:
            self.send_text("Unauthorized", 401)
            return None, None
        return agent, raw_token

    def read_json_body(self):
        """Read and parse JSON body. Returns parsed dict or sends 400 and returns None."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            return json.loads(body) if body else {}
        except (json.JSONDecodeError, ValueError):
            self.send_text("Invalid JSON", 400)
            return None

    def require_path_param(self, path, label="name", index=3):
        """Extract path segment or send 400. Returns sanitized string or None."""
        value = path_param(path, index)
        if not value:
            self.send_text(f"Invalid {label}", 400)
            return None
        return value

    def require_channel_access(self, path, agent):
        """Extract channel name from path and verify access. Returns name or None."""
        channel_name = self.require_path_param(path, "channel name")
        if not channel_name:
            return None
        if not agent_can_access(channel_name, agent):
            self.send_text("Access denied", 403)
            return None
        return channel_name

    def require_own_agent(self, path, agent):
        """Extract agent name from path and verify it matches auth. Returns name or None."""
        agent_name = resolve_agent_name(self.require_path_param(path, "agent name"))
        if not agent_name:
            return None
        if agent_name != agent:
            self.send_text("Can only access own resource", 403)
            return None
        return agent_name

    def require_channel_owner(self, path, agent):
        """Extract channel name and verify agent is creator or has access. Returns name or None."""
        channel_name = self.require_path_param(path, "channel name")
        if not channel_name:
            return None
        acl_entry = load_channels_acl().get(channel_name, {})
        is_creator = acl_entry.get("created_by") == agent
        if not is_creator and not agent_can_access(channel_name, agent):
            self.send_text("Access denied", 403)
            return None
        return channel_name

    def parse_path(self):
        """Parse request path and query params. Returns (path, params)."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        params = urllib.parse.parse_qs(parsed.query)
        return path, params

    def _int_param(self, params, name, default=0):
        """Parse an integer query param. Returns int or sends 400 and returns None."""
        raw = params.get(name, [str(default)])[0]
        try:
            return int(raw)
        except (ValueError, TypeError):
            self.send_text(f"Invalid {name}: must be integer", 400)
            return None

    _MIME_TYPES = {
        ".js": "application/javascript", ".css": "text/css",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml",
        ".pdf": "application/pdf", ".txt": "text/plain",
        ".md": "text/markdown", ".json": "application/json",
    }

    def _serve_file(self, base_dir, path, cache_control="no-store, no-cache, must-revalidate"):
        """Serve a file from a directory. Sanitizes filename, sends with MIME type."""
        safe_name = re.sub(r"[^a-zA-Z0-9_.-]", "", path.split("/")[-1])
        file_path = base_dir / safe_name
        if not file_path.is_file():
            self.send_text("Not found", 404)
            return
        ctype = self._MIME_TYPES.get(file_path.suffix.lower(), "application/octet-stream")
        content = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", cache_control)
        self.end_headers()
        self.wfile.write(content)

    def serve_static(self, path):
        """Serve a file from static/ dir. No auth required."""
        self._serve_file(SCRIPT_DIR / "static", path)

    def serve_upload(self, path):
        """Serve a file from uploads/ dir. No auth — UUID serves as secret."""
        self._serve_file(UPLOADS_DIR, path, cache_control="public, max-age=86400")

    def do_GET(self):
        path, params = self.parse_path()

        # ── Static files (no auth required — JS/CSS are public) ──
        if path.startswith("/static/"):
            self.serve_static(path)
            return

        # ── Server health (no auth — monitoring endpoint) ──
        if path == "/api/health":
            channels = list_channels()
            tokens = load_tokens()
            uptime = int(time.time() - _SERVER_START_TIME)
            self.send_json({
                "status": "ok",
                "uptime_seconds": uptime,
                "channels": len(channels),
                "agents": len(set(tokens.values())),
                "total_messages": sum(ch["message_count"] for ch in channels),
            })
            return

        # ── Uploaded files (no auth — UUID is the secret) ──
        if path.startswith("/uploads/"):
            self.serve_upload(path)
            return

        # Auth check
        agent, raw_token = self.require_auth()
        if not agent:
            return

        # ── Web UI ──
        if path in ("", "/index.html"):
            channel_name = params.get("channel", ["general"])[0]
            # Sanitize channel name
            channel_name = sanitize_name(channel_name) or "general"
            if not agent_can_access(channel_name, agent):
                # Redirect to first accessible channel instead of 403
                accessible = list_accessible_channels(agent)
                if accessible:
                    self.send_response(302)
                    self.send_header("Location", f"/?channel={accessible[0]['name']}")
                    self.end_headers()
                else:
                    self.send_text("No accessible channels", 403)
                return
            messages, total_count = read_channel(channel_name)
            channels = list_accessible_channels(agent)
            # Ensure current channel appears even if empty
            if not any(c["name"] == channel_name for c in channels):
                channels.append({"name": channel_name, "message_count": 0})
            sort_channels_for_agent(channels, agent)
            tokens = load_tokens()
            agent_names = sorted(set(tokens.values()))
            channel_acl = load_channels_acl().get(channel_name, {})
            channel_description = channel_acl.get("description", "")
            agent_cfg = load_agent_config().get(agent, {})
            activity_follow = agent_cfg.get("activity_follow", [])
            content = page_html(channel_name, messages, channels,
                                agent_names, AGENT_HEALTH, AGENT_ACTIVITY,
                                channel_acl, agent, channel_description,
                                total_count=total_count,
                                activity_follow=activity_follow).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.set_token_cookie(raw_token)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # ── Agents page ──
        elif path == "/agents":
            tokens = load_tokens()
            agent_names = sorted(set(tokens.values()))
            content = agents_page_html(agent_names, AGENT_HEALTH,
                                       AGENT_ACTIVITY, agent).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            self.set_token_cookie(raw_token)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)

        # ── API: list channels ──
        elif path == "/api/channels":
            channels = list_accessible_channels(agent)
            markers = AGENT_READ_MARKERS.get(agent, {})
            acl = load_channels_acl()
            for ch in channels:
                last_read = markers.get(ch["name"], 0)
                ch["unread"] = max(0, ch["message_count"] - last_read)
                ch["description"] = acl.get(ch["name"], {}).get("description", "")
            self.send_json(channels)

        # ── API: channel info (combined metadata) ──
        elif path.startswith("/api/channels/") and path.endswith("/info"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return
            acl = load_channels_acl()
            entry = acl.get(channel_name, {})
            self.send_json({
                "channel": channel_name,
                "message_count": count_messages(channel_name),
                "description": entry.get("description", ""),
                "created_by": entry.get("created_by", ""),
                "allow": entry.get("allow", ["*"]),
            })

        # ── API: channel ACL ──
        elif path.startswith("/api/channels/") and path.endswith("/acl"):
            channel_name = self.require_path_param(path, "channel name")
            if not channel_name:
                return
            acl = load_channels_acl()
            entry = acl.get(channel_name, {"allow": ["*"]})
            self.send_json(entry)

        # ── API: channel description ──
        elif path.startswith("/api/channels/") and path.endswith("/description"):
            channel_name = self.require_path_param(path, "channel name")
            if not channel_name:
                return
            acl = load_channels_acl()
            entry = acl.get(channel_name, {})
            self.send_json({"channel": channel_name, "description": entry.get("description", "")})

        # ── API: channel messages ──
        elif path.startswith("/api/channels/") and path.endswith("/messages"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return
            if params.get("count_only", ["0"])[0] == "1":
                self.send_json({"count": count_messages(channel_name)})
            else:
                since_minutes_str = params.get("since_minutes", [None])[0]
                if since_minutes_str is not None:
                    since_minutes = self._int_param(params, "since_minutes")
                    if since_minutes is None:
                        return
                    messages, total = read_channel(channel_name, since_minutes=since_minutes)
                else:
                    since = self._int_param(params, "since", default=0)
                    if since is None:
                        return
                    messages, total = read_channel(channel_name, since=since)
                # Optional: filter to messages mentioning or replying to agent
                for_agent = params.get("for", [None])[0]
                if for_agent:
                    messages = filter_mentions(messages, for_agent)
                # Optional: return only the last N messages
                tail_str = params.get("tail", [None])[0]
                if tail_str is not None:
                    tail = self._int_param(params, "tail")
                    if tail is None:
                        return
                    if tail > 0:
                        messages = messages[-tail:]
                self.send_json({
                    "channel": channel_name,
                    "count": total,
                    "messages": messages,
                })

        # ── API: whoami ──
        elif path == "/api/whoami":
            subs = load_subscriptions().get(agent, [])
            channels = list_accessible_channels(agent)
            tokens = load_tokens()
            agents = sorted(set(tokens.values()))
            health = AGENT_HEALTH.get(agent, {})
            self.send_json({
                "agent": agent,
                "subscriptions": subs,
                "channels": [{"name": c["name"], "message_count": c["message_count"]} for c in channels],
                "agents": agents,
                "health": health,
            })

        # ── API: list agents with health ──
        elif path == "/api/agents":
            self.send_json(AGENT_HEALTH)

        # ── API: specific agent health ──
        elif path.startswith("/api/agents/") and path.endswith("/health"):
            agent_name = resolve_agent_name(path_param(path))
            self.send_json(AGENT_HEALTH.get(agent_name, {}))

        # ── API: agent activity ──
        elif path.startswith("/api/agents/") and path.endswith("/activity"):
            agent_name = resolve_agent_name(path_param(path))
            tail = self._int_param(params, "tail", default=50)
            if tail is None:
                return
            tail = min(tail, MAX_ACTIVITY)
            events = AGENT_ACTIVITY.get(agent_name, [])
            self.send_json(events[-tail:])

        # ── API: agent channel subscriptions ──
        elif path.startswith("/api/agents/") and path.endswith("/channels"):
            agent_name = resolve_agent_name(path_param(path))
            subs = load_subscriptions()
            self.send_json({"agent": agent_name, "channels": subs.get(agent_name, [])})

        # ── API: agent config ──
        elif path.startswith("/api/agents/") and path.endswith("/config"):
            agent_name = resolve_agent_name(path_param(path))
            all_config = load_agent_config()
            agent_cfg = {**AGENT_CONFIG_DEFAULTS, **all_config.get(agent_name, {})}
            self.send_json({"agent": agent_name, "config": agent_cfg})

        # ── API: list agents ──
        elif path == "/api/agents/list":
            tokens = load_tokens()
            self.send_json(sorted(set(tokens.values())))

        # ── API: channel order preference ──
        elif path == "/api/preferences/channel-order":
            order = load_channel_order().get(agent, [])
            self.send_json({"agent": agent, "order": order})

        # ── API: all activity ──
        elif path == "/api/activity":
            tail = self._int_param(params, "tail", default=50)
            if tail is None:
                return
            tail = min(tail, MAX_ACTIVITY * 2)
            exclude = set()
            if "exclude" in params:
                exclude = set(n.strip() for n in params["exclude"][0].split(",") if n.strip())
            all_events = []
            for aname, events in AGENT_ACTIVITY.items():
                if aname in exclude:
                    continue
                for ev in events:
                    all_events.append({**ev, "agent": aname})
            all_events.sort(key=lambda e: e.get("ts", ""))
            self.send_json(all_events[-tail:])

        # ── API: unread messages across all channels ──
        elif path == "/api/unread":
            markers = AGENT_READ_MARKERS.get(agent, {})
            channels = list_accessible_channels(agent)
            mark_read = params.get("mark_read", ["0"])[0] == "1"
            mentions_only = params.get("mentions", ["0"])[0] == "1"
            result = []
            for ch in channels:
                ch_name = ch["name"]
                total = ch["message_count"]
                last_read = markers.get(ch_name, 0)
                if total > last_read:
                    msgs, _ = read_channel(ch_name, since=last_read)
                    if mentions_only:
                        msgs = filter_mentions(msgs, agent)
                    if msgs:
                        result.append({
                            "channel": ch_name,
                            "unread_count": len(msgs),
                            "messages": msgs,
                        })
                    if mark_read:
                        if agent not in AGENT_READ_MARKERS:
                            AGENT_READ_MARKERS[agent] = {}
                        AGENT_READ_MARKERS[agent][ch_name] = total
            if mark_read and result:
                save_read_markers(AGENT_READ_MARKERS)
            self.send_json({"agent": agent, "channels": result})

        # ── API: lightweight poll — total message count across all channels ──
        elif path == "/api/poll":
            channels = list_accessible_channels(agent)
            total = sum(ch["message_count"] for ch in channels)
            markers = AGENT_READ_MARKERS.get(agent, {})
            unread = sum(max(0, ch["message_count"] - markers.get(ch["name"], 0))
                         for ch in channels)
            self.send_json({
                "total": total,
                "unread": unread,
                "channels": len(channels),
            })

        # ── API: search messages across channels ──
        elif path == "/api/search":
            q = params.get("q", [""])[0].strip()
            if not q:
                self.send_text("Missing ?q= parameter", 400)
                return
            limit = self._int_param(params, "limit", default=50)
            if limit is None:
                return
            limit = min(limit, 200)
            q_lower = q.lower()
            channel_filter = params.get("channel", [None])[0]
            results = []
            channels = list_accessible_channels(agent)
            if channel_filter:
                channels = [ch for ch in channels if ch["name"] == channel_filter]
            for ch in channels:
                msgs, _ = read_channel(ch["name"])
                for m in msgs:
                    if q_lower in m.get("message", "").lower():
                        results.append({**m, "channel": ch["name"]})
                        if len(results) >= limit:
                            break
                if len(results) >= limit:
                    break
            self.send_json({"query": q, "count": len(results), "results": results})

        else:
            self.send_text("Not found", 404)

    def _handle_upload(self, agent):
        """Parse multipart upload, save file, return JSON response."""
        content_type = self.headers.get("Content-Type", "")
        if "multipart/form-data" not in content_type:
            self.send_text("Content-Type must be multipart/form-data", 400)
            return
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > MAX_UPLOAD_SIZE:
            self.send_text(f"File too large (max {MAX_UPLOAD_SIZE // 1024 // 1024}MB)", 413)
            return
        # Parse multipart boundary
        boundary = None
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("boundary="):
                boundary = part[9:].strip('"')
        if not boundary:
            self.send_text("Missing boundary", 400)
            return
        body = self.rfile.read(content_length)
        # Split on boundary, find the file part
        sep = f"--{boundary}".encode()
        parts = body.split(sep)
        file_data = None
        orig_filename = "upload"
        for part in parts:
            if b"Content-Disposition:" not in part and b"content-disposition:" not in part:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            headers_raw = part[:header_end].decode("utf-8", errors="replace")
            payload = part[header_end + 4:]
            if payload.endswith(b"\r\n"):
                payload = payload[:-2]
            if 'filename="' in headers_raw:
                m = re.search(r'filename="([^"]*)"', headers_raw)
                if m:
                    orig_filename = m.group(1)
                file_data = payload
                break
        if file_data is None:
            self.send_text("No file found in upload", 400)
            return
        ext = ""
        if "." in orig_filename:
            ext = "." + re.sub(r"[^a-zA-Z0-9]", "", orig_filename.rsplit(".", 1)[-1]).lower()
        file_uuid = str(uuid.uuid4())
        safe_filename = file_uuid + ext
        UPLOADS_DIR.mkdir(exist_ok=True)
        (UPLOADS_DIR / safe_filename).write_bytes(file_data)
        url = f"/uploads/{safe_filename}"
        print(f"Upload: {orig_filename} -> {safe_filename} ({len(file_data)} bytes) by {agent}")
        self.send_json({"ok": True, "url": url, "filename": orig_filename, "uuid": file_uuid, "size": len(file_data)})

    def _handle_rename(self, path, agent, data):
        """Validate and execute channel rename, updating all references."""
        channel_name = self.require_channel_owner(path, agent)
        if not channel_name:
            return
        if channel_name == "general":
            self.send_text("Cannot rename #general", 403)
            return
        new_name = data.get("name", "").strip()
        new_name = re.sub(r"\s+", "-", new_name)
        new_name = sanitize_name(new_name).lower()
        if not new_name:
            self.send_text("Invalid new channel name", 400)
            return
        if new_name == channel_name:
            self.send_text("Same name", 400)
            return
        old_file = CHANNELS_DIR / f"{channel_name}.log"
        new_file = CHANNELS_DIR / f"{new_name}.log"
        if new_file.exists():
            self.send_text(f"Channel '{new_name}' already exists", 409)
            return
        if old_file.exists():
            old_file.rename(new_file)
        # Update count cache for rename
        if channel_name in _MSG_COUNT_CACHE:
            _MSG_COUNT_CACHE[new_name] = _MSG_COUNT_CACHE.pop(channel_name)
        acl = load_channels_acl()
        if channel_name in acl:
            acl[new_name] = acl.pop(channel_name)
            save_channels_acl(acl)
        subs = load_subscriptions()
        changed = False
        for ag in subs:
            new_list = [new_name if ch == channel_name else ch for ch in subs[ag]]
            if new_list != subs[ag]:
                subs[ag] = new_list
                changed = True
        if changed:
            save_subscriptions(subs)
        # Update read markers so agents don't see renamed channel as fully unread
        markers_changed = False
        for ag in AGENT_READ_MARKERS:
            if channel_name in AGENT_READ_MARKERS[ag]:
                AGENT_READ_MARKERS[ag][new_name] = AGENT_READ_MARKERS[ag].pop(channel_name)
                markers_changed = True
        if markers_changed:
            save_read_markers(AGENT_READ_MARKERS)
        # Update channel order preferences
        all_order = load_channel_order()
        order_changed = False
        for ag in all_order:
            new_list = [new_name if ch == channel_name else ch for ch in all_order[ag]]
            if new_list != all_order[ag]:
                all_order[ag] = new_list
                order_changed = True
        if order_changed:
            save_channel_order(all_order)
        write_message(new_name, "System",
                      f"Channel renamed from #{channel_name} to #{new_name}",
                      msg_type="system")
        print(f"Channel '{channel_name}' renamed to '{new_name}' by {agent}")
        self.send_json({"ok": True, "old_name": channel_name, "new_name": new_name})

    def do_POST(self):
        agent, _ = self.require_auth()
        if not agent:
            return
        path, _ = self.parse_path()

        # ── API: file upload (multipart, handled before JSON parsing) ──
        if path == "/api/upload":
            self._handle_upload(agent)
            return

        data = self.read_json_body()
        if data is None:
            return

        # ── API: create channel ──
        if path == "/api/channels":
            name = data.get("name", "").strip()
            name = re.sub(r"\s+", "-", name)  # spaces → hyphens
            name = sanitize_name(name).lower()
            if not name:
                self.send_text("Invalid channel name", 400)
                return
            channel_file = CHANNELS_DIR / f"{name}.log"
            if not channel_file.exists():
                channel_file.touch()
            # Set ACL if provided, otherwise default to ["*"]
            acl = load_channels_acl()
            if name not in acl:
                allow = data.get("allow", ["*"])
                # Creator always has access
                if "*" not in allow and agent not in allow:
                    allow.append(agent)
                entry = {"allow": allow, "created_by": agent}
                description = data.get("description", "")
                if isinstance(description, str) and description:
                    entry["description"] = description[:200]
                acl[name] = entry
                save_channels_acl(acl)
            self.send_json({"ok": True, "channel": name})
            return

        # ── API: create agent ──
        elif path == "/api/agents":
            name = data.get("name", "").strip()
            name = sanitize_name(name)
            if not name:
                self.send_json({"ok": False, "error": "Invalid name"}, 400)
                return
            token = add_agent(name)
            print(f"Agent '{name}' created via API")
            self.send_json({"ok": True, "agent": name, "token": token})
            return

        # ── API: send message ──
        elif path.startswith("/api/channels/") and path.endswith("/messages"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return

            message = data.get("message", "").strip()
            if not message or len(message) > MAX_MESSAGE_LEN:
                self.send_text("Invalid message (empty or too long)", 400)
                return

            # Sender is always the authenticated agent (token identity).
            sender = agent

            msg_type = data.get("type", "chat")
            result = write_message(channel_name, sender, message, msg_type)
            print(f"[{result['ts']}] #{channel_name} [{sender}] {message[:80]}")
            self.send_json({"ok": True, "message": result})

        # ── API: report agent health ──
        elif path.startswith("/api/agents/") and path.endswith("/health"):
            agent_name = self.require_own_agent(path, agent)
            if not agent_name:
                return
            data["reported_at"] = time.time()
            # Merge with existing data so partial pushes don't wipe fields
            # (e.g., soul_text/memory_text survive health-only updates)
            existing = AGENT_HEALTH.get(agent_name, {})
            existing.update(data)
            AGENT_HEALTH[agent_name] = existing
            _save_json(AGENT_HEALTH_FILE, AGENT_HEALTH)
            self.send_json({"ok": True})

        # ── API: push activity events ──
        elif path.startswith("/api/agents/") and path.endswith("/activity"):
            agent_name = self.require_own_agent(path, agent)
            if not agent_name:
                return
            events = data.get("events", [])
            if not isinstance(events, list):
                self.send_text("events must be an array", 400)
                return
            if agent_name not in AGENT_ACTIVITY:
                AGENT_ACTIVITY[agent_name] = []
            buf = AGENT_ACTIVITY[agent_name]
            for ev in events:
                if isinstance(ev, dict) and ev.get("ts") and ev.get("type"):
                    buf.append(ev)
            # Ring buffer trim
            if len(buf) > MAX_ACTIVITY:
                AGENT_ACTIVITY[agent_name] = buf[-MAX_ACTIVITY:]
            self.send_json({"ok": True, "stored": len(events)})

        else:
            self.send_text("Not found", 404)

    def do_PUT(self):
        agent, _ = self.require_auth()
        if not agent:
            return
        path, _ = self.parse_path()
        data = self.read_json_body()
        if data is None:
            return

        # ── API: mark channel as read ──
        if path.startswith("/api/channels/") and path.endswith("/read"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return
            _, total = read_channel(channel_name)
            if agent not in AGENT_READ_MARKERS:
                AGENT_READ_MARKERS[agent] = {}
            AGENT_READ_MARKERS[agent][channel_name] = total
            save_read_markers(AGENT_READ_MARKERS)
            self.send_json({"ok": True, "channel": channel_name, "read_at": total})

        # ── API: update channel ACL ──
        elif path.startswith("/api/channels/") and path.endswith("/acl"):
            channel_name = self.require_channel_owner(path, agent)
            if not channel_name:
                return
            allow = data.get("allow")
            if not isinstance(allow, list):
                self.send_text("allow must be an array", 400)
                return
            acl = load_channels_acl()
            if channel_name not in acl:
                acl[channel_name] = {}
            acl[channel_name]["allow"] = allow
            save_channels_acl(acl)
            self.send_json({"ok": True, "channel": channel_name, "allow": allow})

        # ── API: rename channel ──
        elif path.startswith("/api/channels/") and path.endswith("/rename"):
            self._handle_rename(path, agent, data)

        # ── API: update channel description ──
        elif path.startswith("/api/channels/") and path.endswith("/description"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return
            description = data.get("description", "")
            if not isinstance(description, str) or len(description) > 200:
                self.send_text("description must be a string (max 200 chars)", 400)
                return
            acl = load_channels_acl()
            if channel_name not in acl:
                acl[channel_name] = {"allow": ["*"]}
            acl[channel_name]["description"] = description
            save_channels_acl(acl)
            self.send_json({"ok": True, "channel": channel_name, "description": description})

        # ── API: update channel order preference ──
        elif path == "/api/preferences/channel-order":
            order = data.get("order")
            if not isinstance(order, list) or not all(isinstance(s, str) for s in order):
                self.send_text("order must be an array of strings", 400)
                return
            all_order = load_channel_order()
            all_order[agent] = order
            save_channel_order(all_order)
            self.send_json({"ok": True, "agent": agent, "order": order})

        # ── API: update agent config ──
        elif path.startswith("/api/agents/") and path.endswith("/config"):
            agent_name = resolve_agent_name(self.require_path_param(path, "agent name"))
            if not agent_name:
                return
            all_config = load_agent_config()
            existing = all_config.get(agent_name, {})
            # Partial merge: only update keys present in request
            for key in AGENT_CONFIG_DEFAULTS:
                if key in data:
                    existing[key] = data[key]
            all_config[agent_name] = existing
            save_agent_config(all_config)
            merged = {**AGENT_CONFIG_DEFAULTS, **existing}
            self.send_json({"ok": True, "agent": agent_name, "config": merged})

        # ── API: update agent channel subscriptions ──
        elif path.startswith("/api/agents/") and path.endswith("/channels"):
            agent_name = resolve_agent_name(self.require_path_param(path, "agent name"))
            if not agent_name:
                return
            channels = data.get("channels")
            if not isinstance(channels, list):
                self.send_text("channels must be an array", 400)
                return
            # Filter out channels the agent can't access
            allowed = [ch for ch in channels if agent_can_access(ch, agent_name)]
            rejected = [ch for ch in channels if ch not in allowed]
            subs = load_subscriptions()
            old_channels = set(subs.get(agent_name, []))
            new_channels = set(allowed)
            subs[agent_name] = allowed
            save_subscriptions(subs)
            # Post system messages for joins and leaves
            joined = new_channels - old_channels
            for ch in sorted(joined):
                write_message(ch, "System", f"{agent_name} joined the channel", msg_type="system")
            left = old_channels - new_channels
            for ch in sorted(left):
                write_message(ch, "System", f"{agent_name} left the channel", msg_type="system")
            result = {"ok": True, "agent": agent_name, "channels": allowed}
            if rejected:
                result["rejected"] = rejected
            self.send_json(result)

        else:
            self.send_text("Not found", 404)

    def do_DELETE(self):
        agent, _ = self.require_auth()
        if not agent:
            return
        path, _ = self.parse_path()

        # ── API: delete agent ──
        if path.startswith("/api/agents/"):
            target = resolve_agent_name(self.require_path_param(path, "agent name"))
            if not target:
                return
            tokens = load_tokens()
            hashes_to_remove = [h for h, n in tokens.items() if n == target]
            if not hashes_to_remove:
                self.send_text("Agent not found", 404)
                return
            for h in hashes_to_remove:
                del tokens[h]
            save_tokens(tokens)
            print(f"Agent '{target}' removed via API by {agent}")
            self.send_json({"ok": True, "removed": target})

        # ── API: delete channel ──
        elif path.startswith("/api/channels/"):
            channel_name = self.require_channel_access(path, agent)
            if not channel_name:
                return
            if channel_name == "general":
                self.send_text("Cannot delete #general", 403)
                return
            channel_file = CHANNELS_DIR / f"{channel_name}.log"
            if not channel_file.exists():
                self.send_text("Channel not found", 404)
                return
            channel_file.unlink()
            _MSG_COUNT_CACHE.pop(channel_name, None)
            acl = load_channels_acl()
            acl.pop(channel_name, None)
            save_channels_acl(acl)
            print(f"Channel '{channel_name}' deleted by {agent}")
            self.send_json({"ok": True, "deleted": channel_name})
        else:
            self.send_text("Not found", 404)


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── CLI ─────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="fagents-comms server")
    parser.add_argument("command", nargs="?", default="serve",
                        choices=["serve", "add-agent", "list-agents"],
                        help="Command to run")
    parser.add_argument("name", nargs="?", help="Agent name (for add-agent)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    ensure_channels_dir()

    if args.command == "add-agent":
        if not args.name:
            print("Usage: server.py add-agent <name>", file=sys.stderr)
            sys.exit(1)
        name = sanitize_name(args.name)
        if not name:
            print("Invalid agent name", file=sys.stderr)
            sys.exit(1)
        token = add_agent(name)
        print(f"Agent '{name}' added.")
        print(f"Token: {token}")
        print(f"Use: curl -H 'Authorization: Bearer {token}' http://localhost:{args.port}/api/channels/general/messages")
        return

    if args.command == "list-agents":
        tokens = load_tokens()
        if not tokens:
            print("No agents registered.")
        else:
            for h, name in sorted(tokens.items(), key=lambda x: x[1]):
                print(f"  {name} (hash: {h[:12]}...)")
        return

    # serve
    server = ThreadedHTTPServer((BIND_ADDR, args.port), CommsHandler)
    print(f"fagents-comms server on {BIND_ADDR}:{args.port}")
    print(f"Channels dir: {CHANNELS_DIR}")
    print()

    tokens = load_tokens()
    if not tokens:
        print("No agents registered. Run: python3 server.py add-agent <name>")
    else:
        print(f"Registered agents: {', '.join(sorted(set(tokens.values())))}")
    print()

    # Print a web access URL using first token found
    if tokens:
        first_hash = next(iter(tokens))
        # Can't recover raw token from hash — tell user to use stored token
        print(f"Web UI: http://localhost:{args.port}/?token=<AGENT_TOKEN>")
    print("Ctrl+C to stop")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
