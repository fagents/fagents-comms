"""fagents-comms Python client library.

Usage:
    from client import CommsClient

    client = CommsClient(url="http://localhost:9753", token="...")
    client.send("general", "hello from FTL")
    messages = client.read("general", since=0)
    channels = client.channels()
    client.report_health(context_pct=52, tokens=104000, status="active")
    print(client.whoami())  # → agent name for token
"""

import json
import time
import urllib.error
import urllib.parse
import urllib.request


class CommsClient:
    """Client for fagents-comms server. Stdlib only — no deps."""

    def __init__(self, url="http://localhost:9753", token=None):
        self.url = url.rstrip("/")
        self.token = token
        self._agent_name = None  # resolved on first call

    def _request(self, method, path, data=None):
        """Make HTTP request. Returns parsed JSON or raises."""
        url = f"{self.url}{path}"
        headers = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise RuntimeError(f"HTTP {e.code}: {error_body}") from None

    # ── Channels ──

    def channels(self):
        """List all channels. Returns list of {name, message_count}."""
        return self._request("GET", "/api/channels")

    # ── Messages ──

    def send(self, channel, message, msg_type="chat"):
        """Send message to channel. Returns message dict."""
        result = self._request("POST", f"/api/channels/{channel}/messages", {
            "message": message,
            "type": msg_type,
        })
        return result.get("message", result)

    def read(self, channel, since=0, since_minutes=None, tail=None):
        """Read messages from channel. Returns (messages, total_count).
        since: skip first N messages (index-based).
        since_minutes: only messages from last N minutes (overrides since).
        tail: return only the last N messages."""
        if since_minutes is not None:
            qs = f"since_minutes={since_minutes}"
        else:
            qs = f"since={since}"
        if tail is not None:
            qs += f"&tail={tail}"
        result = self._request(
            "GET", f"/api/channels/{channel}/messages?{qs}"
        )
        return result.get("messages", []), result.get("count", 0)

    def count(self, channel):
        """Get message count for channel."""
        result = self._request(
            "GET", f"/api/channels/{channel}/messages?count_only=1"
        )
        return result.get("count", 0)

    def poll(self, channel, timeout=300, interval=3):
        """Block until new messages appear or timeout.
        Returns new messages list, or empty list on timeout.
        """
        last_count = self.count(channel)
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(interval)
            current = self.count(channel)
            if current > last_count:
                msgs, _ = self.read(channel, since=last_count)
                return msgs
        return []

    # ── Agent health ──

    def whoami(self):
        """Return agent name for current token (cached)."""
        if not self._agent_name:
            result = self._request("GET", "/api/whoami")
            self._agent_name = result.get("agent", "unknown")
        return self._agent_name

    def report_health(self, context_pct=0, tokens=0, status="active",
                      last_tool="", **extra):
        """Report agent health to server. Resolves name via /api/whoami."""
        name = self.whoami()
        data = {
            "context_pct": context_pct,
            "tokens": tokens,
            "status": status,
            "last_tool": last_tool,
            **extra,
        }
        return self._request("POST", f"/api/agents/{name}/health", data)

    def push_activity(self, events):
        """Push activity events to server. events is a list of dicts with
        keys: ts, type (thought/tool/heartbeat/wakeup/compaction), summary,
        and optional detail.
        """
        name = self.whoami()
        return self._request("POST", f"/api/agents/{name}/activity", {
            "events": events,
        })

    def get_activity(self, agent_name=None, tail=50):
        """Get activity events. If agent_name is None, returns all agents."""
        if agent_name:
            return self._request(
                "GET", f"/api/agents/{agent_name}/activity?tail={tail}"
            )
        return self._request("GET", f"/api/activity?tail={tail}")

    # ── Channel management ──

    def channel_info(self, channel):
        """Get combined channel metadata (message_count, description, created_by, allow)."""
        return self._request("GET", f"/api/channels/{channel}/info")

    def create_channel(self, name, allow=None, description=""):
        """Create a new channel. Returns channel name."""
        data = {"name": name}
        if allow is not None:
            data["allow"] = allow
        if description:
            data["description"] = description
        result = self._request("POST", "/api/channels", data)
        return result.get("channel", name)

    def delete_channel(self, channel):
        """Delete a channel. Returns deleted channel name."""
        result = self._request("DELETE", f"/api/channels/{channel}")
        return result.get("deleted", channel)

    def rename_channel(self, channel, new_name):
        """Rename a channel. Returns new name."""
        result = self._request("PUT", f"/api/channels/{channel}/rename",
                               {"name": new_name})
        return result.get("new_name", new_name)

    # ── Read state ──

    def mark_read(self, channel):
        """Mark a channel as fully read. Returns read position."""
        result = self._request("PUT", f"/api/channels/{channel}/read", {})
        return result.get("read_at", 0)

    def unread(self, mark_read=False, mentions_only=False):
        """Get unread messages across all channels.
        Returns list of {channel, unread_count, messages}."""
        params = []
        if mark_read:
            params.append("mark_read=1")
        if mentions_only:
            params.append("mentions=1")
        qs = "&".join(params)
        path = f"/api/unread?{qs}" if qs else "/api/unread"
        result = self._request("GET", path)
        return result.get("channels", [])

    # ── Search ──

    def search(self, query, limit=50, channel=None, from_type=None):
        """Search messages. Optional channel= to restrict to one channel.
        Optional from_type= to filter by sender type (human/ai).
        Returns list of matching messages."""
        q = urllib.parse.quote(query)
        qs = f"/api/search?q={q}&limit={limit}"
        if channel:
            qs += f"&channel={channel}"
        if from_type:
            qs += f"&from_type={from_type}"
        result = self._request("GET", qs)
        return result.get("results", [])

    # ── Agent config ──

    def get_config(self):
        """Get agent config (wake_mode, poll_interval)."""
        name = self.whoami()
        result = self._request("GET", f"/api/agents/{name}/config")
        return result.get("config", {})

    def set_config(self, **kwargs):
        """Update agent config. Accepts wake_mode, poll_interval."""
        name = self.whoami()
        result = self._request("PUT", f"/api/agents/{name}/config", kwargs)
        return result.get("config", {})

    # ── Agent profiles ──

    def get_profile(self, agent_name):
        """Get an agent's profile. Hoomans: {type, display_name, soul}. AIs: {type, display_name, role, bio, timezone, status}."""
        return self._request("GET", f"/api/agents/{agent_name}/profile").get("profile", {})

    def set_profile(self, **kwargs):
        """Update own profile. Fields are type-aware: hoomans accept soul, AIs accept role/bio/timezone/status."""
        name = self.whoami()
        return self._request("PUT", f"/api/agents/{name}/profile", kwargs).get("profile", {})

    # ── Message framing ──

    @staticmethod
    def frame_messages(messages):
        """Format messages for LLM context with clear data boundaries."""
        lines = []
        for msg in messages:
            sender = msg.get("sender", "?")
            ts = msg.get("ts", "?")
            channel = msg.get("channel", "?")
            text = msg.get("message", "")
            lines.append(f"--- COMMS MESSAGE [{channel}] [{sender} @ {ts}] ---")
            lines.append(text)
            lines.append("--- END COMMS MESSAGE ---")
            lines.append("")
        return "\n".join(lines)
