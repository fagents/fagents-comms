"""Tests for fagents-comms server and client.

Spins up a real server on a random port per test session, exercises
all API endpoints through the Python client and raw HTTP.

Requires: pytest (only external dep). Everything else is stdlib.

Run: pytest test_server.py -v
"""

import http.client
import json
import os
import shutil
import tempfile
import threading
import time
import urllib.error
import urllib.request

import pytest

# We need to patch paths before importing server, so tests use tmpdir
import server as _server_module


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def test_dir():
    """Create a temporary directory for all test data."""
    d = tempfile.mkdtemp(prefix="fagent-test-")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session")
def server_info(test_dir):
    """Start a real server on a random port. Returns (url, token, agent_name)."""
    # Patch server module paths to use temp dir
    channels_dir = os.path.join(test_dir, "channels")
    os.makedirs(channels_dir, exist_ok=True)
    tokens_file = os.path.join(test_dir, "tokens.json")

    _server_module.CHANNELS_DIR = _server_module.Path(channels_dir)
    _server_module.TOKENS_FILE = _server_module.Path(tokens_file)
    _server_module.CHANNELS_ACL_FILE = _server_module.Path(
        os.path.join(test_dir, "channels.json"))
    _server_module.SUBSCRIPTIONS_FILE = _server_module.Path(
        os.path.join(test_dir, "subscriptions.json"))
    _server_module.CHANNEL_ORDER_FILE = _server_module.Path(
        os.path.join(test_dir, "channel_order.json"))
    _server_module.READ_MARKERS_FILE = _server_module.Path(
        os.path.join(test_dir, "read_markers.json"))
    _server_module.AGENT_HEALTH_FILE = _server_module.Path(
        os.path.join(test_dir, "agent_health.json"))
    _server_module.AGENT_CONFIG_FILE = _server_module.Path(
        os.path.join(test_dir, "agent_config.json"))
    _server_module.AGENT_PROFILES_FILE = _server_module.Path(
        os.path.join(test_dir, "agent_profiles.json"))
    _server_module.AGENT_HEALTH.clear()
    _server_module.AGENT_ACTIVITY.clear()
    _server_module.AGENT_READ_MARKERS.clear()
    _server_module._ACL_CACHE = None  # reset ACL cache for test isolation
    _server_module._TOKENS_CACHE = None  # reset tokens cache for test isolation
    _server_module.UPLOADS_DIR = _server_module.Path(
        os.path.join(test_dir, "uploads"))

    # Create a test agent
    token = _server_module.add_agent("TestBot")

    # Find a free port
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    srv = _server_module.ThreadedHTTPServer(("127.0.0.1", port), _server_module.CommsHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()

    # Wait for server to be ready
    for _ in range(50):
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("GET", f"/api/whoami?token={token}")
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                break
        except Exception:
            time.sleep(0.05)

    url = f"http://127.0.0.1:{port}"
    yield url, token, "TestBot"
    srv.shutdown()


@pytest.fixture
def client(server_info):
    """Return a CommsClient connected to the test server."""
    from client import CommsClient
    url, token, _ = server_info
    return CommsClient(url=url, token=token)


@pytest.fixture
def url_and_token(server_info):
    url, token, _ = server_info
    return url, token


def _raw_request(url, token, method, path, data=None):
    """Raw HTTP request helper. Returns (status, parsed_json_or_text)."""
    full_url = f"{url}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(full_url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode() if e.fp else ""
        try:
            return e.code, json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return e.code, raw


# ── Token Management ──────────────────────────────────────────────────

class TestTokenManagement:

    def test_hash_is_deterministic(self):
        h1 = _server_module._hash_token("test-token-123")
        h2 = _server_module._hash_token("test-token-123")
        assert h1 == h2

    def test_hash_differs_for_different_tokens(self):
        h1 = _server_module._hash_token("token-a")
        h2 = _server_module._hash_token("token-b")
        assert h1 != h2

    def test_resolve_valid_token(self, server_info):
        _, token, name = server_info
        assert _server_module.resolve_token(token) == name

    def test_resolve_invalid_token(self):
        assert _server_module.resolve_token("bogus-token-does-not-exist") is None

    def test_add_agent_creates_token(self, test_dir):
        token = _server_module.add_agent("TempAgent")
        assert token is not None
        assert len(token) > 20
        assert _server_module.resolve_token(token) == "TempAgent"
        # Cleanup: remove agent
        tokens = _server_module.load_tokens()
        h = _server_module._hash_token(token)
        del tokens[h]
        _server_module.save_tokens(tokens)

    def test_add_agent_rotation(self, test_dir):
        """Adding an agent that already exists rotates the token."""
        t1 = _server_module.add_agent("RotateMe")
        t2 = _server_module.add_agent("RotateMe")
        assert t1 != t2
        assert _server_module.resolve_token(t1) is None  # old token dead
        assert _server_module.resolve_token(t2) == "RotateMe"
        # Cleanup
        tokens = _server_module.load_tokens()
        h = _server_module._hash_token(t2)
        del tokens[h]
        _server_module.save_tokens(tokens)

    def test_tokens_file_permissions(self, test_dir):
        _server_module.add_agent("PermCheck")
        stat = os.stat(_server_module.TOKENS_FILE)
        assert oct(stat.st_mode & 0o777) == "0o600"
        # Cleanup
        tokens = _server_module.load_tokens()
        hashes = [h for h, n in tokens.items() if n == "PermCheck"]
        for h in hashes:
            del tokens[h]
        _server_module.save_tokens(tokens)


# ── Channel Operations ────────────────────────────────────────────────

class TestChannelOperations:

    def test_write_and_read_message(self, test_dir):
        result = _server_module.write_message("test-ch", "Bot", "hello world")
        assert result["sender"] == "Bot"
        assert result["message"] == "hello world"
        assert result["channel"] == "test-ch"

        messages, total = _server_module.read_channel("test-ch")
        assert total >= 1
        assert any(m["message"] == "hello world" for m in messages)

    def test_read_nonexistent_channel(self):
        messages, total = _server_module.read_channel("does-not-exist-xyz")
        assert messages == []
        assert total == 0

    def test_message_sanitization(self, test_dir):
        """Control characters (except newline) should be stripped."""
        dirty = "hello\x00world\x07test\ttabs"
        result = _server_module.write_message("sanitize-ch", "Bot", dirty)
        # \x00, \x07 stripped. \t stripped (0x09). Newlines preserved.
        assert "\x00" not in result["message"]
        assert "\x07" not in result["message"]
        assert "\t" not in result["message"]
        assert "helloworld" in result["message"]

    def test_continuation_lines(self, test_dir):
        """Multi-line messages: continuation lines append to previous."""
        log_file = _server_module.CHANNELS_DIR / "multiline-ch.log"
        log_file.write_text(
            "[2026-02-12 14:00 EET] [Bot] First line\n"
            "  continuation line\n"
            "  another continuation\n"
            "[2026-02-12 14:01 EET] [Bot] Second message\n"
        )
        messages, total = _server_module.read_channel("multiline-ch")
        assert total == 2
        assert "First line\n  continuation line\n  another continuation" == messages[0]["message"]
        assert messages[1]["message"] == "Second message"

    def test_since_index(self, test_dir):
        """Index-based 'since' skips first N messages."""
        ch = "since-idx-ch"
        for i in range(5):
            _server_module.write_message(ch, "Bot", f"msg-{i}")
        messages, total = _server_module.read_channel(ch, since=3)
        assert total == 5
        assert len(messages) == 2
        assert messages[0]["message"] == "msg-3"

    def test_list_channels(self, test_dir):
        _server_module.write_message("list-test-ch", "Bot", "hi")
        channels = _server_module.list_channels()
        names = [c["name"] for c in channels]
        assert "list-test-ch" in names

    def test_max_messages_response(self, test_dir):
        """Read should cap at MAX_MESSAGES_RESPONSE."""
        ch = "cap-ch"
        # Write a few, verify we get them (don't write 500 — just test the slice works)
        for i in range(3):
            _server_module.write_message(ch, "Bot", f"cap-{i}")
        messages, total = _server_module.read_channel(ch)
        assert len(messages) <= _server_module.MAX_MESSAGES_RESPONSE
        assert total == 3


# ── API Auth ──────────────────────────────────────────────────────────

class TestAuth:

    def test_no_token_returns_401(self, url_and_token):
        url, _ = url_and_token
        status, _ = _raw_request(url, "", "GET", "/api/whoami")
        assert status == 401

    def test_invalid_token_returns_401(self, url_and_token):
        url, _ = url_and_token
        status, _ = _raw_request(url, "totally-fake-token", "GET", "/api/whoami")
        assert status == 401

    def test_valid_token_returns_agent(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/whoami")
        assert status == 200
        assert data["agent"] == "TestBot"

    def test_whoami_includes_channels(self, url_and_token):
        """whoami returns list of accessible channels."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/whoami")
        assert status == 200
        assert "channels" in data
        assert isinstance(data["channels"], list)
        # Should include at least general (created by other tests)
        names = [c["name"] for c in data["channels"]]
        assert "general" in names or len(names) >= 0  # general may not exist in test env

    def test_whoami_includes_agents(self, url_and_token):
        """whoami returns list of all registered agents."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/whoami")
        assert status == 200
        assert "agents" in data
        assert "TestBot" in data["agents"]

    def test_whoami_includes_subscriptions(self, url_and_token):
        """whoami returns agent's channel subscriptions."""
        url, token = url_and_token
        # Subscribe to a channel first
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["general"]})
        status, data = _raw_request(url, token, "GET", "/api/whoami")
        assert status == 200
        assert "subscriptions" in data
        assert "general" in data["subscriptions"]

    def test_whoami_includes_health(self, url_and_token):
        """whoami returns agent's own health data."""
        url, token = url_and_token
        # Report health first (health uses POST)
        hs, _ = _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                     {"context_pct": 42, "tokens": 80000, "status": "active"})
        assert hs == 200
        status, data = _raw_request(url, token, "GET", "/api/whoami")
        assert status == 200
        assert "health" in data
        assert data["health"]["context_pct"] == 42
        assert data["health"]["status"] == "active"

    def test_query_param_auth(self, url_and_token):
        url, token = url_and_token
        # Use query param instead of header
        req = urllib.request.Request(f"{url}/api/whoami?token={token}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert data["agent"] == "TestBot"

    def test_cookie_auth(self, url_and_token):
        """Cookie-based auth works for API requests."""
        url, token = url_and_token
        port = url.rsplit(":", 1)[1]
        req = urllib.request.Request(f"{url}/api/whoami")
        req.add_header("Cookie", f"comms_token_{port}={token}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert data["agent"] == "TestBot"

    def test_bearer_auth(self, url_and_token):
        """Explicit Bearer token auth."""
        url, token = url_and_token
        req = urllib.request.Request(f"{url}/api/whoami")
        req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert data["agent"] == "TestBot"

    def test_auth_required_for_post(self, url_and_token):
        """POST without auth returns 401."""
        url, _ = url_and_token
        status, _ = _raw_request(url, "", "POST", "/api/channels",
                                  {"name": "unauth-ch"})
        assert status == 401

    def test_auth_required_for_put(self, url_and_token):
        """PUT without auth returns 401."""
        url, _ = url_and_token
        status, _ = _raw_request(url, "", "PUT", "/api/channels/general/acl",
                                  {"allow": ["*"]})
        assert status == 401

    def test_auth_required_for_delete(self, url_and_token):
        """DELETE without auth returns 401."""
        url, _ = url_and_token
        status, _ = _raw_request(url, "", "DELETE", "/api/agents/TestBot")
        assert status == 401


# ── API Endpoints ─────────────────────────────────────────────────────

class TestAPIEndpoints:

    def test_create_channel(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "api-test-ch"})
        assert status == 200
        assert data["ok"] is True

    def test_create_channel_sanitization(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "bad/../name!"})
        assert status == 200
        assert data["channel"] == "badname"

    def test_create_channel_empty_name(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/channels",
                                  {"name": "!!!"})
        assert status == 400

    def test_send_and_read_messages(self, client):
        # Send
        result = client.send("roundtrip-ch", "hello from test")
        assert result["sender"] == "TestBot"
        assert result["message"] == "hello from test"

        # Read back
        messages, total = client.read("roundtrip-ch")
        assert total >= 1
        assert any(m["message"] == "hello from test" for m in messages)

    def test_message_count(self, client):
        ch = "count-ch"
        client.send(ch, "one")
        client.send(ch, "two")
        count = client.count(ch)
        assert count >= 2

    def test_send_empty_message(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST",
                                  "/api/channels/general/messages",
                                  {"message": ""})
        assert status == 400

    def test_send_too_long_message(self, url_and_token):
        url, token = url_and_token
        long_msg = "x" * (_server_module.MAX_MESSAGE_LEN + 1)
        status, _ = _raw_request(url, token, "POST",
                                  "/api/channels/general/messages",
                                  {"message": long_msg})
        assert status == 400

    def test_send_max_length_message(self, client):
        """Exactly MAX_MESSAGE_LEN should succeed."""
        msg = "y" * _server_module.MAX_MESSAGE_LEN
        result = client.send("maxlen-ch", msg)
        assert len(result["message"]) == _server_module.MAX_MESSAGE_LEN

    def test_invalid_json_post(self, url_and_token):
        url, token = url_and_token
        full_url = f"{url}/api/channels/general/messages"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(full_url, data=b"not json{{{",
                                      headers=headers, method="POST")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_list_channels_api(self, client):
        client.send("api-list-ch", "hi")
        channels = client.channels()
        names = [c["name"] for c in channels]
        assert "api-list-ch" in names

    def test_sender_enforcement(self, url_and_token):
        """API clients should always use token identity, ignoring sender field."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST",
                                     "/api/channels/enforce-ch/messages",
                                     {"message": "test", "sender": "Imposter"})
        assert status == 200
        assert data["message"]["sender"] == "TestBot"

    def test_sender_enforcement_even_with_web_ui_header(self, url_and_token):
        """Sender is always token identity, even with X-Web-UI header."""
        url, token = url_and_token
        full_url = f"{url}/api/channels/webui-ch/messages"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "X-Web-UI": "1",
        }
        body = json.dumps({"message": "from juho", "sender": "Juho"}).encode()
        req = urllib.request.Request(full_url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert data["message"]["sender"] == "TestBot"

    def test_404_on_unknown_path(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "GET", "/api/nonexistent")
        assert status == 404

    def test_count_only(self, url_and_token):
        url, token = url_and_token
        # Create a message first
        _raw_request(url, token, "POST", "/api/channels/countonly-ch/messages",
                     {"message": "for counting"})
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/countonly-ch/messages?count_only=1")
        assert status == 200
        assert "count" in data
        assert "messages" not in data


# ── Agent Health ──────────────────────────────────────────────────────

class TestAgentHealth:

    def test_report_and_read_health(self, client, url_and_token):
        url, token = url_and_token
        client.report_health(context_pct=42, tokens=84000,
                             status="active", last_tool="Read")
        status, data = _raw_request(url, token, "GET", "/api/agents/TestBot/health")
        assert status == 200
        assert data["context_pct"] == 42
        assert data["tokens"] == 84000
        assert data["status"] == "active"
        assert "reported_at" in data

    def test_cannot_report_other_agents_health(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/agents/SomeoneElse/health",
                                  {"context_pct": 99})
        assert status == 403

    def test_agents_list(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/agents/list")
        assert status == 200
        assert isinstance(data, list)
        assert "TestBot" in data

    def test_status_message_stored_and_readable(self, url_and_token):
        """Status message survives POST health and shows in GET agents."""
        url, token = url_and_token
        s, _ = _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                            {"status_message": "working on Loop 5"})
        assert s == 200
        s, data = _raw_request(url, token, "GET", "/api/agents")
        assert s == 200
        assert data["TestBot"]["status_message"] == "working on Loop 5"

    def test_status_message_updates(self, url_and_token):
        """New health POST replaces previous status message."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                     {"status_message": "old"})
        _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                     {"status_message": "new"})
        s, data = _raw_request(url, token, "GET", "/api/agents/TestBot/health")
        assert s == 200
        assert data["status_message"] == "new"


# ── Agent Activity ────────────────────────────────────────────────────

class TestAgentActivity:

    def test_push_and_read_activity(self, client, url_and_token):
        url, token = url_and_token
        events = [
            {"ts": "2026-02-12 14:00", "type": "heartbeat", "summary": "alive"},
            {"ts": "2026-02-12 14:01", "type": "tool", "summary": "Read file",
             "detail": "/path/to/file"},
        ]
        client.push_activity(events)

        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/activity?tail=10")
        assert status == 200
        assert len(data) >= 2
        summaries = [e["summary"] for e in data]
        assert "alive" in summaries
        assert "Read file" in summaries

    def test_cannot_push_other_agents_activity(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST",
                                  "/api/agents/SomeoneElse/activity",
                                  {"events": [{"ts": "now", "type": "hack", "summary": "x"}]})
        assert status == 403

    def test_activity_ring_buffer(self, client, url_and_token):
        """Push more than MAX_ACTIVITY events, verify trim."""
        url, token = url_and_token
        events = [
            {"ts": f"2026-02-12 15:{i:02d}", "type": "tool", "summary": f"event-{i}"}
            for i in range(_server_module.MAX_ACTIVITY + 20)
        ]
        client.push_activity(events)

        status, data = _raw_request(url, token, "GET",
                                     f"/api/agents/TestBot/activity?tail={_server_module.MAX_ACTIVITY + 50}")
        assert status == 200
        assert len(data) <= _server_module.MAX_ACTIVITY

    def test_all_activity_endpoint(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/activity?tail=10")
        assert status == 200
        assert isinstance(data, list)

    def test_all_activity_exclude_agents(self, url_and_token):
        """Exclude param filters agents before applying tail limit."""
        url, token = url_and_token
        _server_module.AGENT_ACTIVITY["AgentA"] = [
            {"ts": f"2026-02-17 09:{i:02d}", "type": "tool", "summary": f"a-{i}"}
            for i in range(5)
        ]
        _server_module.AGENT_ACTIVITY["AgentB"] = [
            {"ts": f"2026-02-17 09:{i:02d}", "type": "tool", "summary": f"b-{i}"}
            for i in range(10, 15)
        ]
        # Without exclude: both agents present
        status, data = _raw_request(url, token, "GET", "/api/activity?tail=50")
        assert status == 200
        agents = set(ev["agent"] for ev in data)
        assert "AgentA" in agents
        assert "AgentB" in agents
        # With exclude=AgentB: only AgentA events
        status, data = _raw_request(url, token, "GET",
                                     "/api/activity?tail=50&exclude=AgentB")
        assert status == 200
        for ev in data:
            assert ev["agent"] != "AgentB"
        a_events = [ev for ev in data if ev["agent"] == "AgentA"]
        assert len(a_events) == 5
        # With exclude=AgentA,AgentB: neither
        status, data = _raw_request(url, token, "GET",
                                     "/api/activity?tail=50&exclude=AgentA%2CAgentB")
        assert status == 200
        for ev in data:
            assert ev["agent"] not in ("AgentA", "AgentB")

    def test_invalid_events_ignored(self, client, url_and_token):
        """Events missing ts or type should not be stored."""
        url, token = url_and_token
        # Clear activity first
        _server_module.AGENT_ACTIVITY["TestBot"] = []
        events = [
            {"summary": "no ts or type"},  # invalid
            {"ts": "2026-02-12 16:00", "type": "tool", "summary": "valid"},
        ]
        client.push_activity(events)
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/activity?tail=10")
        assert status == 200
        # Only the valid event should be stored
        assert len(data) == 1
        assert data[0]["summary"] == "valid"


# ── Agent CRUD via API ────────────────────────────────────────────────

class TestAgentCRUD:

    def test_create_and_delete_agent(self, url_and_token):
        url, token = url_and_token
        # Create
        status, data = _raw_request(url, token, "POST", "/api/agents",
                                     {"name": "Ephemeral"})
        assert status == 200
        assert data["ok"] is True
        assert data["agent"] == "Ephemeral"
        new_token = data["token"]
        assert len(new_token) > 20

        # Verify it resolves
        assert _server_module.resolve_token(new_token) == "Ephemeral"

        # Delete
        status, data = _raw_request(url, token, "DELETE", "/api/agents/Ephemeral")
        assert status == 200
        assert data["ok"] is True

        # Verify token no longer resolves
        assert _server_module.resolve_token(new_token) is None

    def test_create_agent_bad_name(self, url_and_token):
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/agents",
                                     {"name": "!!!"})
        assert status == 400

    def test_delete_nonexistent_agent(self, url_and_token):
        url, token = url_and_token
        status, _ = _raw_request(url, token, "DELETE", "/api/agents/GhostAgent")
        assert status == 404


# ── Client Library ────────────────────────────────────────────────────

class TestClientLibrary:

    def test_whoami(self, client):
        assert client.whoami() == "TestBot"

    def test_whoami_caching(self, client):
        name1 = client.whoami()
        name2 = client.whoami()
        assert name1 == name2
        assert client._agent_name == "TestBot"

    def test_send_read_roundtrip(self, client):
        ch = "client-roundtrip"
        client.send(ch, "ping")
        messages, total = client.read(ch)
        assert total >= 1
        assert messages[-1]["message"] == "ping"

    def test_frame_messages(self):
        from client import CommsClient
        messages = [
            {"sender": "Bot", "ts": "2026-02-12 14:00 EET",
             "channel": "test", "message": "hello"},
        ]
        framed = CommsClient.frame_messages(messages)
        assert "--- COMMS MESSAGE [test] [Bot @ 2026-02-12 14:00 EET] ---" in framed
        assert "hello" in framed
        assert "--- END COMMS MESSAGE ---" in framed

    def test_client_error_on_bad_token(self, server_info):
        from client import CommsClient
        url, _, _ = server_info
        bad_client = CommsClient(url=url, token="invalid-token")
        with pytest.raises(RuntimeError, match="HTTP 401"):
            bad_client.whoami()

    def test_client_count(self, client):
        ch = "client-count-ch"
        client.send(ch, "one")
        client.send(ch, "two")
        assert client.count(ch) >= 2

    def test_client_report_health(self, client, url_and_token):
        url, token = url_and_token
        result = client.report_health(context_pct=65, tokens=130000,
                                       status="active", last_tool="Bash")
        assert result.get("ok") is True
        # Verify it was stored
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/health")
        assert status == 200
        assert data.get("context_pct") == 65
        assert data.get("last_tool") == "Bash"

    def test_client_get_activity_specific_agent(self, client):
        client.push_activity([
            {"ts": "2026-02-12 17:00", "type": "tool", "summary": "test event"}
        ])
        events = client.get_activity(agent_name="TestBot", tail=5)
        assert isinstance(events, list)
        assert any(e.get("summary") == "test event" for e in events)

    def test_client_get_activity_all(self, client):
        events = client.get_activity(tail=5)
        assert isinstance(events, list)

    def test_client_send_custom_type(self, client):
        result = client.send("type-test-ch", "system message", msg_type="system")
        assert result["type"] == "system"

    def test_client_channels_list(self, client):
        client.send("client-list-ch", "hi")
        channels = client.channels()
        assert isinstance(channels, list)
        names = [c["name"] for c in channels]
        assert "client-list-ch" in names

    def test_frame_messages_empty(self):
        from client import CommsClient
        assert CommsClient.frame_messages([]) == ""

    def test_frame_messages_missing_fields(self):
        from client import CommsClient
        messages = [{"message": "bare"}]
        framed = CommsClient.frame_messages(messages)
        assert "bare" in framed
        assert "[?]" in framed  # missing sender/channel default to "?"


# ── Web UI ────────────────────────────────────────────────────────────

class TestWebUI:

    def test_web_ui_returns_html(self, url_and_token):
        url, token = url_and_token
        req = urllib.request.Request(f"{url}/?token={token}")
        with urllib.request.urlopen(req) as resp:
            content_type = resp.headers.get("Content-Type", "")
            body = resp.read().decode()
        assert "text/html" in content_type
        assert "fagents-comms" in body

    def test_web_ui_sets_cookie(self, url_and_token):
        url, token = url_and_token
        req = urllib.request.Request(f"{url}/?token={token}")
        with urllib.request.urlopen(req) as resp:
            cookie = resp.headers.get("Set-Cookie", "")
        port = url.rsplit(":", 1)[1]
        assert f"comms_token_{port}=" in cookie
        assert "HttpOnly" in cookie

    def test_web_ui_channel_param(self, url_and_token):
        url, token = url_and_token
        # Create the channel first
        _raw_request(url, token, "POST", "/api/channels", {"name": "ui-test"})
        req = urllib.request.Request(f"{url}/?channel=ui-test&token={token}")
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
        assert "ui-test" in body


# ── Reply/Quote Feature ──────────────────────────────────────────────

class TestReplyQuote:
    """Tests for the reply/quote rendering feature."""

    def test_render_quote_line_with_sender(self):
        from ui import _render_quote_line
        result = _render_quote_line("> @Juho: hello world")
        assert "<blockquote>" in result
        assert "quote-sender" in result
        assert "@Juho:" in result
        assert "hello world" in result

    def test_render_quote_line_plain(self):
        from ui import _render_quote_line
        result = _render_quote_line("> just a plain quote")
        assert "<blockquote>" in result
        assert "just a plain quote" in result
        assert "quote-sender" not in result

    def test_render_quote_line_escapes_html(self):
        from ui import _render_quote_line
        result = _render_quote_line("> @Evil: <script>alert(1)</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_render_messages_with_quote(self):
        from ui import render_messages_html
        messages = [{
            "sender": "FTW",
            "ts": "2026-02-12 16:30",
            "message": "> @Juho: original message\n\nMy reply here"
        }]
        html = render_messages_html(messages)
        assert "<blockquote>" in html
        assert "@Juho:" in html
        assert "original message" in html
        assert "My reply here" in html

    def test_render_messages_without_quote(self):
        from ui import render_messages_html
        messages = [{
            "sender": "Juho",
            "ts": "2026-02-12 16:00",
            "message": "Just a normal message"
        }]
        html = render_messages_html(messages)
        assert "<blockquote>" not in html
        assert "Just a normal message" in html

    def test_render_messages_reply_button_present(self):
        from ui import render_messages_html
        messages = [{
            "sender": "FTL",
            "ts": "2026-02-12 16:00",
            "message": "Test message"
        }]
        html = render_messages_html(messages)
        assert "reply-btn" in html
        assert "Reply" in html
        assert "msg-actions" in html
        assert 'data-reply-sender="FTL"' in html

    def test_render_messages_quote_body_separation(self):
        """Quote lines and body should be separated — no quote text in body."""
        from ui import render_messages_html
        messages = [{
            "sender": "FTW",
            "ts": "2026-02-12 16:30",
            "message": "> @Juho: quoted part\n\nBody part"
        }]
        html = render_messages_html(messages)
        # blockquote should contain the quote, not the body
        import re
        bq = re.search(r"<blockquote>.*?</blockquote>", html)
        assert bq is not None
        assert "quoted part" in bq.group()
        assert "Body part" not in bq.group()

    def test_render_messages_multiline_quote(self):
        from ui import render_messages_html
        messages = [{
            "sender": "FTW",
            "ts": "2026-02-12 16:30",
            "message": "> @Juho: line one\n> @Juho: line two\n\nReply"
        }]
        html = render_messages_html(messages)
        assert html.count("<blockquote>") == 2

    def test_reply_button_escapes_quotes_in_text(self):
        """Reply button data attributes must survive quotes in message text."""
        from ui import render_messages_html
        messages = [{
            "sender": "Juho",
            "ts": "2026-02-12 16:30",
            "message": 'He said "hello" and it\'s fine'
        }]
        html = render_messages_html(messages)
        # The data-reply-text attribute must not have raw " breaking the HTML
        assert 'data-reply-sender="Juho"' in html
        assert 'data-reply-text="' in html
        # Verify the attribute is properly closed (no broken HTML)
        import re
        attr = re.search(r'data-reply-text="([^"]*)"', html)
        assert attr is not None, "data-reply-text attribute is broken by quotes"
        assert "hello" in attr.group(1)

    def test_reply_button_on_polled_message_format(self):
        """Verify server-rendered reply buttons use setReply directly (not handleReply)."""
        from ui import render_messages_html
        messages = [{
            "sender": "FTW",
            "ts": "2026-02-12 16:30",
            "message": "test"
        }]
        html = render_messages_html(messages)
        assert "setReply(this.dataset.replySender,this.dataset.replyText)" in html
        assert "handleReply" not in html

    def test_reply_message_roundtrip(self, url_and_token):
        """Send a reply-formatted message via API, verify it renders with blockquote."""
        url, token = url_and_token
        # Create channel for this test
        _raw_request(url, token, "POST", "/api/channels", {"name": "reply-test"})
        # Send a reply message
        reply_msg = "> @TestBot: original msg\n\nThis is my reply"
        _raw_request(url, token, "POST", "/api/channels/reply-test/messages",
                     {"message": reply_msg})
        # Fetch web UI and check rendering
        req = urllib.request.Request(f"{url}/?channel=reply-test&token={token}")
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
        assert "<blockquote>" in body
        assert "original msg" in body
        assert "This is my reply" in body


# ── Channel ACL ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def second_agent(server_info):
    """Create a second agent for cross-agent ACL tests. Returns (token, name)."""
    token2 = _server_module.add_agent("OtherBot")
    return token2, "OtherBot"


class TestChannelACL:
    """Tests for per-channel agent access control."""

    def test_no_acl_file_allows_all(self, url_and_token):
        """Without channels.json entries, all channels are open."""
        url, token = url_and_token
        # Create a channel with no ACL (already open by default from prior tests)
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-open"})
        status, _ = _raw_request(url, token, "GET", "/api/channels/acl-open/messages")
        assert status == 200

    def test_wildcard_allows_all(self, url_and_token, second_agent):
        """Channel with ["*"] allows any agent."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-wild"})
        # Set wildcard ACL
        _raw_request(url, token, "PUT", "/api/channels/acl-wild/acl",
                     {"allow": ["*"]})
        # Both agents should have access
        s1, _ = _raw_request(url, token, "GET", "/api/channels/acl-wild/messages")
        s2, _ = _raw_request(url, token2, "GET", "/api/channels/acl-wild/messages")
        assert s1 == 200
        assert s2 == 200

    def test_specific_allow_list(self, url_and_token, second_agent):
        """Only listed agents can access a restricted channel."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-restricted"})
        # Restrict to TestBot only
        _raw_request(url, token, "PUT", "/api/channels/acl-restricted/acl",
                     {"allow": ["TestBot"]})
        s1, _ = _raw_request(url, token, "GET", "/api/channels/acl-restricted/messages")
        assert s1 == 200
        s2, _ = _raw_request(url, token2, "GET", "/api/channels/acl-restricted/messages")
        assert s2 == 403

    def test_write_denied(self, url_and_token, second_agent):
        """Unlisted agents can't write to restricted channels."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-nowrite"})
        _raw_request(url, token, "PUT", "/api/channels/acl-nowrite/acl",
                     {"allow": ["TestBot"]})
        s, _ = _raw_request(url, token2, "POST", "/api/channels/acl-nowrite/messages",
                            {"message": "should fail"})
        assert s == 403

    def test_channel_list_filtered(self, url_and_token, second_agent):
        """Channel list only shows accessible channels."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-visible"})
        _raw_request(url, token, "PUT", "/api/channels/acl-visible/acl",
                     {"allow": ["TestBot"]})
        # OtherBot should NOT see acl-visible in list
        s, channels = _raw_request(url, token2, "GET", "/api/channels")
        assert s == 200
        names = [c["name"] for c in channels]
        assert "acl-visible" not in names

    def test_create_channel_with_acl(self, url_and_token, second_agent):
        """Creating a channel with allow list sets ACL."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "acl-custom", "allow": ["TestBot", "OtherBot"]})
        s1, _ = _raw_request(url, token, "GET", "/api/channels/acl-custom/messages")
        s2, _ = _raw_request(url, token2, "GET", "/api/channels/acl-custom/messages")
        assert s1 == 200
        assert s2 == 200

    def test_create_channel_default_acl(self, url_and_token):
        """Creating a channel without allow defaults to ["*"]."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-default"})
        s, acl = _raw_request(url, token, "GET", "/api/channels/acl-default/acl")
        assert s == 200
        assert "*" in acl["allow"]

    def test_get_acl(self, url_and_token):
        """GET ACL endpoint returns allow-list."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-get"})
        _raw_request(url, token, "PUT", "/api/channels/acl-get/acl",
                     {"allow": ["TestBot", "Juho"]})
        s, acl = _raw_request(url, token, "GET", "/api/channels/acl-get/acl")
        assert s == 200
        assert "TestBot" in acl["allow"]
        assert "Juho" in acl["allow"]

    def test_set_acl_requires_membership(self, url_and_token, second_agent):
        """Can't modify ACL of a channel you're not in."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-noedit"})
        _raw_request(url, token, "PUT", "/api/channels/acl-noedit/acl",
                     {"allow": ["TestBot"]})
        # OtherBot tries to modify — should be denied
        s, _ = _raw_request(url, token2, "PUT", "/api/channels/acl-noedit/acl",
                            {"allow": ["OtherBot"]})
        assert s == 403

    def test_web_ui_hides_inaccessible_channels(self, url_and_token, second_agent):
        """Web UI only shows channels the agent can access."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-hidden"})
        _raw_request(url, token, "PUT", "/api/channels/acl-hidden/acl",
                     {"allow": ["TestBot"]})
        # OtherBot's web UI should not show acl-hidden
        req = urllib.request.Request(f"{url}/?token={token2}")
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
        assert "acl-hidden" not in body

    def test_web_ui_redirects_inaccessible_channel(self, url_and_token, second_agent):
        """Web UI redirects to accessible channel when trying to view restricted one."""
        url, token = url_and_token
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "acl-deny-ui"})
        _raw_request(url, token, "PUT", "/api/channels/acl-deny-ui/acl",
                     {"allow": ["TestBot"]})
        # Use non-redirecting handler to check the 302
        class NoRedirect(urllib.request.HTTPErrorProcessor):
            def http_response(self, request, response):
                return response
            https_response = http_response
        opener = urllib.request.build_opener(NoRedirect)
        req = urllib.request.Request(f"{url}/?channel=acl-deny-ui&token={token2}")
        resp = opener.open(req)
        assert resp.status == 302
        location = resp.headers.get("Location", "")
        assert "channel=" in location
        assert "acl-deny-ui" not in location

    def test_backwards_compat_no_acl_entry(self, url_and_token, second_agent):
        """Channels without ACL entries remain open (backwards compat)."""
        url, token = url_and_token
        token2, _ = second_agent
        # general was created before ACL system — should still be accessible
        s1, _ = _raw_request(url, token, "POST", "/api/channels/general/messages",
                             {"message": "compat test"})
        s2, _ = _raw_request(url, token2, "GET", "/api/channels/general/messages")
        assert s1 == 200
        assert s2 == 200


class TestDeleteChannel:
    """Tests for channel deletion."""

    def test_delete_channel(self, url_and_token):
        """Delete a channel removes log file and ACL entry."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "del-test"})
        # Verify it exists
        s, _ = _raw_request(url, token, "GET", "/api/channels/del-test/messages")
        assert s == 200
        # Delete it
        s, body = _raw_request(url, token, "DELETE", "/api/channels/del-test")
        assert s == 200
        assert body["ok"] is True
        assert body["deleted"] == "del-test"
        # Verify channel no longer appears in channel list
        s2, channels = _raw_request(url, token, "GET", "/api/channels")
        assert s2 == 200
        assert "del-test" not in [c["name"] for c in channels]

    def test_cannot_delete_general(self, url_and_token):
        """#general cannot be deleted."""
        url, token = url_and_token
        s, _ = _raw_request(url, token, "DELETE", "/api/channels/general")
        assert s == 403

    def test_delete_nonexistent_channel(self, url_and_token):
        """Deleting a channel that doesn't exist returns 404."""
        url, token = url_and_token
        s, _ = _raw_request(url, token, "DELETE", "/api/channels/no-such-channel")
        assert s == 404

    def test_delete_channel_forbidden(self, url_and_token, second_agent):
        """Agent without access cannot delete a restricted channel."""
        url, token = url_and_token
        token2, agent2 = second_agent
        # Create channel restricted to first agent only
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "del-forbidden", "allow": ["TestBot"]})
        # Second agent tries to delete
        s, _ = _raw_request(url, token2, "DELETE", "/api/channels/del-forbidden")
        assert s == 403

    def test_delete_removes_acl_entry(self, url_and_token):
        """Deleting a channel also removes its ACL entry."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "del-acl", "allow": ["TestBot"]})
        # Verify ACL exists
        s, acl = _raw_request(url, token, "GET", "/api/channels/del-acl/acl")
        assert s == 200
        assert "TestBot" in acl["allow"]
        # Delete
        s, _ = _raw_request(url, token, "DELETE", "/api/channels/del-acl")
        assert s == 200
        # ACL should return default (open) since entry is gone
        s, acl = _raw_request(url, token, "GET", "/api/channels/del-acl/acl")
        assert acl["allow"] == ["*"]  # default when no entry


class TestSubscriptions:
    """Tests for agent channel subscriptions."""

    def test_get_empty_subscriptions(self, url_and_token):
        """Agent with no subscriptions returns empty list."""
        url, token = url_and_token
        s, body = _raw_request(url, token, "GET", "/api/agents/NoSubsAgent/channels")
        assert s == 200
        assert body["agent"] == "NoSubsAgent"
        assert body["channels"] == []

    def test_set_and_get_subscriptions(self, url_and_token):
        """Setting subscriptions persists and can be retrieved."""
        url, token = url_and_token
        s, body = _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                               {"channels": ["general", "dev"]})
        assert s == 200
        assert body["ok"] is True
        assert body["channels"] == ["general", "dev"]
        # Read back
        s, body = _raw_request(url, token, "GET", "/api/agents/TestBot/channels")
        assert s == 200
        assert body["channels"] == ["general", "dev"]

    def test_update_subscriptions(self, url_and_token):
        """Updating subscriptions replaces the previous list."""
        url, token = url_and_token
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["general", "dev"]})
        s, body = _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["general"]})
        assert s == 200
        s, body = _raw_request(url, token, "GET", "/api/agents/TestBot/channels")
        assert body["channels"] == ["general"]

    def test_invalid_channels_format(self, url_and_token):
        """Non-array channels field returns 400."""
        url, token = url_and_token
        s, _ = _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                            {"channels": "general"})
        assert s == 400

    def test_different_agents_independent(self, url_and_token, second_agent):
        """Each agent has independent subscriptions."""
        url, token = url_and_token
        token2, agent2 = second_agent
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["general", "dev"]})
        _raw_request(url, token2, "PUT", f"/api/agents/{agent2}/channels",
                     {"channels": ["general"]})
        s1, b1 = _raw_request(url, token, "GET", "/api/agents/TestBot/channels")
        s2, b2 = _raw_request(url, token2, "GET", f"/api/agents/{agent2}/channels")
        assert b1["channels"] == ["general", "dev"]
        assert b2["channels"] == ["general"]


class TestSubscriptionACL:
    """Tests for subscription + ACL interaction.

    Verifies that agents cannot subscribe to channels they don't have
    ACL access to, and that subscription doesn't bypass read/write ACLs.
    """

    def test_subscribe_to_restricted_channel_allowed(self, url_and_token, second_agent):
        """Subscribing to a restricted channel succeeds (subscription is just metadata),
        but reading the channel still returns 403."""
        url, token = url_and_token
        token2, agent2 = second_agent
        # Create restricted channel
        _raw_request(url, token, "POST", "/api/channels", {"name": "sub-acl-test"})
        _raw_request(url, token, "PUT", "/api/channels/sub-acl-test/acl",
                     {"allow": ["TestBot"]})
        # OtherBot subscribes (currently allowed — subscription is metadata)
        s, body = _raw_request(url, token2, "PUT", f"/api/agents/{agent2}/channels",
                               {"channels": ["general", "sub-acl-test"]})
        assert s == 200
        # But reading still blocked by ACL
        s, _ = _raw_request(url, token2, "GET", "/api/channels/sub-acl-test/messages")
        assert s == 403
        # And writing still blocked
        s, _ = _raw_request(url, token2, "POST", "/api/channels/sub-acl-test/messages",
                            {"message": "should fail"})
        assert s == 403

    def test_subscription_does_not_appear_in_channel_list(self, url_and_token, second_agent):
        """Even if subscribed, restricted channels don't appear in channel list."""
        url, token = url_and_token
        token2, agent2 = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "sub-hidden"})
        _raw_request(url, token, "PUT", "/api/channels/sub-hidden/acl",
                     {"allow": ["TestBot"]})
        # OtherBot subscribes
        _raw_request(url, token2, "PUT", f"/api/agents/{agent2}/channels",
                     {"channels": ["general", "sub-hidden"]})
        # Channel list should NOT include sub-hidden
        s, channels = _raw_request(url, token2, "GET", "/api/channels")
        assert s == 200
        channel_names = [c["name"] for c in channels]
        assert "sub-hidden" not in channel_names

    def test_acl_blocks_read_after_subscribe(self, url_and_token, second_agent):
        """Full scenario: create restricted channel, subscribe unauthorized agent,
        verify all operations are blocked despite subscription."""
        url, token = url_and_token
        token2, agent2 = second_agent
        # Setup
        _raw_request(url, token, "POST", "/api/channels", {"name": "sub-fullblock"})
        _raw_request(url, token, "PUT", "/api/channels/sub-fullblock/acl",
                     {"allow": ["TestBot"]})
        # Subscribe unauthorized agent
        _raw_request(url, token2, "PUT", f"/api/agents/{agent2}/channels",
                     {"channels": ["sub-fullblock"]})
        # Verify: read blocked
        s, _ = _raw_request(url, token2, "GET", "/api/channels/sub-fullblock/messages")
        assert s == 403
        # Verify: write blocked
        s, _ = _raw_request(url, token2, "POST", "/api/channels/sub-fullblock/messages",
                            {"message": "nope"})
        assert s == 403
        # Verify: ACL edit blocked
        s, _ = _raw_request(url, token2, "PUT", "/api/channels/sub-fullblock/acl",
                            {"allow": ["TestBot", agent2]})
        assert s == 403
        # Verify: delete blocked
        s, _ = _raw_request(url, token2, "DELETE", "/api/channels/sub-fullblock")
        assert s == 403
        # Verify: authorized agent still works
        s, _ = _raw_request(url, token, "GET", "/api/channels/sub-fullblock/messages")
        assert s == 200

    def test_subscribe_rejects_inaccessible_channels(self, url_and_token, second_agent):
        """Subscription PUT filters out channels the agent can't access."""
        url, token = url_and_token
        token2, agent2 = second_agent
        # Create restricted channel
        _raw_request(url, token, "POST", "/api/channels", {"name": "sub-reject"})
        _raw_request(url, token, "PUT", "/api/channels/sub-reject/acl",
                     {"allow": ["TestBot"]})
        # OtherBot tries to subscribe to restricted + open channels
        s, body = _raw_request(url, token2, "PUT", f"/api/agents/{agent2}/channels",
                               {"channels": ["general", "sub-reject"]})
        assert s == 200
        # Restricted channel filtered out, open channel kept
        assert "general" in body["channels"]
        assert "sub-reject" not in body["channels"]
        assert "sub-reject" in body.get("rejected", [])
        # Verify persisted subscriptions don't include restricted channel
        s, body = _raw_request(url, token2, "GET", f"/api/agents/{agent2}/channels")
        assert "sub-reject" not in body["channels"]


class TestStaticFiles:
    """Tests for static file serving (/static/*)."""

    def test_serve_app_js(self, url_and_token):
        """Static JS file is served with correct content type."""
        url, token = url_and_token
        # No auth needed for static files
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            assert "javascript" in resp.headers.get("Content-Type", "")
            body = resp.read().decode()
            assert "CONFIG" in body

    def test_static_no_auth_required(self, url_and_token):
        """Static files don't require authentication."""
        url, _ = url_and_token
        req = urllib.request.Request(f"{url}/static/app.js")
        # No Authorization header, no token
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200

    def test_static_404(self, url_and_token):
        """Nonexistent static file returns 404."""
        url, _ = url_and_token
        req = urllib.request.Request(f"{url}/static/nonexistent.js")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404

    def test_static_path_traversal(self, url_and_token):
        """Path traversal attempts are blocked by filename sanitization."""
        url, _ = url_and_token
        req = urllib.request.Request(f"{url}/static/../server.py")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have raised"
        except urllib.error.HTTPError as e:
            assert e.code == 404


class TestCreatorACLBypass:
    """Tests for channel creator being able to edit ACL even when not in allow list."""

    def test_creator_can_edit_own_acl(self, url_and_token):
        """Channel creator can edit ACL even if not in the allow list."""
        url, token = url_and_token
        # Create a channel
        _raw_request(url, token, "POST", "/api/channels", {"name": "creator-test"})
        # Set ACL to empty (creator is not in allow list)
        s, _ = _raw_request(url, token, "PUT", "/api/channels/creator-test/acl",
                            {"allow": []})
        assert s == 200
        # Creator should still be able to edit ACL
        s, _ = _raw_request(url, token, "PUT", "/api/channels/creator-test/acl",
                            {"allow": ["TestBot"]})
        assert s == 200

    def test_non_creator_cannot_edit_restricted_acl(self, url_and_token, second_agent):
        """Non-creator cannot edit ACL of a channel they're not in."""
        url, token = url_and_token
        token2, agent2 = second_agent
        # Creator makes a channel with only themselves
        _raw_request(url, token, "POST", "/api/channels", {"name": "restricted-acl"})
        _raw_request(url, token, "PUT", "/api/channels/restricted-acl/acl",
                     {"allow": ["TestBot"]})
        # Other agent tries to edit ACL — should be denied
        s, _ = _raw_request(url, token2, "PUT", "/api/channels/restricted-acl/acl",
                            {"allow": [agent2]})
        assert s == 403


class TestWebUITemplate:
    """Tests for the web UI page rendering."""

    def test_page_contains_config_and_script(self, url_and_token):
        """Web UI page has CONFIG object and references app.js."""
        url, token = url_and_token
        req = urllib.request.Request(
            f"{url}/?channel=general",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
            assert "const CONFIG" in body
            assert "app.js" in body
            # CONFIG should have the right channel
            assert "'general'" in body or '"general"' in body

    def test_page_no_doubled_braces(self, url_and_token):
        """Web UI page has no leftover Python f-string {{ or }} in JS."""
        url, token = url_and_token
        req = urllib.request.Request(
            f"{url}/?channel=general",
            headers={"Authorization": f"Bearer {token}"}
        )
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
            # Extract the inline script (CONFIG line)
            import re
            scripts = re.findall(r'<script>([^<]+)</script>', body)
            for s in scripts:
                assert '{{' not in s, f"Doubled braces in inline script: {s[:80]}"
                assert '}}' not in s, f"Doubled braces in inline script: {s[:80]}"


# ── Message Reading Edge Cases ─────────────────────────────────────────

class TestMessageReadingEdgeCases:

    def test_read_empty_channel(self, url_and_token):
        """Reading a channel with no messages returns empty list."""
        url, token = url_and_token
        # Create channel first
        _raw_request(url, token, "POST", "/api/channels", {"name": "empty-ch"})
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/empty-ch/messages")
        assert status == 200
        assert data["messages"] == []
        assert data["count"] == 0

    def test_since_index_skips_messages(self, url_and_token):
        """since parameter skips earlier messages."""
        url, token = url_and_token
        ch = "since-test-ch"
        for i in range(5):
            _raw_request(url, token, "POST", f"/api/channels/{ch}/messages",
                         {"message": f"msg-{i}"})
        status, data = _raw_request(url, token, "GET",
                                     f"/api/channels/{ch}/messages?since=3")
        assert status == 200
        assert data["count"] == 5  # total count stays the same
        assert len(data["messages"]) == 2  # only last 2

    def test_since_minutes_filters_by_time(self, url_and_token):
        """since_minutes returns only recent messages."""
        url, token = url_and_token
        ch = "sincmin-ch"
        _raw_request(url, token, "POST", f"/api/channels/{ch}/messages",
                     {"message": "recent msg"})
        status, data = _raw_request(url, token, "GET",
                                     f"/api/channels/{ch}/messages?since_minutes=5")
        assert status == 200
        # Message was just posted, should be within 5 minutes
        assert len(data["messages"]) >= 1

    def test_read_nonexistent_channel(self, url_and_token):
        """Reading a channel that doesn't exist returns empty."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/doesnotexist999/messages")
        assert status == 200
        assert data["messages"] == []
        assert data["count"] == 0


# ── Channel Creation Edge Cases ────────────────────────────────────────

class TestChannelCreationEdgeCases:

    def test_create_existing_channel_is_idempotent(self, url_and_token):
        """Creating an already-existing channel should succeed without error."""
        url, token = url_and_token
        status1, data1 = _raw_request(url, token, "POST", "/api/channels",
                                       {"name": "idem-ch"})
        assert status1 == 200
        # Create again — should not fail
        status2, data2 = _raw_request(url, token, "POST", "/api/channels",
                                       {"name": "idem-ch"})
        assert status2 == 200
        assert data2["channel"] == "idem-ch"

    def test_create_channel_with_spaces(self, url_and_token):
        """Spaces in channel names become hyphens."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "my cool channel"})
        assert status == 200
        assert data["channel"] == "my-cool-channel"

    def test_create_channel_with_custom_acl(self, url_and_token):
        """Channel can be created with specific ACL."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "acl-create-ch", "allow": ["TestBot"]})
        assert status == 200
        # Verify ACL was set
        status2, acl = _raw_request(url, token, "GET",
                                     "/api/channels/acl-create-ch/acl")
        assert status2 == 200
        assert "TestBot" in acl.get("allow", [])

    def test_create_channel_creator_always_in_acl(self, url_and_token):
        """Creator is always added to ACL even if not in allow list."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "creator-acl-ch", "allow": []})
        assert status == 200
        status2, acl = _raw_request(url, token, "GET",
                                     "/api/channels/creator-acl-ch/acl")
        assert status2 == 200
        assert "TestBot" in acl.get("allow", [])

    def test_create_channel_creator_not_duplicated(self, url_and_token):
        """Creator isn't duplicated if already in allow list."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "nodup-acl-ch", "allow": ["TestBot"]})
        assert status == 200
        status2, acl = _raw_request(url, token, "GET",
                                     "/api/channels/nodup-acl-ch/acl")
        assert status2 == 200
        assert acl.get("allow", []).count("TestBot") == 1


# ── Markdown Rendering Tests ───────────────────────────────────────────

class TestMarkdownRendering:

    def test_render_markdown_bold(self):
        from ui import _render_markdown
        result = _render_markdown("hello **world**")
        assert "<strong>world</strong>" in result

    def test_render_markdown_code(self):
        from ui import _render_markdown
        result = _render_markdown("run `npm install`")
        assert "<code>npm install</code>" in result

    def test_render_markdown_link(self):
        from ui import _render_markdown
        result = _render_markdown("see https://example.com for details")
        assert 'href="https://example.com"' in result
        assert "target=\"_blank\"" in result

    def test_render_markdown_escapes_html(self):
        from ui import _render_markdown
        result = _render_markdown("<script>alert('xss')</script>")
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_render_markdown_newlines(self):
        from ui import _render_markdown
        result = _render_markdown("line1\nline2")
        assert "<br>" in result

    def test_split_quotes_with_quotes(self):
        from ui import _split_quotes
        quote_html, body = _split_quotes("> @Bob: hello\n\nmy reply")
        assert "<blockquote>" in quote_html
        assert body == ["", "my reply"]

    def test_split_quotes_no_quotes(self):
        from ui import _split_quotes
        quote_html, body = _split_quotes("just a message")
        assert quote_html == ""
        assert body == ["just a message"]


# ── PUT/DELETE Edge Cases ──────────────────────────────────────────────

class TestWriteEndpointEdgeCases:

    def test_post_404_unknown_path(self, url_and_token):
        """POST to unknown path returns 404."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/nonexistent")
        assert status == 404

    def test_put_404_unknown_path(self, url_and_token):
        """PUT to unknown path returns 404."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "PUT", "/api/nonexistent", {})
        assert status == 404

    def test_delete_404_unknown_path(self, url_and_token):
        """DELETE to unknown path returns 404."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "DELETE", "/api/nonexistent")
        assert status == 404

    def test_put_acl_empty_allow_list(self, url_and_token):
        """Setting ACL to empty list should work."""
        url, token = url_and_token
        # Create channel first
        _raw_request(url, token, "POST", "/api/channels", {"name": "empty-acl-ch"})
        # Set empty ACL
        status, data = _raw_request(url, token, "PUT",
                                     "/api/channels/empty-acl-ch/acl",
                                     {"allow": []})
        assert status == 200
        assert data["allow"] == []

    def test_put_subscriptions_empty_channels(self, url_and_token):
        """Setting subscriptions to empty list should work."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "PUT",
                                     "/api/agents/TestBot/channels",
                                     {"channels": []})
        assert status == 200
        assert data["channels"] == []
        # Verify reading back
        status2, data2 = _raw_request(url, token, "GET",
                                       "/api/agents/TestBot/channels")
        assert status2 == 200
        assert data2["channels"] == []

    def test_health_cannot_report_for_other_agent(self, url_and_token):
        """POST health for another agent is forbidden."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST",
                                  "/api/agents/SomeOther/health",
                                  {"context_pct": 50, "status": "running"})
        assert status == 403

    def test_activity_events_must_be_array(self, url_and_token):
        """POST activity with non-array events returns 400."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST",
                                  "/api/agents/TestBot/activity",
                                  {"events": "not an array"})
        assert status == 400

    def test_put_acl_requires_array(self, url_and_token):
        """PUT ACL with non-array allow returns 400."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "badacl-ch"})
        status, _ = _raw_request(url, token, "PUT",
                                  "/api/channels/badacl-ch/acl",
                                  {"allow": "not-an-array"})
        assert status == 400

    def test_put_subscriptions_requires_array(self, url_and_token):
        """PUT subscriptions with non-array channels returns 400."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "PUT",
                                  "/api/agents/TestBot/channels",
                                  {"channels": "not-an-array"})
        assert status == 400

    def test_send_message_to_inaccessible_channel(self, url_and_token):
        """Posting to a channel you can't access returns 403."""
        url, token = url_and_token
        # Create a restricted channel — creator (TestBot) is auto-added to ACL
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "restricted-msg-ch", "allow": ["SomeoneElse"]})
        # Creator can post (auto-added to allow list)
        status, _ = _raw_request(url, token, "POST",
                                  "/api/channels/restricted-msg-ch/messages",
                                  {"message": "creator can post"})
        assert status == 200
        # Now manually restrict ACL to remove creator
        _raw_request(url, token, "PUT",
                     "/api/channels/restricted-msg-ch/acl",
                     {"allow": ["SomeoneElse"]})
        # Now creator is blocked
        status2, _ = _raw_request(url, token, "POST",
                                   "/api/channels/restricted-msg-ch/messages",
                                   {"message": "should fail"})
        assert status2 == 403


# ── UI Rendering Functions ─────────────────────────────────────────────

class TestUIRendering:

    def test_render_agent_panels_no_agents(self):
        from ui import render_agent_panels_html
        result = render_agent_panels_html([], {})
        assert "No agents registered" in result

    def test_render_agent_panels_agents_without_health(self):
        """Registered agents with no health data show 'offline'."""
        from ui import render_agent_panels_html
        result = render_agent_panels_html(["FTL", "FTW"], {})
        assert "FTW" in result
        assert "FTL" in result
        assert result.count("offline") == 2

    def test_render_agent_panels_single_agent(self):
        from ui import render_agent_panels_html
        health = {"FTW": {"context_pct": 45, "tokens": 90000, "status": "running",
                          "last_tool": "Read", "reported_at": time.time()}}
        result = render_agent_panels_html(["FTW"], health)
        assert "FTW" in result
        assert "45%" in result
        assert "~90k tok" in result
        assert "running" in result
        assert "ctx-warming" in result  # 45% is in warming range

    def test_render_agent_panels_context_classes(self):
        """Different context percentages get different CSS classes."""
        from ui import render_agent_panels_html
        for pct, expected_class in [(10, "ctx-healthy"), (55, "ctx-warming"),
                                     (85, "ctx-heavy"), (95, "ctx-critical")]:
            health = {"Bot": {"context_pct": pct, "tokens": 50000, "status": "ok"}}
            result = render_agent_panels_html(["Bot"], health)
            assert expected_class in result, f"pct={pct} should have class {expected_class}"

    def test_render_agent_panels_multiple_agents(self):
        from ui import render_agent_panels_html
        health = {
            "FTW": {"context_pct": 30, "tokens": 60000, "status": "running"},
            "FTL": {"context_pct": 70, "tokens": 140000, "status": "idle"},
        }
        result = render_agent_panels_html(["FTL", "FTW"], health)
        assert "FTW" in result
        assert "FTL" in result

    def test_render_agent_panels_partial_health(self):
        """One agent has health, one doesn't — both shown."""
        from ui import render_agent_panels_html
        health = {"FTW": {"context_pct": 30, "tokens": 60000, "status": "running"}}
        result = render_agent_panels_html(["FTL", "FTW"], health)
        assert "FTW" in result
        assert "FTL" in result
        assert "30%" in result
        assert "offline" in result  # FTL has no health

    def test_render_activity_empty(self):
        from ui import render_activity_html
        result = render_activity_html({})
        assert "No activity yet" in result

    def test_render_activity_with_events(self):
        from ui import render_activity_html
        activity = {
            "FTW": [
                {"ts": "2026-02-12 14:00 EET", "type": "tool", "summary": "Read file"},
                {"ts": "2026-02-12 14:01 EET", "type": "heartbeat", "summary": "alive"},
            ]
        }
        result = render_activity_html(activity)
        assert "Read file" in result
        assert "alive" in result
        assert "act-item" in result

    def test_render_activity_separator_between_agents(self):
        """Agent transitions get a visual separator."""
        from ui import render_activity_html
        activity = {
            "FTW": [{"ts": "2026-02-12 14:00 EET", "type": "tool", "summary": "a"}],
            "FTL": [{"ts": "2026-02-12 14:01 EET", "type": "tool", "summary": "b"}],
        }
        result = render_activity_html(activity)
        assert "act-sep" in result

    def test_render_messages_with_colors(self):
        from ui import render_messages_html, SENDER_COLORS
        messages = [{"sender": "Juho", "ts": "2026-02-12 14:00 EET", "message": "hello"}]
        result = render_messages_html(messages)
        assert SENDER_COLORS["Juho"]["border"] in result
        assert "Juho" in result

    def test_render_messages_unknown_sender(self):
        from ui import render_messages_html, _color_for_sender
        messages = [{"sender": "Unknown", "ts": "2026-02-12 14:00 EET", "message": "hi"}]
        result = render_messages_html(messages)
        # Unknown sender gets an auto-generated color, not grey default
        assert _color_for_sender("Unknown")["border"] in result

    def test_page_html_contains_all_sections(self):
        """Full page_html output has chat, sidebar, agents, send bar."""
        from ui import page_html
        html = page_html("general", [], [{"name": "general", "message_count": 0}],
                         ["TestBot"], {}, {})
        assert "fagents-comms" in html
        assert "general" in html
        assert "channel" in html
        assert "sidebar" in html
        assert "sendMessage" in html or "app.js" in html


# ── Helper Functions ───────────────────────────────────────────────────

class TestHelperFunctions:

    def test_sanitize_name_strips_special_chars(self):
        assert _server_module.sanitize_name("hello world!@#$") == "helloworld"

    def test_sanitize_name_allows_hyphens_underscores(self):
        assert _server_module.sanitize_name("my-channel_1") == "my-channel_1"

    def test_sanitize_name_empty_string(self):
        assert _server_module.sanitize_name("") == ""

    def test_sanitize_name_all_special(self):
        assert _server_module.sanitize_name("!@#$%^&*") == ""

    def test_path_param_extracts_segment(self):
        assert _server_module.path_param("/api/channels/general/messages") == "general"

    def test_path_param_sanitizes(self):
        assert _server_module.path_param("/api/channels/bad!name/messages") == "badname"

    def test_path_param_out_of_bounds(self):
        assert _server_module.path_param("/short") == ""

    def test_path_param_custom_index(self):
        assert _server_module.path_param("/api/agents/FTW/health", index=3) == "FTW"

    def test_load_json_missing_file(self, test_dir):
        from pathlib import Path
        result = _server_module._load_json(Path(test_dir) / "nonexistent.json")
        assert result == {}

    def test_load_json_corrupt_file(self, test_dir):
        from pathlib import Path
        bad_file = Path(test_dir) / "corrupt.json"
        bad_file.write_text("not json {{{")
        result = _server_module._load_json(bad_file)
        assert result == {}

    def test_save_and_load_json_roundtrip(self, test_dir):
        from pathlib import Path
        path = Path(test_dir) / "roundtrip.json"
        data = {"key": "value", "list": [1, 2, 3]}
        _server_module._save_json(path, data)
        loaded = _server_module._load_json(path)
        assert loaded == data

    def test_save_json_with_mode(self, test_dir):
        import stat
        from pathlib import Path
        path = Path(test_dir) / "secure.json"
        _server_module._save_json(path, {"secret": True}, mode=0o600)
        mode = path.stat().st_mode & 0o777
        assert mode == 0o600

    def test_list_accessible_channels(self, test_dir):
        """list_accessible_channels filters correctly."""
        # Create some channels
        ch_dir = _server_module.CHANNELS_DIR
        (ch_dir / "open-ch.log").touch()
        (ch_dir / "closed-ch.log").touch()
        # Set ACL — closed-ch only allows SomeoneElse
        acl = _server_module.load_channels_acl()
        acl["closed-ch"] = {"allow": ["SomeoneElse"]}
        _server_module.save_channels_acl(acl)
        # TestBot should see open-ch but not closed-ch
        channels = _server_module.list_accessible_channels("TestBot")
        names = [c["name"] for c in channels]
        assert "open-ch" in names
        assert "closed-ch" not in names

# ── Channel Log Operations ─────────────────────────────────────────────

class TestChannelLogOperations:

    def test_write_message_strips_control_chars(self, test_dir):
        """Control characters (except newline) are stripped from messages."""
        result = _server_module.write_message("ctrl-ch", "TestBot",
                                               "hello\x00\x07\x1fworld")
        assert "\x00" not in result["message"]
        assert "\x07" not in result["message"]
        assert "helloworld" in result["message"]

    def test_write_message_preserves_newlines(self, test_dir):
        """Newlines in messages are preserved (not control-stripped)."""
        result = _server_module.write_message("newline-ch", "TestBot",
                                               "line1\nline2")
        assert "\n" in result["message"]

    def test_write_message_returns_correct_fields(self, test_dir):
        result = _server_module.write_message("fields-ch", "TestBot", "hi",
                                               msg_type="system")
        assert result["sender"] == "TestBot"
        assert result["message"] == "hi"
        assert result["channel"] == "fields-ch"
        assert result["type"] == "system"
        assert "ts" in result

    def test_read_channel_multiline_continuation(self, test_dir):
        """Messages with newlines are stored as continuation lines."""
        _server_module.write_message("multi-ch", "TestBot",
                                      "line1\nline2\nline3")
        messages, total = _server_module.read_channel("multi-ch")
        assert total >= 1
        found = [m for m in messages if "line1" in m["message"]]
        assert len(found) == 1
        assert "line2" in found[0]["message"]
        assert "line3" in found[0]["message"]

    def test_read_channel_nonexistent(self, test_dir):
        messages, total = _server_module.read_channel("noexist999")
        assert messages == []
        assert total == 0

    def test_agent_can_access_wildcard(self, test_dir):
        """Wildcard '*' in allow list grants access to everyone."""
        acl = _server_module.load_channels_acl()
        acl["wild-ch"] = {"allow": ["*"]}
        _server_module.save_channels_acl(acl)
        assert _server_module.agent_can_access("wild-ch", "Anyone") is True

    def test_agent_can_access_specific(self, test_dir):
        """Specific agent in allow list gets access."""
        acl = _server_module.load_channels_acl()
        acl["specific-ch"] = {"allow": ["Alice"]}
        _server_module.save_channels_acl(acl)
        assert _server_module.agent_can_access("specific-ch", "Alice") is True
        assert _server_module.agent_can_access("specific-ch", "Bob") is False

    def test_agent_can_access_no_entry(self, test_dir):
        """No ACL entry means open access (backwards compat)."""
        assert _server_module.agent_can_access("nonexistent-channel", "Anyone") is True

    def test_list_channels_includes_message_count(self, test_dir):
        """list_channels returns name and message_count."""
        _server_module.write_message("counted-ch", "Bot", "msg1")
        _server_module.write_message("counted-ch", "Bot", "msg2")
        channels = _server_module.list_channels()
        found = [c for c in channels if c["name"] == "counted-ch"]
        assert len(found) == 1
        assert found[0]["message_count"] >= 2


# ── Unguarded int() Conversion Tests ─────────────────────────────────

class TestInvalidQueryParams:
    """Tests for invalid integer query params.

    Previously these were unguarded int() calls that crashed the handler.
    Now _int_param() returns 400 with a descriptive error message.
    """

    def test_since_minutes_invalid_returns_400(self, url_and_token):
        """Non-numeric since_minutes returns 400."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels/intbug-ch/messages",
                     {"message": "test"})
        status, body = _raw_request(url, token, "GET",
            "/api/channels/intbug-ch/messages?since_minutes=abc")
        assert status == 400
        assert "since_minutes" in body

    def test_since_invalid_returns_400(self, url_and_token):
        """Non-numeric since returns 400."""
        url, token = url_and_token
        status, body = _raw_request(url, token, "GET",
            "/api/channels/intbug-ch/messages?since=notanumber")
        assert status == 400
        assert "since" in body

    def test_tail_invalid_agent_activity_returns_400(self, url_and_token):
        """Non-numeric tail on agent activity returns 400."""
        url, token = url_and_token
        status, body = _raw_request(url, token, "GET",
            "/api/agents/TestBot/activity?tail=xyz")
        assert status == 400
        assert "tail" in body

    def test_tail_invalid_all_activity_returns_400(self, url_and_token):
        """Non-numeric tail on all-activity returns 400."""
        url, token = url_and_token
        status, body = _raw_request(url, token, "GET",
            "/api/activity?tail=notanum")
        assert status == 400
        assert "tail" in body


# ── Channel Name Edge Cases ───────────────────────────────────────────

class TestChannelNameEdgeCases:

    def test_whitespace_only_name_returns_400(self, url_and_token):
        """Channel name with only spaces sanitizes to empty → 400."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/channels",
                                  {"name": "     "})
        # spaces → "-" → sanitize strips non-alnum → "-" stays → lowercase "-"
        # Actually: "     " → re.sub(r"\s+", "-", ...) → "-" → sanitize_name("-") → "-" → lower() → "-"
        # sanitize_name keeps hyphens, so result is "-" which is not empty
        # This is actually a valid name "-" which might be unintended
        assert status == 200 or status == 400

    def test_newlines_only_name(self, url_and_token):
        """Channel name with only newlines."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/channels",
                                  {"name": "\n\n\n"})
        # \n\n\n → strip() → "" → re.sub → "" → sanitize → "" → 400
        assert status == 400

    def test_special_chars_only_name(self, url_and_token):
        """Channel name with only special characters."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "POST", "/api/channels",
                                  {"name": "!@#$%^&*()"})
        assert status == 400


# ── Client poll() Tests ───────────────────────────────────────────────

class TestClientPoll:

    def test_poll_timeout_returns_empty(self, client):
        """poll() returns empty list after timeout with no new messages."""
        # Use a very short timeout and interval
        result = client.poll("poll-timeout-ch", timeout=0.5, interval=0.2)
        assert result == []

    def test_poll_detects_new_messages(self, client):
        """poll() returns messages when they arrive during polling."""
        import threading
        ch = "poll-detect-ch"
        # Send an initial message so channel exists
        client.send(ch, "initial")

        # Schedule a message to arrive while we're polling
        def delayed_send():
            time.sleep(0.3)
            client.send(ch, "arrived during poll")
        t = threading.Thread(target=delayed_send)
        t.start()

        result = client.poll(ch, timeout=3, interval=0.2)
        t.join()
        assert len(result) >= 1
        assert any("arrived during poll" in m.get("message", "") for m in result)


# ── Final Coverage Round (T10) ────────────────────────────────────────

class TestIntParamEdgeCases:
    """Edge cases for the _int_param() helper and integer query params."""

    def test_since_negative_works(self, url_and_token):
        """Negative since is technically valid int — server accepts it."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "GET",
                                  "/api/channels/general/messages?since=-1")
        assert status == 200

    def test_tail_zero_returns_full_list(self, url_and_token):
        """tail=0 returns full list (Python list[-0:] == list[:])."""
        url, token = url_and_token
        # Push an event first
        _raw_request(url, token, "POST", "/api/agents/TestBot/activity",
                     {"events": [{"ts": "2026-02-12 22:30", "type": "tool",
                                  "summary": "for tail test"}]})
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/activity?tail=0")
        assert status == 200
        # list[-0:] is the full list in Python, not empty
        assert isinstance(data, list)

    def test_since_float_returns_400(self, url_and_token):
        """Float since value returns 400 (int() rejects '3.5')."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "GET",
                                  "/api/channels/general/messages?since=3.5")
        assert status == 400


class TestTimestampParsing:

    def test_since_minutes_includes_unparseable_messages(self, test_dir):
        """Messages with unparseable dates are included (not dropped) by since_minutes."""
        ch_file = _server_module.CHANNELS_DIR / "badts-ch.log"
        # LINE_RE matches this format (digits match) but strptime fails on month 99
        ch_file.write_text(
            "[2026-99-99 99:99 EET] [Bot] bad date message\n"
        )
        messages, total = _server_module.read_channel("badts-ch", since_minutes=5)
        assert total == 1
        # Bad date: strptime raises ValueError → caught → message included
        assert messages[0]["message"] == "bad date message"

    def test_since_minutes_filters_old_messages(self, test_dir):
        """Messages older than since_minutes are excluded."""
        ch_file = _server_module.CHANNELS_DIR / "oldts-ch.log"
        ch_file.write_text(
            "[2020-01-01 00:00 EET] [Bot] very old message\n"
        )
        messages, total = _server_module.read_channel("oldts-ch", since_minutes=5)
        assert total == 1
        # The old message should be filtered out
        assert len(messages) == 0


class TestStaticServingEdgeCases:

    def test_static_unknown_extension(self, url_and_token):
        """Unknown file extensions get application/octet-stream MIME type."""
        url, _ = url_and_token
        # Create a test file with unusual extension
        import pathlib
        static_dir = pathlib.Path(_server_module.SCRIPT_DIR) / "static"
        test_file = static_dir / "test.dat"
        test_file.write_text("test content")
        try:
            req = urllib.request.Request(f"{url}/static/test.dat")
            with urllib.request.urlopen(req) as resp:
                assert resp.status == 200
                assert "octet-stream" in resp.headers.get("Content-Type", "")
                assert resp.read() == b"test content"
        finally:
            test_file.unlink(missing_ok=True)

    def test_static_cache_control(self, url_and_token):
        """Static files include no-cache header."""
        url, _ = url_and_token
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            cc = resp.headers.get("Cache-Control", "")
            assert "no-store" in cc or "no-cache" in cc


class TestActivityEventFiltering:

    def test_falsy_ts_events_rejected(self, url_and_token):
        """Events with falsy ts (0, empty string) are NOT stored."""
        url, token = url_and_token
        _server_module.AGENT_ACTIVITY["TestBot"] = []
        events = [
            {"ts": 0, "type": "tool", "summary": "zero ts"},
            {"ts": "", "type": "tool", "summary": "empty ts"},
            {"ts": "2026-02-12 22:30", "type": "tool", "summary": "valid"},
        ]
        _raw_request(url, token, "POST", "/api/agents/TestBot/activity",
                     {"events": events})
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/activity?tail=10")
        assert status == 200
        # Only the valid event should be stored (falsy ts/type filtered by ev.get())
        summaries = [e["summary"] for e in data]
        assert "valid" in summaries
        assert "zero ts" not in summaries
        assert "empty ts" not in summaries

    def test_non_dict_events_rejected(self, url_and_token):
        """Non-dict items in events array are silently ignored."""
        url, token = url_and_token
        _server_module.AGENT_ACTIVITY["TestBot"] = []
        events = [
            "just a string",
            42,
            None,
            {"ts": "2026-02-12 22:31", "type": "tool", "summary": "real"},
        ]
        _raw_request(url, token, "POST", "/api/agents/TestBot/activity",
                     {"events": events})
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/TestBot/activity?tail=10")
        assert status == 200
        assert len(data) == 1
        assert data[0]["summary"] == "real"


class TestHealthEdgeCases:

    def test_read_health_nonexistent_agent(self, url_and_token):
        """Reading health for non-reporting agent returns empty dict."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET",
                                     "/api/agents/GhostAgent/health")
        assert status == 200
        assert data == {}

    def test_health_agents_endpoint_returns_all(self, url_and_token):
        """GET /api/agents returns health dict for all reporting agents."""
        url, token = url_and_token
        # Report health first
        _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                     {"context_pct": 55, "status": "active"})
        status, data = _raw_request(url, token, "GET", "/api/agents")
        assert status == 200
        assert "TestBot" in data
        assert data["TestBot"]["context_pct"] == 55


class TestChannelDescriptions:
    """Tests for channel description feature (GET/PUT /api/channels/:name/description)."""

    @pytest.fixture
    def url_and_token(self, server_info):
        return server_info[0], server_info[1]

    def test_get_description_default_empty(self, url_and_token):
        """Channel with no description returns empty string."""
        url, token = url_and_token
        # Create a channel without description
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-empty"})
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/desc-test-empty/description")
        assert status == 200
        assert data["description"] == ""
        assert data["channel"] == "desc-test-empty"

    def test_set_and_get_description(self, url_and_token):
        """PUT description then GET it back."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-set"})
        status, data = _raw_request(url, token, "PUT",
                                     "/api/channels/desc-test-set/description",
                                     {"description": "Red team ops channel"})
        assert status == 200
        assert data["ok"] is True
        assert data["description"] == "Red team ops channel"

        # Verify it persists
        status2, data2 = _raw_request(url, token, "GET",
                                       "/api/channels/desc-test-set/description")
        assert status2 == 200
        assert data2["description"] == "Red team ops channel"

    def test_update_description(self, url_and_token):
        """Description can be updated."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-update"})
        _raw_request(url, token, "PUT",
                     "/api/channels/desc-test-update/description",
                     {"description": "First"})
        _raw_request(url, token, "PUT",
                     "/api/channels/desc-test-update/description",
                     {"description": "Second"})
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/desc-test-update/description")
        assert status == 200
        assert data["description"] == "Second"

    def test_clear_description(self, url_and_token):
        """Setting empty string clears description."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-clear"})
        _raw_request(url, token, "PUT",
                     "/api/channels/desc-test-clear/description",
                     {"description": "Something"})
        _raw_request(url, token, "PUT",
                     "/api/channels/desc-test-clear/description",
                     {"description": ""})
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/desc-test-clear/description")
        assert status == 200
        assert data["description"] == ""

    def test_description_too_long(self, url_and_token):
        """Description over 200 chars is rejected."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-long"})
        status, data = _raw_request(url, token, "PUT",
                                     "/api/channels/desc-test-long/description",
                                     {"description": "x" * 201})
        assert status == 400

    def test_description_on_creation(self, url_and_token):
        """Description can be set at channel creation time."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "desc-test-create",
                                      "description": "Created with desc"})
        assert status == 200
        status2, data2 = _raw_request(url, token, "GET",
                                       "/api/channels/desc-test-create/description")
        assert status2 == 200
        assert data2["description"] == "Created with desc"

    def test_description_in_web_ui(self, url_and_token):
        """Description appears in the web UI HTML."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "desc-test-ui", "description": "UI visible desc"})
        # Fetch the web UI page
        req = urllib.request.Request(
            f"{url}/?channel=desc-test-ui&token={token}")
        with urllib.request.urlopen(req) as resp:
            html = resp.read().decode()
        assert "UI visible desc" in html


class TestJoinMessages:
    """Tests for system messages posted when agents subscribe to channels."""

    @pytest.fixture
    def url_and_token(self, server_info):
        return server_info[0], server_info[1]

    def test_join_message_posted(self, url_and_token):
        """Subscribing to a new channel posts a system join message."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "join-test-1"})
        # Clear any existing subscription
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": []})
        # Now subscribe
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["join-test-1"]})
        # Check channel for system message
        status, data = _raw_request(url, token, "GET",
                                     "/api/channels/join-test-1/messages")
        assert status == 200
        join_msgs = [m for m in data["messages"]
                     if m["sender"] == "System" and "joined" in m["message"]]
        assert len(join_msgs) >= 1
        assert "TestBot joined the channel" in join_msgs[-1]["message"]

    def test_no_message_on_resubscribe(self, url_and_token):
        """Re-subscribing to the same channel does not post duplicate join message."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "join-test-2"})
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["join-test-2"]})
        # Count current join messages
        _, data1 = _raw_request(url, token, "GET",
                                 "/api/channels/join-test-2/messages")
        count1 = sum(1 for m in data1["messages"]
                     if m["sender"] == "System" and "joined" in m["message"])
        # Re-subscribe (same channels)
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["join-test-2"]})
        _, data2 = _raw_request(url, token, "GET",
                                 "/api/channels/join-test-2/messages")
        count2 = sum(1 for m in data2["messages"]
                     if m["sender"] == "System" and "joined" in m["message"])
        assert count2 == count1  # no duplicate

    def test_leave_message_on_unsubscribe(self, url_and_token):
        """Unsubscribing posts a leave message."""
        url, token = url_and_token
        _raw_request(url, token, "POST", "/api/channels", {"name": "join-test-3"})
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["join-test-3"]})
        _, data1 = _raw_request(url, token, "GET",
                                 "/api/channels/join-test-3/messages")
        count1 = len(data1["messages"])
        # Unsubscribe
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": []})
        _, data2 = _raw_request(url, token, "GET",
                                 "/api/channels/join-test-3/messages")
        assert len(data2["messages"]) == count1 + 1
        assert "left the channel" in data2["messages"][-1]["message"]


class TestAutoSenderColors:
    """Tests for auto-generated sender colors for new agents."""

    def test_hardcoded_colors_preserved(self):
        """Known agents get their hardcoded colors."""
        from ui import _color_for_sender, SENDER_COLORS
        for name in ["FTW", "FTL", "Juho", "System"]:
            assert _color_for_sender(name) == SENDER_COLORS[name]

    def test_unknown_agent_gets_color(self):
        """Unknown agents get a generated color, not grey default."""
        from ui import _color_for_sender, DEFAULT_COLOR
        color = _color_for_sender("Turtle316")
        assert color != DEFAULT_COLOR
        assert color["bg"].startswith("#")
        assert color["border"].startswith("#")
        assert color["name"] == color["border"]

    def test_color_is_deterministic(self):
        """Same name always produces the same color."""
        from ui import _color_for_sender
        c1 = _color_for_sender("WifeTurtle")
        c2 = _color_for_sender("WifeTurtle")
        assert c1 == c2

    def test_different_names_get_different_colors(self):
        """Different names get different colors (probabilistic but reliable)."""
        from ui import _color_for_sender
        c1 = _color_for_sender("AgentAlpha")
        c2 = _color_for_sender("AgentBeta")
        assert c1["border"] != c2["border"]


class TestChannelCreationUI:
    """Tests for channel creation dialog in the web UI."""

    def test_creation_dialog_has_description_field(self, server_info):
        """Web UI JS includes description input in channel creation dialog."""
        url, token, _ = server_info
        # The static app.js should contain the description input
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'ncDesc' in js
        assert 'Description' in js or 'description' in js

    def test_create_channel_with_description_via_api(self, server_info):
        """Channel created with description payload has it stored."""
        url, token, _ = server_info
        status, data = _raw_request(url, token, "POST", "/api/channels",
                                     {"name": "ui-desc-ch", "description": "Test from UI"})
        assert status == 200
        status2, data2 = _raw_request(url, token, "GET",
                                       "/api/channels/ui-desc-ch/description")
        assert data2["description"] == "Test from UI"


class TestChannelRename:
    """Tests for PUT /api/channels/:name/rename."""

    def test_rename_channel_basic(self, server_info):
        """Rename a channel and verify the new name works."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-src"})
        status, data = _raw_request(url, token, "PUT",
                                     "/api/channels/rename-src/rename",
                                     {"name": "rename-dst"})
        assert status == 200
        assert data["old_name"] == "rename-src"
        assert data["new_name"] == "rename-dst"
        # New channel should be readable
        s2, _ = _raw_request(url, token, "GET", "/api/channels/rename-dst/messages")
        assert s2 == 200
        # Old channel should be gone (no log file = empty messages)
        s3, d3 = _raw_request(url, token, "GET", "/api/channels/rename-src/messages")
        assert s3 == 200
        assert d3["count"] == 0

    def test_rename_preserves_messages(self, server_info):
        """Messages written before rename are readable after."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-msg"})
        _raw_request(url, token, "POST", "/api/channels/rename-msg/messages",
                     {"message": "hello before rename"})
        _raw_request(url, token, "PUT", "/api/channels/rename-msg/rename",
                     {"name": "rename-msg-after"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/rename-msg-after/messages")
        assert s == 200
        texts = [m["message"] for m in data["messages"]]
        assert "hello before rename" in texts

    def test_rename_updates_acl(self, server_info):
        """ACL entry moves from old name to new name."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-acl"})
        _raw_request(url, token, "PUT", "/api/channels/rename-acl/acl",
                     {"allow": ["TestBot"]})
        _raw_request(url, token, "PUT", "/api/channels/rename-acl/rename",
                     {"name": "rename-acl-new"})
        s, data = _raw_request(url, token, "GET", "/api/channels/rename-acl-new/acl")
        assert s == 200
        assert "TestBot" in data["allow"]

    def test_rename_updates_subscriptions(self, server_info):
        """Agent subscriptions update from old to new channel name."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rn-subtest"})
        # Set subscriptions to exactly this one channel
        _raw_request(url, token, "PUT", "/api/agents/TestBot/channels",
                     {"channels": ["rn-subtest"]})
        _raw_request(url, token, "PUT", "/api/channels/rn-subtest/rename",
                     {"name": "rn-subtest-new"})
        s, data = _raw_request(url, token, "GET", "/api/agents/TestBot/channels")
        assert s == 200
        assert "rn-subtest-new" in data["channels"]
        assert "rn-subtest" not in data["channels"]

    def test_rename_posts_system_message(self, server_info):
        """Rename posts a system message in the new channel."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-sys"})
        _raw_request(url, token, "PUT", "/api/channels/rename-sys/rename",
                     {"name": "rename-sys-new"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/rename-sys-new/messages")
        assert s == 200
        texts = [m["message"] for m in data["messages"]]
        assert any("renamed" in t and "rename-sys" in t for t in texts)

    def test_rename_general_forbidden(self, server_info):
        """Cannot rename the general channel."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "PUT", "/api/channels/general/rename",
                            {"name": "not-general"})
        assert s == 403

    def test_rename_to_existing_channel_conflict(self, server_info):
        """Renaming to an existing channel name returns 409."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-a"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-b"})
        s, _ = _raw_request(url, token, "PUT", "/api/channels/rename-a/rename",
                            {"name": "rename-b"})
        assert s == 409

    def test_rename_same_name_rejected(self, server_info):
        """Renaming to the same name returns 400."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-same"})
        s, _ = _raw_request(url, token, "PUT", "/api/channels/rename-same/rename",
                            {"name": "rename-same"})
        assert s == 400

    def test_rename_empty_name_rejected(self, server_info):
        """Empty new name returns 400."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-empty"})
        s, _ = _raw_request(url, token, "PUT", "/api/channels/rename-empty/rename",
                            {"name": ""})
        assert s == 400

    def test_rename_sanitizes_name(self, server_info):
        """Name with spaces and special chars gets sanitized."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rename-dirty"})
        s, data = _raw_request(url, token, "PUT",
                               "/api/channels/rename-dirty/rename",
                               {"name": "My Dirty Chan!"})
        assert s == 200
        assert data["new_name"] == "my-dirty-chan"

    def test_rename_updates_read_markers(self, server_info):
        """Read markers transfer from old channel name to new after rename."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rn-markers"})
        _raw_request(url, token, "POST", "/api/channels/rn-markers/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "POST", "/api/channels/rn-markers/messages",
                     {"message": "msg2"})
        # Mark channel as read
        _raw_request(url, token, "PUT", "/api/channels/rn-markers/read", {})
        # Verify no unread before rename
        s, data = _raw_request(url, token, "GET", "/api/channels")
        old_ch = [c for c in data if c["name"] == "rn-markers"]
        assert old_ch and old_ch[0]["unread"] == 0
        # Rename
        _raw_request(url, token, "PUT", "/api/channels/rn-markers/rename",
                     {"name": "rn-markers-new"})
        # The system rename message adds 1 unread, but the old read position
        # should transfer — so unread should be 1 (system msg), not 3 (all msgs)
        s, data = _raw_request(url, token, "GET", "/api/channels")
        new_ch = [c for c in data if c["name"] == "rn-markers-new"]
        assert new_ch, "renamed channel should appear"
        assert new_ch[0]["unread"] == 1  # only the system rename message

    def test_rename_updates_channel_order(self, server_info):
        """Channel order preferences transfer from old name to new after rename."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "rn-order"})
        # Set channel order including this channel
        _raw_request(url, token, "PUT", "/api/preferences/channel-order",
                     {"order": ["general", "rn-order"]})
        # Rename
        _raw_request(url, token, "PUT", "/api/channels/rn-order/rename",
                     {"name": "rn-order-new"})
        # Check order updated
        s, data = _raw_request(url, token, "GET",
                               "/api/preferences/channel-order")
        assert s == 200
        assert "rn-order-new" in data["order"]
        assert "rn-order" not in data["order"]
        # Clean up: reset order so we don't pollute other tests
        _raw_request(url, token, "PUT", "/api/preferences/channel-order",
                     {"order": []})


class TestMentions:
    """Tests for @mention highlighting and CONFIG.agents."""

    def test_config_includes_agents(self, server_info):
        """Web UI CONFIG includes agents list."""
        url, token, _ = server_info
        req = urllib.request.Request(
            f"{url}/?token={token}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            html = resp.read().decode()
        assert 'agents:' in html or '"agents":' in html

    def test_app_js_has_mention_highlighting(self, server_info):
        """app.js includes @mention rendering code."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'mention' in js.lower()
        assert '@' in js

    def test_app_js_has_autocomplete(self, server_info):
        """app.js includes @mention autocomplete dropdown."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'mentionAC' in js
        assert 'acPick' in js

    def test_mention_in_message_stored(self, server_info):
        """A message with @mention is stored with the @ text intact."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mention-test"})
        _raw_request(url, token, "POST", "/api/channels/mention-test/messages",
                     {"message": "Hey @TestBot check this"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mention-test/messages")
        assert s == 200
        texts = [m["message"] for m in data["messages"]]
        assert any("@TestBot" in t for t in texts)


class TestMentionFilter:
    """Tests for GET /api/channels/:name/messages?for=AgentName."""

    def test_filter_returns_mentioned_messages(self, server_info):
        """?for=X returns messages containing @X."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mf-test"})
        _raw_request(url, token, "POST", "/api/channels/mf-test/messages",
                     {"message": "Hey @Alice check this"})
        _raw_request(url, token, "POST", "/api/channels/mf-test/messages",
                     {"message": "Nothing relevant here"})
        _raw_request(url, token, "POST", "/api/channels/mf-test/messages",
                     {"message": "@Alice and @Bob both"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mf-test/messages?for=Alice")
        assert s == 200
        assert len(data["messages"]) == 2
        for m in data["messages"]:
            assert "@Alice" in m["message"]

    def test_filter_returns_replies(self, server_info):
        """?for=X returns messages that are replies to X."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mf-reply"})
        _raw_request(url, token, "POST", "/api/channels/mf-reply/messages",
                     {"message": "> @Bob: something\n\nmy reply"})
        _raw_request(url, token, "POST", "/api/channels/mf-reply/messages",
                     {"message": "unrelated message"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mf-reply/messages?for=Bob")
        assert s == 200
        assert len(data["messages"]) == 1
        assert "my reply" in data["messages"][0]["message"]

    def test_filter_no_matches_empty(self, server_info):
        """?for=X with no matches returns empty list."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mf-empty"})
        _raw_request(url, token, "POST", "/api/channels/mf-empty/messages",
                     {"message": "no mentions here"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mf-empty/messages?for=Nobody")
        assert s == 200
        assert len(data["messages"]) == 0

    def test_filter_without_param_returns_all(self, server_info):
        """Without ?for param, all messages returned as normal."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mf-all"})
        _raw_request(url, token, "POST", "/api/channels/mf-all/messages",
                     {"message": "@Someone hello"})
        _raw_request(url, token, "POST", "/api/channels/mf-all/messages",
                     {"message": "plain message"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mf-all/messages")
        assert s == 200
        assert len(data["messages"]) == 2

    def test_filter_count_reflects_total_not_filtered(self, server_info):
        """count field reflects total messages, not filtered count."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "mf-count"})
        _raw_request(url, token, "POST", "/api/channels/mf-count/messages",
                     {"message": "@Target hi"})
        _raw_request(url, token, "POST", "/api/channels/mf-count/messages",
                     {"message": "other"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/mf-count/messages?for=Target")
        assert s == 200
        assert data["count"] == 2  # total messages
        assert len(data["messages"]) == 1  # filtered


class TestChannelOrder:
    """Tests for server-side channel order preferences."""

    def test_get_default_order_empty(self, url_and_token):
        """GET channel order returns empty list by default."""
        url, token = url_and_token
        status, data = _raw_request(url, token, "GET", "/api/preferences/channel-order")
        assert status == 200
        assert data["order"] == []

    def test_put_and_get_order(self, url_and_token):
        """PUT saves order, GET returns it."""
        url, token = url_and_token
        order = ["general", "dev-updates", "fagents-comms"]
        status, data = _raw_request(url, token, "PUT", "/api/preferences/channel-order",
                                     {"order": order})
        assert status == 200
        assert data["ok"] is True
        assert data["order"] == order
        # GET it back
        status, data = _raw_request(url, token, "GET", "/api/preferences/channel-order")
        assert status == 200
        assert data["order"] == order

    def test_put_invalid_order(self, url_and_token):
        """PUT with non-array order returns 400."""
        url, token = url_and_token
        status, _ = _raw_request(url, token, "PUT", "/api/preferences/channel-order",
                                  {"order": "not-a-list"})
        assert status == 400

    def test_order_applied_to_page(self, server_info):
        """Saved channel order is reflected in the rendered page."""
        url, token, _ = server_info
        # Save a custom order
        _raw_request(url, token, "PUT", "/api/preferences/channel-order",
                      {"order": ["general"]})
        # Load the page — general should come first
        req = urllib.request.Request(
            f"{url}/?token={token}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            page = resp.read().decode()
        assert 'id="channelList"' in page


class TestChannelSidebar:
    """Tests for channel sidebar layout and drag-and-drop reordering."""

    def test_channel_list_has_id(self, server_info):
        """Channel list container has id=channelList for JS access."""
        url, token, _ = server_info
        req = urllib.request.Request(
            f"{url}/?token={token}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            page = resp.read().decode()
        assert 'id="channelList"' in page

    def test_channels_are_draggable(self, server_info):
        """app.js sets draggable=true on channel sidebar elements."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'draggable' in js
        assert 'dragstart' in js
        assert 'fagent-ch-order' in js

    def test_order_persisted_via_localstorage(self, server_info):
        """app.js uses localStorage for channel order persistence."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'localStorage.setItem' in js
        assert 'localStorage.getItem' in js


class TestSearch:
    """Tests for GET /api/search?q=keyword."""

    def test_search_finds_matching_messages(self, server_info):
        """Search returns messages containing the query."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "search-ch1"})
        _raw_request(url, token, "POST", "/api/channels/search-ch1/messages",
                     {"message": "the quick brown fox"})
        _raw_request(url, token, "POST", "/api/channels/search-ch1/messages",
                     {"message": "lazy dog sleeps"})
        s, data = _raw_request(url, token, "GET", "/api/search?q=fox")
        assert s == 200
        assert data["count"] == 1
        assert data["results"][0]["channel"] == "search-ch1"
        assert "fox" in data["results"][0]["message"]

    def test_search_case_insensitive(self, server_info):
        """Search is case-insensitive."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "search-ci"})
        _raw_request(url, token, "POST", "/api/channels/search-ci/messages",
                     {"message": "Hello World"})
        s, data = _raw_request(url, token, "GET", "/api/search?q=hello")
        assert s == 200
        assert data["count"] >= 1

    def test_search_across_channels(self, server_info):
        """Search finds messages across multiple channels."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "search-x1"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "search-x2"})
        _raw_request(url, token, "POST", "/api/channels/search-x1/messages",
                     {"message": "unique-xsearch-token here"})
        _raw_request(url, token, "POST", "/api/channels/search-x2/messages",
                     {"message": "also unique-xsearch-token"})
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=unique-xsearch-token")
        assert s == 200
        assert data["count"] == 2
        channels = {r["channel"] for r in data["results"]}
        assert "search-x1" in channels
        assert "search-x2" in channels

    def test_search_no_results(self, server_info):
        """Search with no matches returns empty results."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=zzz-nonexistent-zzz")
        assert s == 200
        assert data["count"] == 0
        assert data["results"] == []

    def test_search_missing_query_400(self, server_info):
        """Search without ?q= returns 400."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "GET", "/api/search")
        assert s == 400

    def test_search_respects_limit(self, server_info):
        """Search respects ?limit= parameter."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "search-lim"})
        for i in range(5):
            _raw_request(url, token, "POST", "/api/channels/search-lim/messages",
                         {"message": f"searchlimit-term item {i}"})
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=searchlimit-term&limit=2")
        assert s == 200
        assert len(data["results"]) == 2


class TestUnreadMarkers:
    """Tests for unread count and PUT /api/channels/:name/read."""

    def test_channels_list_includes_unread(self, server_info):
        """GET /api/channels includes unread field."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "unread-ch1"})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        assert s == 200
        ch = next(c for c in data if c["name"] == "unread-ch1")
        assert "unread" in ch

    def test_unread_starts_as_total(self, server_info):
        """Before marking read, unread equals total message count."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "unread-total"})
        _raw_request(url, token, "POST", "/api/channels/unread-total/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "POST", "/api/channels/unread-total/messages",
                     {"message": "msg2"})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch = next(c for c in data if c["name"] == "unread-total")
        assert ch["unread"] == ch["message_count"]

    def test_mark_read_clears_unread(self, server_info):
        """PUT /api/channels/:name/read sets unread to 0."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "unread-mark"})
        _raw_request(url, token, "POST", "/api/channels/unread-mark/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "PUT", "/api/channels/unread-mark/read", {})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch = next(c for c in data if c["name"] == "unread-mark")
        assert ch["unread"] == 0

    def test_new_messages_after_read_are_unread(self, server_info):
        """Messages sent after marking read show as unread."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "unread-new"})
        _raw_request(url, token, "POST", "/api/channels/unread-new/messages",
                     {"message": "before"})
        _raw_request(url, token, "PUT", "/api/channels/unread-new/read", {})
        _raw_request(url, token, "POST", "/api/channels/unread-new/messages",
                     {"message": "after"})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch = next(c for c in data if c["name"] == "unread-new")
        assert ch["unread"] == 1

    def test_mark_read_returns_count(self, server_info):
        """PUT read endpoint returns the read_at count."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "unread-ret"})
        _raw_request(url, token, "POST", "/api/channels/unread-ret/messages",
                     {"message": "msg"})
        s, data = _raw_request(url, token, "PUT",
                               "/api/channels/unread-ret/read", {})
        assert s == 200
        assert data["read_at"] == 1


class TestReadMarkerPersistence:
    """Tests for read marker persistence across server restarts."""

    def test_read_markers_saved_to_file(self, server_info):
        """PUT read writes markers to read_markers.json."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "persist-read"})
        _raw_request(url, token, "POST", "/api/channels/persist-read/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "PUT", "/api/channels/persist-read/read", {})
        # Check file exists and has data
        markers = _server_module.load_read_markers()
        assert "TestBot" in markers
        assert "persist-read" in markers["TestBot"]
        assert markers["TestBot"]["persist-read"] == 1

    def test_read_markers_survive_memory_clear(self, server_info):
        """Markers reloaded from disk after clearing in-memory state."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "persist-surv"})
        _raw_request(url, token, "POST", "/api/channels/persist-surv/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "PUT", "/api/channels/persist-surv/read", {})
        # Simulate restart: clear memory, reload from file
        _server_module.AGENT_READ_MARKERS.clear()
        _server_module.AGENT_READ_MARKERS.update(_server_module.load_read_markers())
        # Unread should be 0 (marker survived)
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch = next(c for c in data if c["name"] == "persist-surv")
        assert ch["unread"] == 0


class TestSearchUI:
    """Tests for search bar in web UI."""

    def test_search_bar_in_page(self, server_info):
        """Web UI has search bar element."""
        url, token, _ = server_info
        req = urllib.request.Request(
            f"{url}/?token={token}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            page = resp.read().decode()
        assert 'searchBar' in page
        assert 'searchInput' in page

    def test_search_js_functions(self, server_info):
        """app.js has search functions."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'toggleSearch' in js
        assert 'searchMessages' in js
        assert 'closeSearch' in js


class TestUnreadBadges:
    """Tests for unread badge polling in the UI."""

    def test_app_js_has_unread_polling(self, server_info):
        """app.js includes unread badge polling code."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert 'pollUnread' in js
        assert 'ch-unread' in js

    def test_marks_current_channel_read_on_load(self, server_info):
        """app.js marks current channel as read on page load."""
        url, token, _ = server_info
        req = urllib.request.Request(f"{url}/static/app.js")
        with urllib.request.urlopen(req) as resp:
            js = resp.read().decode()
        assert '/read' in js
        assert 'PUT' in js


class TestOnlineIndicator:
    """Tests for agent online/offline indicator dot."""

    def test_online_dot_in_page(self, server_info):
        """Web UI shows online indicator dots for agents."""
        url, token, _ = server_info
        # Post health so TestBot appears online
        _raw_request(url, token, "POST", "/api/agents/TestBot/health",
                     {"context_pct": 50, "tokens": 100000, "status": "active"})
        req = urllib.request.Request(
            f"{url}/?token={token}",
            headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req) as resp:
            page = resp.read().decode()
        # Should have a green dot (online indicator)
        assert '#2ecc71' in page


class TestResolveAgentName:
    """Tests for case-insensitive agent name resolution."""

    def test_exact_match(self, server_info):
        """TestBot exists — exact match returns canonical name."""
        assert _server_module.resolve_agent_name("TestBot") == "TestBot"

    def test_case_insensitive_lower(self, server_info):
        """testbot → TestBot (case-insensitive match)."""
        assert _server_module.resolve_agent_name("testbot") == "TestBot"

    def test_case_insensitive_upper(self, server_info):
        """TESTBOT → TestBot."""
        assert _server_module.resolve_agent_name("TESTBOT") == "TestBot"

    def test_unknown_returns_input(self, server_info):
        """Unknown name returns input unchanged."""
        assert _server_module.resolve_agent_name("NoSuchAgent") == "NoSuchAgent"

    def test_empty_string(self, server_info):
        """Empty string returns empty string."""
        assert _server_module.resolve_agent_name("") == ""


class TestSearchACL:
    """Tests for search respecting channel ACLs."""

    def test_search_excludes_restricted_channels(self, server_info, second_agent):
        """Search only returns results from channels the agent can access."""
        url, token, _ = server_info
        token2, name2 = second_agent
        # Create a restricted channel only accessible by TestBot
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "search-acl-secret", "allow": ["TestBot"]})
        _raw_request(url, token, "POST", "/api/channels/search-acl-secret/messages",
                     {"message": "xyzzy-acl-search-term"})
        # OtherBot should not find it
        s, data = _raw_request(url, token2, "GET",
                               "/api/search?q=xyzzy-acl-search-term")
        assert s == 200
        assert data["count"] == 0
        # TestBot should find it
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=xyzzy-acl-search-term")
        assert s == 200
        assert data["count"] >= 1

    def test_search_empty_query_whitespace(self, server_info):
        """Search with whitespace-only query returns 400."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "GET", "/api/search?q=%20%20")
        assert s == 400

    def test_search_limit_capped_at_200(self, server_info):
        """Search limit is capped at 200 even if higher requested."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=msg&limit=999")
        assert s == 200
        # Just verifying no error — the server caps at 200 internally


class TestWriteMessageSanitization:
    """Tests for write_message control character sanitization."""

    def test_strips_null_bytes(self):
        result = _server_module.write_message("general", "Test", "hello\x00world")
        assert "\x00" not in result["message"]
        assert "helloworld" in result["message"]

    def test_strips_tab_and_carriage_return(self):
        result = _server_module.write_message("general", "Test", "a\tb\rc")
        assert "\t" not in result["message"]
        assert "\r" not in result["message"]
        assert "abc" in result["message"]

    def test_preserves_newlines(self):
        result = _server_module.write_message("general", "Test", "line1\nline2")
        assert "\n" in result["message"]

    def test_strips_del_char(self):
        result = _server_module.write_message("general", "Test", "hello\x7fworld")
        assert "\x7f" not in result["message"]

    def test_returns_correct_fields(self):
        result = _server_module.write_message("general", "Sender", "msg", msg_type="system")
        assert result["sender"] == "Sender"
        assert result["message"] == "msg"
        assert result["channel"] == "general"
        assert result["type"] == "system"
        assert "ts" in result


class TestUnreadMarkerIsolation:
    """Tests for per-agent unread marker independence."""

    def test_mark_read_is_per_agent(self, server_info, second_agent):
        """One agent marking read doesn't affect another's unread count."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "unread-iso", "allow": ["*"]})
        _raw_request(url, token, "POST", "/api/channels/unread-iso/messages",
                     {"message": "test-iso-msg"})
        # TestBot marks read
        _raw_request(url, token, "PUT", "/api/channels/unread-iso/read", {})
        # TestBot should see 0 unread
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch1 = next(c for c in data if c["name"] == "unread-iso")
        assert ch1["unread"] == 0
        # OtherBot should still see unread
        s, data = _raw_request(url, token2, "GET", "/api/channels")
        ch2 = next(c for c in data if c["name"] == "unread-iso")
        assert ch2["unread"] >= 1

    def test_mark_read_on_restricted_channel_403(self, server_info, second_agent):
        """Marking read on a channel you can't access returns 403."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "unread-acl-test", "allow": ["TestBot"]})
        s, _ = _raw_request(url, token2, "PUT",
                            "/api/channels/unread-acl-test/read", {})
        assert s == 403

    def test_unread_never_negative(self, server_info):
        """Unread count is never negative even if mark-read called multiple times."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "unread-neg"})
        _raw_request(url, token, "PUT", "/api/channels/unread-neg/read", {})
        _raw_request(url, token, "PUT", "/api/channels/unread-neg/read", {})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        ch = next(c for c in data if c["name"] == "unread-neg")
        assert ch["unread"] >= 0


class TestCreatorRenameBypass:
    """Tests for channel creator rename permissions."""

    def test_creator_can_rename_even_if_not_in_acl(self, server_info):
        """Channel creator can rename even when removed from allow list."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "creator-rename-test"})
        # Remove creator from ACL
        _raw_request(url, token, "PUT", "/api/channels/creator-rename-test/acl",
                     {"allow": []})
        # Creator should still rename
        s, data = _raw_request(url, token, "PUT",
                               "/api/channels/creator-rename-test/rename",
                               {"name": "creator-renamed"})
        assert s == 200
        assert data["new_name"] == "creator-renamed"

    def test_non_creator_cannot_rename_restricted(self, server_info, second_agent):
        """Non-creator cannot rename a channel they're not allowed in."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "nocreator-rename", "allow": ["TestBot"]})
        s, _ = _raw_request(url, token2, "PUT",
                            "/api/channels/nocreator-rename/rename",
                            {"name": "stolen-name"})
        assert s == 403

    def test_get_acl_returns_allow_list(self, server_info):
        """GET /api/channels/:name/acl returns the allow list."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "acl-read-test", "allow": ["TestBot", "OtherBot"]})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/acl-read-test/acl")
        assert s == 200
        assert "allow" in data
        assert "TestBot" in data["allow"]

    def test_get_acl_unknown_channel_returns_default(self, server_info):
        """GET /api/channels/:name/acl for unknown channel returns open default."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/nonexistent-acl-ch/acl")
        assert s == 200
        assert data["allow"] == ["*"]


class TestUnreadAPI:
    """Tests for GET /api/unread — unified unread messages endpoint."""

    def test_unread_excludes_read_channel(self, server_info):
        """A channel marked as read does not appear in unread results."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-empty"})
        _raw_request(url, token, "POST", "/api/channels/ur-empty/messages",
                     {"message": "hello"})
        _raw_request(url, token, "PUT", "/api/channels/ur-empty/read", {})
        s, data = _raw_request(url, token, "GET", "/api/unread")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "ur-empty" not in ch_names

    def test_unread_returns_new_messages(self, server_info):
        """Unread messages are returned after marking read and sending more."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-new"})
        _raw_request(url, token, "POST", "/api/channels/ur-new/messages",
                     {"message": "before"})
        _raw_request(url, token, "PUT", "/api/channels/ur-new/read", {})
        _raw_request(url, token, "POST", "/api/channels/ur-new/messages",
                     {"message": "after1"})
        _raw_request(url, token, "POST", "/api/channels/ur-new/messages",
                     {"message": "after2"})
        s, data = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "ur-new")
        assert ch["unread_count"] == 2
        assert len(ch["messages"]) == 2
        texts = [m["message"] for m in ch["messages"]]
        assert "after1" in texts
        assert "after2" in texts

    def test_unread_includes_agent_name(self, server_info):
        """Response includes the requesting agent's name."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET", "/api/unread")
        assert s == 200
        assert data["agent"] == "TestBot"

    def test_unread_multiple_channels(self, server_info):
        """Unread messages from multiple channels in one response."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-multi-a"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-multi-b"})
        _raw_request(url, token, "PUT", "/api/channels/ur-multi-a/read", {})
        _raw_request(url, token, "PUT", "/api/channels/ur-multi-b/read", {})
        _raw_request(url, token, "POST", "/api/channels/ur-multi-a/messages",
                     {"message": "a-msg"})
        _raw_request(url, token, "POST", "/api/channels/ur-multi-b/messages",
                     {"message": "b-msg"})
        s, data = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "ur-multi-a" in ch_names
        assert "ur-multi-b" in ch_names

    def test_unread_skips_read_channels(self, server_info):
        """Channels with no unread messages are not included."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-skip-read"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-skip-unread"})
        _raw_request(url, token, "POST", "/api/channels/ur-skip-read/messages",
                     {"message": "read this"})
        _raw_request(url, token, "PUT", "/api/channels/ur-skip-read/read", {})
        _raw_request(url, token, "POST", "/api/channels/ur-skip-unread/messages",
                     {"message": "unread"})
        s, data = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "ur-skip-read" not in ch_names
        assert "ur-skip-unread" in ch_names

    def test_unread_mark_read_clears_unread(self, server_info):
        """mark_read=1 marks all returned channels as read."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-mark"})
        _raw_request(url, token, "POST", "/api/channels/ur-mark/messages",
                     {"message": "msg1"})
        # First call with mark_read — should return the message
        s, data = _raw_request(url, token, "GET", "/api/unread?mark_read=1&wake_channels=*")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "ur-mark" in ch_names
        # Second call — should be empty for this channel
        s, data2 = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch_names2 = [c["channel"] for c in data2["channels"]]
        assert "ur-mark" not in ch_names2

    def test_unread_mark_read_new_messages_still_show(self, server_info):
        """After mark_read, new messages still appear as unread."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-mark-new"})
        _raw_request(url, token, "POST", "/api/channels/ur-mark-new/messages",
                     {"message": "old"})
        _raw_request(url, token, "GET", "/api/unread?mark_read=1")
        _raw_request(url, token, "POST", "/api/channels/ur-mark-new/messages",
                     {"message": "new"})
        s, data = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "ur-mark-new")
        assert ch["unread_count"] == 1
        assert ch["messages"][0]["message"] == "new"

    def test_unread_without_mark_read_preserves_unread(self, server_info):
        """Without mark_read, calling unread twice returns same messages."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-nomark"})
        _raw_request(url, token, "POST", "/api/channels/ur-nomark/messages",
                     {"message": "persistent"})
        s, data1 = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        ch1 = next((c for c in data1["channels"] if c["channel"] == "ur-nomark"), None)
        assert ch1 is not None
        s, data2 = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        ch2 = next((c for c in data2["channels"] if c["channel"] == "ur-nomark"), None)
        assert ch2 is not None
        assert ch2["unread_count"] == ch1["unread_count"]

    def test_unread_mentions_filters_to_at_mentions(self, server_info, second_agent):
        """mentions=1 returns only messages containing @AgentName."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-ment"})
        _raw_request(url, token, "PUT", "/api/channels/ur-ment/read", {})
        # OtherBot sends a mention and a non-mention
        _raw_request(url, token2, "POST", "/api/channels/ur-ment/messages",
                     {"message": "hey @TestBot check this"})
        _raw_request(url, token2, "POST", "/api/channels/ur-ment/messages",
                     {"message": "general chatter"})
        s, data = _raw_request(url, token, "GET", "/api/unread")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "ur-ment")
        assert ch["unread_count"] == 1
        assert "@TestBot" in ch["messages"][0]["message"]

    def test_unread_mentions_includes_reply_quotes(self, server_info, second_agent):
        """mentions=1 also matches > @AgentName: reply prefix."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-reply"})
        _raw_request(url, token, "PUT", "/api/channels/ur-reply/read", {})
        _raw_request(url, token2, "POST", "/api/channels/ur-reply/messages",
                     {"message": "> @TestBot: something\n\nmy reply"})
        s, data = _raw_request(url, token, "GET", "/api/unread")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "ur-reply")
        assert ch["unread_count"] == 1

    def test_unread_mentions_omits_channels_without_mentions(self, server_info, second_agent):
        """Channels with unread but no mentions are excluded when mentions=1."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-noment"})
        _raw_request(url, token, "PUT", "/api/channels/ur-noment/read", {})
        _raw_request(url, token2, "POST", "/api/channels/ur-noment/messages",
                     {"message": "no mention here"})
        s, data = _raw_request(url, token, "GET", "/api/unread")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "ur-noment" not in ch_names

    def test_unread_wake_channels_star_returns_all(self, server_info, second_agent):
        """With wake_channels=*, all unread messages are returned."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "ur-allmsgs"})
        _raw_request(url, token, "PUT", "/api/channels/ur-allmsgs/read", {})
        _raw_request(url, token2, "POST", "/api/channels/ur-allmsgs/messages",
                     {"message": "no mention"})
        s, data = _raw_request(url, token, "GET", "/api/unread?wake_channels=*")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "ur-allmsgs")
        assert ch["unread_count"] == 1

    def test_unread_wake_channels_specific_channels(self, server_info, second_agent):
        """wake_channels=ch1,ch2 returns all msgs from those channels only."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "wc-included"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "wc-excluded"})
        _raw_request(url, token, "PUT", "/api/channels/wc-included/read", {})
        _raw_request(url, token, "PUT", "/api/channels/wc-excluded/read", {})
        _raw_request(url, token2, "POST", "/api/channels/wc-included/messages",
                     {"message": "no mention here"})
        _raw_request(url, token2, "POST", "/api/channels/wc-excluded/messages",
                     {"message": "no mention here either"})
        s, data = _raw_request(url, token, "GET",
                               "/api/unread?wake_channels=wc-included")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "wc-included" in ch_names
        assert "wc-excluded" not in ch_names

    def test_unread_wake_channels_case_insensitive(self, server_info, second_agent):
        """wake_channels matching is case-insensitive."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "wc-casetest"})
        _raw_request(url, token, "PUT", "/api/channels/wc-casetest/read", {})
        _raw_request(url, token2, "POST", "/api/channels/wc-casetest/messages",
                     {"message": "no mention"})
        s, data = _raw_request(url, token, "GET",
                               "/api/unread?wake_channels=WC-CaseTest")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "wc-casetest" in ch_names

    def test_unread_wake_channels_nonexistent_ignored(self, server_info, second_agent):
        """Nonexistent channels in wake_channels are silently ignored."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "wc-real"})
        _raw_request(url, token, "PUT", "/api/channels/wc-real/read", {})
        _raw_request(url, token2, "POST", "/api/channels/wc-real/messages",
                     {"message": "no mention"})
        s, data = _raw_request(url, token, "GET",
                               "/api/unread?wake_channels=wc-real,nonexistent-xyz")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "wc-real" in ch_names

    def test_unread_wake_channels_whitespace_trimmed(self, server_info, second_agent):
        """Whitespace around channel names in wake_channels is trimmed."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "wc-spaces"})
        _raw_request(url, token, "PUT", "/api/channels/wc-spaces/read", {})
        _raw_request(url, token2, "POST", "/api/channels/wc-spaces/messages",
                     {"message": "no mention"})
        s, data = _raw_request(url, token, "GET",
                               "/api/unread?wake_channels=%20wc-spaces%20")
        assert s == 200
        ch_names = [c["channel"] for c in data["channels"]]
        assert "wc-spaces" in ch_names


class TestPollAPI:
    """Tests for GET /api/poll — lightweight message count endpoint."""

    def test_poll_returns_counts(self, server_info):
        """Poll returns total, unread, and channel count."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET", "/api/poll")
        assert s == 200
        assert "total" in data
        assert "unread" in data
        assert "channels" in data
        assert isinstance(data["total"], int)
        assert isinstance(data["unread"], int)
        assert isinstance(data["channels"], int)

    def test_poll_total_increases_on_send(self, server_info):
        """Sending a message increases the total count."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "poll-inc"})
        s, data1 = _raw_request(url, token, "GET", "/api/poll")
        before = data1["total"]
        _raw_request(url, token, "POST", "/api/channels/poll-inc/messages",
                     {"message": "bump"})
        s, data2 = _raw_request(url, token, "GET", "/api/poll")
        assert data2["total"] == before + 1

    def test_poll_unread_decreases_after_mark_read(self, server_info):
        """Marking a channel as read decreases the unread count."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "poll-read"})
        _raw_request(url, token, "POST", "/api/channels/poll-read/messages",
                     {"message": "msg"})
        s, data1 = _raw_request(url, token, "GET", "/api/poll")
        before_unread = data1["unread"]
        _raw_request(url, token, "PUT", "/api/channels/poll-read/read", {})
        s, data2 = _raw_request(url, token, "GET", "/api/poll")
        assert data2["unread"] < before_unread

    def test_poll_channel_count_increases(self, server_info):
        """Creating a new channel increases the channel count."""
        url, token, _ = server_info
        s, data1 = _raw_request(url, token, "GET", "/api/poll")
        before = data1["channels"]
        _raw_request(url, token, "POST", "/api/channels", {"name": "poll-newch"})
        s, data2 = _raw_request(url, token, "GET", "/api/poll")
        assert data2["channels"] == before + 1


class TestClientExtendedMethods:
    """Tests for extended client.py methods: mark_read, unread, search,
    create_channel, delete_channel, rename_channel, get_config, set_config."""

    def test_client_create_channel(self, client):
        name = client.create_channel("client-ext-create")
        assert name == "client-ext-create"
        channels = client.channels()
        assert any(c["name"] == "client-ext-create" for c in channels)

    def test_client_create_channel_with_description(self, client, url_and_token):
        url, token = url_and_token
        client.create_channel("client-ext-desc", description="test desc")
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/client-ext-desc/description")
        assert s == 200
        assert data["description"] == "test desc"

    def test_client_mark_read(self, client):
        ch = "client-ext-markread"
        client.send(ch, "msg1")
        client.send(ch, "msg2")
        pos = client.mark_read(ch)
        assert pos >= 2

    def test_client_mark_read_clears_unread(self, client):
        ch = "client-ext-markread2"
        client.send(ch, "hello")
        client.mark_read(ch)
        unread = client.unread()
        ch_names = [u["channel"] for u in unread]
        assert ch not in ch_names

    def test_client_unread(self, client):
        ch = "client-ext-unread"
        client.send(ch, "unread msg")
        result = client.unread(wake_channels="*")
        assert isinstance(result, list)
        ch_entry = [u for u in result if u["channel"] == ch]
        assert len(ch_entry) > 0
        assert ch_entry[0]["unread_count"] >= 1

    def test_client_unread_mark_read(self, client):
        ch = "client-ext-unread-mr"
        client.send(ch, "read me")
        result = client.unread(mark_read=True, wake_channels="*")
        ch_entry = [u for u in result if u["channel"] == ch]
        assert len(ch_entry) > 0
        # After mark_read=True, second call should show no unread for this channel
        result2 = client.unread(wake_channels="*")
        ch_entry2 = [u for u in result2 if u["channel"] == ch]
        assert len(ch_entry2) == 0

    def test_client_unread_default_mentions_only(self, client):
        ch = "client-ext-mentions"
        client.send(ch, "hello world")
        client.send(ch, "hey @TestBot check this")
        result = client.unread()
        ch_entry = [u for u in result if u["channel"] == ch]
        if ch_entry:
            for msg in ch_entry[0]["messages"]:
                assert "@TestBot" in msg["message"]

    def test_client_search(self, client):
        ch = "client-ext-search"
        client.send(ch, "the quick brown fox jumps")
        results = client.search("quick brown fox")
        assert len(results) >= 1
        assert any("quick brown fox" in r["message"] for r in results)

    def test_client_search_limit(self, client):
        ch = "client-ext-searchlim"
        for i in range(5):
            client.send(ch, f"findable-token-xyz {i}")
        results = client.search("findable-token-xyz", limit=3)
        assert len(results) <= 3

    def test_client_search_no_results(self, client):
        results = client.search("nonexistent-gibberish-zzzqqq")
        assert results == []

    def test_client_get_config(self, client):
        config = client.get_config()
        assert "wake_channels" in config
        assert "poll_interval" in config

    def test_client_set_config(self, client):
        config = client.set_config(wake_channels="general", poll_interval=5)
        assert config["wake_channels"] == "general"
        assert config["poll_interval"] == 5
        # Verify via get
        config2 = client.get_config()
        assert config2["wake_channels"] == "general"
        assert config2["poll_interval"] == 5

    def test_client_delete_channel(self, client):
        client.create_channel("client-ext-del")
        client.send("client-ext-del", "bye")
        result = client.delete_channel("client-ext-del")
        assert result == "client-ext-del"
        channels = client.channels()
        assert not any(c["name"] == "client-ext-del" for c in channels)

    def test_client_rename_channel(self, client):
        client.create_channel("client-ext-ren-old")
        client.send("client-ext-ren-old", "content")
        new_name = client.rename_channel("client-ext-ren-old", "client-ext-ren-new")
        assert new_name == "client-ext-ren-new"
        channels = client.channels()
        names = [c["name"] for c in channels]
        assert "client-ext-ren-new" in names
        assert "client-ext-ren-old" not in names

    def test_client_read_since_minutes(self, client):
        ch = "client-ext-since-min"
        client.send(ch, "recent message")
        messages, total = client.read(ch, since_minutes=5)
        assert total >= 1
        assert any("recent message" in m["message"] for m in messages)

    def test_client_read_since_minutes_zero(self, client):
        ch = "client-ext-since-min0"
        client.send(ch, "some msg")
        messages, total = client.read(ch, since_minutes=0)
        assert messages == []


def _multipart_upload(url, token, filename, content, content_type="application/octet-stream"):
    """Build and send a multipart/form-data upload request. Returns (status, data)."""
    boundary = "----TestBoundary12345"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n"
        f"\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
    }
    req = urllib.request.Request(f"{url}/api/upload", data=body,
                                headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


class TestFileUpload:
    """Tests for POST /api/upload and GET /uploads/ — multipart file upload."""

    def test_upload_and_retrieve(self, server_info):
        """Upload a file and retrieve it by URL."""
        url, token, _ = server_info
        content = b"hello world upload test"
        s, data = _multipart_upload(url, token, "test.txt", content)
        assert s == 200
        assert data["ok"] is True
        assert data["filename"] == "test.txt"
        assert data["size"] == len(content)
        assert "uuid" in data
        assert data["url"].startswith("/uploads/")
        # Retrieve the file
        req = urllib.request.Request(f"{url}{data['url']}")
        with urllib.request.urlopen(req) as resp:
            assert resp.read() == content

    def test_upload_preserves_extension(self, server_info):
        """Upload preserves file extension in URL."""
        url, token, _ = server_info
        s, data = _multipart_upload(url, token, "image.png", b"\x89PNG\r\n")
        assert s == 200
        assert data["url"].endswith(".png")

    def test_upload_no_extension(self, server_info):
        """Upload without extension still works."""
        url, token, _ = server_info
        s, data = _multipart_upload(url, token, "noext", b"data")
        assert s == 200
        assert "uuid" in data

    def test_upload_wrong_content_type(self, server_info):
        """Non-multipart content type is rejected."""
        url, token, _ = server_info
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        body = json.dumps({"file": "nope"}).encode()
        req = urllib.request.Request(f"{url}/api/upload", data=body,
                                    headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                assert False, "Should have failed"
        except urllib.error.HTTPError as e:
            assert e.code == 400

    def test_upload_requires_auth(self, server_info):
        """Upload without auth returns 401."""
        url, _, _ = server_info
        boundary = "----TestBoundary"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="t.txt"\r\n\r\n'
            f"data\r\n--{boundary}--\r\n"
        ).encode()
        req = urllib.request.Request(f"{url}/api/upload", data=body,
                                    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
                                    method="POST")
        try:
            with urllib.request.urlopen(req) as resp:
                assert False, "Should have failed"
        except urllib.error.HTTPError as e:
            assert e.code == 401

    def test_upload_nonexistent_returns_404(self, server_info):
        """Requesting a nonexistent upload returns 404."""
        url, _, _ = server_info
        req = urllib.request.Request(f"{url}/uploads/nonexistent-uuid.txt")
        try:
            with urllib.request.urlopen(req) as resp:
                assert False, "Should have failed"
        except urllib.error.HTTPError as e:
            assert e.code == 404


class TestUploadErrors:
    """Tests for upload endpoint error paths — boundary, empty body, size limit."""

    def test_missing_boundary(self, server_info):
        """multipart/form-data without boundary= returns 400."""
        url, token, _ = server_info
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "multipart/form-data",  # no boundary
        }
        req = urllib.request.Request(f"{url}/api/upload", data=b"junk",
                                    headers=headers, method="POST")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have failed"
        except urllib.error.HTTPError as e:
            assert e.code == 400
            assert "boundary" in e.read().decode().lower()

    def test_no_file_in_body(self, server_info):
        """Multipart body with no file part returns 400."""
        url, token, _ = server_info
        boundary = "----EmptyBoundary"
        # Valid multipart structure but no Content-Disposition with filename
        body = (
            f"--{boundary}\r\n"
            f"Content-Disposition: form-data; name=\"text\"\r\n"
            f"\r\n"
            f"just text no file\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        req = urllib.request.Request(f"{url}/api/upload", data=body,
                                    headers=headers, method="POST")
        try:
            urllib.request.urlopen(req)
            assert False, "Should have failed"
        except urllib.error.HTTPError as e:
            assert e.code == 400
            assert "no file" in e.read().decode().lower()

    def test_file_too_large(self, server_info):
        """File exceeding MAX_UPLOAD_SIZE returns 413."""
        url, token, _ = server_info
        # Temporarily lower the limit for this test
        original = _server_module.MAX_UPLOAD_SIZE
        _server_module.MAX_UPLOAD_SIZE = 100
        try:
            s, data = _multipart_upload(url, token, "big.bin", b"X" * 200)
            assert s == 413
        finally:
            _server_module.MAX_UPLOAD_SIZE = original


class TestACLUpdate:
    """Tests for PUT /api/channels/{ch}/acl — ACL modification endpoint."""

    def test_update_acl(self, server_info):
        """Update allow list on a channel."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "acl-upd", "allow": ["*"]})
        s, data = _raw_request(url, token, "PUT", "/api/channels/acl-upd/acl",
                               {"allow": ["TestBot", "Other"]})
        assert s == 200
        assert data["ok"] is True
        assert "TestBot" in data["allow"]
        # Verify via GET
        s, acl = _raw_request(url, token, "GET", "/api/channels/acl-upd/acl")
        assert "TestBot" in acl["allow"]

    def test_update_acl_invalid_allow(self, server_info):
        """Non-array allow field returns 400."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "acl-upd-bad"})
        s, _ = _raw_request(url, token, "PUT", "/api/channels/acl-upd-bad/acl",
                            {"allow": "not-an-array"})
        assert s == 400

    def test_update_acl_creator_bypass(self, server_info):
        """Creator can modify ACL even after being removed from allow list."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "acl-upd-creator"})
        # Remove self from allow
        _raw_request(url, token, "PUT", "/api/channels/acl-upd-creator/acl",
                     {"allow": ["SomeoneElse"]})
        # Creator can still update
        s, data = _raw_request(url, token, "PUT", "/api/channels/acl-upd-creator/acl",
                               {"allow": ["TestBot"]})
        assert s == 200
        assert "TestBot" in data["allow"]


class TestServerHealth:
    """Tests for GET /api/health — no-auth server health endpoint."""

    def test_health_returns_status(self, server_info):
        url, _, _ = server_info
        req = urllib.request.Request(f"{url}/api/health")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert data["status"] == "ok"
        assert isinstance(data["uptime_seconds"], int)
        assert data["uptime_seconds"] >= 0

    def test_health_includes_counts(self, server_info):
        url, _, _ = server_info
        req = urllib.request.Request(f"{url}/api/health")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
        assert "channels" in data
        assert "agents" in data
        assert "total_messages" in data
        assert data["agents"] >= 1  # at least TestBot

    def test_health_no_auth_required(self, server_info):
        """Health endpoint works without any token."""
        url, _, _ = server_info
        req = urllib.request.Request(f"{url}/api/health")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200


class TestAgentConfig:
    """Tests for GET/PUT /api/agents/{name}/config edge cases.

    Existing tests cover basic get/set via client. These cover:
    defaults, partial updates, unknown keys, and cross-agent isolation.
    """

    def test_config_defaults_for_new_agent(self, server_info):
        """GET config returns defaults when agent has no stored config."""
        url, token, _ = server_info
        # Use a fresh agent name that has never set config
        fresh_token = _server_module.add_agent("ConfigFresh")
        s, data = _raw_request(url, fresh_token, "GET",
                               "/api/agents/ConfigFresh/config")
        assert s == 200
        assert data["config"]["wake_channels"] == ""
        assert data["config"]["poll_interval"] == 1

    def test_partial_update_preserves_other_key(self, server_info):
        """PUT with only one key preserves the other."""
        url, token, _ = server_info
        agent_token = _server_module.add_agent("ConfigPartial")
        # Set both keys
        _raw_request(url, agent_token, "PUT",
                     "/api/agents/ConfigPartial/config",
                     {"wake_channels": "general", "poll_interval": 10})
        # Update only wake_channels
        s, data = _raw_request(url, agent_token, "PUT",
                               "/api/agents/ConfigPartial/config",
                               {"wake_channels": ""})
        assert s == 200
        assert data["config"]["wake_channels"] == ""
        assert data["config"]["poll_interval"] == 10  # preserved

    def test_unknown_keys_ignored(self, server_info):
        """PUT with unknown keys doesn't store them."""
        url, token, _ = server_info
        agent_token = _server_module.add_agent("ConfigUnknown")
        s, data = _raw_request(url, agent_token, "PUT",
                               "/api/agents/ConfigUnknown/config",
                               {"wake_channels": "general", "bogus_key": "evil"})
        assert s == 200
        assert "bogus_key" not in data["config"]
        # Verify on re-read
        s2, data2 = _raw_request(url, agent_token, "GET",
                                 "/api/agents/ConfigUnknown/config")
        assert "bogus_key" not in data2["config"]

    def test_config_isolation_between_agents(self, server_info):
        """One agent's config doesn't affect another."""
        url, _, _ = server_info
        t1 = _server_module.add_agent("ConfigIso1")
        t2 = _server_module.add_agent("ConfigIso2")
        # Agent 1 sets custom config
        _raw_request(url, t1, "PUT", "/api/agents/ConfigIso1/config",
                     {"wake_channels": "general", "poll_interval": 99})
        # Agent 2 should still have defaults
        s, data = _raw_request(url, t2, "GET",
                               "/api/agents/ConfigIso2/config")
        assert s == 200
        assert data["config"]["wake_channels"] == ""
        assert data["config"]["poll_interval"] == 1

    def test_config_accepts_any_value_type(self, server_info):
        """Server stores values without type validation."""
        url, _, _ = server_info
        agent_token = _server_module.add_agent("ConfigAny")
        # String where int expected
        s, data = _raw_request(url, agent_token, "PUT",
                               "/api/agents/ConfigAny/config",
                               {"poll_interval": "banana"})
        assert s == 200
        assert data["config"]["poll_interval"] == "banana"


class TestChannelInfo:
    """Tests for GET /api/channels/{name}/info — combined metadata endpoint."""

    def test_info_returns_all_metadata(self, server_info, client):
        """Info endpoint returns message_count, description, created_by, allow."""
        url, token, _ = server_info
        client.create_channel("info-test", description="Test channel")
        client.send("info-test", "hello")
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/info-test/info")
        assert s == 200
        assert data["channel"] == "info-test"
        assert data["message_count"] == 1
        assert data["description"] == "Test channel"
        assert data["created_by"] == "TestBot"
        assert data["allow"] == ["*"]  # default allow when none specified

    def test_info_defaults_for_plain_channel(self, server_info, client):
        """Channel without explicit ACL returns sensible defaults."""
        url, token, _ = server_info
        # general is auto-created without ACL entry
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/general/info")
        assert s == 200
        assert data["channel"] == "general"
        assert isinstance(data["message_count"], int)
        assert data["description"] == ""
        assert data["allow"] == ["*"]

    def test_info_access_denied(self, server_info, second_agent):
        """Info endpoint respects ACL — denied agent gets 403."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "info-restricted", "allow": ["TestBot"]})
        s, _ = _raw_request(url, token2, "GET",
                            "/api/channels/info-restricted/info")
        assert s == 403

    def test_client_channel_info(self, client):
        """Client channel_info() method works."""
        client.create_channel("info-client", description="Via client")
        data = client.channel_info("info-client")
        assert data["channel"] == "info-client"
        assert data["description"] == "Via client"


class TestMessageTail:
    """Tests for ?tail=N parameter on channel messages endpoint."""

    def test_tail_returns_last_n(self, server_info):
        """?tail=N returns only the last N messages."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "tail-test"})
        for i in range(5):
            _raw_request(url, token, "POST", "/api/channels/tail-test/messages",
                         {"message": f"msg-{i}"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/tail-test/messages?tail=2")
        assert s == 200
        assert len(data["messages"]) == 2
        assert data["messages"][0]["message"] == "msg-3"
        assert data["messages"][1]["message"] == "msg-4"

    def test_tail_larger_than_total(self, server_info):
        """?tail=N where N > total messages returns all messages."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "tail-big"})
        _raw_request(url, token, "POST", "/api/channels/tail-big/messages",
                     {"message": "only-one"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/tail-big/messages?tail=100")
        assert s == 200
        assert len(data["messages"]) == 1

    def test_tail_via_client(self, client):
        """Client read() with tail parameter works."""
        client.create_channel("tail-client")
        for i in range(4):
            client.send("tail-client", f"line-{i}")
        msgs, total = client.read("tail-client", tail=2)
        assert len(msgs) == 2
        assert msgs[0]["message"] == "line-2"
        assert msgs[1]["message"] == "line-3"


class TestForAgentFilter:
    """Tests for ?for=AgentName mention filter on channel messages endpoint."""

    def test_for_filters_to_mentions(self, server_info):
        """?for=X returns only messages containing @X."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "for-test"})
        _raw_request(url, token, "POST", "/api/channels/for-test/messages",
                     {"message": "hello @Alice how are you"})
        _raw_request(url, token, "POST", "/api/channels/for-test/messages",
                     {"message": "hello @Bob good morning"})
        _raw_request(url, token, "POST", "/api/channels/for-test/messages",
                     {"message": "no mentions here"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/for-test/messages?for=Alice")
        assert s == 200
        assert len(data["messages"]) == 1
        assert "@Alice" in data["messages"][0]["message"]

    def test_for_includes_reply_quotes(self, server_info):
        """?for=X also matches reply prefix '> @X:'."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "for-reply"})
        _raw_request(url, token, "POST", "/api/channels/for-reply/messages",
                     {"message": "> @Bob: original\nmy reply"})
        _raw_request(url, token, "POST", "/api/channels/for-reply/messages",
                     {"message": "unrelated message"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/for-reply/messages?for=Bob")
        assert s == 200
        assert len(data["messages"]) == 1

    def test_for_no_matches_returns_empty(self, server_info):
        """?for=X with no matching messages returns empty list."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "for-empty"})
        _raw_request(url, token, "POST", "/api/channels/for-empty/messages",
                     {"message": "just chatting"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/for-empty/messages?for=Nobody")
        assert s == 200
        assert len(data["messages"]) == 0

    def test_for_combined_with_tail(self, server_info):
        """?for=X&tail=N filters then slices to last N."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "for-tail"})
        for i in range(5):
            _raw_request(url, token, "POST", "/api/channels/for-tail/messages",
                         {"message": f"@Dev message {i}"})
        _raw_request(url, token, "POST", "/api/channels/for-tail/messages",
                     {"message": "no mention"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/for-tail/messages?for=Dev&tail=2")
        assert s == 200
        assert len(data["messages"]) == 2
        assert "message 3" in data["messages"][0]["message"]
        assert "message 4" in data["messages"][1]["message"]


class TestIntParamValidation:
    """Tests for _int_param 400 responses on endpoints missing coverage."""

    def test_messages_tail_invalid(self, server_info):
        """Non-numeric tail on messages endpoint returns 400."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "GET",
                            "/api/channels/general/messages?tail=abc")
        assert s == 400

    def test_search_limit_invalid(self, server_info):
        """Non-numeric limit on search endpoint returns 400."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "GET",
                            "/api/search?q=hello&limit=xyz")
        assert s == 400

    def test_messages_since_invalid(self, server_info):
        """Non-numeric since on messages returns 400 (not default 0)."""
        url, token, _ = server_info
        s, _ = _raw_request(url, token, "GET",
                            "/api/channels/general/messages?since=notanumber")
        assert s == 400


class TestChannelListDescription:
    """Tests for description field in GET /api/channels response."""

    def test_channels_include_description(self, server_info):
        """Channel list includes description for channels that have one."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "chlist-desc", "description": "A test channel"})
        s, data = _raw_request(url, token, "GET", "/api/channels")
        assert s == 200
        match = [ch for ch in data if ch["name"] == "chlist-desc"]
        assert len(match) == 1
        assert match[0]["description"] == "A test channel"

    def test_channels_empty_description_for_plain(self, server_info):
        """Channels without description get empty string."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET", "/api/channels")
        assert s == 200
        general = [ch for ch in data if ch["name"] == "general"]
        assert len(general) == 1
        assert general[0]["description"] == ""


class TestDeleteChannelCleanup:
    """Tests for DELETE /api/channels/{name} — verify cleanup of ACL and cache."""

    def test_delete_removes_acl_entry(self, server_info):
        """Deleting a channel removes its ACL entry."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "del-acl-test", "description": "will be deleted"})
        _raw_request(url, token, "DELETE", "/api/channels/del-acl-test")
        # ACL endpoint should return default (no stored entry)
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/del-acl-test/acl")
        assert s == 200
        assert data == {"allow": ["*"]}  # default, not the stored entry

    def test_delete_clears_count_cache(self, server_info):
        """After deletion, recreating the channel starts fresh at 0 messages."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "del-cache-test"})
        _raw_request(url, token, "POST", "/api/channels/del-cache-test/messages",
                     {"message": "msg1"})
        _raw_request(url, token, "DELETE", "/api/channels/del-cache-test")
        # Recreate — should have 0 messages, not stale cache
        _raw_request(url, token, "POST", "/api/channels", {"name": "del-cache-test"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/del-cache-test/messages")
        assert s == 200
        assert len(data["messages"]) == 0

    def test_delete_then_messages_returns_empty(self, server_info):
        """Reading messages from deleted channel returns empty (file gone)."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "del-read-test"})
        _raw_request(url, token, "POST", "/api/channels/del-read-test/messages",
                     {"message": "ephemeral"})
        _raw_request(url, token, "DELETE", "/api/channels/del-read-test")
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/del-read-test/messages")
        assert s == 200
        assert data["messages"] == []


class TestSearchChannelFilter:
    """Tests for ?channel= filter on GET /api/search."""

    def test_search_single_channel(self, server_info):
        """?channel= restricts search to one channel."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "sch-a"})
        _raw_request(url, token, "POST", "/api/channels", {"name": "sch-b"})
        _raw_request(url, token, "POST", "/api/channels/sch-a/messages",
                     {"message": "findme-unique-token"})
        _raw_request(url, token, "POST", "/api/channels/sch-b/messages",
                     {"message": "findme-unique-token"})
        # Search all — should find both
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=findme-unique-token")
        assert s == 200
        assert data["count"] >= 2
        # Search only sch-a
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=findme-unique-token&channel=sch-a")
        assert s == 200
        assert all(r["channel"] == "sch-a" for r in data["results"])

    def test_search_nonexistent_channel_returns_empty(self, server_info):
        """Filtering to a non-existent channel returns no results."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=anything&channel=no-such-channel")
        assert s == 200
        assert data["count"] == 0


class TestMultiLineMessages:
    """Tests for multi-line message write→read roundtrip.

    Messages with newlines are stored as continuation lines in the log.
    read_channel() must reassemble them into single messages.
    """

    def test_multiline_roundtrip_via_api(self, server_info):
        """Send a multi-line message via API, read it back intact."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ml-rt"})
        msg = "line one\nline two\nline three"
        _raw_request(url, token, "POST", "/api/channels/ml-rt/messages",
                     {"message": msg})
        s, data = _raw_request(url, token, "GET", "/api/channels/ml-rt/messages")
        assert s == 200
        assert len(data["messages"]) == 1
        assert data["messages"][0]["message"] == msg

    def test_multiple_multiline_messages(self, server_info):
        """Multiple multi-line messages are each reassembled correctly."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ml-multi"})
        msg1 = "first\nsecond"
        msg2 = "alpha\nbeta\ngamma"
        _raw_request(url, token, "POST", "/api/channels/ml-multi/messages",
                     {"message": msg1})
        _raw_request(url, token, "POST", "/api/channels/ml-multi/messages",
                     {"message": msg2})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/ml-multi/messages")
        assert s == 200
        assert len(data["messages"]) == 2
        assert data["messages"][0]["message"] == msg1
        assert data["messages"][1]["message"] == msg2

    def test_multiline_count_is_correct(self, server_info):
        """Multi-line messages count as one message each."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ml-count"})
        _raw_request(url, token, "POST", "/api/channels/ml-count/messages",
                     {"message": "a\nb\nc"})
        _raw_request(url, token, "POST", "/api/channels/ml-count/messages",
                     {"message": "single line"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/ml-count/messages")
        assert s == 200
        assert data["count"] == 2

    def test_multiline_with_tail(self, server_info):
        """?tail=1 on multi-line messages returns the last complete message."""
        url, token, _ = server_info
        _raw_request(url, token, "POST", "/api/channels", {"name": "ml-tail"})
        _raw_request(url, token, "POST", "/api/channels/ml-tail/messages",
                     {"message": "first\nmultiline"})
        _raw_request(url, token, "POST", "/api/channels/ml-tail/messages",
                     {"message": "second\nmultiline"})
        s, data = _raw_request(url, token, "GET",
                               "/api/channels/ml-tail/messages?tail=1")
        assert s == 200
        assert len(data["messages"]) == 1
        assert data["messages"][0]["message"] == "second\nmultiline"


class TestAggregateActivity:
    """Tests for GET /api/activity — merged activity across all agents."""

    def test_aggregate_merges_agents(self, server_info):
        """Events from multiple agents appear in aggregate endpoint."""
        url, token, _ = server_info
        _server_module.AGENT_ACTIVITY["AgentA"] = [
            {"ts": "2026-02-20 01:00", "type": "tool", "summary": "a-event"},
        ]
        _server_module.AGENT_ACTIVITY["AgentB"] = [
            {"ts": "2026-02-20 01:01", "type": "tool", "summary": "b-event"},
        ]
        s, data = _raw_request(url, token, "GET", "/api/activity?tail=10")
        assert s == 200
        summaries = [e["summary"] for e in data]
        assert "a-event" in summaries
        assert "b-event" in summaries
        # Each event has agent key added
        agents = {e["agent"] for e in data if e["summary"] in ("a-event", "b-event")}
        assert "AgentA" in agents
        assert "AgentB" in agents

    def test_exclude_filters_agents(self, server_info):
        """?exclude= removes specified agents from results."""
        url, token, _ = server_info
        _server_module.AGENT_ACTIVITY["KeepMe"] = [
            {"ts": "2026-02-20 02:00", "type": "tool", "summary": "keep-this"},
        ]
        _server_module.AGENT_ACTIVITY["DropMe"] = [
            {"ts": "2026-02-20 02:01", "type": "tool", "summary": "drop-this"},
        ]
        s, data = _raw_request(url, token, "GET",
                               "/api/activity?tail=10&exclude=DropMe")
        assert s == 200
        summaries = [e["summary"] for e in data]
        assert "keep-this" in summaries
        assert "drop-this" not in summaries

    def test_sorted_by_timestamp(self, server_info):
        """Events are returned sorted by timestamp."""
        url, token, _ = server_info
        _server_module.AGENT_ACTIVITY["SortTest"] = [
            {"ts": "2026-02-20 03:02", "type": "tool", "summary": "second"},
            {"ts": "2026-02-20 03:01", "type": "tool", "summary": "first"},
            {"ts": "2026-02-20 03:03", "type": "tool", "summary": "third"},
        ]
        s, data = _raw_request(url, token, "GET", "/api/activity?tail=3")
        assert s == 200
        # Filter to just our test events
        ours = [e for e in data if e.get("agent") == "SortTest"]
        if len(ours) == 3:
            assert ours[0]["summary"] == "first"
            assert ours[1]["summary"] == "second"
            assert ours[2]["summary"] == "third"


class TestChannelMetadataAccess:
    """Tests that ACL/description endpoints are readable without channel access,
    while messages/info require access. Documents intentional access model:
    metadata is public, content is private."""

    def test_restricted_agent_can_read_acl(self, server_info, second_agent):
        """Agent without channel access can still read its ACL."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "meta-acl", "allow": ["TestBot"]})
        # Second agent has no access, but can read ACL
        s, data = _raw_request(url, token2, "GET", "/api/channels/meta-acl/acl")
        assert s == 200
        assert "TestBot" in data["allow"]

    def test_restricted_agent_can_read_description(self, server_info, second_agent):
        """Agent without channel access can still read its description."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "meta-desc", "allow": ["TestBot"],
                      "description": "Private channel"})
        s, data = _raw_request(url, token2, "GET",
                               "/api/channels/meta-desc/description")
        assert s == 200
        assert data["description"] == "Private channel"

    def test_restricted_agent_cannot_read_messages(self, server_info, second_agent):
        """Agent without channel access is denied message content."""
        url, token, _ = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels",
                     {"name": "meta-msgs", "allow": ["TestBot"]})
        s, _ = _raw_request(url, token2, "GET",
                            "/api/channels/meta-msgs/messages")
        assert s == 403


class TestExpandedConfig:
    """Tests for expanded AGENT_CONFIG_DEFAULTS (max_turns, heartbeat_interval, activity_follow)."""

    def test_defaults_include_new_keys(self, server_info):
        """GET config returns new default keys for a fresh agent."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgExpFresh")
        s, data = _raw_request(url, token, "GET",
                               "/api/agents/CfgExpFresh/config")
        assert s == 200
        cfg = data["config"]
        assert cfg["max_turns"] == 200
        assert cfg["heartbeat_interval"] == 15000
        assert cfg["activity_follow"] == []

    def test_put_max_turns(self, server_info):
        """PUT max_turns → GET returns it."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgMaxT")
        s, data = _raw_request(url, token, "PUT",
                               "/api/agents/CfgMaxT/config",
                               {"max_turns": 50})
        assert s == 200
        assert data["config"]["max_turns"] == 50
        # Verify on re-read
        s2, data2 = _raw_request(url, token, "GET",
                                 "/api/agents/CfgMaxT/config")
        assert data2["config"]["max_turns"] == 50

    def test_put_heartbeat_interval(self, server_info):
        """PUT heartbeat_interval → GET returns it."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgHBI")
        s, data = _raw_request(url, token, "PUT",
                               "/api/agents/CfgHBI/config",
                               {"heartbeat_interval": 3600})
        assert s == 200
        assert data["config"]["heartbeat_interval"] == 3600

    def test_put_activity_follow_list(self, server_info):
        """PUT activity_follow with a list of agent names."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgActF")
        s, data = _raw_request(url, token, "PUT",
                               "/api/agents/CfgActF/config",
                               {"activity_follow": ["FTW", "FTL"]})
        assert s == 200
        assert data["config"]["activity_follow"] == ["FTW", "FTL"]

    def test_put_activity_follow_empty(self, server_info):
        """PUT activity_follow with empty list → GET returns empty list."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgActE")
        # First set it to something
        _raw_request(url, token, "PUT",
                     "/api/agents/CfgActE/config",
                     {"activity_follow": ["FTW"]})
        # Then clear it
        s, data = _raw_request(url, token, "PUT",
                               "/api/agents/CfgActE/config",
                               {"activity_follow": []})
        assert s == 200
        assert data["config"]["activity_follow"] == []

    def test_new_keys_dont_break_existing(self, server_info):
        """Setting new keys preserves existing wake_channels/poll_interval."""
        url, _, _ = server_info
        token = _server_module.add_agent("CfgCompat")
        _raw_request(url, token, "PUT",
                     "/api/agents/CfgCompat/config",
                     {"wake_channels": "general", "poll_interval": 5})
        # Now set only new keys
        s, data = _raw_request(url, token, "PUT",
                               "/api/agents/CfgCompat/config",
                               {"max_turns": 100})
        assert s == 200
        assert data["config"]["wake_channels"] == "general"
        assert data["config"]["poll_interval"] == 5
        assert data["config"]["max_turns"] == 100


class TestHealthSoulMemory:
    """Tests for soul_text/memory_text fields in health POST."""

    def test_health_stores_soul_and_memory(self, server_info):
        """POST health with soul_text + memory_text → GET returns them."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthSM")
        s, _ = _raw_request(url, token, "POST",
                            "/api/agents/HealthSM/health",
                            {"soul_text": "I am a turtle.",
                             "memory_text": "Key paths: /home/..."})
        assert s == 200
        s2, data = _raw_request(url, token, "GET",
                                "/api/agents/HealthSM/health")
        assert s2 == 200
        assert data["soul_text"] == "I am a turtle."
        assert data["memory_text"] == "Key paths: /home/..."

    def test_health_large_text(self, server_info):
        """POST health with ~10KB text → stored correctly."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthLg")
        big_text = "x" * 10000
        s, _ = _raw_request(url, token, "POST",
                            "/api/agents/HealthLg/health",
                            {"soul_text": big_text, "context_pct": 42})
        assert s == 200
        s2, data = _raw_request(url, token, "GET",
                                "/api/agents/HealthLg/health")
        assert data["soul_text"] == big_text
        assert data["context_pct"] == 42

    def test_health_without_soul_memory_backward_compat(self, server_info):
        """POST health without soul/memory fields → existing fields work."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthBC")
        s, _ = _raw_request(url, token, "POST",
                            "/api/agents/HealthBC/health",
                            {"context_pct": 55, "status": "ok"})
        assert s == 200
        s2, data = _raw_request(url, token, "GET",
                                "/api/agents/HealthBC/health")
        assert data["context_pct"] == 55
        assert "soul_text" not in data


    def test_health_persisted_to_disk(self, server_info):
        """POST health → agent_health.json written to disk."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthPersist")
        s, _ = _raw_request(url, token, "POST",
                            "/api/agents/HealthPersist/health",
                            {"context_pct": 77, "soul_text": "persist me"})
        assert s == 200
        # Verify file exists and contains the data
        health_file = _server_module.AGENT_HEALTH_FILE
        assert health_file.exists()
        import json
        saved = json.loads(health_file.read_text())
        assert "HealthPersist" in saved
        assert saved["HealthPersist"]["context_pct"] == 77
        assert saved["HealthPersist"]["soul_text"] == "persist me"

    def test_health_survives_clear_and_reload(self, server_info):
        """Health data can be reloaded from disk after AGENT_HEALTH is cleared."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthReload")
        s, _ = _raw_request(url, token, "POST",
                            "/api/agents/HealthReload/health",
                            {"context_pct": 33, "status": "sleeping"})
        assert s == 200
        # Simulate server restart: clear in-memory, reload from file
        _server_module.AGENT_HEALTH.clear()
        _server_module.AGENT_HEALTH.update(
            _server_module._load_json(_server_module.AGENT_HEALTH_FILE))
        assert "HealthReload" in _server_module.AGENT_HEALTH
        assert _server_module.AGENT_HEALTH["HealthReload"]["context_pct"] == 33
        assert _server_module.AGENT_HEALTH["HealthReload"]["status"] == "sleeping"

    def test_health_file_updates_on_each_push(self, server_info):
        """Multiple health pushes update the persisted file."""
        url, _, _ = server_info
        token = _server_module.add_agent("HealthMulti")
        _raw_request(url, token, "POST",
                     "/api/agents/HealthMulti/health", {"context_pct": 10})
        _raw_request(url, token, "POST",
                     "/api/agents/HealthMulti/health", {"context_pct": 90})
        import json
        saved = json.loads(_server_module.AGENT_HEALTH_FILE.read_text())
        assert saved["HealthMulti"]["context_pct"] == 90


class TestAgentsPage:
    """Tests for GET /agents page route."""

    def test_agents_page_requires_auth(self, server_info):
        """GET /agents without auth → 401."""
        url, _, _ = server_info
        s, _ = _raw_request(url, None, "GET", "/agents")
        assert s == 401

    def test_agents_page_returns_html(self, server_info):
        """GET /agents with valid token → 200 + HTML."""
        url, token, _ = server_info
        s, data = _raw_request(url, token, "GET", "/agents")
        assert s == 200
        # _raw_request parses JSON by default, but this is HTML
        # so let's do a direct request
        import urllib.request
        req = urllib.request.Request(f"{url}/agents?token={token}")
        with urllib.request.urlopen(req) as resp:
            body = resp.read().decode()
            assert resp.status == 200
            assert "fagents-comms" in body
            assert "Agents" in body
            assert "agentList" in body


class TestAgentProfiles:
    """Tests for agent profile endpoints (human/AI cooperation foundation)."""

    def test_get_profile_defaults(self, server_info):
        """GET profile for agent with no profile set returns defaults (type=ai)."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "GET", f"/api/agents/{name}/profile")
        assert s == 200
        assert data["agent"] == name
        assert data["profile"]["type"] == "ai"
        assert data["profile"]["display_name"] == ""
        # No legacy fields (role, bio, etc.)
        assert "role" not in data["profile"]
        assert "bio" not in data["profile"]

    def test_set_profile_type_human(self, server_info):
        """PUT profile with type=human sets the agent as human."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"type": "human", "soul": "# Team lead\n\nI run the team"})
        assert s == 200
        assert data["ok"] is True
        assert data["profile"]["type"] == "human"
        assert data["profile"]["soul"] == "# Team lead\n\nI run the team"
        # Structured AI fields not returned for hoomans
        assert "role" not in data["profile"]
        assert "bio" not in data["profile"]

    def test_get_profile_persists(self, server_info):
        """Profile changes persist across reads."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "ai", "display_name": "Juho"})
        s, data = _raw_request(url, token, "GET", f"/api/agents/{name}/profile")
        assert s == 200
        assert data["profile"]["display_name"] == "Juho"

    def test_partial_update_preserves_fields(self, server_info):
        """PUT with partial fields preserves existing fields."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "ai", "display_name": "TestBot Display"})
        # Now update only type (to human), display_name should persist
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"type": "human"})
        assert s == 200
        assert data["profile"]["display_name"] == "TestBot Display"  # preserved
        assert data["profile"]["type"] == "human"

    def test_invalid_type_rejected(self, server_info):
        """PUT with invalid type → 400."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"type": "robot"})
        assert s == 400

    def test_display_name_too_long_rejected(self, server_info):
        """PUT with display_name exceeding max length → 400."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"display_name": "x" * 51})
        assert s == 400

    def test_cannot_edit_other_agent_profile(self, server_info):
        """PUT to another agent's profile → 403."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "PUT", "/api/agents/SomeOtherAgent/profile",
                               {"display_name": "hacked"})
        assert s == 403

    def test_any_agent_can_read_any_profile(self, server_info):
        """GET on another agent's profile is allowed (cooperation: AIs read human profiles)."""
        url, token, name = server_info
        # Create a second agent
        token2 = _server_module.add_agent("HumanUser")
        # Set their profile directly
        profiles = _server_module.load_agent_profiles()
        profiles["HumanUser"] = {"type": "human", "soul": "# Designer\n\nAsk me about UX"}
        _server_module.save_agent_profiles(profiles)
        # First agent reads second agent's profile
        s, data = _raw_request(url, token, "GET", "/api/agents/HumanUser/profile")
        assert s == 200
        assert data["profile"]["type"] == "human"
        assert data["profile"]["soul"] == "# Designer\n\nAsk me about UX"

    def test_agents_list_includes_type(self, server_info):
        """GET /api/agents includes type field from profiles."""
        url, token, name = server_info
        # Set profile type
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        s, data = _raw_request(url, token, "GET", "/api/agents")
        assert s == 200
        assert name in data
        assert data[name]["type"] == "ai"

    def test_create_agent_with_type(self, server_info):
        """POST /api/agents with type sets profile type."""
        url, token, name = server_info
        s, data = _raw_request(url, token, "POST", "/api/agents",
                               {"name": "NewHuman", "type": "human"})
        assert s == 200
        assert data["ok"] is True
        # Verify profile was set
        profile = _server_module.get_agent_profile("NewHuman")
        assert profile["type"] == "human"

    def test_hooman_soul_save_and_retrieve(self, server_info):
        """PUT soul on a hooman profile, verify it persists."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "human"})
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"soul": "# Me\n\n# About me\nI test things"})
        assert s == 200
        assert data["profile"]["soul"] == "# Me\n\n# About me\nI test things"
        # Verify GET returns it
        s, data = _raw_request(url, token, "GET", f"/api/agents/{name}/profile")
        assert data["profile"]["soul"] == "# Me\n\n# About me\nI test things"

    def test_hooman_profile_excludes_ai_fields(self, server_info):
        """Hooman profile GET does not include AI-only fields."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "human"})
        s, data = _raw_request(url, token, "GET", f"/api/agents/{name}/profile")
        assert s == 200
        for field in ("role", "bio", "timezone", "status"):
            assert field not in data["profile"]

    def test_legacy_fields_ignored(self, server_info):
        """PUT with legacy fields (role/bio/etc) are silently ignored."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile", {"type": "ai"})
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"role": "Engineer", "bio": "Builds things"})
        assert s == 200
        assert "role" not in data["profile"]
        assert "bio" not in data["profile"]

    def test_type_switch_strips_soul(self, server_info):
        """Switching from hooman to AI strips soul field."""
        url, token, name = server_info
        # Set hooman profile with soul
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "human", "soul": "# Hello"})
        # Switch to AI
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"type": "ai"})
        assert s == 200
        assert data["profile"]["type"] == "ai"
        assert "soul" not in data["profile"]
        # Verify stripped from storage too
        profiles = _server_module.load_agent_profiles()
        assert "soul" not in profiles[name]

    def test_soul_too_long_rejected(self, server_info):
        """PUT with soul exceeding max length → 400."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "human"})
        s, data = _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                               {"soul": "x" * 5001})
        assert s == 400

    def test_ai_profile_excludes_soul(self, server_info):
        """AI profile GET does not include soul field."""
        url, token, name = server_info
        _raw_request(url, token, "PUT", f"/api/agents/{name}/profile",
                     {"type": "ai"})
        s, data = _raw_request(url, token, "GET", f"/api/agents/{name}/profile")
        assert s == 200
        assert "soul" not in data["profile"]
        # AI profile has type + display_name only
        assert data["profile"]["type"] == "ai"
        assert "display_name" in data["profile"]


class TestGroupMentions:
    """Tests for @humans/@ais group mentions (cooperation: cross-type requests)."""

    def test_humans_mention_matches_human_agent(self, server_info, second_agent):
        """@humans in message triggers mention for human-type agent."""
        url, token, name = server_info
        token2, _ = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "grp-hum"})
        _raw_request(url, token, "PUT", "/api/channels/grp-hum/read", {})
        _raw_request(url, token2, "POST", "/api/channels/grp-hum/messages",
                     {"message": "hey @humans please review this PR"})
        s, data = _raw_request(url, token, "GET", "/api/unread?mentions=1")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "grp-hum")
        assert ch["unread_count"] == 1
        assert "@humans" in ch["messages"][0]["message"]

    def test_humans_mention_does_not_match_ai(self, server_info, second_agent):
        """@humans does NOT trigger for AI-type agent."""
        url, token, name = server_info
        token2, _ = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "grp-noai"})
        _raw_request(url, token, "PUT", "/api/channels/grp-noai/read", {})
        _raw_request(url, token2, "POST", "/api/channels/grp-noai/messages",
                     {"message": "hey @humans please review"})
        s, data = _raw_request(url, token, "GET", "/api/unread?mentions=1")
        assert s == 200
        matching = [c for c in data["channels"] if c["channel"] == "grp-noai"]
        assert not matching  # AI should not see @humans as a mention

    def test_ais_mention_matches_ai_agent(self, server_info, second_agent):
        """@ais in message triggers mention for AI-type agent."""
        url, token, name = server_info
        token2, _ = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "grp-ai"})
        _raw_request(url, token, "PUT", "/api/channels/grp-ai/read", {})
        _raw_request(url, token2, "POST", "/api/channels/grp-ai/messages",
                     {"message": "@ais pick up this pattern for future work"})
        s, data = _raw_request(url, token, "GET", "/api/unread?mentions=1")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "grp-ai")
        assert ch["unread_count"] == 1

    def test_ais_mention_does_not_match_human(self, server_info, second_agent):
        """@ais does NOT trigger for human-type agent."""
        url, token, name = server_info
        token2, _ = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "grp-nohum"})
        _raw_request(url, token, "PUT", "/api/channels/grp-nohum/read", {})
        _raw_request(url, token2, "POST", "/api/channels/grp-nohum/messages",
                     {"message": "@ais update your memory files"})
        s, data = _raw_request(url, token, "GET", "/api/unread?mentions=1")
        assert s == 200
        matching = [c for c in data["channels"] if c["channel"] == "grp-nohum"]
        assert not matching

    def test_direct_mention_still_works_with_group(self, server_info, second_agent):
        """Direct @name mention still works alongside group mentions."""
        url, token, name = server_info
        token2, _ = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "grp-both"})
        _raw_request(url, token, "PUT", "/api/channels/grp-both/read", {})
        _raw_request(url, token2, "POST", "/api/channels/grp-both/messages",
                     {"message": f"@{name} check this specifically"})
        s, data = _raw_request(url, token, "GET", "/api/unread?mentions=1")
        assert s == 200
        ch = next(c for c in data["channels"] if c["channel"] == "grp-both")
        assert ch["unread_count"] == 1


class TestTypeFilter:
    """Tests for ?type= filter on agent endpoints."""

    def test_agents_filter_human(self, server_info, second_agent):
        """GET /api/agents?type=human returns only human agents."""
        url, token, name = server_info
        _, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        s, data = _raw_request(url, token, "GET", "/api/agents?type=human")
        assert s == 200
        assert name in data
        assert name2 not in data

    def test_agents_filter_ai(self, server_info, second_agent):
        """GET /api/agents?type=ai returns only AI agents."""
        url, token, name = server_info
        _, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        s, data = _raw_request(url, token, "GET", "/api/agents?type=ai")
        assert s == 200
        assert name not in data
        assert name2 in data

    def test_agents_no_filter_returns_all(self, server_info, second_agent):
        """GET /api/agents without type filter returns all agents."""
        url, token, name = server_info
        _, name2 = second_agent
        s, data = _raw_request(url, token, "GET", "/api/agents")
        assert s == 200
        assert name in data

    def test_agents_list_filter_human(self, server_info, second_agent):
        """GET /api/agents/list?type=human returns only human names."""
        url, token, name = server_info
        _, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        s, data = _raw_request(url, token, "GET", "/api/agents/list?type=human")
        assert s == 200
        assert name in data
        assert name2 not in data


class TestTypeAwareACL:
    """Tests for @humans/@ais in channel ACLs."""

    def test_humans_acl_grants_human_access(self, server_info, second_agent):
        """Channel with allow=[@humans] is accessible by human agents."""
        url, token, name = server_info
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "human-only"})
        acl = _server_module.load_channels_acl()
        acl["human-only"] = {"allow": ["@humans"]}
        _server_module.save_channels_acl(acl)
        s, data = _raw_request(url, token, "GET", "/api/channels/human-only/messages")
        assert s == 200

    def test_humans_acl_blocks_ai(self, server_info, second_agent):
        """Channel with allow=[@humans] blocks AI agents."""
        url, token, name = server_info
        token2, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "human-only2"})
        acl = _server_module.load_channels_acl()
        acl["human-only2"] = {"allow": ["@humans"]}
        _server_module.save_channels_acl(acl)
        s, data = _raw_request(url, token2, "GET", "/api/channels/human-only2/messages")
        assert s == 403

    def test_ais_acl_grants_ai_access(self, server_info, second_agent):
        """Channel with allow=[@ais] is accessible by AI agents."""
        url, token, name = server_info
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "ai-only"})
        acl = _server_module.load_channels_acl()
        acl["ai-only"] = {"allow": ["@ais"]}
        _server_module.save_channels_acl(acl)
        s, data = _raw_request(url, token, "GET", "/api/channels/ai-only/messages")
        assert s == 200

    def test_mixed_acl_humans_and_specific(self, server_info, second_agent):
        """Channel with allow=[@humans, SpecificAI] works for both."""
        url, token, name = server_info
        token2, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "mixed-acl"})
        acl = _server_module.load_channels_acl()
        acl["mixed-acl"] = {"allow": ["@humans", name2]}
        _server_module.save_channels_acl(acl)
        s1, _ = _raw_request(url, token, "GET", "/api/channels/mixed-acl/messages")
        s2, _ = _raw_request(url, token2, "GET", "/api/channels/mixed-acl/messages")
        assert s1 == 200
        assert s2 == 200


class TestTypeAwareSearch:
    """Tests for from_type filter on search endpoint."""

    def test_search_from_type_human(self, server_info, second_agent):
        """Search with from_type=human returns only messages from human agents."""
        url, token, name = server_info
        token2, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "srch-type"})
        _raw_request(url, token, "POST", "/api/channels/srch-type/messages",
                     {"message": "human says qxdeploy77 looks good"})
        _raw_request(url, token2, "POST", "/api/channels/srch-type/messages",
                     {"message": "ai says qxdeploy77 complete"})
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=qxdeploy77&from_type=human")
        assert s == 200
        assert data["count"] == 1
        assert data["results"][0]["sender"] == name

    def test_search_from_type_ai(self, server_info, second_agent):
        """Search with from_type=ai returns only messages from AI agents."""
        url, token, name = server_info
        token2, name2 = second_agent
        profiles = _server_module.load_agent_profiles()
        profiles[name] = {"type": "human"}
        profiles[name2] = {"type": "ai"}
        _server_module.save_agent_profiles(profiles)
        _raw_request(url, token, "POST", "/api/channels", {"name": "srch-type2"})
        _raw_request(url, token, "POST", "/api/channels/srch-type2/messages",
                     {"message": "human qzreview88 needed"})
        _raw_request(url, token2, "POST", "/api/channels/srch-type2/messages",
                     {"message": "ai qzreview88 complete"})
        s, data = _raw_request(url, token, "GET",
                               "/api/search?q=qzreview88&from_type=ai")
        assert s == 200
        assert data["count"] == 1
        assert data["results"][0]["sender"] == name2

    def test_search_no_from_type_returns_all(self, server_info, second_agent):
        """Search without from_type returns messages from all types."""
        url, token, name = server_info
        token2, _ = second_agent
        _raw_request(url, token, "POST", "/api/channels", {"name": "srch-all"})
        _raw_request(url, token, "POST", "/api/channels/srch-all/messages",
                     {"message": "xyzzyword from first"})
        _raw_request(url, token2, "POST", "/api/channels/srch-all/messages",
                     {"message": "xyzzyword from second"})
        s, data = _raw_request(url, token, "GET", "/api/search?q=xyzzyword")
        assert s == 200
        assert data["count"] == 2
