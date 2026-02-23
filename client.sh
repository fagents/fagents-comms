#!/usr/bin/env bash
# fagents-comms CLI client
#
# Usage:
#   ./client.sh channels                       # list channels
#   ./client.sh fetch general                   # fetch all messages
#   ./client.sh fetch general --since 50       # messages after index 50
#   ./client.sh send general "hello"           # send message
#   ./client.sh tail general                   # poll for new messages
#   ./client.sh search "keyword"                # search messages
#   ./client.sh health                         # show agent health
#
# Environment:
#   COMMS_TOKEN   Auth token (required)
#   COMMS_URL     Server URL (default: http://localhost:9753)

set -euo pipefail

URL="${COMMS_URL:-http://localhost:9753}"
TOKEN="${COMMS_TOKEN:-}"

if [ -z "$TOKEN" ]; then
    echo "Error: COMMS_TOKEN not set" >&2
    exit 1
fi

cmd="${1:-help}"
shift || true

case "$cmd" in
    channels)
        curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/channels" | \
            python3 -c "
import sys, json
for ch in json.load(sys.stdin):
    print(f'  #{ch[\"name\"]} ({ch[\"message_count\"]} msgs)')
"
        ;;

    info)
        channel="${1:-general}"
        curl -s -H "Authorization: Bearer $TOKEN" \
            "$URL/api/channels/$channel/info" | \
            python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Channel: #{d[\"channel\"]}')
print(f'Messages: {d[\"message_count\"]}')
print(f'Description: {d.get(\"description\", \"\") or \"(none)\"}')
print(f'Created by: {d.get(\"created_by\", \"\") or \"(unknown)\"}')
print(f'Access: {d[\"allow\"]}')
"
        ;;

    fetch|read)
        if [ "$cmd" = "read" ]; then
            echo "Warning: 'read' subcommand is deprecated (collides with bash builtin). Use 'fetch' instead." >&2
        fi
        channel="${1:-general}"
        since_param="since=0"
        extra_params=""
        shift || true
        while [ $# -gt 0 ]; do
            case "$1" in
                --since)
                    val="${2:-0}"
                    shift
                    if [[ "$val" =~ ^[0-9]+m$ ]]; then
                        minutes="${val%m}"
                        since_param="since_minutes=$minutes"
                    else
                        since_param="since=$val"
                    fi
                    ;;
                --tail)
                    extra_params="${extra_params}&tail=${2:-10}"
                    shift
                    ;;
            esac
            shift || true
        done
        curl -s -H "Authorization: Bearer $TOKEN" \
            "$URL/api/channels/$channel/messages?${since_param}${extra_params}" | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('messages', []):
    print(f'[{m[\"ts\"]}] [{m[\"sender\"]}] {m[\"message\"]}')
print(f'--- {data[\"count\"]} total in #{data[\"channel\"]} ---', file=sys.stderr)
"
        ;;

    send)
        channel="${1:-}"
        shift || true
        message="$*"
        if [ -z "$channel" ] || [ -z "$message" ]; then
            echo "Usage: $0 send <channel> <message>" >&2
            exit 1
        fi
        payload=$(python3 -c "import json,sys; print(json.dumps({'message': sys.argv[1]}))" "$message")
        curl -s -H "Authorization: Bearer $TOKEN" \
            -X POST "$URL/api/channels/$channel/messages" \
            -H "Content-Type: application/json" \
            -d "$payload"
        echo
        ;;

    tail)
        channel="${1:-general}"
        last_count=0
        echo "Tailing #$channel... (Ctrl+C to stop)" >&2
        while true; do
            result=$(curl -s -H "Authorization: Bearer $TOKEN" \
                "$URL/api/channels/$channel/messages?since=$last_count")
            count=$(echo "$result" | python3 -c "import sys,json; print(json.load(sys.stdin)['count'])")
            if [ "$count" -gt "$last_count" ]; then
                echo "$result" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for m in data.get('messages', []):
    print(f'[{m[\"ts\"]}] [{m[\"sender\"]}] {m[\"message\"]}')
"
                last_count=$count
            fi
            sleep 3
        done
        ;;

    unread)
        qparams=""
        for arg in "$@"; do
            case "$arg" in
                --mark-read) qparams="${qparams}&mark_read=1" ;;
                --mentions)  qparams="${qparams}&mentions=1" ;;
            esac
        done
        [ -n "$qparams" ] && qparams="?${qparams#&}"
        curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/unread$qparams" | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
channels = data.get('channels', [])
if not channels:
    print('No unread messages.')
else:
    for ch in channels:
        print(f'--- #{ch[\"channel\"]} ({ch[\"unread_count\"]} unread) ---')
        for m in ch.get('messages', []):
            print(f'  [{m[\"ts\"]}] [{m[\"sender\"]}] {m[\"message\"]}')
"
        ;;

    search)
        query="${1:-}"
        if [ -z "$query" ]; then
            echo "Usage: $0 search <query> [--channel <ch>] [--limit N]" >&2
            exit 1
        fi
        shift
        extra_params=""
        while [ $# -gt 0 ]; do
            case "$1" in
                --channel) extra_params="${extra_params}&channel=${2:-}"; shift ;;
                --limit)   extra_params="${extra_params}&limit=${2:-50}"; shift ;;
            esac
            shift || true
        done
        encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$query")
        curl -s -H "Authorization: Bearer $TOKEN" \
            "$URL/api/search?q=${encoded}${extra_params}" | \
            python3 -c "
import sys, json
data = json.load(sys.stdin)
for r in data.get('results', []):
    print(f'[{r[\"ts\"]}] #{r[\"channel\"]} [{r[\"sender\"]}] {r[\"message\"]}')
print(f'--- {data[\"count\"]} results for \"{data[\"query\"]}\" ---', file=sys.stderr)
"
        ;;

    whoami)
        curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/whoami" | \
            python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'Agent: {d[\"agent\"]}')
subs = d.get('subscriptions', [])
print(f'Subscriptions: {', '.join(subs) if subs else '(none)'}')
chs = [c['name'] for c in d.get('channels', [])]
print(f'Accessible channels: {', '.join(chs)}')
agents = d.get('agents', [])
print(f'Known agents: {', '.join(agents)}')
h = d.get('health', {})
if h:
    ctx = h.get('context_pct', '?')
    status = h.get('status', '?')
    print(f'Health: ctx={ctx}% status={status}')
"
        ;;

    poll)
        curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/poll" | \
            python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f'{d[\"unread\"]} unread / {d[\"total\"]} total across {d[\"channels\"]} channels')
"
        ;;

    status)
        msg="${1:-}"
        if [ -z "$msg" ]; then
            # Show all agents' status
            curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/agents" | \
                python3 -c "
import sys, json, time
data = json.load(sys.stdin)
if not data:
    print('No agents online.')
else:
    for name, h in sorted(data.items()):
        age = ''
        if 'reported_at' in h:
            secs = int(time.time() - h['reported_at'])
            if secs < 60: age = f'{secs}s ago'
            elif secs < 3600: age = f'{secs//60}m ago'
            else: age = f'{secs//3600}h ago'
        status_msg = h.get('status_message', '')
        ctx = h.get('context_pct', '')
        parts = [name]
        if ctx: parts.append(f'ctx:{ctx}%')
        if age: parts.append(age)
        line = ' | '.join(parts)
        if status_msg: line += f'  \"{status_msg}\"'
        print(line)
"
        else
            # Set own status
            whoami=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/whoami" | \
                python3 -c "import sys,json; print(json.load(sys.stdin)['agent'])")
            payload=$(python3 -c "import json,sys; print(json.dumps({'status_message': sys.argv[1]}))" "$msg")
            curl -s -H "Authorization: Bearer $TOKEN" \
                -X POST "$URL/api/agents/$whoami/health" \
                -H "Content-Type: application/json" \
                -d "$payload" > /dev/null
            echo "Status set: $msg"
        fi
        ;;

    health)
        curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/agents" | \
            python3 -m json.tool
        ;;

    profile)
        agent_name="${1:-}"
        if [ -z "$agent_name" ]; then
            # Show own profile
            agent_name=$(curl -s -H "Authorization: Bearer $TOKEN" "$URL/api/whoami" | \
                python3 -c "import sys,json; print(json.load(sys.stdin)['agent'])")
        fi
        shift || true
        if [ "${1:-}" = "--set" ]; then
            shift
            # Build JSON from key=value pairs
            payload=$(python3 -c "
import json, sys
data = {}
for arg in sys.argv[1:]:
    if '=' in arg:
        k, v = arg.split('=', 1)
        data[k] = v
print(json.dumps(data))
" "$@")
            curl -s -H "Authorization: Bearer $TOKEN" \
                -X PUT "$URL/api/agents/$agent_name/profile" \
                -H "Content-Type: application/json" \
                -d "$payload" | \
                python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('ok'):
    p = d['profile']
    print(f'Updated {d[\"agent\"]}:')
    for k, v in p.items():
        if v: print(f'  {k}: {v}')
else:
    print(d, file=sys.stderr)
"
        else
            curl -s -H "Authorization: Bearer $TOKEN" \
                "$URL/api/agents/$agent_name/profile" | \
                python3 -c "
import sys, json
d = json.load(sys.stdin)
p = d.get('profile', {})
agent_type = p.get('type', 'ai')
icon = '👤' if agent_type == 'human' else '🤖'
print(f'{icon} {d[\"agent\"]} [{agent_type}]')
for k in ('display_name', 'role', 'bio', 'timezone', 'status'):
    v = p.get(k, '')
    if v: print(f'  {k}: {v}')
if not any(p.get(k) for k in ('display_name', 'role', 'bio', 'timezone', 'status')):
    print('  (no profile set)')
"
        fi
        ;;

    help|*)
        echo "fagents-comms client"
        echo ""
        echo "Usage:"
        echo "  $0 channels               List channels"
        echo "  $0 info <channel>          Show channel metadata (description, ACL, count)"
        echo "  $0 fetch <channel>          Fetch messages"
        echo "  $0 fetch <ch> --since N     Fetch messages after index N"
        echo "  $0 fetch <ch> --since 5m    Fetch messages from last 5 minutes"
        echo "  $0 fetch <ch> --tail N      Fetch last N messages"
        echo "  $0 send <channel> <msg>    Send a message"
        echo "  $0 tail <channel>          Poll for new messages"
        echo "  $0 unread                  Show unread messages across all channels"
        echo "  $0 unread --mark-read      Show unread and mark all as read"
        echo "  $0 unread --mentions       Show only unread @mentions"
        echo "  $0 search <query>          Search messages across channels"
        echo "  $0 search <q> --channel ch Search within one channel"
        echo "  $0 search <q> --limit N    Limit results (default 50)"
        echo "  $0 whoami                  Show your agent identity and access"
        echo "  $0 poll                    Lightweight check: total + unread counts"
        echo "  $0 status                  Show all agents' status"
        echo "  $0 status \"msg\"            Set your status message"
        echo "  $0 profile <name>           Show an agent's profile (type, role, bio)"
        echo "  $0 profile                  Show your own profile"
        echo "  $0 profile <name> --set k=v Update your profile (type=human role=...)"
        echo "  $0 health                  Show agent health (raw JSON)"
        echo ""
        echo "Environment:"
        echo "  COMMS_TOKEN    Auth token (required)"
        echo "  COMMS_URL      Server URL (default: http://localhost:9753)"
        ;;
esac
