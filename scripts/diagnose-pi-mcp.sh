#!/usr/bin/env bash
# diagnose-pi-mcp.sh - Check consistency between this MCP server binary and
# pi's cached tool metadata. Run this when pi shows MCP-related errors
# (e.g. "tools.function.parameters is not a valid moonshot flavored json
# schema") or when pi shows an outdated tool list after rebuilding.
#
# Exit code 0 = everything consistent; 1 = problem found (fix is printed).

set -u

MCP_JSON="$HOME/.pi/agent/mcp.json"
CACHE="$HOME/.pi/agent/mcp-cache.json"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="$REPO_ROOT/target/release/embedded-debugger-mcp"

info()  { printf '  %s\n' "$*"; }
ok()    { printf '  \033[32mOK\033[0m   %s\n' "$*"; }
bad()   { printf '  \033[31mFAIL\033[0m %s\n' "$*"; PROBLEM=1; }
PROBLEM=0

echo "== 1. pi MCP config ($MCP_JSON) =="
if [ ! -f "$MCP_JSON" ]; then
    bad "mcp.json not found; the embedded-debugger server is not configured in pi."
else
    CONFIG_CMD=$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
print(d.get("mcpServers",{}).get("embedded-debugger",{}).get("command",""))
' "$MCP_JSON" 2>/dev/null)
    if [ -z "$CONFIG_CMD" ]; then
        bad "no 'embedded-debugger' server entry in mcp.json."
    elif [ "$CONFIG_CMD" != "$BINARY" ]; then
        bad "mcp.json points to a different binary:"
        info "  config: $CONFIG_CMD"
        info "  repo:   $BINARY"
        info "  -> Fix: update 'command' in $MCP_JSON, then rm \"$CACHE\" and reload pi."
    else
        ok "config points to this repo's release binary."
    fi
fi

echo "== 2. Release binary =="
if [ ! -x "$BINARY" ]; then
    bad "release binary missing: $BINARY"
    info "  -> Fix: cargo build --release"
else
    ok "binary exists ($(stat -f '%Sm' "$BINARY"))."
fi

echo "== 3. Binary schema style (live tools/list) =="
BIN_STYLE=$(python3 - "$BINARY" <<'PY'
import json,subprocess,sys
p=subprocess.Popen([sys.argv[1],'serve'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                   stderr=subprocess.DEVNULL,text=True)
def send(o): p.stdin.write(json.dumps(o)+'\n'); p.stdin.flush()
try:
    send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2025-06-18","capabilities":{},
        "clientInfo":{"name":"diagnose","version":"1"}}})
    p.stdout.readline()
    send({"jsonrpc":"2.0","method":"notifications/initialized"})
    send({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}})
    resp=json.loads(p.stdout.readline())
    tools=resp.get('result',{}).get('tools',[])
    text=json.dumps(tools)
    style='old-definitions' if '#/definitions/' in text else 'defs'
    print(f"{style} {len(tools)}")
finally:
    p.kill()
PY
)
BIN_REFS=$(echo "$BIN_STYLE" | cut -d' ' -f1)
BIN_TOOLS=$(echo "$BIN_STYLE" | cut -d' ' -f2)
if [ "$BIN_REFS" = "defs" ]; then
    ok "binary emits \$defs-style schemas ($BIN_TOOLS tools)."
else
    bad "binary emits old #/definitions/ schemas — rebuild from current sources:"
    info "  -> Fix: cargo build --release"
fi

echo "== 4. pi metadata cache ($CACHE) =="
if [ ! -f "$CACHE" ]; then
    ok "no cache file; pi will fetch fresh metadata from the binary on next start."
else
    if grep -q '#/definitions/' "$CACHE"; then
        bad "cache contains old #/definitions/ schemas (stale, from a previous build)."
        info "  -> Fix: rm \"$CACHE\" then reload pi."
    else
        ok "cache has no old-style refs."
    fi
    CACHE_TOOLS=$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
e=d.get("servers",{}).get("embedded-debugger")
print(len(e["tools"]) if e else -1)
' "$CACHE" 2>/dev/null)
    if [ "$CACHE_TOOLS" = "-1" ]; then
        info "cache has no embedded-debugger entry; pi will fetch on next start."
    elif [ "$CACHE_TOOLS" != "$BIN_TOOLS" ]; then
        bad "cache has $CACHE_TOOLS tools but the binary exposes $BIN_TOOLS (stale tool list)."
        info "  -> Fix: rm \"$CACHE\" then reload pi."
    else
        ok "cache tool count matches binary ($BIN_TOOLS)."
    fi
fi

echo "== 5. Leftover server processes =="
LEFTOVER=$(pgrep -fl 'embedded-debugger-mcp serve' || true)
if [ -n "$LEFTOVER" ]; then
    info "running server process(es) (keep-alive is normal while pi is open):"
    info "$LEFTOVER"
    info "If pi was reloaded but errors persist, kill them: pkill -f 'embedded-debugger-mcp serve'"
else
    ok "no running server processes."
fi

echo
if [ "$PROBLEM" = "0" ]; then
    echo "RESULT: all checks passed. If pi still errors, reload pi (cache refreshes on start)."
else
    echo "RESULT: problem(s) found — apply the '-> Fix:' hints above, then reload pi."
fi
exit "$PROBLEM"
