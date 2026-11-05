#!/bin/bash
# Seed a demo instance with realistic DFIR sessions for manual screenshots.
set -u
PORT=18450
BASE="http://127.0.0.1:$PORT"
DIR=/tmp/opencode/manual
STORE=$DIR/store
ADM="manual-demo-token"
AH="X-Admin-Token: $ADM"

rm -rf "$STORE"; mkdir -p "$STORE"
cd /home/taas0011/Projects/evidence_upload
export PATH=$PATH:/usr/local/go/bin
go build -o "$DIR/evidence-upload" . || exit 1
"$DIR/evidence-upload" -port $PORT -storage "$STORE" -no-browser -admin-token "$ADM" -alert-log "$DIR/alerts.log" >"$DIR/server.log" 2>&1 &
echo $! > "$DIR/server.pid"
for i in $(seq 1 30); do curl -sf "$BASE/api/baseurl" >/dev/null 2>&1 && break; sleep 0.3; done

# helper files
mkdir -p "$DIR/seed"
printf 'IP Detection Report\n===================\nLocal IP: 10.20.4.117\nPublic Internet IP: 203.0.113.44\nForwarded For: N/A\nReal IP Header: N/A\nProtocol: HTTP/1.1\nUser Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15\n' > "$DIR/seed/ip_detection_20261105.txt"
head -c 2621440 /dev/urandom > "$DIR/seed/memdump_host01.raw"
head -c 1048576 /dev/urandom > "$DIR/seed/triage_collection_host01.zip"
head -c 524288 /dev/urandom > "$DIR/seed/firewall_logs_export.csv"
head -c 2097152 /dev/urandom > "$DIR/seed/mailbox_export.pst"
head -c 327680 /dev/urandom > "$DIR/seed/browser_history_chrome.sqlite"

create_session() {
  curl -s -X POST "$BASE/admin/api/create" -H 'Content-Type: application/json' -H "$AH" \
    -d "{\"duration\": 86400000000000, \"description\": $1}"
}
upload() { # token secret file...
  local tok="$1" sec="$2"; shift 2
  local args=()
  for f in "$@"; do args+=(-F "files=@$f"); done
  curl -s -X POST "$BASE/api/upload" -F "token=$tok" -F "secret=$sec" "${args[@]}" >/dev/null
}

S1=$(create_session '"CASE-2026-0442 — Ransomware (Кристал)"')
T1=$(echo "$S1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
K1=$(echo "$S1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')
upload "$T1" "$K1" "$DIR/seed/ip_detection_20261105.txt" "$DIR/seed/memdump_host01.raw" "$DIR/seed/triage_collection_host01.zip" "$DIR/seed/firewall_logs_export.csv"

S2=$(create_session '"CASE-2026-0451 — Business Email Compromise"')
T2=$(echo "$S2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
K2=$(echo "$S2" | python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')
upload "$T2" "$K2" "$DIR/seed/ip_detection_20261105.txt" "$DIR/seed/mailbox_export.pst"

S3=$(create_session '"CASE-2026-0455 — Insider Threat (Jörg M.)"')
T3=$(echo "$S3" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
K3=$(echo "$S3" | python3 -c 'import sys,json;print(json.load(sys.stdin)["secret"])')
upload "$T3" "$K3" "$DIR/seed/ip_detection_20261105.txt" "$DIR/seed/browser_history_chrome.sqlite"

# save creds for the screenshot step
python3 - "$DIR" <<EOF
import json
json.dump({"s1": {"t": "$T1", "k": "$K1"}, "s2": {"t": "$T2", "k": "$K2"}, "s3": {"t": "$T3", "k": "$K3"}, "admin": "$ADM"}, open("$DIR/creds.json", "w"))
EOF

curl -s -H "$AH" "$BASE/admin/api/sessions" | python3 -c 'import sys,json; d=json.load(sys.stdin); [print(s["description"], "-", len(s["uploaded_files"]), "files") for s in d]'
echo "server pid: $(cat $DIR/server.pid)"
