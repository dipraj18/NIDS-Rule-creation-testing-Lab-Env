#!/bin/bash
# snort_tests_auto.sh - safe, lab-only rule verification script with auto-detected target
# Usage: sudo ./snort_tests_auto.sh [TARGET]
# If TARGET is omitted the script will try to auto-detect the host ip (non-loopback).

set -euo pipefail

# Detect primary non-loopback IPv4 address and interface
DETECTED_IFACE=$(ip -o -4 addr show scope global | awk '{print $2; exit}' || true)
DETECTED_IP=$(ip -o -4 addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1 || true)

#Fallbacks
if [[ -z "$DETECTED_IFACE" || -z "$DETECTED_IP" ]]; then
  echo "[!] could not auto-detect an interface/IP. Falling back to 127.0.0.1"
  DETECTED_IFACE="lo"
  DETECTED_IP="127.0.0.1"
fi

TARGET="${1:-$DETECTED_IP}"

echo "Using interface: $DETECTED_IFACE"
echo "Using target: $TARGET"
echo "Make sure snort is running and monitoring the interfaces for $TARGET."
echo "Press Ctrl+C to abort now (5s)..."
sleep 5

# 1) ICMP test (should trigger ICMP rule)
echo -e "\n[1] ICMP test (ping $TARGET)"
ping -c 1 "$TARGET" || true
sleep 2

# 2) Small SYN scan (nmap -sS of first 100 ports) - light & short
echo -e "\n[2] Small SYN scan (nmap -sS 1-100) - short"
if command -v nmap >/dev/null 2>&1; then
  sudo nmap -sS -p 1-100 -T3 "$TARGET" >/dev/null || true
else
  echo "[!] nmap not found - skipping SYN scan"
fi
sleep 3

# 3) Port connect loop to simulate SSH connection attempts
echo -e "\n[3] Simulate multiple quick TCP connects to port 22 (SSH)"
for i in {1..6}; do
  timeout 1 bash -c "echo > /dev/tcp/$TARGET/22" 2>/dev/null ||true
  sleep 0.4
done
sleep 3
# 4) HTTP "login" request to trigger HTTP brute-force rule (if webserver present)
echo -e "\n[4] HTTP login-style requests (if webserver exists on $TARGET)"
if command -v curl >/dev/null 2>&1; then
  for i in {1..12}; do
    curl -s "http://$TARGET/?action=login" >/dev/null || true
    sleep 0.2
  done
else
   echo "[!] curl not found - skipping HTTP requests"
fi
sleep 3

# 5) SQL injection test (if webapp present)
echo -e "\n[5] SQLi-style test (if webapp exists on $TARGET)"
if command -v curl >/dev/null 2>&1; then
  curl -s "http://$TARGET/vuln.php?user=' OR '1'='1" >/dev/null || true
else
  echo "[!] curl not found - skipping SQLi test"
fi
sleep 2

# 6) DNS-style long test (if DNS port is monitored locally)
echo -e "\n[6] Send long UDP payload to port 53 (DNS test) - may be ignored if no DNS listener"
if command -v nc >/dev/null 2>&1; then
  printf 'a%.0s' {1..200} | nc -u -w1 "$TARGET" 53 2>/dev/null || true
else
  echo "[!] nc not found - skipping DNS test"
fi
sleep 2

# 7) NOP sled test - requires a listener on the target (run 'nc -l -p 4444 >/dev/null &' on targer first)
echo -e "\n[7] NOP sled test (requires a listener on port 4444 on $TARGET)"
python3 - <<PYCODE 2>/dev/null || true
import socket,sys
try:
   s=socket.socket()
   s.settimeout(2)
   s.connect(("$TARGET",4444))
   s.send(b"\x90"*200)
   s.close()
except Exception:
   pass
PYCODE
sleep 2
echo -e "\nAll test sent. Watch Snort console/logs for alerts (sids: 1000001,1000002,100003,100004 etc.)."
echo "Tip: Run Snort in Terminal A like this:"
echo "sudo snort -c /etc/snort/snort.lua -i $DETECTED_IFACE -A alert_fast"