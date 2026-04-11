#!/bin/bash

echo "[+] Configuring routing..."

IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -n1)
echo "[+] IP = $IP"

# wait a little for networking and gateway to be reachable
sleep 3

if [[ "$IP" =~ ^10\.0\.0\.(2|3|10|11|12)$ ]]; then
    ip route replace 10.0.0.16/28 via 10.0.0.1 || echo "[!] Route add failed for Subnet A host"
fi

if [[ "$IP" =~ ^10\.0\.0\.(18|19|26|27|28)$ ]]; then
    ip route replace 10.0.0.0/28 via 10.0.0.17 || echo "[!] Route add failed for Subnet B host"
fi

echo "[✓] Routes configured"
ip route || true

tail -f /dev/null