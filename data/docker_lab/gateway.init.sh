#!/bin/bash
set -e

echo "[+] Enabling routing..."

echo 1 > /proc/sys/net/ipv4/ip_forward

echo "[+] Configuring iptables..."

# Accept forwarding
iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT

# MASQUERADE (THIS IS THE MISSING PIECE)
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

echo "[✓] Gateway ready"

ip addr
ip route
iptables -L
iptables -t nat -L

tail -f /dev/null