# 🖧 Docker Enterprise Network Lab – Complete Network Diagram & Architecture

---

## 1. 🏗️ Network Topology Overview

                ┌───────────────────────────┐
                │        GATEWAY            │
                │     (Router Container)    │
                │---------------------------│
                │  eth0 → 10.0.0.1          │
                │  eth1 → 10.0.0.17         │
                └──────────┬────────────────┘
                           │
    ┌──────────────────────┴──────────────────────┐
    │                                             │

🌐 Subnet A (10.0.0.0/28)                🌐 Subnet B (10.0.0.16/28)
Docker GW: 10.0.0.14                    Docker GW: 10.0.0.30

┌─────────────────────────┐             ┌─────────────────────────┐
│        SERVERS          │             │        SERVERS          │
│-------------------------│             │-------------------------│
│ SRV-01 → 10.0.0.2       │             │ SRV-03 → 10.0.0.18      │
│ SRV-02 → 10.0.0.3       │             │ SRV-04 → 10.0.0.19      │
└─────────────────────────┘             └─────────────────────────┘

┌─────────────────────────┐             ┌─────────────────────────┐
│      WORKSTATIONS       │             │      WORKSTATIONS       │
│-------------------------│             │-------------------------│
│ WS-01 → 10.0.0.10       │             │ WS-04 → 10.0.0.26       │
│ WS-02 → 10.0.0.11       │             │ WS-05 → 10.0.0.27       │
│ WS-03 → 10.0.0.12       │             │ WS-06 → 10.0.0.28       │
└─────────────────────────┘             └─────────────────────────┘

---

## 2. 🌐 Subnet Definitions

### Subnet A
Network:            10.0.0.0/28  
Range:              10.0.0.0 – 10.0.0.15  
Gateway (Docker):   10.0.0.14  
Gateway (Custom):   10.0.0.1  

### Subnet B
Network:            10.0.0.16/28  
Range:              10.0.0.16 – 10.0.0.31  
Gateway (Docker):   10.0.0.30  
Gateway (Custom):   10.0.0.17  

---

## 3. 🖥️ Asset Inventory Mapping

### Subnet A Assets
10.0.0.2   → SRV-01 (Domain Controller)  
10.0.0.3   → SRV-02 (DNS/DHCP)  
10.0.0.10  → WS-01 (Finance Workstation)  
10.0.0.11  → WS-02 (HR Workstation)  
10.0.0.12  → WS-03 (Operations Workstation)  

### Subnet B Assets
10.0.0.18  → SRV-03 (File Server)  
10.0.0.19  → SRV-04 (Web/Application Server)  
10.0.0.26  → WS-04 (Sales Workstation)  
10.0.0.27  → WS-05 (Developer Workstation)  
10.0.0.28  → WS-06 (Data Scientist Workstation)  

---

## 4. 🔁 Traffic Flow

### 4.1 Same Subnet Communication

WS-01 (10.0.0.10)  
↓  
SRV-01 (10.0.0.2)  

### 4.2 Cross Subnet Communication

WS-01 (10.0.0.10)  
↓ route via 10.0.0.1  
Gateway (eth0)  
↓ forward  
Gateway (eth1)  
↓  
SRV-03 (10.0.0.18)  

---

## 5. ⚙️ Routing Logic

### Subnet A Hosts
ip route add 10.0.0.16/28 via 10.0.0.1  

### Subnet B Hosts
ip route add 10.0.0.0/28 via 10.0.0.17  

---

## 6. 🔐 Gateway Configuration

echo 1 > /proc/sys/net/ipv4/ip_forward  

iptables -A FORWARD -i eth0 -o eth1 -j ACCEPT  
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT  

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE  
iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE  

---

## 7. 🔍 Network Discovery Commands

docker exec -it ws_01 nmap -sn 10.0.0.0/28  
docker exec -it ws_01 nmap -sn 10.0.0.16/28  

---

## 8. 🧪 Validation Commands

docker ps  

docker exec -it ws_01 ip route  
docker exec -it gateway ip route  

docker exec -it ws_01 ping 10.0.0.2  
docker exec -it ws_01 ping 10.0.0.18  

docker exec -it ws_04 ping 10.0.0.2  

---

## 9. 🚀 Lab Operations

### Start Lab
docker compose up -d --build  

### Stop Lab
docker compose down  

### Clean Networks
docker network prune -f  

---
