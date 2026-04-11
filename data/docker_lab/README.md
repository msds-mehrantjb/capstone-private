# docker_lab (no lab_services)

This folder contains a simplified Docker lab with no per-role service folders.
All non-gateway hosts use one generic image: `host.Dockerfile`.
The lab is enough to:
- bring the environment up
- validate the merged config
- assess the running network
- generate `AssetInventory.json`

## Files in this folder
- `docker-compose.yml`
- `gateway.Dockerfile`
- `gateway.init.sh`
- `host.Dockerfile`
- `host.init.sh`
- `merged_lab_config.json`
- `validate_lab.py`
- `assess_network.py`

```cmd 
start "" "C:\Program Files\Docker\Docker\Docker Desktop.exe"
```
```cmd
docker version
docker info
```

## Step-by-step (Windows Terminal)

### 1) Open the folder
```cmd
cd C:\path	o\docker_lab
```

### 2) Start and build the lab
```cmd
docker compose up -d --build
```

### 3) Confirm containers are running
```cmd
docker ps
```

You should see these containers:
- gateway
- srv_01
- srv_02
- srv_03
- srv_04
- ws_01
- ws_02
- ws_03
- ws_04
- ws_05
- ws_06

### 4) Validate the merged lab configuration
```cmd
python validate_lab.py
```

Expected result:
```text
Validation passed.
```

### 5) Assess the running lab and generate the inventory
```cmd
python assess_network.py
```

Expected output file created in the same folder:
```text
AssetInventory.json
```

### 6) View the generated inventory
```cmd
type AssetInventory.json
```

### 7) Optional connectivity checks
Same subnet:
```cmd
docker exec -it ws_01 ping 10.0.0.2
```

Cross subnet:
```cmd
docker exec -it ws_01 ping 10.0.0.18
```

Cross subnet from the other side:
```cmd
docker exec -it ws_04 ping 10.0.0.2
```

Manual network scan:
```cmd
docker exec -it ws_01 nmap -sn 10.0.0.0/28
docker exec -it ws_01 nmap -sn 10.0.0.16/28
```

### 8) Stop the lab
```cmd
docker compose down
docker rm -f ws_03 ws_01 ws_02 ws_04 ws_05 ws_06 srv_01 srv_02 srv_03 srv_04 gateway
docker network prune -f
```

## Notes
- This simplified lab does not simulate different host services with separate service folders.
- It is intended for lab startup, config validation, subnet reachability, and asset assessment.
- `AssetInventory.json` is generated only after you run `python assess_network.py`.
