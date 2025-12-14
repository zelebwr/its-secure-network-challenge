#!/bin/bash

# ==========================================
# AUTOMATED SURICATA + MIKROTIK TZSP SETUP
# For Debian 12 (Bookworm) / 11 (Bullseye)
# ==========================================

# Colors for pretty output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
  echo -e "${RED}Please run as root (sudo ./setup_ids.sh)${NC}"
  exit
fi

echo -e "${BLUE}[1/6] Updating System and Installing Dependencies...${NC}"
apt-get update
# Install Suricata, Python tools, and Bridge utilities
# specific version of Suricata might be needed, but default repo is usually fine for labs
DEBIAN_FRONTEND=noninteractive apt-get install -y suricata python3-scapy python3-netifaces bridge-utils net-tools curl

echo -e "${BLUE}[2/6] Configuring Dummy Interface (dummy0)...${NC}"
# Load dummy module
modprobe dummy
# Create the interface now
ip link add dummy0 type dummy 2>/dev/null
ip link set dummy0 up
ip link set dummy0 arp off
ip link set dummy0 multicast off

# Make it persistent (survive reboot)
cat > /etc/modules-load.d/dummy.conf <<EOF
dummy
EOF

# Add to interfaces file if not exists
if ! grep -q "iface dummy0" /etc/network/interfaces; then
cat >> /etc/network/interfaces <<EOF

# Virtual Interface for IDS Inspection
auto dummy0
iface dummy0 inet manual
    pre-up ip link add dummy0 type dummy
    up ip link set dummy0 up
    up ip link set dummy0 arp off
    up ip link set dummy0 multicast off
EOF
fi

echo -e "${BLUE}[3/6] Creating TZSP Decapsulator Script...${NC}"
# We place this in /usr/local/bin for global access
cat > /usr/local/bin/tzsp_stripper.py <<'PYTHON_EOF'
#!/usr/bin/env python3
from scapy.all import *
import socket
import os

# Configuration
LISTEN_IP = "10.99.99.2"    # The IP of this IDS Server
LISTEN_PORT = 37008         # Default MikroTik TZSP port
TARGET_IFACE = "dummy0"     # The interface Suricata listens to

print(f"[*] Starting TZSP Stripper Service")
print(f"[*] Listening on {LISTEN_IP}:{LISTEN_PORT}")
print(f"[*] Forwarding to {TARGET_IFACE}")

# Create a socket to catch the raw UDP packets
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.bind((LISTEN_IP, LISTEN_PORT))
except OSError as e:
    print(f"[!] Error binding to port: {e}")
    exit(1)

while True:
    try:
        # Receive packet (Max UDP size)
        data, addr = sock.recvfrom(65535)
        
        # MikroTik TZSP headers are 5 bytes (Version + Type + Protocol + etc)
        # We strip the first 5 bytes to get the encapsulated Ethernet frame
        if len(data) > 5:
            inner_packet = data[5:]
            # Inject packet into dummy interface
            sendp(Ether(inner_packet), iface=TARGET_IFACE, verbose=False)
            
    except KeyboardInterrupt:
        break
    except Exception as e:
        # Continue running even if a packet is malformed
        pass
PYTHON_EOF

chmod +x /usr/local/bin/tzsp_stripper.py

echo -e "${BLUE}[4/6] Creating Systemd Service for Decapsulator...${NC}"
# This ensures the python script runs automatically in the background
cat > /etc/systemd/system/tzsp-stripper.service <<EOF
[Unit]
Description=MikroTik TZSP Packet Stripper
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/tzsp_stripper.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# Enable and Start the service
systemctl daemon-reload
systemctl enable tzsp-stripper
systemctl restart tzsp-stripper

echo -e "${BLUE}[5/6] Configuring Suricata...${NC}"
# Backup original config
cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak

# Update HOME_NET to match your internal subnets (10.20.0.0/16)
# We use sed to replace the default HOME_NET line
sed -i 's/HOME_NET: "\[192.168.0.0\/16,10.0.0.0\/8,172.16.0.0\/12\]"/HOME_NET: "\[10.20.0.0\/16\]"/' /etc/suricata/suricata.yaml

# Update Interface from eth0 to dummy0
# We look for the af-packet section and replace eth0
sed -i 's/interface: eth0/interface: dummy0/' /etc/suricata/suricata.yaml

# Download latest rules
echo "Updating Suricata Rules (this might take a moment)..."
suricata-update

echo -e "${BLUE}[6/6] Starting Services...${NC}"
systemctl restart suricata

echo -e "${GREEN}==============================================${NC}"
echo -e "${GREEN}   INSTALLATION COMPLETE!   ${NC}"
echo -e "${GREEN}==============================================${NC}"
echo -e "1. Check the TZSP Stripper status: ${BLUE}systemctl status tzsp-stripper${NC}"
echo -e "2. Check Suricata status:          ${BLUE}systemctl status suricata${NC}"
echo -e "3. View Alerts Live:               ${BLUE}tail -f /var/log/suricata/fast.log${NC}"
echo -e ""
echo -e "Wait about 30 seconds for Suricata to load all rules before testing."