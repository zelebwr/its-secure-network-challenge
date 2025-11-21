# Configuration Scripting Export

Here are the full scripting we did to every network node in our work for the network security challenge.

## A. Router Configuration

### 1. Edge Router Configuration Export

Here is the configuration export for the MikroTIk Router for the Edge Router

```bash
[admin@EdgeRouter-ITS] > /export
# 2025-11-21 11:12:55 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] comment="WAN - To Internet (GNS3 NAT Cloud)" \
    disable-running-check=no
set [ find default-name=ether2 ] comment="LAN - To Core Firewall (10.0.0.2)" disable-running-check=\
    no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/port
set 0 name=serial0
/ip address
add address=10.0.0.1/30 interface=ether2 network=10.0.0.0
/ip dhcp-client
add interface=ether1
/ip firewall address-list
add address=10.0.0.2 list=SAFE_MANAGEMENT
add address=10.1.40.0/30 list=SAFE_MANAGEMENT
add address=10.20.40.0/24 list=SAFE_MANAGEMENT
/ip firewall filter
add action=accept chain=input comment="Allow Established Connections" connection-state=\
    established,related
add action=accept chain=input comment="Allow Ping (Limited)" protocol=icmp
add action=accept chain=input comment="Allow Management from Core Firewall Only" src-address=\
    10.0.0.2
add action=accept chain=input comment="Allow Admin Management" src-address-list=SAFE_MANAGEMENT
add action=drop chain=input comment="DROP All External Access to Router" in-interface=ether1
add action=drop chain=input comment="DROP ALL OTHER MANAGEMENT"
/ip firewall nat
add action=masquerade chain=srcnat out-interface=ether1
add action=dst-nat chain=dstnat comment="Port Forward HTTP to Web Server" dst-port=80 in-interface=\
    ether1 protocol=tcp to-addresses=10.20.60.10 to-ports=80
add action=dst-nat chain=dstnat comment="Port Forward HTTPS to Web Server" dst-port=443 \
    in-interface=ether1 protocol=tcp to-addresses=10.20.60.10 to-ports=443
add action=dst-nat chain=dstnat comment="Port Forward DNS to DNS Server" dst-port=53 in-interface=\
    ether1 protocol=udp to-addresses=10.20.60.11 to-ports=53
add action=dst-nat chain=dstnat comment="Port Forward DNS TCP to DNS Server" dst-port=53 \
    in-interface=ether1 protocol=tcp to-addresses=10.20.60.11 to-ports=53
add action=dst-nat chain=dstnat comment="Port Forward SMTP to Mail Server" dst-port=25 \
    in-interface=ether1 protocol=tcp to-addresses=10.20.60.11 to-ports=25
add action=dst-nat chain=dstnat comment="Port Forward Submission to Mail Server" dst-port=587 \
    in-interface=ether1 protocol=tcp to-addresses=10.20.60.11 to-ports=587
add action=dst-nat chain=dstnat comment="Port Forward IMAPS to Mail Server" dst-port=993 \
    in-interface=ether1 protocol=tcp to-addresses=10.20.60.11 to-ports=993
/ip route
add comment="Router Links" dst-address=10.1.0.0/16 gateway=10.0.0.2
add comment="Clients (Admin, Student, DMZ)" dst-address=10.20.0.0/18 gateway=10.0.0.2
/radius
add address=10.20.40.10 service=login timeout=3s
add address=10.20.40.10 service=login timeout=3s
/snmp
set contact=admin@its.ac.id enabled=yes location="ITS Network Infrastructure"
/system identity
set name=EdgeRouter-ITS
/system note
set note="My config is saved!" show-at-login=no
/user aaa
set use-radius=yes
```

### 2. Firewall Configuration Export

Here is the configuration export for the MikroTik Router for the Firewall

```bash
[admin@Firewall] > /export
# 2025-11-21 11:03:52 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/port
set 0 name=serial0
/ip address
add address=10.0.0.2/30 interface=ether1 network=10.0.0.0
add address=10.1.40.1/30 interface=ether2 network=10.1.40.0
add address=10.1.20.1/30 interface=ether3 network=10.1.20.0
add address=10.1.30.1/30 interface=ether4 network=10.1.30.0
add address=10.1.10.1/30 interface=ether5 network=10.1.10.0
add address=10.1.50.1/30 interface=ether6 network=10.1.50.0
add address=10.1.60.1/30 interface=ether7 network=10.1.60.0
/ip firewall address-list
add address=10.20.40.0/24 list=NET_ADMIN
add address=10.20.20.0/24 list=NET_AKADEMIK
add address=10.20.30.0/24 list=NET_IOT
add address=10.20.8.0/22 list=NET_MAHASISWA
add address=10.20.48.0/22 list=NET_GUEST
add address=10.20.60.0/24 list=NET_DMZ
add address=10.1.0.0/16 list=NET_INFRA
add address=10.1.40.2 comment="Admin Router Uplink" list=NET_ADMIN
add address=10.1.60.2 comment="DMZ Router Uplink" list=NET_DMZ
/ip firewall filter
add action=accept chain=input comment="Allow Established/Related Connections" connection-state=\
    established,related,untracked
add action=drop chain=input comment="Drop Invalid Connections" connection-state=invalid
add action=accept chain=input comment="Allow Admin Access (SSH/Winbox)" src-address-list=NET_ADMIN
add action=accept chain=input comment="Allow ICMP (Ping) - Limited" limit=5,10:packet protocol=icmp
add action=drop chain=input comment="DROP ALL other Traffic to Firewall"
add action=accept chain=forward comment="FastTrack Established/Related" connection-state=\
    established,related,untracked
add action=drop chain=forward comment="Drop Invalid" connection-state=invalid
add action=jump chain=forward comment="Jump: Traffic FROM Admin" jump-target=from_admin \
    src-address-list=NET_ADMIN
add action=jump chain=forward comment="Jump: Traffic FROM Akademik" jump-target=from_akademik \
    src-address-list=NET_AKADEMIK
add action=jump chain=forward comment="Jump: Traffic FROM Mahasiswa" jump-target=from_mahasiswa \
    src-address-list=NET_MAHASISWA
add action=jump chain=forward comment="Jump: Traffic FROM IoT" jump-target=from_iot \
    src-address-list=NET_IOT
add action=jump chain=forward comment="Jump: Traffic FROM Guest" jump-target=from_guest \
    src-address-list=NET_GUEST
add action=jump chain=forward comment="Jump: Traffic FROM DMZ" jump-target=from_dmz \
    src-address-list=NET_DMZ
add action=accept chain=from_admin comment="Admin -> ANY"
add action=accept chain=from_akademik comment="Akademik -> Internet" out-interface=ether1
add action=accept chain=from_akademik comment="Akademik -> DNS (Internal)" dst-address=10.20.60.11 \
    dst-port=53 protocol=udp
add action=accept chain=from_akademik comment="Akademik -> DNS (Internal)" dst-address=10.20.60.11 \
    dst-port=53 protocol=tcp
add action=accept chain=from_akademik comment="Akademik -> IoT (Data Collection)" dst-address-list=\
    NET_IOT
add action=drop chain=from_akademik comment="DROP Akademik -> Any Internal" dst-address=10.0.0.0/8 \
    log=yes log-prefix=AKD_BLOCK:
add action=accept chain=from_mahasiswa comment="MHS -> DNS (Internal)" dst-address=10.20.60.11 \
    dst-port=53 protocol=udp
add action=accept chain=from_mahasiswa comment="MHS -> DNS (Internal)" dst-address=10.20.60.11 \
    dst-port=53 protocol=tcp
add action=drop chain=from_mahasiswa comment="BLOCK MHS -> Internal Networks" dst-address=\
    10.0.0.0/8 log=yes log-prefix=MHS_BLOCKED:
add action=accept chain=from_mahasiswa comment="MHS -> Internet" out-interface=ether1
add action=accept chain=from_guest comment="Guest -> DNS (Internal)" dst-address=10.20.60.11 \
    dst-port=53 protocol=udp
add action=drop chain=from_guest comment="BLOCK Guest -> Internal Networks" dst-address=10.0.0.0/8 \
    log=yes log-prefix=GUEST_BLOCK:
add action=accept chain=from_guest comment="Guest -> Internet" out-interface=ether1
add action=accept chain=from_iot comment="IoT -> MQTT Server (If needed)" dst-address=10.20.30.20 \
    dst-port=1883 protocol=tcp
add action=accept chain=from_iot comment="IoT -> Internet" out-interface=ether1
add action=drop chain=from_iot comment="DROP IoT -> All Internal" log=yes log-prefix=IOT_BLOCK:
add action=accept chain=from_dmz comment="DMZ -> Internet (Updates)" out-interface=ether1
add action=drop chain=from_dmz comment="DROP DMZ -> Internal (Safety Net)" dst-address=10.0.0.0/8 \
    log=yes log-prefix=DMZ_BLOCK:
add action=accept chain=forward comment="Allow Public Internet to DMZ" dst-address-list=NET_DMZ \
    dst-port=80,443,25,587,993 in-interface=ether1 protocol=tcp
add action=drop chain=forward comment="DROP ALL Unexpected Forward Traffic" log=yes log-prefix=\
    FINAL_DROP:
/ip route
add dst-address=0.0.0.0/0 gateway=10.0.0.1
add dst-address=10.20.40.0/24 gateway=10.1.40.2
add dst-address=10.20.20.0/24 gateway=10.1.20.2
add dst-address=10.20.30.0/24 gateway=10.1.30.2
add dst-address=10.20.10.0/22 gateway=10.1.10.2
add dst-address=10.20.50.0/22 gateway=10.1.50.2
add dst-address=10.20.60.0/24 gateway=10.1.60.2
add dst-address=10.20.60.0/24 gateway=10.1.60.2
/system identity
set name=Firewall
/system note
set show-at-login=no
```

### 3. Admin Configuration Export

Here is the configuration export for the MikroTik Router for the Admin

```bash
[admin@Admin] > /export
# 2025-11-21 11:10:29 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_admin ranges=10.20.40.10-10.20.40.254
/ip dhcp-server
add address-pool=pool_admin interface=ether2 name=dhcp_admin
/port
set 0 name=serial0
/ip address
add address=10.1.40.2/30 interface=ether1 network=10.1.40.0
add address=10.20.40.1/24 interface=ether2 network=10.20.40.0
/ip dhcp-server network
add address=10.20.40.0/24 dns-server=8.8.8.8 gateway=10.20.40.1
/ip route
add dst-address=0.0.0.0/0 gateway=10.1.40.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=Admin
/system note
set show-at-login=no
```

### 4. Akademik Configuration Export

Here is the configuration export for the MikroTik Router for the Akademik

```bash 
[admin@Akademik] > /export
# 2025-11-21 11:09:57 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_akademik ranges=10.20.20.10-10.20.20.254
/ip dhcp-server
add address-pool=pool_akademik interface=ether2 name=dhcp_akademik
/port
set 0 name=serial0
/ip address
add address=10.1.20.2/30 interface=ether1 network=10.1.20.0
add address=10.20.20.1/24 interface=ether2 network=10.20.20.0
/ip dhcp-server network
add address=10.20.20.0/24 dns-server=8.8.8.8 gateway=10.20.20.1
/ip route
add dst-address=0.0.0.0/0 gateway=10.1.20.1
add comment="route -> Mahasiswa" dst-address=10.20.8.0/22 gateway=10.1.20.1
add comment="route -> Riset&IoT" dst-address=10.20.30.0/24 gateway=10.1.20.1
add comment="route -> Admin" dst-address=10.20.40.0/24 gateway=10.1.20.1
add comment="route -> Guest" dst-address=10.20.48.0/22 gateway=10.1.20.1
add comment="route -> DMZ/DNS" dst-address=10.20.60.0/24 gateway=10.1.20.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=Akademik
/system note
set show-at-login=no
```

### 5. Riset & IoT Configuration Export

Here is the configuration export for the MikroTik Router for the Riset & IoT

```bash
[admin@Riset-dan-IOT] > /export
# 2025-11-21 11:09:22 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_riset ranges=10.20.30.10-10.20.30.254
/ip dhcp-server
add address-pool=pool_riset interface=ether2 name=dhcp_riset
/port
set 0 name=serial0
/ip address
add address=10.1.30.2/30 interface=ether1 network=10.1.30.0
add address=10.20.30.1/24 interface=ether2 network=10.20.30.0
/ip dhcp-server network
add address=10.20.30.0/24 dns-server=8.8.8.8 gateway=10.20.30.1
/ip route
add dst-address=0.0.0.0/0 gateway=10.1.30.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=Riset-dan-IOT
/system note
set show-at-login=no
```

### 6. Mahasiswa Configuration Export

Here is the configuration export for the MikroTik Router for the Mahasiswa

```bash 
[admin@Mahasiswa] > /export
# 2025-11-21 11:08:36 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_mahasiswa ranges=10.20.10.10-10.20.10.254
/ip dhcp-server
add address-pool=pool_mahasiswa interface=ether2 name=dhcp_mahasiswa
/port
set 0 name=serial0
/ip address
add address=10.1.10.2/30 interface=ether1 network=10.1.10.0
add address=10.20.10.1/22 interface=ether2 network=10.20.8.0
/ip dhcp-server network
add address=10.20.8.0/22 dns-server=10.20.60.11 gateway=10.20.10.1
/ip route
add comment="Default to Firewall" dst-address=0.0.0.0/0 gateway=10.1.10.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=Mahasiswa
/system note
set note="My config is saved!" show-at-login=no
```

### 7. Guest Configuration Export

Here is the configuration export for the MikroTik Router for the Guest

```bash
[admin@Guest] > /export
# 2025-11-21 11:07:47 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_guest ranges=10.20.50.10-10.20.50.254
/ip dhcp-server
add address-pool=pool_guest interface=ether2 name=dhcp_guest
/port
set 0 name=serial0
/ip address
add address=10.1.50.2/30 interface=ether1 network=10.1.50.0
add address=10.20.50.1/22 interface=ether2 network=10.20.48.0
/ip dhcp-server network
add address=10.20.48.0/22 dns-server=8.8.8.8 gateway=10.20.50.1
/ip route
add dst-address=0.0.0.0/0 gateway=10.1.50.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=Guest
/system note
set show-at-login=no
```

### 8. DMZ Configuration Export

Here is the configuration export for the MikroTik Router for the DMZ

```bash
[admin@DMZ] > /export
# 2025-11-21 11:06:30 by RouterOS 7.16
# software id =
#
/interface ethernet
set [ find default-name=ether1 ] disable-running-check=no
set [ find default-name=ether2 ] disable-running-check=no
set [ find default-name=ether3 ] disable-running-check=no
set [ find default-name=ether4 ] disable-running-check=no
set [ find default-name=ether5 ] disable-running-check=no
set [ find default-name=ether6 ] disable-running-check=no
set [ find default-name=ether7 ] disable-running-check=no
set [ find default-name=ether8 ] disable-running-check=no
/ip pool
add name=pool_dmz ranges=10.20.60.10-10.20.60.254
/ip dhcp-server
add address-pool=pool_dmz interface=ether2 name=dhcp_dmz
/port
set 0 name=serial0
/ip address
add address=10.1.60.2/30 interface=ether1 network=10.1.60.0
add address=10.20.60.1/24 interface=ether2 network=10.20.60.0
/ip dhcp-server network
add address=10.20.60.0/24 dns-server=8.8.8.8 gateway=10.20.60.1
/ip firewall filter
add action=accept chain=input comment="Allow Established" connection-state=established,related
add action=accept chain=input comment="Allow Ping" protocol=icmp
add action=accept chain=input comment="Allow Management from Core" src-address=10.0.0.2
add action=drop chain=input comment="DROP All External Access" in-interface=ether1
/ip firewall nat
add action=masquerade chain=srcnat comment="Internet Access" out-interface=ether1
/ip route
add dst-address=0.0.0.0/0 gateway=10.1.60.1
/ip service
set www disabled=yes
set ssh address=10.20.40.0/24
/system identity
set name=DMZ
/system note
set show-at-login=no
```

## B. End Devices Configuration

### 1. Network Node Interface Configuration

#### a. PC-GUEST1 End Device Configuration

Here is the configuration for the end device `PC-GUEST1` in `/etc/network/interfaces`

```bash
# /etc/netwrok/interfaces

source /etc/network/interfaces.d/*
# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for enp2s0
auto enp2s0
iface enp2s0 inet dhcp
```

#### b. PC-GUEST2 End Device Configuration

Here is the configuration for the end device `PC-GUEST2` in `/etc/network/interfaces`

```bash
# /etc/

source /etc/network/interfaces.d/*
# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for enp2s0
auto enp2s0
iface enp2s0 inet dhcp
```

#### c. PC-MAHASISWA1 End Device Configuration

Here is the configuration for the end device `PC-MAHASISWA1` in `/etc/network/interfaces`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for enp2s0
auto enp2s0
iface enp2s0 inet dhcp
```

#### d. PC-MAHASISWA2 End Device Configuration

Here is the configuration for the end device `PC-MAHASISWA2` in `/etc/network/interfaces`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for enp2s0
auto enp2s0
iface enp2s0 inet dhcp
```

### 2. Riset & IoT Configuration Service

#### a. Server Service 

Here is a table that describes the service on the `Riset&IoT` router.

| Server Role              | Functionality                                                |
| ------------------------ | ------------------------------------------------------------ |
| IotT Broker (MQTT/Kafka) | Gather real-time data from the vulnerable IoT                |
| Lab/Compute Server       | Processing research data that needs a high computation power |

#### b. IoTBroker End Device Configuration

Here is the configuration for the end device `IoTBroker` in `/etc/network/interfaces`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for ens4
#auto ens4
#iface ens4 inet dhcp

# Static config for enp2s0
auto enp2s0
iface enp2s0 inet static
        address 10.20.30.10
        netmask 255.255.255.0
        gateway 10.20.30.1
        dns-nameservers 8.8.8.8
```

Here is the configuration for the end device `IoTBroker` in `~/.bashrc`

```bash
#~/.bashrc

cat > setup-iot.sh <<'EOF'
#!/bin/bash

# --- KONFIGURASI VARIABEL ---
IFACE="enp2s0"
IP_ADDR="10.20.30.10/24"
GATEWAY="10.20.30.1"

echo "=== 1. Mengaktifkan Interface Jaringan ==="
sudo ip link set $IFACE up
sudo ip addr flush dev $IFACE
sudo ip addr add $IP_ADDR dev $IFACE
sudo ip route add default via $GATEWAY

echo "=== 2. Set DNS Google ==="
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

echo "=== 3. Cek Koneksi Internet ==="
sleep 2
if ping -c 2 google.com > /dev/null 2>&1; then
    echo ">> Internet OK! Melanjutkan instalasi..."
    
    echo "=== 4. Install Mosquitto MQTT Broker ==="
    sudo apt update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y mosquitto mosquitto-clients

    echo "=== 5. Konfigurasi Mosquitto (Allow Remote Access) ==="
    # Secara default mosquitto memblokir akses luar, kita buka port 1883
    sudo bash -c 'cat > /etc/mosquitto/mosquitto.conf <<EOL
listener 1883
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
EOL'

    echo "=== 6. Restart Service ==="
    sudo systemctl enable mosquitto
    sudo systemctl restart mosquitto

    echo "=== STATUS: SIAP ==="
    echo "IoT Broker berjalan di IP: $IP_ADDR Port 1883"
    sudo systemctl status mosquitto --no-pager
else
    echo ">> GAGAL! Tidak ada koneksi internet. Cek kabel ke Mikrotik/NAT."
fi
EOF

# --- Eksekusi Script ---
chmod +x setup-iot.sh
sudo bash setup-iot.sh
```

#### c. LabServer End Device Configuration

Here is the configuration for the end device `LabServer` in `/etc/network/interfaces`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for ens4
#auto ens4
#iface ens4 inet dhcp

# Static config for enp2s0
auto enp2s0
iface enp2s0 inet static
        address 10.20.30.20
        netmask 255.255.255.0
        gateway 10.20.30.1
        dns-nameservers 8.8.8.8
```

Here is the configuration for the end device `IoTBroker` in `~/.bashrc`\

```bash
# ~/.bashrc

cat > setup-compute.sh <<'EOF'
#!/bin/bash

# --- KONFIGURASI VARIABEL ---
IFACE="enp2s0"
IP_ADDR="10.20.30.20/24"
GATEWAY="10.20.30.1"

echo "=== 1. Mengaktifkan Interface Jaringan ==="
sudo ip link set $IFACE up
sudo ip addr flush dev $IFACE
sudo ip addr add $IP_ADDR dev $IFACE
sudo ip route add default via $GATEWAY

echo "=== 2. Set DNS Google ==="
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

echo "=== 3. Cek Koneksi Internet ==="
sleep 2
if ping -c 2 google.com > /dev/null 2>&1; then
    echo ">> Internet OK! Melanjutkan instalasi..."
    
    echo "=== 4. Install Apache & Python ==="
    sudo apt update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y apache2 python3

    echo "=== 5. Buat Dashboard Simulasi ==="
    sudo bash -c 'cat > /var/www/html/index.html <<EOL
<html>
<head>
  <title>Lab Compute Server</title>
  <style>body{background-color:#222;color:#0f0;font-family:monospace;padding:50px;}</style>
</head>
<body>
  <h1>⚡ HIGH PERFORMANCE COMPUTING LAB ⚡</h1>
  <p>IP Address: 10.20.30.20</p>
  <p>Status: <span style="color:yellow;animation:blink 1s infinite;">PROCESSING DATA...</span></p>
  <hr>
  <p>Current Job: Analysis of IoT Sensor Array</p>
  <p>CPU Load: 88% | RAM Usage: 12GB/16GB</p>
</body>
</html>
EOL'

    echo "=== 6. Buat Script Python Dummy (Opsional) ==="
    cat > /home/debian/simulasi_riset.py <<PY
import time, random
print("Memulai kalkulasi data riset...")
while True:
    val = random.randint(1000,9999)
    print(f"Processing Batch ID: {val} - [OK]")
    time.sleep(2)
PY

    echo "=== 7. Restart Service ==="
    sudo systemctl enable apache2
    sudo systemctl restart apache2

    echo "=== STATUS: SIAP ==="
    echo "Compute Server berjalan. Akses web di http://10.20.30.20"
    ip addr show $IFACE | grep inet
else
    echo ">> GAGAL! Tidak ada koneksi internet. Cek kabel ke Mikrotik/NAT."
fi
EOF

# --- Eksekusi Script ---
chmod +x setup-compute.sh
sudo bash setup-compute.sh
```

### 3. Akademik Configuration Service

#### a. Server Service

| Server Role               | Functionality                                    |
| ------------------------- | ------------------------------------------------ |
| File Server (Samba/NFS)   | Saving Data/sensitive document                   |
| Database Server (SIA/LMS) | Provide structured data for the main application |

#### b. FileServer End Device Configuration

Here is the configuration for the end device `FileServer` in `/.bashrc`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for ens4
#auto ens4
#iface ens4 inet dhcp

# Static config for enp2s0
auto enp2s0
iface enp2s0 inet static
        address 10.20.20.10
        netmask 255.255.255.0
        gateway 10.20.20.1
        dns-nameservers 8.8.8.8
```

#### c. DatabaseServer End Device Configuration

Here is the configuration for the end device `DatabaseServer` in `/etc/network/interfaces`

```bash
# /etc/network/interfaces

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# DHCP config for ens4
#auto ens4
#iface ens4 inet dhcp

# Static config for enp2s0
auto enp2s0
iface enp2s0 inet static
        address 10.20.20.20
        netmask 255.255.255.0
        gateway 10.20.20.1
        dns-nameservers 8.8.8.8
```

### 3. DMZ Configuration Service

#### a. Server Service

| Server Role                      | Functionality                             |
| -------------------------------- | ----------------------------------------- |
| Public Web Server (Nginx/Apache) | Expoesed service straight to the internet |
| Public DNS/Mail Server           | Basic Service for public communication    |

#### b. PublicWebServer End Device Configuration

Here is the configuration for the end device `PublicWebServer` in `~/.bashrc`

```bash
# ~/.bashrc

cat > setup-webserver.sh <<'EOF'
#!/bin/bash

IFACE="enp2s0"

echo "=== Mengaktifkan Interface ==="
sudo ip link set $IFACE up

echo "=== Set IP Address 10.20.60.10 ==="
sudo ip addr add 10.20.60.10/24 dev $IFACE
sudo ip route add default via 10.20.60.1

echo "=== Set DNS ==="
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

echo "=== Testing Connectivity ==="
ping -c 2 10.20.60.1
ping -c 2 8.8.8.8

if ping -c 2 google.com > /dev/null 2>&1; then
    echo "=== Internet OK! Installing Nginx ==="
    sudo apt update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y nginx

    # Buat halaman test
    echo "<h1>DMZ Web Server</h1><p>IP: 10.20.60.10</p>" | sudo tee /var/www/html/index.html

    # Enable & Start
    sudo systemctl enable nginx
    sudo systemctl start nginx

    echo "=== Status Nginx ==="
    sudo systemctl status nginx --no-pager

    echo "=== IP Configuration ==="
    ip addr show $IFACE

    echo "=== Test Web Server ==="
    curl http://localhost

else
    echo "=== GAGAL! Tidak ada koneksi internet ==="
fi
EOF

chmod +x setup-webserver.sh
sudo bash setup-webserver.sh
```

#### c. MailServer End Device Configuration

Here is the configuration for the end device `MailServer` in `~/.bashrc`

```bash
# ~/.bashrc

cat > setup-dns-mail.sh <<'EOF'
#!/bin/bash

IFACE="enp2s0"

echo "=== Mengaktifkan Interface ==="
sudo ip link set $IFACE up

echo "=== Set IP Address 10.20.60.11 ==="
sudo ip addr add 10.20.60.11/24 dev $IFACE
sudo ip route add default via 10.20.60.1

echo "=== Set DNS ==="
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

echo "=== Testing Connectivity ==="
ping -c 2 10.20.60.1
ping -c 2 8.8.8.8

if ping -c 2 google.com > /dev/null 2>&1; then
    echo "=== Internet OK! Installing Bind9 & Postfix ==="
    sudo apt update

    # Install Bind9 (DNS)
    sudo DEBIAN_FRONTEND=noninteractive apt install -y bind9 bind9utils

    # Install Postfix (Mail)
    echo "postfix postfix/main_mailer_type select Internet Site" | sudo debconf-set-selections
    echo "postfix postfix/mailname string mail.dmz.local" | sudo debconf-set-selections
    sudo DEBIAN_FRONTEND=noninteractive apt install -y postfix

    # Enable & Start
    sudo systemctl enable bind9 postfix
    sudo systemctl start bind9 postfix

    echo "=== Status Services ==="
    sudo systemctl status bind9 --no-pager
    sudo systemctl status postfix --no-pager

    echo "=== IP Configuration ==="
    ip addr show $IFACE

else
    echo "=== GAGAL! Tidak ada koneksi internet ==="
fi
EOF

chmod +x setup-dns-mail.sh
sudo bash setup-dns-mail.sh
```

### 4. Admin Configuration Service

#### a. Server Service

| Server Role                             | Functionality                                                             |
| --------------------------------------- | ------------------------------------------------------------------------- |
| Authentication Server (LDAP/Radius)     | Control every login access.                                               |
| Monitoring & Log Server (Zabbix/syslog) | Audit & Network Health: Watch over and gather log data from every device. |

#### b. AuthenticationServer End Device Configuration

Here is the configuration for the end device `AuthenticationServer` in `~/.bashrc`

```bash
# ~/.bashrc
cat > fix-radius-final.sh <<'EOF'
#!/bin/bash
DB_PASSWORD="RadiusPass2024!"
RADIUS_SECRET="ITS_Radius_Secret_2024"

echo "=========================================="
echo "   FIX RADIUS - USER DATABASE ISSUE"
echo "=========================================="

# Stop FreeRADIUS
sudo systemctl stop freeradius

# Cek apakah user ada di database
echo "=== Checking Current Users in Database ==="
sudo mysql -uroot -p$DB_PASSWORD radius -e "SELECT * FROM radcheck;"

# Hapus semua user lama dan insert ulang
echo ""
echo "=== Recreating Test Users ==="
sudo mysql -uroot -p$DB_PASSWORD radius <<SQL
DELETE FROM radcheck;
INSERT INTO radcheck (username, attribute, op, value) VALUES
('admin', 'Cleartext-Password', ':=', 'admin123'),
('netadmin', 'Cleartext-Password', ':=', 'netadmin123'),
('operator', 'Cleartext-Password', ':=', 'operator123');
SQL

echo "✓ Users recreated"

# Verify users
echo ""
echo "=== Current Users in Database ==="
sudo mysql -uroot -p$DB_PASSWORD radius -e "SELECT username, attribute, value FROM radcheck;"

# Restart FreeRADIUS
echo ""
echo "=== Restarting FreeRADIUS ==="
sudo systemctl start freeradius
sleep 3

sudo systemctl status freeradius --no-pager | head -15

# Test authentication
echo ""
echo "=== Testing Authentication ==="
echo "Test 1: User 'admin' with password 'admin123'"
radtest admin admin123 127.0.0.1 0 testing123

echo ""
echo "Test 2: User 'netadmin' with password 'netadmin123'"
radtest netadmin netadmin123 127.0.0.1 0 testing123

echo ""
echo "Test 3: Wrong password (should be rejected)"
radtest admin wrongpass 127.0.0.1 0 testing123

echo ""
echo "=========================================="
echo "   RADIUS Server Status"
echo "=========================================="
if sudo systemctl is-active --quiet freeradius; then
    echo "✓ FreeRADIUS is RUNNING"
    echo ""
    echo "Test from RouterOS:"
    echo "/radius add address=10.20.40.10 secret=$RADIUS_SECRET service=login"
    echo "/user aaa set use-radius=yes"
else
    echo "✗ FreeRADIUS is NOT RUNNING"
fi
echo "=========================================="

EOF

chmod +x fix-radius-final.sh
sudo bash fix-radius-final.sh
```

#### c. MonitoringServer End Device Configuration

Here is the configuration for the end device `MailServer` in `~/.bashrc`

```bash
# ~/.bashrc
cat > /tmp/simple-monitoring-final.sh <<'SCRIPT'
#!/bin/bash
IFACE="enp2s0"
IP_ADDR="10.20.40.11"
GATEWAY="10.20.40.1"

echo "=========================================="
echo "   SIMPLE MONITORING SERVER"
echo "=========================================="

# Set Static IP
echo "=== Setting Static IP ==="
sudo dhclient -r $IFACE 2>/dev/null
sudo ip addr flush dev $IFACE
sudo ip link set $IFACE down
sleep 1
sudo ip link set $IFACE up
sudo ip addr add $IP_ADDR/24 dev $IFACE
sudo ip route add default via $GATEWAY 2>/dev/null
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Make persistent
sudo tee /etc/network/interfaces.d/$IFACE > /dev/null <<NET
auto $IFACE
iface $IFACE inet static
    address $IP_ADDR
    netmask 255.255.255.0
    gateway $GATEWAY
    dns-nameservers 8.8.8.8
NET

echo "✓ IP configured: $IP_ADDR"

# Install web server & PHP
echo ""
echo "=== Installing Web Tools ==="
sudo apt update
sudo DEBIAN_FRONTEND=noninteractive apt install -y apache2 php libapache2-mod-php

# Create home page
sudo tee /var/www/html/index.html > /dev/null <<'HTML'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ITS Monitoring Server</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 30px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 {
            color: white;
            text-align: center;
            font-size: 3em;
            margin-bottom: 20px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .subtitle {
            color: rgba(255,255,255,0.9);
            text-align: center;
            font-size: 1.2em;
            margin-bottom: 40px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 25px;
        }
        .card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            transition: all 0.3s ease;
        }
        .card:hover {
            transform: translateY(-10px);
            box-shadow: 0 15px 50px rgba(0,0,0,0.3);
        }
        .card h2 {
            color: #667eea;
            font-size: 1.8em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-item {
            display: flex;
            align-items: center;
            padding: 12px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        .status-item:last-child { border-bottom: none; }
        .dot {
            width: 14px;
            height: 14px;
            border-radius: 50%;
            background: #4CAF50;
            margin-right: 12px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.7; transform: scale(1.1); }
        }
        .btn {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 15px 30px;
            text-decoration: none;
            border-radius: 10px;
            font-weight: 600;
            margin: 8px;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);
        }
        .info-box {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
        }
        .info-label {
            color: #666;
            font-size: 0.9em;
            font-weight: 600;
        }
        .info-value {
            color: #667eea;
            font-size: 1.1em;
            font-weight: bold;
        }
        pre {
            background: #2d2d2d;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 10px;
            overflow-x: auto;
            font-size: 0.9em;
            line-height: 1.6;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🖥 ITS Monitoring Server</h1>
        <p class="subtitle">Centralized Logging & Network Monitoring System</p>

        <div class="grid">
            <div class="card">
                <h2>📊 Server Information</h2>
                <div class="info-box">
                    <div class="info-label">IP Address</div>
                    <div class="info-value">10.20.40.11</div>
                </div>
                <div class="info-box">
                    <div class="info-label">Network</div>
                    <div class="info-value">Admin Network (10.20.40.0/24)</div>
                </div>
                <div class="info-box">
                    <div class="info-label">Purpose</div>
                    <div class="info-value">Log Collection & SNMP Monitoring</div>
                </div>
            </div>

            <div class="card">
                <h2>🔥 Active Services</h2>
                <div class="status-item">
                    <div class="dot"></div>
                    <div>
                        <strong>Rsyslog Server</strong><br>
                        <small style="color: #666;">UDP/TCP Port 514</small>
                    </div>
                </div>
                <div class="status-item">
                    <div class="dot"></div>
                    <div>
                        <strong>SNMP Agent</strong><br>
                        <small style="color: #666;">UDP Port 161</small>
                    </div>
                </div>
                <div class="status-item">
                    <div class="dot"></div>
                    <div>
                        <strong>Apache Web Server</strong><br>
                        <small style="color: #666;">TCP Port 80</small>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>📝 Quick Access</h2>
                <a href="/logs.php" class="btn">📋 View Logs</a>
                <a href="/devices.php" class="btn">🌐 Devices</a>
                <a href="/stats.php" class="btn">📈 Statistics</a>
            </div>
        </div>

        <div class="card" style="margin-top: 25px;">
            <h2>⚙ RouterOS Configuration</h2>
            <p style="margin-bottom: 15px; color: #666;">
                Copy and paste these commands to each RouterOS device:
            </p>
            <pre># Enable Remote Logging to this server
/system logging action
add name=remote-log remote=10.20.40.11 target=remote

/system logging
add action=remote-log topics=info
add action=remote-log topics=warning
add action=remote-log topics=error
add action=remote-log topics=critical
add action=remote-log topics=firewall

# Enable SNMP for monitoring
/snmp set enabled=yes contact="admin@its.ac.id" location="ITS Network"
/snmp community
add name=public addresses=10.20.40.11/32 read-access=yes

# Test connectivity
/tool ping 10.20.40.11 count=5</pre>
        </div>
    </div>
</body>
</html>
HTML

# Create logs viewer
sudo tee /var/www/html/logs.php > /dev/null <<'PHP'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Live Syslog Viewer</title>
    <meta http-equiv="refresh" content="30">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Courier New', monospace;
            background: #1e1e1e;
            color: #d4d4d4;
        }
        .header {
            background: linear-gradient(135deg, #2d2d2d 0%, #1e1e1e 100%);
            padding: 25px;
            border-bottom: 3px solid #007acc;
            box-shadow: 0 2px 10px rgba(0,0,0,0.5);
        }
        h1 {
            color: #4ec9b0;
            margin: 0;
            font-size: 2em;
        }
        .nav {
            margin-top: 15px;
            display: flex;
            gap: 10px;
        }
        .nav a {
            color: white;
            background: #007acc;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            transition: all 0.3s;
        }
        .nav a:hover {
            background: #005a9e;
            transform: translateY(-2px);
        }
        .content { padding: 25px; }
        .section {
            background: #2d2d2d;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #007acc;
        }
        h2 {
            color: #4ec9b0;
            margin-bottom: 15px;
        }
        pre {
            background: #1e1e1e;
            padding: 20px;
            border-radius: 8px;
            font-size: 13px;
            line-height: 1.8;
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
        }
        .error { color: #f48771; font-weight: bold; }
        .warning { color: #dcdcaa; }
        .info { color: #9cdcfe; }
        .success { color: #4ec9b0; }
        .timestamp { color: #858585; }
        .footer {
            text-align: center;
            color: #858585;
            padding: 20px;
            border-top: 1px solid #2d2d2d;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            background: #007acc;
            border-radius: 5px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>📋 Live Syslog Viewer</h1>
        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/logs.php">🔄 Refresh Now</a>
            <a href="/devices.php">🌐 Devices</a>
            <a href="/stats.php">📈 Stats</a>
        </div>
    </div>

    <div class="content">
        <div class="section">
            <h2>📁 Log Directories</h2>
            <pre><?php
                $output = shell_exec('ls -lhtr /var/log/remote/ 2>/dev/null');
                if($output) {
                    echo $output;
                } else {
                    echo "📁 No log directories yet\n\n";
                    echo "⏳ Waiting for RouterOS devices to send logs...\n";
                    echo "Configure devices using the commands on the home page.";
                }
            ?></pre>
        </div>

        <div class="section">
            <h2>📝 Recent Logs <span class="badge">Last 300 lines</span></h2>
            <pre><?php
                $logs = shell_exec('find /var/log/remote -type f -name "*.log" -exec tail -10 {} \; 2>/dev/null | tail -300');

                if($logs) {
                    // Syntax highlighting
                    $logs = htmlspecialchars($logs);
                    $logs = preg_replace('/(error|ERROR|fail|FAIL|denied|DENIED)/i', '<span class="error">$1</span>', $logs);
                    $logs = preg_replace('/(warning|WARNING|warn|WARN)/i', '<span class="warning">$1</span>', $logs);
                    $logs = preg_replace('/(success|SUCCESS|accepted|ACCEPTED|ok|OK)/i', '<span class="success">$1</span>', $logs);
                    $logs = preg_replace('/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/', '<span class="timestamp">$1</span>', $logs);
                    $logs = preg_replace('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', '<span class="info">$1</span>', $logs);
                    echo $logs;
                } else {
                    echo "📝 <span class='info'>No logs received yet</span>\n\n";
                    echo "Configure RouterOS devices with:\n\n";
                    echo "/system logging action add name=remote-log remote=10.20.40.11 target=remote\n";
                    echo "/system logging add action=remote-log topics=info,warning,error,critical,firewall\n\n";
                    echo "Then test with: /log print";
                }
            ?></pre>
        </div>
    </div>

    <div class="footer">
        ⏱ Auto-refresh: 30 seconds |
        💾 Storage: /var/log/remote/ |
        🕐 Last updated: <?php echo date('Y-m-d H:i:s'); ?>
    </div>
</body>
</html>
PHP

# Create devices viewer
sudo tee /var/www/html/devices.php > /dev/null <<'PHP'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Network Devices</title>
    <meta http-equiv="refresh" content="60">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 30px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        h1 {
            color: #667eea;
            margin-bottom: 30px;
            font-size: 2.5em;
        }
        .nav {
            margin-bottom: 30px;
            display: flex;
            gap: 15px;
        }
        .nav a {
            padding: 12px 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.3s;
        }
        .nav a:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        thead tr {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        th, td {
            padding: 18px 15px;
            text-align: left;
        }
        th {
            font-weight: 700;
            text-transform: uppercase;
            font-size: 0.85em;
            letter-spacing: 1px;
        }
        tbody tr {
            border-bottom: 1px solid #e0e0e0;
            transition: all 0.3s;
        }
        tbody tr:hover {
            background: #f8f9fa;
            transform: scale(1.01);
        }
        .status-online {
            color: #4CAF50;
            font-weight: bold;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .status-offline {
            color: #999;
        }
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #4CAF50;
            display: inline-block;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        .empty {
            text-align: center;
            padding: 60px;
            color: #999;
        }
        .empty-icon {
            font-size: 4em;
            margin-bottom: 20px;
        }
        .stats {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            margin-top: 30px;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
        }
        .stat-box {
            text-align: center;
        }
        .stat-value {
            font-size: 2.5em;
            color: #667eea;
            font-weight: bold;
        }
        .stat-label {
            color: #666;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Network Devices</h1>

        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/logs.php">📋 Logs</a>
            <a href="/devices.php">🔄 Refresh</a>
            <a href="/stats.php">📈 Stats</a>
        </div>

        <table>
            <thead>
                <tr>
                    <th>Device Name</th>
                    <th>Last Activity</th>
                    <th>Time Ago</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
            <?php
            $dirs = glob('/var/log/remote/*', GLOB_ONLYDIR);
            if(!empty($dirs)) {
                foreach($dirs as $dir) {
                    $hostname = basename($dir);
                    $mtime = filemtime($dir);
                    $ago = time() - $mtime;
                    $is_online = $ago < 300; // Online if active in last 5 minutes

                    $time_ago = $ago < 60 ? $ago . 's ago' :
                               ($ago < 3600 ? floor($ago/60) . 'm ago' :
                               floor($ago/3600) . 'h ago');

                    echo "<tr>";
                    echo "<td><strong>$hostname</strong></td>";
                    echo "<td>" . date('Y-m-d H:i:s', $mtime) . "</td>";
                    echo "<td>$time_ago</td>";

                    if($is_online) {
                        echo "<td class='status-online'><span class='status-dot'></span> Online</td>";
                    } else {
                        echo "<td class='status-offline'>Inactive</td>";
                    }
                    echo "</tr>";
                }
            } else {
                echo "<tr><td colspan='4' class='empty'>";
                echo "<div class='empty-icon'>📭</div>";
                echo "<h3>No devices detected yet</h3>";
                echo "<p>Configure RouterOS devices to send logs to this server</p>";
                echo "</td></tr>";
            }
            ?>
            </tbody>
        </table>

        <div class="stats">
            <div class="stat-box">
                <div class="stat-value"><?php echo count($dirs); ?></div>
                <div class="stat-label">Total Devices</div>
            </div>
            <div class="stat-box">
                <div class="stat-value"><?php
                    $online = 0;
                    foreach($dirs as $dir) {
                        if((time() - filemtime($dir)) < 300) $online++;
                    }
                    echo $online;
                ?></div>
                <div class="stat-label">Online Now</div>
            </div>
            <div class="stat-box">
                <div class="stat-value"><?php
                    echo shell_exec('find /var/log/remote -type f | wc -l') ?: 0;
                ?></div>
                <div class="stat-label">Log Files</div>
            </div>
        </div>

        <p style="color: #666; margin-top: 30px; text-align: center;">
            ⏱ Auto-refresh: 60 seconds |
            Last updated: <?php echo date('H:i:s'); ?>
        </p>
    </div>
</body>
</html>
PHP

# Create stats page
sudo tee /var/www/html/stats.php > /dev/null <<'PHP'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Server Statistics</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            padding: 30px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #667eea; margin-bottom: 30px; }
        .nav {
            margin-bottom: 30px;
            display: flex;
            gap: 10px;
        }
        .nav a {
            padding: 10px 20px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 5px;
        }
        .card {
            background: white;
            padding: 25px;
            margin-bottom: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #667eea;
            margin-bottom: 15px;
        }
        pre {
            background: #2d2d2d;
            color: #d4d4d4;
            padding: 20px;
            border-radius: 8px;
            overflow-x: auto;
            font-size: 14px;
            line-height: 1.6;
        }
        .highlight { color: #4ec9b0; font-weight: bold; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📈 Server Statistics</h1>

        <div class="nav">
            <a href="/">🏠 Home</a>
            <a href="/logs.php">📋 Logs</a>
            <a href="/devices.php">🌐 Devices</a>
            <a href="/stats.php">🔄 Refresh</a>
        </div>

        <div class="card">
            <h2>💾 Disk Usage</h2>
            <pre><?php echo shell_exec('df -h / | tail -1'); ?></pre>
        </div>

        <div class="card">
            <h2>📊 Log Statistics</h2>
            <pre><?php
                $total_files = shell_exec('find /var/log/remote -type f 2>/dev/null | wc -l');
                $total_size = shell_exec('du -sh /var/log/remote 2>/dev/null | cut -f1');

                echo "Total log files: <span class='highlight'>" . trim($total_files) . "</span>\n";
                echo "Total log size: <span class='highlight'>" . trim($total_size) . "</span>\n\n";
                echo "Storage by device:\n";
                echo shell_exec('du -sh /var/log/remote/*/ 2>/dev/null');
            ?></pre>
        </div>

        <div class="card">
            <h2>⚙ Service Status</h2>
            <pre><?php
                $rsyslog = trim(shell_exec('systemctl is-active rsyslog'));
                $apache = trim(shell_exec('systemctl is-active apache2'));
                $snmp = trim(shell_exec('systemctl is-active snmpd'));

                echo "Rsyslog: <span class='highlight'>" . ($rsyslog == 'active' ? '✓ Running' : '✗ Stopped') . "</span>\n";
                echo "Apache2: <span class='highlight'>" . ($apache == 'active' ? '✓ Running' : '✗ Stopped') . "</span>\n";
                echo "SNMP: <span class='highlight'>" . ($snmp == 'active' ? '✓ Running' : '✗ Stopped') . "</span>\n";
            ?></pre>
        </div>

        <div class="card">
            <h2>🌐 Network Ports</h2>
            <pre><?php
                echo shell_exec("sudo ss -tulnp | grep -E ':(514|80|161)' | awk '{print \$1\" \"\$5}' | sort -u");
            ?></pre>
        </div>

        <div class="card">
            <h2>⏰ System Uptime</h2>
            <pre><?php echo shell_exec('uptime'); ?></pre>
        </div>
    </div>
</body>
</html>
PHP

# Set permissions
sudo chown -R www-data:www-data /var/www/html/
sudo chmod 755 /var/www/html/*.php

# Enable services
sudo a2enmod php* 2>/dev/null
sudo systemctl enable rsyslog apache2 snmpd
sudo systemctl restart apache2

echo ""
echo "=== Verifying Installation ==="
systemctl is-active rsyslog && echo "✓ Rsyslog" || echo "✗ Rsyslog"
systemctl is-active apache2 && echo "✓ Apache2" || echo "✗ Apache2"
systemctl is-active snmpd && echo "✓ SNMP" || echo "✗ SNMP"

echo ""
echo "=== Ports Status ==="
sudo ss -tulnp | grep -E ':(514|80|161)' | awk '{print $5}' | sort -u

echo ""
echo "=== Network Configuration ==="
ip addr show $IFACE | grep "inet "

echo ""
echo "=== Disk Usage ==="
df -h / | tail -1

echo ""
echo "=========================================="
echo "   ✅ MONITORING SERVER READY!"
echo "=========================================="
echo "IP: $IP_ADDR"
echo ""
echo "Services:"
echo "  ✓ Rsyslog (Port 514)"
echo "  ✓ SNMP (Port 161)"
echo "  ✓ Web Dashboard (Port 80)"
echo ""
echo "Access:"
echo "  http://$IP_ADDR/"
echo "  http://$IP_ADDR/logs.php"
echo "  http://$IP_ADDR/devices.php"
echo "  http://$IP_ADDR/stats.php"
echo "=========================================="

SCRIPT

chmod +x /tmp/simple-monitoring-final.sh
bash /tmp/simple-monitoring-final.sh
```