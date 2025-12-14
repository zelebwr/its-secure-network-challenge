<div align="center">

<img src="./images/logo%20ITS.png" alt="Logo ITS" width="250">

# Operasi Mata Elang: Mengungkap Serangan Tersembunyi di Jaringan DTI ITS

## Implementasi Intrusion Detection System (IDS)

![Network Security](https://img.shields.io/badge/Network-Security-blue?style=for-the-badge)
![MikroTik](https://img.shields.io/badge/MikroTik-RouterOS-orange?style=for-the-badge)

</div>

---

<div align="center">

### Disusun Oleh - Kelompok 5

| Nama | NRP |
|------|-----|
| Arya Bisma Putra Refman | 5027241036 |
| Jonathan Zelig Sutopo | 5027241047 |
| M. Alfaeran Auriga Ruswandi | 5027241115 |
| Tiara Fatimah Azzahra | 5027241090 |

**Teknologi Informasi**  
**Institut Teknologi Sepuluh Nopember**

</div>

---

## Daftar Isi

- [1. Latar Belakang](#1-latar-belakang)
- [2. Konfigurasi IDS](#2-konfigurasi-ids)
  - [2.1. Topologi & Penempatan](#21-topologi--penempatan)
  - [2.2. Persiapan Sistem](#22-persiapan-sistem)
  - [2.3. Rule Deteksi](#23-rule-deteksi)
- [3. Simulasi Serangan](#3-simulasi-serangan)
- [4. Analisis Hasil](#4-analisis-hasil)
- [5. Kesimpulan](#5-kesimpulan)

---

## 1. Latar Belakang

Departemen Teknologi Informasi ITS melaporkan adanya indikasi kebocoran data dari subnet Riset & IoT (10.20.30.0/24). Log firewall menunjukkan lonjakan traffic mencurigakan dari subnet Mahasiswa (10.20.10.0/24). Tim menduga ini adalah **serangan berantai**: Scanning → Brute Force → Data Exfiltration.

**Platform IDS yang digunakan:** MikroTik RouterOS dengan Firewall Filter + Layer-7 Protocol

---

## 2. Konfigurasi IDS

### 2.1. Topologi & Penempatan

![Topology](images/topology.png)

**Subnet yang dimonitor:**
- **Mahasiswa** (10.20.10.0/24)
- **Akademik** (10.20.20.0/24)
- **Riset & IoT** (10.20.30.0/24)
- **Admin** (10.20.40.0/24)

**Posisi IDS:** Router Firewall (Core/Backbone)

| Strategi | Manfaat |
|----------|---------|
| **Choke Point Terpusat** | Visibilitas 360° untuk memantau Lateral Movement antar-subnet |
| **Efisiensi Resource** | Deep Packet Inspection dipusatkan pada perangkat Core |
| **Defense in Depth** | Integrasi langsung antara IDS dan Firewall |
| **Bypass NAT** | IP asli penyerang tetap terlihat untuk forensik |

### 2.2. Persiapan Sistem

**1. Connection Tracking**
```bash
/ip firewall connection tracking set enabled=yes tcp-established-timeout=1h
```

![Bukti Connection Tracking](ids_images/bukti_conntrack.png)

**2. NTP Client**
```bash
/system ntp client set enabled=yes servers=10.20.40.10
```

![Bukti NTP Configuration](ids_images/bukti_ntp.png)

**3. Buffer Log**
```bash
/system logging action set memory memory-lines=2000
```

![Bukti Logging Setup](ids_images/bukti_logging.png)

**4. Address List (HOME_NET)**
```bash
/ip firewall address-list add list=HOME_NET address=10.20.0.0/16
```

![Bukti Address List](ids_images/bukti_address_list.png)

### 2.3. Rule Deteksi

![Bukti Rule Placement](ids_images/bukti_rule_ids.png)

#### Rule 1: Port Scanning
```bash
/ip firewall filter add action=add-src-to-address-list address-list="port_scanners" \
    address-list-timeout=1h chain=forward protocol=tcp psd=21,3s,3:1 \
    comment="IDS: Detect Port Scan" log=yes log-prefix="[IDS-PORT-SCAN]"
```

#### Rule 2: SSH Brute Force
```bash
/ip firewall filter add chain=forward protocol=tcp dst-port=22 connection-state=new \
    dst-limit=1/1m,4,dst-address/1m action=passthrough \
    comment="IDS: Detect SSH Brute Force" log=yes log-prefix="[IDS-SSH-BRUTE]"
```

#### Rule 3: Malware BlackSun
```bash
/ip firewall layer7-protocol add name="IDS-BlackSun" regexp="BlackSun"
/ip firewall filter add action=passthrough chain=forward layer7-protocol="IDS-BlackSun" \
    comment="IDS: Detect BlackSun Malware" log=yes log-prefix="[IDS-ALERT-BLACKSUN]"
```

#### Rule 4: Password Theft (LFI)
```bash
/ip firewall layer7-protocol add name="IDS-Passwd" regexp="etc/passwd"
/ip firewall filter add action=passthrough chain=forward layer7-protocol="IDS-Passwd" \
    comment="IDS: Detect Password Theft" log=yes log-prefix="[IDS-ALERT-PASSWD]"
```

#### Rule 5: SQL Injection
```bash
/ip firewall layer7-protocol add name="IDS-SQLi" regexp="UNION SELECT"
/ip firewall filter add action=passthrough chain=forward layer7-protocol="IDS-SQLi" \
    comment="IDS: Detect SQL Injection" log=yes log-prefix="[IDS-ALERT-SQLi]"
```

#### Rule 6: Root Response (Server Compromise)
```bash
/ip firewall layer7-protocol add name="IDS-RootCheck" regexp="uid=0\\(root\\)"
/ip firewall filter add action=passthrough chain=forward layer7-protocol="IDS-RootCheck" \
    comment="IDS: Detect Root Response" log=yes log-prefix="[IDS-ALERT-ROOT]"
```

#### Ringkasan Rules

| No | Serangan | Log Prefix | Pattern |
|----|----------|------------|---------|
| 1 | Port Scanning | `[IDS-PORT-SCAN]` | PSD=21,3s,3:1 |
| 2 | SSH Brute Force | `[IDS-SSH-BRUTE]` | dst-limit |
| 3 | Malware BlackSun | `[IDS-ALERT-BLACKSUN]` | `BlackSun` |
| 4 | Password Theft | `[IDS-ALERT-PASSWD]` | `etc/passwd` |
| 5 | SQL Injection | `[IDS-ALERT-SQLi]` | `UNION SELECT` |
| 6 | Root Response | `[IDS-ALERT-ROOT]` | `uid=0(root)` |

---

## 3. Simulasi Serangan

### Bypass Firewall

Sebelum simulasi, disable rule yang memblokir traffic Mahasiswa:
```bash
/ip firewall filter disable [find comment~"BLOCK MHS"]
```

![Bukti Firewall Bypass](ids_images/bukti_block_mahasiswa.png)

Gambar di atas menunjukkan rule blokir Mahasiswa telah di-disable.

### 3.1. Port Scanning
```bash
nmap -Pn -sS -F 10.20.30.20
```
![Bukti Log Port Scan](ids_images/bukti_port_scan.png)
> ✅ Alert `[IDS-PORT-SCAN]` terdeteksi

### 3.2. SSH Brute Force
```bash
for i in {1..10}; do ssh admin@10.20.30.20; done
```
![Bukti Log SSH Brute](ids_images/bukti_attack_1.png)
> ✅ Alert `[IDS-SSH-BRUTE]` terdeteksi

### 3.3. LFI (Password Theft)
```bash
curl "http://10.20.30.20/page=../../etc/passwd"
```
![Bukti Log LFI](ids_images/bukti_ids_l7_exfil.png)
> ✅ Alert `[IDS-ALERT-PASSWD]` terdeteksi

### 3.4. Malware BlackSun
```bash
curl -A "BlackSun" http://testmynids.org/uid/index.html
```
![Bukti Log BlackSun](images/ids-blacksun.png)
> ✅ Alert `[IDS-ALERT-BLACKSUN]` terdeteksi

### 3.5. SQL Injection
```bash
curl -X POST -d "search=UNION SELECT 1,2,3" http://testmynids.org/
```
![Bukti Log SQL Injection](images/ids-sqli.png)
> ✅ Alert `[IDS-ALERT-SQLi]` terdeteksi

### 3.6. Root Response
```bash
curl http://testmynids.org/uid/index.html
```
![Bukti Log Root Response](images/ids-root.png)
> ✅ Alert `[IDS-ALERT-ROOT]` terdeteksi

### Ringkasan Hasil

| No | Serangan | Status |
|----|----------|--------|
| 1 | Port Scanning | ✅ Terdeteksi |
| 2 | SSH Brute Force | ✅ Terdeteksi |
| 3 | LFI (Password Theft) | ✅ Terdeteksi |
| 4 | Malware BlackSun | ✅ Terdeteksi |
| 5 | SQL Injection | ✅ Terdeteksi |
| 6 | Root Response | ✅ Terdeteksi |

---

## 4. Analisis Hasil

### Akurasi Deteksi

| Serangan | Akurasi | Catatan |
|----------|---------|---------|
| Port Scanning | ⭐⭐⭐⭐ Tinggi | Efektif untuk scan agresif, lemah terhadap stealth scan |
| SSH Brute Force | ⭐⭐⭐ Sedang | Sensitif threshold, perlu whitelist admin |
| Layer-7 (LFI, SQLi, etc) | ⭐⭐⭐⭐⭐ Sangat Tinggi | Pattern matching akurat, false positive rendah |

### Kelemahan (Blind Spots)

| Kelemahan | Solusi |
|-----------|--------|
| **HTTPS/TLS** | IDS buta terhadap traffic terenkripsi → SSL Inspection |
| **Stealth Scan** | Timing lambat bypass PSD → Tuning threshold |
| **Obfuscated Payloads** | URL encode bypass regex → Tambah pattern |

### Dampak Performa

Layer-7 inspection membebani CPU. Untuk produksi dengan throughput >1Gbps, pertimbangkan dedicated IDS appliance.

---

## 5. Kesimpulan

MikroTik berhasil difungsikan sebagai **IDS sederhana namun efektif** tanpa biaya tambahan. Semua 6 jenis serangan terdeteksi dengan sukses.

**Rekomendasi:**
- Integrasi SIEM untuk visualisasi & alerting
- SSL Inspection untuk traffic HTTPS
- Tuning threshold untuk mengurangi false positives

---

<div align="center">

**Keamanan Jaringan Komputer - Teknologi Informasi**  
**Institut Teknologi Sepuluh Nopember**  
*2024/2025*

</div>
