### Cheatsheet Implementasi IDS (Operasi Mata Elang)

**TARGET DEVICE**: Masukkan semua perintah ini di terminal **Router Firewall (Core)**.
*(Jangan masukkan di Edge Router atau Router Mahasiswa)*

---

#### 1. Persiapan Sistem Router (System Hardening)
Agar modul IDS berjalan stabil dan log terbaca jelas.

```bash
# a. Aktifkan Connection Tracking (Wajib untuk IDS)
/ip firewall connection tracking set enabled=yes tcp-established-timeout=1h
# Verifikasi:
/ip firewall connection tracking print

# b. Setting Waktu (NTP) agar log valid
# Catatan: Jika error, gunakan "servers=" (v7) alih-alih "primary-ntp=" (v6)
/system ntp client set enabled=yes servers=10.20.40.10
# Verifikasi:
/system ntp client print

# c. Perbesar kapasitas Log
/system logging action set memory memory-lines=2000
# Verifikasi:
/system logging action print
```

---

#### 2. Definisi Variabel Jaringan
Kita beri label mana jaringan "Rumah" (Trusted) dan mana "Luar".

```bash
# Definisikan HOME_NET (Seluruh subnet internal kita)
/ip firewall address-list add list=HOME_NET address=10.20.0.0/16

# Verifikasi & Hapus Duplikat:
/ip firewall address-list print
# Jika ada duplikat, hapus dengan: /ip firewall address-list remove [NOMOR]
```

---

#### 3. Pasang Rule IDS (Custom Rules)
Copy-paste perintah ini untuk membuat sensor deteksi.

```bash
# --- RULE 1: DETEKSI SSH BRUTE FORCE (Hydra) ---
/ip firewall filter add chain=forward protocol=tcp dst-port=22 connection-state=new dst-limit=1/1m,4,dst-address/1m action=passthrough comment="IDS: Detect SSH Brute Force" log=yes log-prefix="[IDS-SSH-BRUTE]"

# --- RULE 2: DETEKSI L7 EXFILTRATION (Steal Password) ---
# Langkah 2a: Buat Regex
/ip firewall layer7-protocol add name="L7-LFI-Passwd" regexp="etc/passwd"
# Langkah 2b: Pasang Filter
/ip firewall filter add chain=forward layer7-protocol="L7-LFI-Passwd" action=passthrough comment="IDS: Detect LFI Exfiltration" log=yes log-prefix="[IDS-L7-EXFIL]"

# --- RULE 3: DETEKSI PORT SCAN (Nmap) ---
# Perhatikan spasi pada psd !
/ip firewall filter add chain=forward protocol=tcp psd=21,3s,3:1 action=add-src-to-address-list address-list="port_scanners" address-list-timeout=1h comment="IDS: Detect Port Scan" log=yes log-prefix="[IDS-PORT-SCAN]"
```

**Hapus Duplikat (Jika Salah Ketik):**
```bash
/ip firewall filter print
# /ip firewall filter remove [NOMOR]
```

---

#### 4. PINDAHKAN RULE KE ATAS (SANGAT PENTING!)
Secara default, rule baru ada di paling bawah. Jika di atasnya ada rule "DROP", IDS tidak akan jalan.
**Solusi:** Pindahkan rule IDS ke urutan 0, 1, dan 2.

```bash
# Cek nomor rule IDS Anda saat ini (misal nomor 38, 39, 40)
/ip firewall filter print

# Pindahkan ke atas (Ganti angka 38/39/40 dengan nomor asli di router Anda)
/ip firewall filter move [NOMOR_IDS_1] destination=0
/ip firewall filter move [NOMOR_IDS_2] destination=1
/ip firewall filter move [NOMOR_IDS_3] destination=2

# Verifikasi Akhir:
/ip firewall filter print
# Pastikan 3 rule IDS ada di paling atas (0-2).
```

---

#### 5. BYPASS FIREWALL (WAJIB!)
Agar serangan simulasi bisa masuk, nonaktifkan rule blokir Mahasiswa.

```bash
# Cari rule "BLOCK MHS -> Internal" (Cek rule yang action-nya 'drop' dari chain 'from_mahasiswa')
/ip firewall filter print

# Matikan rule tersebut (Misal nomor 29 atau 21)
/ip firewall filter disable [NOMOR_RULE_BLOCK_MHS]

# Verifikasi:
# Pastikan ada tanda "X" di sebelah kiri rule tersebut.
```

---

#### 5. Jalankan Simulasi Serangan (Dari PC Mahasiswa)
Masuk ke terminal PC Attacker (Mahasiswa) dan jalankan satu per satu.

**a. Serangan Port Scan:**
```bash
sudo nmap -sS -F 10.20.30.20
```
*-> Cek log Mikrotik: Harus muncul "[IDS-PORT-SCAN]"*

**b. Serangan SSH Brute Force:**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.20.30.20 -t 4
```
*-> Cek log Mikrotik: Harus muncul "[IDS-SSH-BRUTE]"*

**c. Serangan Pencurian Data (LFI):**
```bash
curl "http://10.20.30.20/dashboard.php?page=../../etc/passwd"
```
*-> Cek log Mikrotik: Harus muncul "[IDS-L7-EXFIL]"*

---

#### 6. Melihat Log Serangan (Untuk Screenshot)
Kembali ke terminal **Router Firewall**. Gunakan perintah ini untuk melihat hasil deteksi IDS.

```bash
# Lihat semua log yang mengandung kata "IDS"
/log print where message~"IDS"

# Atau gunakan mode 'follow' untuk melihat secara real-time saat serangan terjadi
/log print follow where message~"IDS"
```
**Tugas Anda:** Screenshot output log ini yang menampilkan pesan `[IDS-PORT-SCAN]`, `[IDS-SSH-BRUTE]`, dan `[IDS-L7-EXFIL]`.

---

#### 7. Selesai
Setelah semua log muncul, ambil screenshot dan simpan ke folder `ids_images`. Jangan lupa nyalakan kembali firewall rule blokir Mahasiswa jika sudah selesai demo.
