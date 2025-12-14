# ITS Secure Network Challenge

## Mengamankan Infrastruktur Digital Departemen Teknologi Informasi dari Ancaman Internal dan Eksternal

Departemen Teknologi Informasi ITS (DTI ITS) baru saja melakukan restrukturisasi infrastruktur jaringan. Sekarang terdapat 5 subnet utama yang saling terhubung melalui core router di laboratorium jaringan. Namun, setelah insiden kebocoran data dan lonjakan traffic aneh dari jaringan mahasiswa, pihak departemen meminta tim keamanan internal (yaitu kalian) untuk mendesain dan menguji sistem pertahanan jaringan berbasis ACL dan Firewall.

Kalian diberi topologi dasar dan akses penuh untuk memodifikasi, menambah perangkat, maupun mengubah kebijakan — selama desain kalian bisa dibuktikan efektif dan efisien.

Subnet minimal (boleh diubah sesuai desain kelompok):

- Mahasiswa → 10.20.10.0/24
- Akademik → 10.20.20.0/24
- Riset & IoT → 10.20.30.0/24
- Admin → 10.20.40.0/24
- Guest → 10.20.50.0/24

Perangkat:

- 1 Edge Router
- 1 Firewall (bisa pakai pfSense / ASA / iptables VM)
- 2–3 Router internal (Admin Router, Student Router, dll.)
- Beberapa PC simulasi untuk uji konektivitas dan serangan

Tantangan Utama :
- Tidak ada langkah eksplisit.
- Tiap kelompok harus menafsirkan sendiri prioritas keamanan, aturan akses, serta pendekatan yang dipakai.

Kalian diminta untuk menjawab pertanyaan-pertanyaan besar berikut melalui sistem yang kalian bangun:

### 1. Bagaimana kalian mendefinisikan “keamanan yang seimbang” untuk jaringan kampus ini?

- Siapa saja yang boleh mengakses layanan akademik, server, dan riset?
- Siapa yang tidak boleh?
- Bagaimana memastikan keamanan tanpa menghambat kolaborasi antar departemen?
💡 Hasil diharapkan: rancangan kebijakan ACL dan firewall yang menggambarkan filosofi keamanan kalian sendiri.

### 2. Jika terjadi serangan internal, apa bentuk “pertahanan berlapis” yang paling efektif?

- Buat asumsi jenis serangan realistis yang mungkin terjadi di jaringan kampus (misalnya sniffing, scanning, DDoS mini, privilege abuse).
- Desain sistem berlapis yang mampu mendeteksi, menghambat, atau memitigasi serangan itu.
💡 Hasil diharapkan: bukti konfigurasi dan hasil simulasi serangan + mitigasi.

### 3. Bagaimana kalian membuktikan bahwa sistem kalian “benar-benar bekerja”?

- Apa indikator keamanan yang kalian pakai untuk mengukur efektivitasnya?
- Bagaimana cara menguji bahwa ACL dan firewall berfungsi sesuai harapan (tanpa false positive/negative berlebihan)?
- Bagaimana kalian memverifikasi performa (latency, availability) tetap layak?
💡 Hasil diharapkan: metode pengujian dan hasil evaluasi performa.

### 4. Bagaimana kalian merancang sistem yang tetap adaptif?

- Bayangkan jaringan ini akan terus berkembang: penambahan lab baru, server cloud, atau dosen tamu.
- Apakah sistem kalian mudah diperluas tanpa mengulang semuanya dari awal?
💡 Hasil diharapkan: rancangan desain modular, dokumentasi perubahan, atau simulasi penambahan jaringan baru.

## Output yang Diharapkan

Dokumen laporan singkat (maks. 8 halaman)
Berisi:
- Desain topologi akhir (bisa dimodifikasi dari standar)
- Filosofi dan kebijakan keamanan
- Hasil uji akses dan simulasi serangan
- Evaluasi efektivitas & efisiensi
- File proyek GNS3 (dengan konfigurasi lengkap ACL dan Firewall)

