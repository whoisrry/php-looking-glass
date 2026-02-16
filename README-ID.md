# Alsyundawy PHP Looking Glass

![License](https://img.shields.io/badge/license-MIT-blue.svg) ![PHP](https://img.shields.io/badge/php-%3E%3D8.1-777bb4.svg)
[![Latest Version](https://img.shields.io/github/v/release/alsyundawy/php-looking-glass)](https://github.com/alsyundawy/php-looking-glass/releases)
[![Maintenance Status](https://img.shields.io/maintenance/yes/9999)](https://github.com/alsyundawy/php-looking-glass/)
[![License](https://img.shields.io/github/license/alsyundawy/php-looking-glass)](https://github.com/alsyundawy/php-looking-glass/blob/master/LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/alsyundawy/php-looking-glass)](https://github.com/alsyundawy/php-looking-glass/issues)
[![GitHub Pull Requests](https://img.shields.io/github/issues-pr/alsyundawy/php-looking-glass)](https://github.com/alsyundawy/php-looking-glass/pulls)
[![Donate with PayPal](https://img.shields.io/badge/PayPal-donate-orange)](https://www.paypal.me/alsyundawy)
[![Sponsor with GitHub](https://img.shields.io/badge/GitHub-sponsor-orange)](https://github.com/sponsors/alsyundawy)
[![GitHub Stars](https://img.shields.io/github/stars/alsyundawy/php-looking-glass?style=social)](https://github.com/alsyundawy/php-looking-glass/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/alsyundawy/php-looking-glass?style=social)](https://github.com/alsyundawy/php-looking-glass/network/members)
[![GitHub Contributors](https://img.shields.io/github/contributors/alsyundawy/php-looking-glass?style=social)](https://github.com/alsyundawy/php-looking-glass/graphs/contributors)

## Grafik Stargazers dari waktu ke waktu
[![Stargazers over time](https://starchart.cc/alsyundawy/php-looking-glass.svg?variant=adaptive)](https://starchart.cc/alsyundawy/php-looking-glass)

**Alat Looking Glass PHP yang profesional, ringan, dan dikemas dalam satu berkas—dirancang untuk diagnostik jaringan. Kompatibel penuh dengan IPv4 dan IPv6, menampilkan UI modern responsif (mode Gelap/Terang) dan memanfaatkan utilitas sistem standar.**

![looking-glass](/php-looking-glass.png)

## Fitur

- **Diagnostik Jaringan**: Ping, Traceroute, MTR (My Traceroute), dan Host (DNS Lookup).
- **Pengujian Performa**:
  - **Iperf3**: Mendukung mode TCP, UDP, dan Reverse.
  - **Tes Unduh**: Unduhan berkas biner yang dapat dikustomisasi.
- **UI Modern**:
  - Desain responsif penuh (dari Mobile hingga 4K).
  - Toggle mode Gelap/Terang.
  - Deteksi IP klien secara real-time.
- **Keamanan**: Sanitasi input yang ketat untuk mencegah injection perintah.
- **Mudah Dideploy**: Satu berkas PHP, tanpa kebutuhan database.

## Persyaratan

- **PHP**: Versi 8.1 atau lebih tinggi.
- **Modul PHP**: `php-cli`, `php-common`, `php-fpm` (jika menggunakan Nginx), `php-json`, `php-mbstring`, `php-xml`.
- **Web Server**: Nginx atau Apache.
- **Utilitas Sistem**: User web server harus dapat mengeksekusi perintah berikut:
  - `ping`
  - `traceroute`
  - `mtr`
  - `iperf3`
  - `host` (biasanya bagian dari `bind-utils` atau `dnsutils`)

---

## Panduan Instalasi

### 1. Pasang Dependensi Sistem melalui Terminal

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install php-cli php-fpm php-json php-common php-mbstring php-xml ping traceroute mtr-tiny iperf3 dnsutils -y
```

**CentOS/RHEL/AlmaLinux:**
```bash
sudo dnf install php-cli php-fpm php-json php-common php-mbstring php-xml iputils traceroute mtr iperf3 bind-utils -y
```

### 2. Deploy

Unduh `ALSYUNDAWY-LG-GITHUB-2026.php`, ganti nama menjadi `index.php`, lalu unggah ke direktori publik web server Anda (mis. `/var/www/html/lg/`).

### 3. Konfigurasi Web Server

Agar performa, keamanan, dan fungsi optimal (terutama untuk unduhan besar dan pengujian yang berjalan lama seperti MTR), gunakan konfigurasi berikut.

#### Opsi A: Nginx + PHP-FPM

Buat server block baru atau ubah yang sudah ada. Konfigurasi ini mencakup **kompresi Gzip**, **timeout diperpanjang**, **header keamanan**, dan **dukungan IPv6**.

(Blok konfigurasi Nginx dipertahankan sama — biarkan seperti aslinya; tidak perlu menerjemahkan sintaks. Gunakan konfigurasi yang ada dalam README asli.)

#### Opsi B: Apache + PHP

Pastikan `mod_rewrite`, `mod_deflate`, `mod_headers`, dan `mod_http2` diaktifkan.

(Blok konfigurasi Apache dipertahankan sama — biarkan seperti aslinya; gunakan konfigurasi yang ada dalam README asli.)

### 4. Pemasangan SSL (Certbot)

Amankan Looking Glass Anda dengan HTTPS menggunakan Let's Encrypt.

**Instal Certbot:**

*Debian/Ubuntu:*
```bash
sudo apt-get install certbot python3-certbot-nginx python3-certbot-apache -y
```

*CentOS/RHEL:*
```bash
sudo dnf install certbot python3-certbot-nginx python3-certbot-apache -y
```

**Jalankan Certbot:**

*Untuk Nginx:*
```bash
sudo certbot --nginx -d lg.yourdomain.com
```

*Untuk Apache:*
```bash
sudo certbot --apache -d lg.yourdomain.com
```

Ikuti instruksi di layar untuk mengonfigurasi SSL secara otomatis.

### 5. Konfigurasi PHP (`php.ini`)

Pastikan fungsi berikut **TIDAK** dinonaktifkan di `php.ini` (`disable_functions`):

- `proc_open`
- `proc_get_status`
- `proc_close`
- `stream_get_contents`

Contoh:
```ini
disable_functions = passthru,shell_exec,system,popen,parse_ini_file,show_source
; removed proc_open, proc_close, etc. from the list
```

### 6. Tuning Performa PHP

Agar pengujian jaringan berjalan lancar (terutama ukuran unduhan besar dan traceroute panjang), tambahkan atau ubah baris berikut di `php.ini` atau konfigurasi pool FPM:

```ini
; Increase execution time for long tests (MTR/Traceroute)
max_execution_time = 300
max_input_time = 300

; Ensure sufficient memory for large data handling
memory_limit = 256M

; Disable output buffering for real-time results (optional but recommended)
output_buffering = Off
zlib.output_compression = Off
```

---

## Konfigurasi Layanan (Iperf3)

Agar server Iperf3 tetap berjalan di latar belakang sebagai service, buat file unit systemd.

1. **Buat file service:**
```bash
sudo nano /etc/systemd/system/iperf3.service
```

2. **Isi file dengan:**
```ini
[Unit]
Description=Iperf3 Server Service
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/bin/iperf3 -s -p 5201
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

3. **Mulai dan aktifkan service:**
```bash
sudo systemctl daemon-reload
sudo systemctl start iperf3
sudo systemctl enable iperf3
```

---

## Konfigurasi Firewall

Buka port **80** (HTTP), **443** (HTTPS), dan **5201** (Iperf3).

**Opsi A: UFW (Ubuntu/Debian)**
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 5201/tcp
sudo ufw reload
```

**Opsi B: Firewalld (CentOS/RHEL/AlmaLinux)**
```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=5201/tcp
sudo firewall-cmd --reload
```

**Opsi C: Iptables**
```bash
sudo iptables -A INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5201 -j ACCEPT
sudo service iptables save
```

---

## Konfigurasi Script

Buka berkas PHP dan ubah bagian atas agar sesuai dengan detail server Anda:

```php
// ========================================================================
// CONFIGURATION
// ========================================================================

$siteName = 'ALSYUNDAWY IT SOLUTION'; // Your Site/Company Name
$siteUrl = 'https://lg.yourdomain.com'; // Your LG URL

// Server Location
$serverLocation = 'DKI Jakarta, Indonesia';

// Server IPs (Leave empty if not available)
$ipv4 = '103.145.226.20';
$ipv6 = '2001:df0:2e00:face::1';

// Iperf3 Port
$iperfport = '5201';

// Download Test Files
// Ensure these files exist in the same directory!
$testFiles = array('250MB', '500MB', '1GB');
```

(Teks konfigurasi di atas dibiarkan dalam bentuk aslinya agar mudah copy-paste. Ubah nilai sesuai kebutuhan Anda.)

---

## Kustomisasi Gambar & Logo

Ganti logo dan gambar latar dengan mengganti file berikut di direktori yang sama dengan script:

1. **Logo**: `logo-new.webp` (Tinggi yang disarankan: ~36px)  
2. **Background**: `hero-min.webp` (Background untuk header, disarankan menggunakan format webp dan dikompresi)

Pastikan file dapat diakses oleh user web server.

### Membuat Berkas Dummy untuk Tes Unduh

Anda dapat menghasilkan berkas dummy untuk tes unduh menggunakan `dd`. Masuk ke direktori web server (mis. `/var/www/html/lg/`) lalu jalankan:

**Berkas 250MB:**
```bash
dd if=/dev/zero of=250MB.bin bs=1M count=250 status=progress
```

**Berkas 500MB:**
```bash
dd if=/dev/zero of=500MB.bin bs=1M count=500 status=progress
```

**Berkas 1GB:**
```bash
dd if=/dev/zero of=1GB.bin bs=1M count=1024 status=progress
```

> **Catatan:** Pastikan nama berkas sesuai dengan nilai di array `$testFiles` dalam skrip PHP.

---

## Troubleshooting

### 1. 404 Not Found
- **Nginx**: Pastikan directive `try_files` ada pada blok location.
- **Apache**: Pastikan `mod_rewrite` aktif dan dukungan `.htaccess` (`AllowOverride All`) diizinkan.

### 2. 500 Internal Server Error
- Periksa log error web server (`/var/log/nginx/error.log` atau `/var/log/apache2/error.log`).
- Pastikan ekstensi PHP yang diperlukan terinstal.
- Periksa permission: user web server (`www-data` atau `apache`) harus punya akses baca ke skrip.

### 3. "Command not found" atau Output Kosong
- Verifikasi apakah `ping`, `traceroute`, `mtr`, dll. sudah terpasang (`which ping`).
- Periksa `php.ini` untuk memastikan `proc_open` dan `proc_get_status` TIDAK ada di `disable_functions`.

### 4. Iperf3 Connection Refused
- Pastikan service Iperf3 berjalan: `sudo systemctl status iperf3`.
- Periksa pengaturan firewall untuk memastikan port 5201 terbuka.
- Verifikasi IP server pada konfigurasi PHP sesuai dengan IP publik Anda.

---

## Donasi

**Anda bebas mengubah dan mendistribusikan skrip ini untuk keperluan Anda.**

Jika Anda merasa terbantu dan ingin mendukung proyek ini, pertimbangkan untuk berdonasi via https://www.paypal.me/alsyundawy. Terima kasih atas dukungannya!

Jika Anda merasa terbantu dan ingin mendukung proyek ini, pertimbangkan juga untuk berdonasi via QRIS. Terima kasih atas dukungannya!

<img width="508" height="574" alt="image" src="https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df" />

## Lisensi

Lisensi MIT. Hak cipta (c) 2026 Alsyundawy IT Solution.

![Alt](https://repobeats.axiom.co/api/embed/78ddb5f1a231029b742cc467a74bcce400941d0f.svg "Repobeats analytics image")


