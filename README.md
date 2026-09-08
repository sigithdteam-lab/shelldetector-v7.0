GNU General Public License v3.0
Copyright (C) 2026 sigithdteam-lab


WebShell Detector Pro v7.0 adalah script bash untuk mendeteksi web shell, malware, crypto miner, ransomware, dan phishing pada server web. Script ini menggunakan pendekatan hybrid signature-based dengan kemampuan auto-update pattern dari berbagai sumber terpercaya.

---

🎯 KEGUNAAN

1. Keamanan Server Web

· Mendeteksi backdoor dan web shell yang disembunyikan di file PHP, JS, HTML, dll.
· Mencegah serangan hacker dengan menemukan celah keamanan sebelum dieksploitasi

2. Forensik Digital

· Investigasi awal saat website terindikasi terkena hack
· Melacak file-file mencurigakan yang ditinggalkan attacker

3. Monitoring Keamanan

· Scanning rutin untuk memastikan tidak ada file berbahaya
· Cocok untuk ISP, hosting provider, dan admin server

4. Kepatuhan Keamanan

· Memenuhi standar keamanan untuk audit website
· Dokumentasi temuan melalui laporan lengkap

---

⚙️ CARA KERJA

Alur Proses Scanning:

```
1. LOAD PATTERN
   ↓
2. UPDATE PATTERN (jika auto-update aktif)
   ↓
3. SCAN FILE
   ↓
4. DETEKSI dengan MULTI-PATTERN
   ↓
5. KATEGORISASI ANCAMAN
   ↓
6. GENERATE REPORT
```

Mekanisme Deteksi:

A. Pattern Matching

Script memiliki 15+ kategori pattern yang dicocokkan dengan konten file:

Kategori Contoh Pattern Fungsi
Dangerous Functions eval(, system(, exec( Deteksi fungsi berbahaya PHP
Critical Patterns c99shell, r57shell, wso Deteksi web shell terkenal
Crypto Miners xmrig, stratum, pool Deteksi penambang crypto
Ransomware openssl_encrypt, .encrypted Deteksi ransomware
Phishing login.php, oauth, credential Deteksi halaman phishing
Obfuscation base64_decode.*eval, gzinflate Deteksi kode obfuscated
Custom Keywords sincan, sodok, mhl Deteksi signature hacker Indonesia

B. File Analysis

· Membaca konten file (max 5MB normal, 20MB deep scan)
· Mengecek ekstensi file (PHP, JS, HTML, SH, dll.)
· Menghitung hash MD5 untuk identifikasi unik
· Memeriksa tipe file (text/binary)

C. Layered Detection

```
FILE → Check Extension → Check Content → Multi-Pattern Scan → Categorize Threat
```

---

🔥 FITUR UNGGULAN

1. Auto Pattern Update

Mengunduh pattern dari 10+ sumber:

```bash
Sumber Pattern:
├── YARA Rules (Malware Detection)
├── PHP Malware Finder
├── Wordfence Patterns
├── Neo23x0 Signature Base
├── MalwareBazaar API
├── ExploitDB
├── CVE List 2025
└── Custom Repositories
```

2. 20+ Pattern Categories

No Kategori Pattern Jumlah Pattern
1 Dangerous Patterns 30+
2 Dangerous Functions 50+
3 Suspicious Names 40+
4 Critical Patterns 20+
5 Crypto Patterns 30+
6 Ransomware Patterns 15+
7 Phishing Patterns 15+
8 YARA Patterns 25+
9 Falco Patterns 15+
10 Obfuscated Patterns 15+
11 WP Malware 10+
12 PHP Object Injection 10+
13 Interpreter Patterns 12+
14 Cookie Patterns 8+
15 Laravel Patterns 8+
16 Joomla Patterns 8+
17 Drupal Patterns 8+
18 Custom Keywords 10+

3. Mode Scanning

Mode Fitur Penggunaan
normal Scan cepat dengan pattern standar Daily monitoring
deep Deep scan + semua ekstensi teks Investigasi mendalam
full Deep + JSON output Audit keamanan
update-only Hanya update pattern Update database pattern

4. Output & Reporting

```
Output:
├── LOG_FILE (scan_YYYYMMDD_HHMMSS.log) - Log lengkap
├── REPORT_FILE (report_YYYYMMDD_HHMMSS.txt) - Laporan
├── ALERT_FILE (alerts_YYYYMMDD_HHMMSS.txt) - Alert kritis
└── JSON_FILE (scan_YYYYMMDD_HHMMSS.json) - Format JSON
```

5. Visual Output

Script menampilkan output berwarna dengan ikon:

Ikon Arti
💀 Critical Threat
⛏️ Crypto Miner
🔒 Ransomware
🎣 Phishing
🦠 Malware
🔍 Custom Keyword
⚠️ Suspicious
✅ Clean

---

📥 AUTO UPDATE PATTERN

Proses Auto Update:

```bash
1. Download dari 10+ sumber
   ↓
2. Ekstrak pattern dari YARA, PHP, dan teks
   ↓
3. Kategorisasi otomatis
   ↓
4. Deduplikasi pattern
   ↓
5. Cache pattern di /var/log/webshell_detector/patterns/
   ↓
6. Integrasi dengan pattern core
```

Sumber Pattern yang Diupdate:

1. YARA Rules - Aturan deteksi malware
2. PHP Malware Finder - Pattern malware PHP
3. Wordfence - Pattern dari plugin keamanan WordPress
4. Neo23x0 - Signature base referensi
5. MalwareBazaar - Database malware terbaru
6. ExploitDB - Database exploit
7. CVE List - Daftar kerentanan terbaru
8. Custom Repositories - Pattern komunitas

---

🔧 MANUAL UPDATE PATTERN

Cara 1: Update Only Mode

```bash
./shelldetector.sh update-only
```

Output:

```
🔄 Pattern Update Only Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Downloading patterns from: YARA_INDEX
✓ Downloaded: YARA_INDEX
Downloading patterns from: PHP_MALWARE_FINDER
✓ Downloaded: PHP_MALWARE_FINDER
...
✓ Downloaded 8/8 pattern sources
Extracting patterns...
✓ Extracted 150 new patterns
✓ Patterns updated successfully!
Pattern cache: /var/log/webshell_detector/patterns/pattern_cache.txt
```

Cara 2: Update + Scan

```bash
./shelldetector.sh /var/www/html
```

Script akan auto-update pattern lalu melakukan scan.

Cara 3: Custom Pattern Manual

Tambahkan pattern ke array CUSTOM_KEYWORD_PATTERNS:

```bash
CUSTOM_KEYWORD_PATTERNS=(
    "sincan"
    "sodok"
    "mhl"
    "c99_modified"
    "custom_backdoor_2026"
)
```

---

🏆 KEUNGGULAN SCRIPT

1. Comprehensive Detection

· ✅ Mendeteksi 15+ jenis ancaman
· ✅ Support 25+ ekstensi file
· ✅ 500+ pattern bawaan + update otomatis

2. Smart Pattern Management

· ✅ Auto-update dari 10+ sumber terpercaya
· ✅ Pattern caching untuk performa
· ✅ Deduplikasi otomatis
· ✅ Kategorisasi pattern cerdas

3. User-Friendly

· ✅ Output berwarna dengan ikon
· ✅ Progress bar real-time
· ✅ 4 mode scanning fleksibel
· ✅ Help lengkap dengan contoh

4. Zero File Modification

· ✅ LOG ONLY - Tidak menghapus file
· ✅ Aman untuk environment production
· ✅ Audit trail lengkap

5. Multi-Format Output

· ✅ Log file detail
· ✅ Report ringkas
· ✅ Alert kritis terpisah
· ✅ JSON untuk integrasi

6. Optimized Performance

· ✅ Skip direktori sistem
· ✅ Batch processing
· ✅ Limit ukuran file
· ✅ Caching pattern

7. Indonesian Context

· ✅ Pattern khusus hacker Indonesia
· ✅ Keyword: sincan, sodok, mhl, dll.
· ✅ Cocok untuk server di Indonesia

---

📊 PERBANDINGAN DENGAN TOOL LAIN

Fitur WebShell Detector Pro | ClamAV  |Maldet
Auto Update Pattern ✅ (10+ sumber) | ✅  | ✅
Web Shell Detection ✅ (Khusus) ⚠️ ✅
Crypto Miner Detection ✅ ⚠️ ❌
Ransomware Detection ✅ ⚠️ ⚠️
Phishing Detection ✅ ❌ ❌
Custom Keyword Support ✅ ❌ ✅
Indonesian Context ✅ ❌ ❌
Output JSON ✅ ⚠️ ✅
No File Deletion ✅ ❌ ❌

---

🚀 CONTOH PENGGUNAAN

1. Scan Cepat Harian

```bash
# Auto-update + scan normal
./shelldetector.sh /var/www/html
```

2. Deep Scan untuk Investigasi

```bash
# Deep scan dengan JSON output
./shelldetector.sh deep /var/www/html --json
```

3. Update Pattern Saja

```bash
# Update database pattern
./shelldetector.sh update-only
```

4. Scan tanpa Auto-Update

```bash
# Gunakan pattern yang sudah ada
./shelldetector.sh --no-update /var/www/html
```

5. Full Audit

```bash
# Full scan + laporan lengkap
./shelldetector.sh full /var/www/html
```

---

📝 KESIMPULAN

WebShell Detector Pro v7.0 adalah solusi keamanan server yang komprehensif, modern, dan user-friendly. Dengan kemampuan auto-update pattern dan deteksi multi-layered, script ini sangat cocok untuk:

· 🔐 Administrator Server - Monitoring keamanan harian
· 🏢 Hosting Provider - Scan website klien
· 🔍 Security Analyst - Investigasi incident
· 🛡️ Developer - Cek keamanan aplikasi web

Keunggulan utama: Auto update pattern dari berbagai sumber membuat deteksi selalu up-to-date terhadap ancaman terbaru.
