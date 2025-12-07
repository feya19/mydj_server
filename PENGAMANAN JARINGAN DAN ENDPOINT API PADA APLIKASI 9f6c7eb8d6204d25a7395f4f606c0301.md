# PENGAMANAN JARINGAN DAN ENDPOINT API PADA APLIKASI JURNAL HARIAN GURU DENGAN INTEGRASI WAZUH SIEM

---

| **Nama** | **NIM** |
| --- | --- |
| Fahmi Yahya | 2341720089 |
| Muhammad Rifqi Rizqullah | 2341720091 |
| Ashrul Rifki Ardiyhasa | 244107023005 |
| Muhammad Zaki | 2341720052 |

---

## BAB I: PENDAHULUAN

### 1.1 Latar Belakang

Dalam era digital saat ini, aplikasi berbasis web menjadi kebutuhan penting dalam dunia pendidikan, termasuk aplikasi jurnal harian guru yang menyimpan data sensitif seperti informasi siswa, penilaian, dan kegiatan pembelajaran. Namun, meningkatnya ancaman keamanan siber seperti serangan brute force, SQL injection, dan Denial of Service (DoS) membuat keamanan aplikasi menjadi prioritas utama.

Wazuh SIEM (Security Information and Event Management) merupakan platform open-source yang dapat mendeteksi ancaman, memonitor integritas sistem, dan merespons insiden keamanan secara real-time. Integrasi Wazuh dengan aplikasi FastAPI akan memberikan lapisan keamanan tambahan melalui monitoring log, deteksi anomali, dan analisis perilaku jaringan.

Project ini bertujuan mengimplementasikan sistem keamanan berlapis pada aplikasi jurnal harian guru dengan melakukan simulasi berbagai jenis serangan untuk menguji efektivitas sistem deteksi dan respons yang telah dibangun.

### 1.2 Rumusan Masalah

1. Bagaimana mengimplementasikan pengamanan endpoint API pada aplikasi jurnal harian guru menggunakan FastAPI?
2. Bagaimana mengintegrasikan Wazuh SIEM untuk monitoring dan deteksi ancaman keamanan secara real-time?
3. Bagaimana efektivitas sistem keamanan dalam mendeteksi dan merespons serangan Port Scanning, SSH Brute Force, SQL Injection, dan API Flooding?
4. Bagaimana membuat dashboard monitoring keamanan yang informatif untuk administrator sistem?

### 1.3 Tujuan

1. Membangun aplikasi jurnal harian guru dengan arsitektur keamanan berlapis menggunakan FastAPI
2. Mengintegrasikan Wazuh SIEM untuk monitoring log dan deteksi ancaman
3. Melakukan simulasi serangan keamanan dan menganalisis respons sistem
4. Mengimplementasikan mekanisme mitigasi otomatis terhadap ancaman yang terdeteksi
5. Membuat dokumentasi lengkap implementasi keamanan aplikasi

### 1.4 Manfaat

**Manfaat Teoritis:**

- Memahami konsep keamanan aplikasi web dan API secara komprehensif
- Menguasai implementasi SIEM dalam ekosistem aplikasi modern
- Memahami teknik-teknik serangan siber dan cara mitigasinya

**Manfaat Praktis:**

- Menghasilkan aplikasi jurnal harian guru yang aman dan terpercaya
- Memberikan panduan implementasi keamanan untuk aplikasi serupa
- Meningkatkan awareness terhadap pentingnya keamanan aplikasi di lingkungan pendidikan

---

## BAB II: TINJAUAN PUSTAKA

### 2.1 FastAPI

FastAPI adalah framework modern untuk membangun API dengan Python yang berbasis pada type hints. Framework ini menawarkan performa tinggi, validasi data otomatis, dan dokumentasi API interaktif. FastAPI sangat cocok untuk aplikasi yang membutuhkan keamanan tinggi karena dukungan native-nya terhadap OAuth2, JWT, dan berbagai mekanisme autentikasi.

### 2.2 Wazuh SIEM

Wazuh adalah platform keamanan open-source yang menyediakan:

- **Log Analysis**: Analisis log dari berbagai sumber secara terpusat
- **Intrusion Detection**: Deteksi intrusi berbasis signature dan anomaly
- **File Integrity Monitoring**: Monitoring perubahan file sistem
- **Vulnerability Detection**: Deteksi kerentanan pada sistem
- **Incident Response**: Respons otomatis terhadap insiden keamanan

### 2.3 Jenis-Jenis Serangan

**Port Scanning**
Teknik reconnaissance untuk mengidentifikasi port terbuka dan layanan yang berjalan pada target. Tools seperti Nmap sering digunakan untuk melakukan port scanning.

**SSH Brute Force**
Serangan yang mencoba berbagai kombinasi username dan password secara sistematis untuk mendapatkan akses SSH ke server.

**SQL Injection**
Teknik injeksi kode SQL berbahaya melalui input aplikasi untuk memanipulasi database, mengakses data tidak authorized, atau merusak data.

**API Flooding (DoS)**
Serangan yang membanjiri API dengan request berlebihan untuk menghabiskan resource server dan membuat layanan tidak dapat diakses oleh pengguna legitimate.

### 2.4 Keamanan Endpoint API

Pengamanan endpoint API meliputi:

- Autentikasi dan Otorisasi (JWT, OAuth2)
- Rate Limiting dan Throttling
- Input Validation dan Sanitization
- HTTPS/TLS Encryption
- CORS Policy
- API Gateway dan WAF

---

## BAB III: METODOLOGI

### 3.1 Metode Penelitian

Project ini menggunakan pendekatan **Research and Development (R&D)** dengan model pengembangan **Agile** yang terdiri dari iterasi sprint untuk pengembangan dan pengujian sistem keamanan.

### 3.2 Tahapan Pelaksanaan

### **Minggu 1: Persiapan dan Pengembangan Aplikasi**

**Hari 1-2: Setup Environment**

- Instalasi Python, FastAPI, PostgreSQL/MySQL
- Instalasi Wazuh Manager dan Agent
- Setup Docker containers untuk isolasi testing
- Perancangan database dan arsitektur sistem

**Hari 3-5: Pengembangan Core Application**

- Implementasi API endpoints dasar (CRUD jurnal)
- Implementasi autentikasi JWT
- Implementasi input validation dan sanitization
- Implementasi rate limiting dengan SlowAPI
- Setup logging structure JSON

**Hari 6-7: Integrasi Keamanan Dasar**

- Konfigurasi HTTPS dengan Nginx
- Implementasi CORS policy
- Setup Fail2ban
- Testing API endpoints dasar

### **Minggu 2: Integrasi Wazuh dan Konfigurasi Security**

**Hari 8-9: Konfigurasi Wazuh**

- Konfigurasi log collection dari FastAPI ke Wazuh Agent
- Pembuatan custom rules untuk deteksi serangan
- Konfigurasi active response mechanisms
- Setup dashboard Wazuh dan alert notifications

**Hari 10-11: Fine-tuning Security Rules**

- Testing dan penyesuaian rules Wazuh
- Konfigurasi threshold detection
- Setup integration dengan Fail2ban
- Implementasi automated response scripts

**Hari 12-14: Persiapan Testing Environment**

- Setup isolated network untuk penetration testing
- Instalasi tools: Nmap, Hydra, SQLmap, Locust
- Persiapan wordlist dan payload untuk testing
- Dokumentasi baseline system performance

### **Minggu 3: Simulasi Serangan, Analisis, dan Dokumentasi**

**Hari 15-16: Simulasi Serangan**

- Hari 15 Pagi: Port Scanning dengan Nmap
- Hari 15 Siang: SSH Brute Force dengan Hydra
- Hari 16 Pagi: SQL Injection dengan SQLmap
- Hari 16 Siang: API Flooding dengan Locust
- Real-time monitoring dan pencatatan hasil

**Hari 17-18: Analisis Hasil**

- Analisis log Wazuh untuk setiap jenis serangan
- Evaluasi detection rate dan response time
- Perhitungan false positive rate
- Identifikasi area improvement
- Fine-tuning rules berdasarkan hasil testing

**Hari 19-21: Dokumentasi dan Finalisasi**

- Penyusunan laporan hasil testing
- Dokumentasi konfigurasi sistem
- Pembuatan user manual dan admin guide
- Persiapan presentasi hasil project
- Penyusunan laporan akhir lengkap

### 3.3 Alat dan Bahan

**Hardware:**

- Server/VM untuk Wazuh Manager
- Server/VM untuk FastAPI Application
- Workstation untuk testing dan attacking

**Software:**

- Python 3.9+
- FastAPI dan dependencies (Uvicorn, SQLAlchemy, Pydantic)
- PostgreSQL/MySQL
- Wazuh 4.x
- Docker & Docker Compose
- Nmap
- Hydra
- SQLmap
- Apache Bench/Locust
- Git

**Tools Tambahan:**

- Postman/Insomnia untuk API testing
- Wireshark untuk network analysis
- Fail2ban untuk IP blocking
- Nginx sebagai reverse proxy

### 3.4 Arsitektur Sistem

```
┌─────────────────┐
│   End Users     │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Nginx (Proxy)  │
│   + WAF Rules   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐       ┌──────────────────┐
│   FastAPI App   │──────▶│   PostgreSQL     │
│   + JWT Auth    │       │    Database      │
│   + Logging     │       └──────────────────┘
└────────┬────────┘
         │
         │ Logs
         ▼
┌─────────────────┐       ┌──────────────────┐
│  Wazuh Agent    │──────▶│  Wazuh Manager   │
└─────────────────┘       └──────────────────┘
                          

```

### 3.5 Skenario Pengujian

### **Test Case 1: Port Scanning**

- Tools: Nmap
- Command: `nmap -sS -p- <target_ip>`
- Expected: Wazuh mendeteksi scan activity dan trigger alert level 7+
- Response: IP blocking via active response

### **Test Case 2: SSH Brute Force**

- Tools: Hydra
- Command: `hydra -l admin -P wordlist.txt ssh://<target_ip>`
- Expected: Wazuh mendeteksi multiple failed authentication
- Response: Temporary IP ban setelah 5 failed attempts

### **Test Case 3: SQL Injection**

- Tools: SQLmap atau manual injection
- Payload: `' OR '1'='1' --`, `1' UNION SELECT NULL--`
- Expected: Input validation menolak request, Wazuh log suspicious patterns
- Response: Alert dan block request dengan pattern SQL injection

### **Test Case 4: API Flooding (DoS)**

- Tools: Locust atau Apache Bench
- Command: `ab -n 10000 -c 100 http://<target>/api/endpoint`
- Expected: Rate limiter membatasi request, Wazuh deteksi abnormal traffic
- Response: Temporary throttling dan alert kepada admin

### 3.6 Metrik Keberhasilan

1. **Detection Rate**: Persentase serangan yang berhasil dideteksi oleh Wazuh
2. **Response Time**: Waktu rata-rata dari deteksi hingga active response
3. **False Positive Rate**: Persentase alert yang bukan merupakan ancaman nyata
4. **System Performance**: Impact monitoring terhadap performa aplikasi
5. **Recovery Time**: Waktu yang dibutuhkan sistem untuk recovery dari serangan

---

## BAB IV: RENCANA IMPLEMENTASI

### 4.1 Fitur Aplikasi Jurnal Harian Guru

**Modul Autentikasi:**

- Login dengan JWT token
- Role-based access control (Admin, Guru, Kepala Sekolah)
- Refresh token mechanism

**Modul Jurnal:**

- Create, Read, Update, Delete jurnal harian
- Upload attachment (dengan validation file type dan size)
- Filter jurnal berdasarkan tanggal, mata pelajaran, kelas
- Export jurnal ke PDF

**Modul Keamanan:**

- Logging setiap aktivitas user
- Rate limiting per endpoint
- Input validation dan sanitization
- CORS configuration
- HTTPS enforcement

### 4.2 Konfigurasi Wazuh

**Custom Rules untuk FastAPI:**

```xml
<!-- Deteksi SQL Injection Attempt -->
<rule id="100001" level="12">
  <decoded_as>json</decoded_as>
  <field name="message">SQL injection</field>
  <description>SQL Injection attempt detected</description>
  <group>web,sql_injection,</group>
</rule>

<!-- Deteksi API Rate Limit Exceeded -->
<rule id="100002" level="8">
  <decoded_as>json</decoded_as>
  <field name="status_code">429</field>
  <description>API Rate limit exceeded</description>
  <group>web,dos,</group>
</rule>

<!-- Deteksi Multiple Failed Login -->
<rule id="100003" level="10" frequency="5" timeframe="120">
  <decoded_as>json</decoded_as>
  <field name="event_type">authentication_failed</field>
  <description>Multiple failed login attempts</description>
  <group>authentication_failures,</group>
</rule>

```

**Active Response Configuration:**

```xml
<!-- Block IP after 5 failed login attempts -->
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <rules_id>100003</rules_id>
  <timeout>600</timeout>
</active-response>

```

### 4.3 Implementasi Rate Limiting

```python
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/api/login")
@limiter.limit("5/minute")
async def login(request: Request, credentials: LoginSchema):
    # Login logic
    pass

@app.get("/api/journals")
@limiter.limit("100/minute")
async def get_journals(request: Request):
    # Get journals logic
    pass

```

### 4.4 Logging Structure

Setiap request akan di-log dengan format JSON:

```json
{
  "timestamp": "2025-11-24T10:30:00Z",
  "event_type": "api_request",
  "method": "POST",
  "endpoint": "/api/journals",
  "user_id": "user123",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0...",
  "status_code": 200,
  "response_time_ms": 45,
  "payload_size": 1024
}

```

---

## BAB V: JADWAL PELAKSANAAN

| Minggu | Hari | Kegiatan | Output |
| --- | --- | --- | --- |
| **1** | 1-2 | Setup environment dan instalasi tools | Environment siap digunakan |
|  | 3-5 | Pengembangan aplikasi FastAPI | Aplikasi jurnal dengan API endpoints |
|  | 6-7 | Integrasi keamanan dasar | Aplikasi dengan autentikasi dan rate limiting |
| **2** | 8-9 | Konfigurasi Wazuh SIEM | Wazuh terintegrasi dengan aplikasi |
|  | 10-11 | Fine-tuning security rules | Custom rules dan active response |
|  | 12-14 | Persiapan testing environment | Tools dan environment testing siap |
| **3** | 15-16 | Simulasi 4 jenis serangan | Data hasil serangan dan response |
|  | 17-18 | Analisis hasil dan evaluasi | Laporan analisis keamanan |
|  | 19-21 | Dokumentasi dan finalisasi | Laporan akhir lengkap |

### Timeline Detail per Hari:

**Minggu 1 - Development Phase**

- **Hari 1-2**: Setup & Planning
- **Hari 3-5**: Core Development
- **Hari 6-7**: Security Implementation

**Minggu 2 - Security Integration**

- **Hari 8-9**: Wazuh Configuration
- **Hari 10-11**: Security Fine-tuning
- **Hari 12-14**: Testing Preparation

**Minggu 3 - Testing & Documentation**

- **Hari 15-16**: Attack Simulations (4 serangan)
- **Hari 17-18**: Analysis & Evaluation
- **Hari 19-21**: Final Documentation

---

## BAB VI: PENUTUP

### 6.1 Kesimpulan Awal

Project ini akan menghasilkan sistem aplikasi jurnal harian guru yang tidak hanya fungsional tetapi juga memiliki lapisan keamanan yang robust. Dengan integrasi Wazuh SIEM, setiap aktivitas mencurigakan dapat dideteksi dan ditangani secara real-time, memberikan perlindungan maksimal terhadap data sensitif di lingkungan pendidikan.

### 6.2 Kontribusi

Project ini diharapkan dapat menjadi:

1. Referensi implementasi keamanan API untuk aplikasi pendidikan
2. Studi kasus integrasi SIEM dalam aplikasi skala kecil hingga menengah
3. Panduan praktis pengujian keamanan aplikasi web
4. Kontribusi terhadap peningkatan awareness keamanan siber di institusi pendidikan

---

## DAFTAR PUSTAKA

1. FastAPI Documentation. (2025). *Security Best Practices*. https://fastapi.tiangolo.com/tutorial/security/
2. Wazuh Documentation. (2025). *User Manual*. https://documentation.wazuh.com/
3. OWASP Foundation. (2024). *OWASP Top 10 - 2024*. https://owasp.org/www-project-top-ten/
4. NIST. (2023). *Cybersecurity Framework*. National Institute of Standards and Technology.
5. Stallings, W. (2023). *Network Security Essentials: Applications and Standards* (7th ed.). Pearson.