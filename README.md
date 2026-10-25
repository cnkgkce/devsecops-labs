# 🛡️ Mini DevSecOps Lab & AI FP Eliminator

Bu repo, tamamen **ücretsiz ve açık kaynaklı** araçlardan oluşan, tek bir bundle (`docker compose`) halinde çalışan uçtan uca bir DevSecOps lab ortamıdır.

Pipeline boyunca **SAST**, **SCA** ve **Container Security** adımları işletilir ve üretilen bulgular üzerinden **AI Destekli False Positive (FP) Eliminasyonu** gerçekleştirilir.

---

## 🏗️ Mimari & Kullanılan Teknolojiler

```
devsecops-labs/
├── docker-compose.yml          # Jenkins servisi & volume bağlamaları
├── jenkins/
│   ├── Dockerfile              # Docker CLI, Trivy, Semgrep, Python3 hazır imaj
│   ├── casc.yaml               # Zero-touch Jenkins kurulumu (admin:admin + hazır pipeline)
│   └── plugins.txt             # Gerekli Jenkins pluginleri
├── sample-app/                 # Kasıtlı zafiyetler içeren Node.js uygulaması
│   ├── server.js               # SQLi, Cmd Injection, XSS, Path Traversal + Bilinçli FP'ler
│   ├── package.json            # Zafiyetli npm bağımlılıkları (Lodash, Axios, JWT, EJS vb.)
│   └── Dockerfile              # Güvenlik açıkları olan konteyner imajı
├── pipeline/
│   └── Jenkinsfile             # Uçtan uca DevSecOps Pipeline kodu
├── ai-engine/                  # [Faz 2] AI Tabanlı FP Eliminasyon Motoru
│   ├── analyzer.py             # Semgrep JSON çıktısını ayrıştıran ve AI ile filtreleyen script
│   ├── prompts.py              # AppSec odaklı LLM Prompt şablonları
│   └── requirements.txt
└── reports/                    # Pipeline tarama çıktılarının (JSON) üretildiği dizin
```

### Güvenlik Araçları Matrisi

| Kategori | Araç | Kullanım Amacı | Çıktı Formatı |
| :--- | :--- | :--- | :--- |
| **CI/CD** | **Jenkins LTS (Docker)** | Pipeline orkestrasyonu | Konsol & Dashboard |
| **SAST** | **Semgrep (Free/OSS)** | Kaynak kod statik analizi | `reports/semgrep-results.json` |
| **SCA** | **Trivy `fs` (Open Source)** | `package.json` ve kütüphane zafiyetleri | `reports/trivy-sca-results.json` |
| **Container** | **Trivy `image`** | Docker imajı işletim sistemi paket zafiyetleri | `reports/trivy-container-results.json` |
| **AI Triage** | **AI FP Eliminator** | SAST bulgularını analiz edip yanlış alarmları eleme | `reports/semgrep-ai-triaged.json` |

---

## 🚀 Hızlı Başlangıç (Tek Komut)

### 1. Docker Desktop'ın Çalıştığından Emin Olun
macOS üzerinde Docker Desktop uygulamasını başlatın.

### 2. Ortamı Ayağa Kaldırın
Terminalden proje dizinine gelip şu komutu çalıştırın:

```bash
docker compose up -d --build
```

Bu komut:
1. Docker CLI, Trivy ve Semgrep araçlarını içeren özel Jenkins imajını derler.
2. Gerekli eklentileri (Pipeline, Stage View, JCasC, ANSIColor vb.) otomatik yükler.
3. Jenkins Configuration as Code (JCasC) ile `admin:admin` kullanıcısını ve **`DevSecOps-Security-Pipeline`** işini hazır olarak oluşturur.

### 3. Jenkins Arayüzüne Giriş Yapın
Tarayıcınızdan açın:
- **URL:** [http://localhost:8080](http://localhost:8080)
- **Kullanıcı Adı:** `admin`
- **Şifre:** `admin`

---

## 🧪 Pipeline'ı Çalıştırma & İnceleme

1. Jenkins ana sayfasında **`DevSecOps-Security-Pipeline`** projesine tıklayın.
2. Sol menüden **"Build Now"** (Şimdi Yapılandır) butonuna basın.
3. Pipeline aşağıdaki adımları sırayla işletecektir:
   - **Stage 0 - Setup:** Ortamdaki araçların (`semgrep`, `trivy`, `docker`, `python3`) doğrulanması.
   - **Stage 1 - SAST (Semgrep):** `sample-app/server.js` taranır; SQLi, Command Injection, XSS, Secret bulguları tespit edilir.
   - **Stage 2 - SCA (Trivy fs):** `sample-app/package.json` taranır; Lodash Prototype Pollution, Axios SSRF vb. zafiyetler raporlanır.
   - **Stage 3 - Build:** Zafiyetli Node.js uygulamasının Docker imajı derlenir.
   - **Stage 4 - Container Security (Trivy image):** Derlenen `vulnerable-node-app:latest` imajındaki OS CVE'leri taranır.
   - **Stage 5 - AI Triage (Faz 2 Hazırlığı):** Semgrep bulguları `ai-engine/analyzer.py` tarafından taranarak True Positive vs False Positive olarak etiketlenir.
   - **Post - Artifacts:** Bütün JSON raporları Jenkins'te arşivlenir ve projenin `reports/` klasörüne yazılır.

---

## 🧠 Faz 2: AI Destekli FP Eliminasyonu Detayı

Statik analiz araçları kuralları gereği desensel eşleşme yapar ve sıkça **False Positive (Yanlış Alarm)** üretir.

`sample-app/server.js` dosyasında bilinçli olarak hem gerçek açıklar hem de yanıltıcı senaryolar kurgulanmıştır:

### Gerçek Açıklar (True Positives):
- **Command Injection:** `exec("ping -c 1 " + host)` (Doğrudan kullanıcı girdisi)
- **SQL Injection:** `SELECT * FROM users WHERE username = '${username}'`
- **Reflected XSS:** `res.send("<h1>Hello " + name + "</h1>")`
- **Path Traversal:** `fs.readFileSync(path.join(__dirname, 'logs', filename))`
- **Hardcoded Secret:** Gerçek formatta AWS Key ve JWT Secret

### Yanıltıcı / Güvenli Senaryolar (False Positives):
- **Mock Token:** `const MOCK_API_TEST_TOKEN = "test_environment_mock_token_xyz123";`
  - *SAST Neden Yanılır:* Regex anahtar kelimeleri yakalar.
  - *AI Neden Eler:* Değişken adı ve içeriğin bir test sabiti olduğunu anlar.
- **Whitelist Korumalı Komut:** `if (ALLOWED_SERVICES.includes(service)) { exec('uptime') }`
  - *SAST Neden Yanılır:* `exec()` fonksiyonunu kullanıcı parametresine yakın gördüğü için uyarır.
  - *AI Neden Eler:* Girdinin strict bir whitelist'ten geçtiğini ve çalıştırılan komutun statik (`uptime`) olduğunu tespit eder.
- **Sanitize Edilmiş HTML:** `res.send("<h2>Welcome back, " + safeEscapeHtml(user) + "</h2>")`
  - *SAST Neden Yanılır:* String concatenation ve `res.send` kalıbı.
  - *AI Neden Eler:* Çıktının `safeEscapeHtml` filtresinden geçtiğini görür.

### AI Engine Çalışma Prensibi:
`ai-engine/analyzer.py` modülü:
1. `reports/semgrep-results.json` dosyasını okur.
2. Her bulgu için kuralı, etkilenen kod bloğunu ve CWE bilgisini prompt haline getirir.
3. LLM (Ollama yerel modeli veya Gemini / OpenAI API) üzerinden analiz ettirip JSON verdict alır.
4. Gürültüyü (noise) elimine ederek sadece gerçek zafiyetleri geliştiriciye raporlar.
