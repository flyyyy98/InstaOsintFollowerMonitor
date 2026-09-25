# 🕵️‍♂️ InstaOsintFollowerMonitor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10 | 3.11" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="MIT License" />
  <img src="https://img.shields.io/badge/OSINT-Passive%20Sentinel-red?style=for-the-badge" alt="OSINT Sentinel" />
  <img src="https://img.shields.io/badge/DevSecOps-GitHub%20Actions-orange?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions" />
</p>

<p align="center">
  <b>Automated passive OSINT intelligence tool for monitoring Instagram followers, detect unfollowers, analyze bot probability, track activity heatmaps, and archive profile changes without API restrictions.</b>
</p>

<p align="center">
  <a href="#-english">English</a> •
  <a href="#-español">Español</a>
</p>

---

## 🌐 English

### 📌 Overview
**InstaOsintFollowerMonitor** is an automated Open Source Intelligence (OSINT) framework designed for passive, differential surveillance of public Instagram targets. Built with DevSecOps best practices, it operates seamlessly on local environments or scheduled serverless runners via GitHub Actions.

### 🚀 Key Capabilities
- **Differential Set Analysis**: Calculates mathematical differences ($\Delta$) across runs to isolate new followers and unfollowers with zero false positives.
- **Bot & Fake Detection Heuristic**: Calculates bot likelihood based on follower-to-following ratios, default avatars, bio spam patterns, and numerical username structures.
- **Cross-Platform OSINT**: Correlates new detected usernames across platforms (TikTok, Telegram, GitHub, Reddit).
- **Temporal Activity & Sleep Gap Analysis**: Analyzes posting patterns and stories timestamps to deduce likely time zones and sleep windows.
- **Story Auto-Archiver**: Backs up active Stories before the 24-hour expiration window.
- **Multi-Channel Dispatcher**: Real-time alerts to Telegram and WhatsApp.
- **Data Center IP Defense (OPSEC)**: Bypasses cloud datacenter IP blocks and 2FA interactive challenges using pre-authenticated Base64 session serialization (`IG_SESSION_BASE64`).

---

### 📁 Repository Structure
```text
├── .github/
│   └── workflows/
│       └── instagram_monitor.yml   # CI/CD Workflow (Scheduled Cron every 3h & Dispatch)
├── .env.example                    # Environment template
├── .gitignore                      # Security exclusions (sessions, keys, caches)
├── LICENSE                         # MIT License
├── requirements.txt                # Python dependencies
├── tracker.py                      # Main OSINT engine
├── test_tracker.py                 # Offline mock test suite (Zero credentials required)
└── README.md                       # Documentation
```

---

### ⚡ Quick Start (Local)

#### 1. Setup Environment
```bash
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

pip install -r requirements.txt
```

#### 2. Run Offline Tests (No credentials required)
Test the entire diffing logic, bot heuristics, and reporting without touching Instagram's servers:
```bash
python test_tracker.py
```

#### 3. Configuration
Copy the template and configure your credentials:
```bash
cp .env.example .env
```
Edit `.env`:
```ini
IG_USERNAME=your_burner_account
IG_PASSWORD=your_burner_password
TARGET_ACCOUNT=target_username_without_at

# Optional: Instant Telegram Alerts
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Optional: WhatsApp Alerts (CallMeBot)
WHATSAPP_PHONE=
WHATSAPP_APIKEY=
```

#### 4. Run Tracker
```bash
python tracker.py
```

---

### ☁️ Continuous Surveillance via GitHub Actions (CI/CD)

#### Step 1: Export Pre-Authenticated Session (Recommended)
To prevent Meta from flagging Azure/GitHub datacenter IP addresses, authenticate once locally and export your session string:
```bash
python tracker.py --export-session
```
Copy the generated Base64 output.

#### Step 2: Configure Repository Secrets
In your repository, navigate to **Settings** > **Secrets and variables** > **Actions** > **New repository secret**:

| Secret | Description | Required |
| :--- | :--- | :---: |
| `IG_USERNAME` | Operator burner Instagram account | Yes |
| `IG_PASSWORD` | Operator account password | Optional (if session provided) |
| `TARGET_ACCOUNT` | Target username (without `@`) | Yes |
| `IG_SESSION_BASE64` | Base64 encoded session string | **Recommended** |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot API token | Optional |
| `TELEGRAM_CHAT_ID` | Telegram Chat ID for alerts | Optional |
| `WHATSAPP_PHONE` | WhatsApp number for CallMeBot | Optional |
| `WHATSAPP_APIKEY` | CallMeBot WhatsApp API Key | Optional |

#### Step 3: Triggering
- **Automated**: Runs every 3 hours (`0 */3 * * *`) on GitHub's cloud runners.
- **Manual**: Go to **Actions** > **Instagram Passive Follower Monitor** > **Run workflow**.

---

### ⚖️ Legal & Ethical Disclaimer
This tool is intended strictly for educational, security research, and authorized OSINT investigations. The author assumes no liability for misuse, account rate limits, or violations of platform Terms of Service. Always adhere to legal and OPSEC principles.

---

## 🇪🇸 Español

### 📌 Descripción General
**InstaOsintFollowerMonitor** es un sistema automatizado de inteligencia de fuentes abiertas (OSINT) diseñado para realizar monitoreo pasivo, continuo y diferencial sobre cuentas públicas de Instagram, integrando mejores prácticas de DevSecOps, control de límites de tasa (rate-limiting) y CI/CD en GitHub Actions.

### 🚀 Características Principales
- **Análisis Diferencial ($\Delta$)**: Determina con precisión matemática nuevos seguidores y pérdidas de seguidores (*unfollowers*) entre escaneos sucesivos.
- **Heurística de Detección de Bots y Cuentas Falsas**: Evalúa ratio de seguidores/seguidos, fotos predeterminadas, patrones de spam en biografía y sufijos numéricos.
- **Búsqueda Cruzada Multiplataforma**: Correlaciona nombres de usuario detectados en TikTok, Telegram, GitHub y Reddit.
- **Mapa de Actividad y Análisis de Ventana de Sueño (*Sleep Gap*)**: Deduce hábitos de conexión y husos horarios aproximados según marcas temporales de posts e historias.
- **Respaldo de Historias**: Descarga y preserva historias activas antes de su expiración a las 24 horas.
- **Alertas Multicanal**: Despacho instantáneo de notificaciones a Telegram y WhatsApp.
- **Evasión de Bloqueos por IP (OPSEC)**: Inyección de sesiones pre-autenticadas vía **Base64** (`IG_SESSION_BASE64`) para evitar *checkpoints* desde servidores cloud.

---

### ⚡ Inicio Rápido (Local)

#### 1. Configurar Entorno
```bash
python -m venv venv

# En Windows:
.\venv\Scripts\activate

# En Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

#### 2. Prueba Unitaria Offline (Sin credenciales)
Prueba la lógica de conjuntos y reportes sin conectarte a Instagram:
```bash
python test_tracker.py
```

#### 3. Configuración
```bash
cp .env.example .env
```
Edita `.env` con tu cuenta secundaria y el objetivo a monitorear.

#### 4. Ejecución
```bash
python tracker.py
```

---

### ☁️ Despliegue en GitHub Actions (24/7)

1. **Exportar Sesión**: Ejecuta `python tracker.py --export-session` y copia la cadena Base64 generada.
2. **Cargar Secrets**: Agrega `IG_USERNAME`, `TARGET_ACCOUNT`, `IG_SESSION_BASE64` y tus credenciales de alerta en **Settings > Secrets and variables > Actions**.
3. **Monitoreo Automático**: Se ejecutará cada 3 horas automáticamente y enviará alertas cuando detecte cambios.

---

## 📄 Licencia y Autoría
Desarrollado bajo licencia **MIT** por [flyyyy98](https://github.com/flyyyy98). Consulta el archivo [LICENSE](LICENSE) para más detalles.
