<div align="center">
  <img src="https://github.com/shadowcopyrz/etkg/blob/main/img/logo_alt.png?raw=true" alt="logo"/>

  ![License](https://img.shields.io/github/license/shadowcopyrz/etkg)

# ESET-KeyGen
ESET-KeyGen - Trial-Key & Account generator for ESET Products

---

## ⚠️ Disclaimer ⚠️
### Important: This tool is for educational purposes only.
Using this tool may violate ESET's terms of service and could have legal implications.

The authors and contributors are not responsible for any misuse or damage caused by this project.

Use at your own risk and only on systems you own or have explicit permission to test.

</div>

---
## 🐳 Quick Start (Docker)

The fastest way to get the web dashboard running on a Linux server — no manual Python, Chrome or library setup required.

### 1. Install Docker (Debian / Ubuntu)
```bash
curl -fsSL https://get.docker.com | sh
```

### 2. Clone and start
```bash
git clone https://github.com/chrisdaloa/etkg.git
cd etkg
ETKG_PASSWORD=yourpassword docker compose up -d --build
```

Open `http://<SERVER-IP>:8000` in your browser and log in with the password you set.

### Common commands
| Task | Command |
|------|---------|
| Update to latest code | `git pull && docker compose restart` |
| Rebuild image (after `requirements.txt` changes) | `docker compose up -d --build` |
| View live logs | `docker compose logs -f` |
| Stop | `docker compose down` |

> Generated files (`ESET KEYS *.txt`, `eset-keygen-config.json`) are saved in the project directory on the host and survive restarts and updates.

---
## ✨ Additional Features (this fork)

This fork adds the following features on top of the original project:

### Bug fixes
- **Italian UI support** — all button text variants for the Italian ESET interface are recognised (`continua`, `termina per ora`, `finisci per ora`)
- **Disabled button handling** — the click logic now waits for buttons to become enabled instead of throwing `ElementClickInterceptedException`; falls back to a JS click when an overlay intercepts the element

### Web interface (`webapp.py`)
A browser-based UI that lets you run the script from any device without a terminal.

#### Option A — Docker (recommended, zero manual setup)

Requires [Docker](https://docs.docker.com/engine/install/) with the Compose plugin.

```bash
git clone https://github.com/chrisdaloa/etkg.git
cd etkg
ETKG_PASSWORD=yourpassword docker compose up -d --build
```

Open `http://<SERVER-IP>:8000` in your browser.

| Task | Command |
|------|---------|
| Update code | `git pull && docker compose restart` |
| Rebuild image (after `requirements.txt` changes) | `docker compose up -d --build` |
| View logs | `docker compose logs -f` |
| Stop | `docker compose down` |

The container uses **Chromium** (installed from apt, chromedriver version always in sync).
All generated files (`ESET KEYS *.txt`, `eset-keygen-config.json`, `ESET-KeyGen.log`) are written to the project directory on the host via bind-mount and persist across restarts.

#### Option B — Manual install

**Install dependencies:**
```bash
pip install fastapi "uvicorn[standard]" python-multipart
# or simply:
pip install -r requirements.txt
```

**Start manually:**
```bash
uvicorn webapp:app --host 0.0.0.0 --port 8000
# with password protection:
ETKG_PASSWORD=yourpassword uvicorn webapp:app --host 0.0.0.0 --port 8000
```

**Run as a systemd service (auto-start on boot):**
```ini
# /etc/systemd/system/etkg-web.service
[Unit]
Description=ESET KeyGen Web Dashboard
After=network.target

[Service]
WorkingDirectory=/root/etkg
ExecStart=/root/etkg/venv/bin/uvicorn webapp:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
Environment="ETKG_PASSWORD=yourpassword"

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload && systemctl enable --now etkg-web
```

**Features:**
- **Login form** — optional password protection via `ETKG_PASSWORD` env var; custom dark-themed login page (no browser Basic Auth popup)
- All CLI settings exposed as form controls (mode, browser, email API, repeat, headless, proxy file, output file, flags)
- **Live log streaming** — output appears in real time via Server-Sent Events; **Stop** button to kill the running process
- **Per-repetition result cards** — when repeat > 1, each iteration shows its own green (success) or red (error) card with copyable fields
- **Copy buttons** — one-click copy for log, individual fields (email / password / key) and the full result block
- **Settings persistence** — "Save settings" writes all options to the existing `eset-keygen-config.json`; fields are pre-filled on next page load
- **Proxy pool** — paste any proxy list URL (Webshare or other sources returning `ip:port:user:pass`); when repeat > 1, each iteration uses a different proxy automatically; URL is saved to config
- **Recent files sidebar** — shows the last 5 generated `.txt` key/account files with per-field and per-entry copy buttons; refreshes automatically after each run
- **Linux server / LXC ready** — runs headless by default; no display required

### Reinstallation on a new Linux machine

Complete steps to set up this fork from scratch on a new Linux server or LXC container.

**1. Clone the fork**
```bash
git clone https://github.com/chrisdaloa/etkg.git
cd etkg
```

**2. Install Python dependencies**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**3. Install Chrome or Chromium**
```bash
# Google Chrome
wget -q -O /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install -y /tmp/chrome.deb

# or Chromium
apt install -y chromium chromium-driver
```

**4. Install system libraries (headless server / LXC)**
```bash
apt install -y libnss3 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2
```

**5. Configure the systemd service (auto-start on boot)**
```bash
nano /etc/systemd/system/etkg-web.service
```
```ini
[Unit]
Description=ESET KeyGen Web Dashboard
After=network.target

[Service]
WorkingDirectory=/root/etkg
ExecStart=/root/etkg/venv/bin/uvicorn webapp:app --host 0.0.0.0 --port 8000
Restart=on-failure
RestartSec=5
Environment="ETKG_PASSWORD=yourpassword"

[Install]
WantedBy=multi-user.target
```
```bash
systemctl daemon-reload && systemctl enable --now etkg-web
```

**6. Verify**

Open `http://<SERVER-IP>:8000` in your browser.

> **Note:** `eset-keygen-config.json` (saved settings) is not tracked by git. Copy it manually from the old installation if you want to preserve your configuration.

---

## Original project

This is a fork of [shadowcopyrz/etkg](https://github.com/shadowcopyrz/etkg).

For CLI usage, known errors, browser setup on Windows/Mac, GitHub Actions workflow, contributing guidelines and donations refer to the [upstream repository](https://github.com/shadowcopyrz/etkg).
