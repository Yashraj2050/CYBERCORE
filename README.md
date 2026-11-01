# CYBERCORE — AI-Powered Digital Security & Threat Intelligence

CYBERCORE is a full-stack cybersecurity platform providing real-time AI-assisted threat detection, phishing and URL analysis, message scam detection, password breach verification, file/hash analysis, and a browser security shield.

---

## 🚀 Quick Start

Run both the frontend and backend with a single command:

```bash
./start.sh
```

### Manual Run

#### 1. Backend (FastAPI)
```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # configure any API keys if needed
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- **Backend API**: `http://localhost:8000`
- **Swagger Documentation**: `http://localhost:8000/docs`

#### 2. Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```
- **Web App**: `http://localhost:3000`

---

## 🧩 Chrome Extension (MV3)

To load the real-time protection browser extension:
1. Open Google Chrome (or any Chromium browser: Brave, Edge, Arc).
2. Navigate to `chrome://extensions/`.
3. Enable **Developer mode** (toggle in top right).
4. Click **Load unpacked**.
5. Select the `extension/` directory inside this repository.

The extension connects to the local backend on `http://localhost:8000` to inspect URLs and active tabs in real time.

---

## 📁 Repository Structure

```
CyberCore/
├── backend/            # FastAPI backend application
│   ├── app/
│   │   ├── main.py     # Application entry point & router mounting
│   │   ├── config.py   # Pydantic settings & environment configuration
│   │   ├── models/     # Pydantic schemas & response models
│   │   ├── routers/    # API endpoints (scan, password, messages, etc.)
│   │   ├── services/   # Core intelligence services (DNS, WHOIS, SSL, etc.)
│   │   └── utils/      # Helper utilities & security helpers
│   ├── requirements.txt
│   └── .env.example
├── frontend/           # Next.js 16 App Router application
│   ├── src/
│   │   ├── app/        # Pages (Dashboard, Scanner, Password, etc.)
│   │   ├── components/ # Bento grid, layout, navbar, cards, UI
│   │   └── lib/        # API client & backend connection
│   └── package.json
├── extension/          # Manifest V3 Chrome Extension
│   ├── manifest.json
│   ├── background.js
│   ├── popup.html
│   └── content.js
├── DESIGN.md           # CyberCore Obsidian Design System specs
└── start.sh            # One-click startup script
```

