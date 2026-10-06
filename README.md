# 🛡️ Sentinel-AI: Zero-Trust AI Privacy, Threat Detection & Governance Gateway

> **Production-grade, full-stack AI Security & Privacy Gateway.**  
> Intercepts prompts & outputs between enterprise users and LLMs to detect prompt injections/jailbreaks, automatically anonymizes PII/PHI using reversible synthetic tokenization, computes an Explainable Trust & Safety Index (0–100), and maintains a tamper-evident security telemetry log.

---

## 🌟 Key Capabilities

- **⚡ Real-Time Zero-Trust Ingress Proxy:** Intercepts and parses every prompt before it reaches upstream LLMs.
- **🔒 Reversible Synthetic Tokenization (PII/PHI Vault):** Detects Emails, Phone Numbers, SSNs, Credit Cards, IP Addresses, Names, Medical Record Numbers (MRN), and Cloud API Keys. Replaces them with identifiable tokens (e.g. `[EMAIL_1]`, `[SSN_1]`) and supports authorized zero-knowledge detokenization.
- **🛑 Adversarial Threat & Jailbreak Neutralizer:** Real-time heuristic and signature detection for DAN archetypes, instruction overrides, system prompt extraction probes, reverse shells, and malicious code payloads.
- **📊 Explainable Trust & Safety Index (0–100):** Mathematically derived score with granular penalty breakdown (Injection Risk, PII density, Heuristic anomalies).
- **📋 Tamper-Evident Security Telemetry:** High-resolution audit log with client IP hashing, timestamps, decision verdicts (`ALLOW`, `SANITIZE_AND_FORWARD`, `QUARANTINE_BLOCKED`), and sub-20ms proxy latency.
- **🎯 Dynamic Cockpit Playground:** Dual-pane live inspector, preset attack vector injection, and interactive PII reveal/conceal toggles.

---

## 📁 Repository Structure

```text
sentinel-ai/
├── client/                     # Frontend: React 18, Vite, TypeScript, Tailwind CSS
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.tsx
│   │   │   ├── MetricCards.tsx
│   │   │   ├── LiveInspector.tsx
│   │   │   ├── ThreatVisualizer.tsx
│   │   │   ├── AuditLogsTable.tsx
│   │   │   └── TrustScoreGauge.tsx
│   │   ├── services/
│   │   │   └── api.ts          # API client with local/Render fallback
│   │   ├── types/
│   │   │   └── index.ts        # TypeScript schemas
│   │   ├── App.tsx
│   │   ├── main.tsx
│   │   └── index.css
│   ├── index.html
│   ├── package.json
│   ├── tailwind.config.js
│   ├── postcss.config.js
│   ├── tsconfig.json
│   ├── vercel.json             # Vercel client-level SPA rewrites
│   └── vite.config.ts
├── server/                     # Backend: Python 3.10+, FastAPI, Uvicorn, Pydantic v2
│   ├── app/
│   │   ├── core/
│   │   │   ├── config.py       # CORS & environment configuration
│   │   │   ├── security.py     # Threat detection & Trust Index engine
│   │   │   ├── pii_engine.py   # Reversible PII tokenization engine
│   │   │   └── audit_store.py  # In-memory telemetry log & metrics
│   │   ├── models/
│   │   │   └── schemas.py      # Pydantic v2 validation models
│   │   ├── routers/
│   │   │   ├── analyze.py      # /api/v1/scan, /detokenize, /presets
│   │   │   └── audit.py        # /api/v1/audit-logs, /metrics
│   │   └── main.py             # FastAPI entrypoint & /health check
│   ├── requirements.txt
│   ├── Procfile                # Render web process declaration
│   ├── render.yaml             # Render Blueprint specification
│   └── .python-version         # Pinned Python version
├── vercel.json                 # Vercel root-level deployment routing
├── .env.example
├── .gitignore
└── README.md
```

---

## 🚀 Cloud Deployment Instructions

### 1. Push to GitHub
1. Initialize git and commit the codebase:
   ```bash
   git add .
   git commit -m "feat: complete Sentinel-AI gateway monorepo"
   git push -u origin main
   ```
   Repository URL: [https://github.com/erusanimanogna4-lucky/trust-ai](https://github.com/erusanimanogna4-lucky/trust-ai)

---

### 2. Backend Deployment on Render (FastAPI)

1. Log into [Render.com](https://dashboard.render.com).
2. Click **New +** and select **Web Service**.
3. Connect your GitHub repository.
4. Configure the Web Service settings:
   - **Name**: `sentinel-ai-api` (or your preferred name)
   - **Region**: Select closest to your users (e.g., Oregon, Frankfurt)
   - **Root Directory**: `server` *(Important!)*
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. **Environment Variables**:
   - `ENVIRONMENT` = `production`
   - `PYTHON_VERSION` = `3.11.8`
6. **Health Check Path**: `/health`
7. Click **Create Web Service**.
8. Once deployed, copy your Render service URL:  
   👉 `https://sentinel-ai-api.onrender.com`

> **Note on Render Free Tier:** The free tier spins down on idle and wakes up in ~30–45 seconds upon the first HTTP ping. The frontend contains an intelligent resilience layer so it loads smoothly during wake-up.

---

### 3. Frontend Deployment on Vercel (React + Vite)

1. Log into [Vercel.com](https://vercel.com).
2. Click **Add New...** -> **Project**.
3. Import your GitHub repository.
4. Under **Project Settings**:
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click *Edit* and select `client`
5. Under **Environment Variables**, add:
   - **Key**: `VITE_API_BASE_URL`
   - **Value**: `https://sentinel-ai-api.onrender.com` *(Replace with your actual Render URL)*
6. Click **Deploy**.
7. Vercel will install dependencies, build the TypeScript bundle, and provide your live production URL (e.g., `https://sentinel-ai.vercel.app`).

---

## 💻 Local Development Setup

### Running the Backend (`/server`):
```bash
cd server

# Optional: activate virtual environment
python -m venv venv
# Windows:
.\venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
API will run on [http://localhost:8000](http://localhost:8000).  
Interactive Swagger docs available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Running the Frontend (`/client`):
```bash
cd client
npm install
npm run dev
```
Client dashboard will run on [http://localhost:5173](http://localhost:5173).

---

## 📡 API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Cloud health probe returning `{ status: "healthy", service: "Sentinel-AI" }` |
| `POST` | `/api/v1/scan` | Intercepts prompt, masks PII, analyzes threats, calculates trust score |
| `POST` | `/api/v1/detokenize` | Restores synthetic tokens (`[EMAIL_1]`) back to original values |
| `GET` | `/api/v1/audit-logs` | Retrieves tamper-evident telemetry logs with query filtering |
| `GET` | `/api/v1/metrics` | Returns aggregated metrics (throughput, blocked threats, redacted PII) |
| `GET` | `/api/v1/presets` | Returns curated library of adversarial attack vectors |

---

## 🛡️ Trust & Safety Algorithm Formula

$$\text{Trust Index} = \max(0, 100 - \text{Injection Penalty} - \text{PII Penalty} - \text{Heuristic Penalty})$$

- **Injection Penalty** (0 to -40 pts): Derived from prompt injection & jailbreak vector confidence.
- **PII / PHI Penalty** (0 to -30 pts): Calculated by density of credentials, SSNs, and healthcare IDs.
- **Heuristic Penalty** (0 to -30 pts): Triggered by malicious system leakage or command execution patterns.

---

## 📄 License
MIT License. Built for enterprise security operations and zero-trust AI architectures.
