# ContextShield

A Gmail Add-on that analyzes opened emails and produces a maliciousness score, verdict, and human-readable reasoning — built security-first.

---

## What It Does

When you open an email in Gmail, ContextShield automatically analyzes it and displays:

- A **risk score** (0–100)
- A **verdict**: SAFE / SUSPICIOUS / MALICIOUS
- **Plain-language reasoning** explaining the verdict
- **Typed signals** — the specific indicators that fired (DKIM fail, spoofed sender, dangerous attachment, etc.)

---

## Architecture

```
Gmail (user opens email)
        │
        ▼
 Google Apps Script Add-on
   • Extracts metadata + plain text only
   • Attachment content never leaves the client
   • Signs every request with a Google OIDC token
        │ HTTPS + OIDC
        ▼
 FastAPI Backend on Cloud Run
   ┌──────────────────────────────────────┐
   │ 1. OIDC token verification           │
   │ 2. Rate limiting (per identity)      │
   │ 3. Input sanitization               │
   │ 4. Heuristic engine  ← security core │
   │ 5. Groq LLM          ← explainability│
   │ 6. Pydantic output validation        │
   └──────────────────────────────────────┘
        │
        ▼
 Add-on Card UI — score, verdict, reasoning, signals
```

### Why two stages?

**Heuristics are the security engine. The LLM is the explainability layer.**

Security decisions (DKIM/SPF/DMARC failures, homoglyph domains, dangerous attachments) are made by deterministic, auditable code. The LLM synthesizes these into plain-language reasoning and catches subtle social engineering the rules miss. A `score_floor` from heuristics ensures the LLM cannot be prompt-injected into downgrading a verdict.

---

## Security Design

| Threat | Mitigation |
|---|---|
| Unauthenticated backend calls | Google OIDC token, audience exact-match to service URL |
| Token reuse / abuse | Per-identity rate limiting (30 req/min) |
| Prompt injection via email body | XML delimiters, system/user role separation, explicit adversarial warning in system prompt |
| LLM verdict manipulation | `score_floor` enforced in code — heuristic signals cannot be overridden by email content |
| Malformed LLM output | Pydantic schema validation + score clamping |
| SSRF via extracted URLs | No DNS resolution; private IP blocklist; scheme allowlist |
| Attachment content leakage | Only filename + MIME type sent — never content |
| API key exposure | GCP Secret Manager only; never in source or image |
| Email content retention | Zero storage; only verdict + score logged |
| Container privilege escalation | Non-root user; minimal base image (`python:3.12-slim`) |
| Oversized / fuzzing payloads | Strict field length limits; `extra=forbid` on Pydantic model |

---

## Heuristic Signals

| Signal | What it detects | Severity |
|---|---|---|
| `dkim_fail` | DKIM signature verification failed | High |
| `spf_fail` | SPF check failed or softfailed | High |
| `dmarc_fail` | DMARC policy failed | High |
| `reply_to_mismatch` | Reply-To domain differs from From domain | High |
| `display_name_spoofing` | Display name contains a known brand but domain does not | Critical |
| `homoglyph_domain` | Sender domain uses characters confusable with a known brand | Critical |
| `dangerous_attachment` | Attachment extension is executable or macro-capable | Critical |
| `suspicious_tld` | Domain uses a TLD commonly associated with abuse | High |
| `url_shortener` | Email contains a URL shortener link | Medium |
| `ip_as_hostname` | URL uses a raw IP address instead of a domain | High |
| `ssrf_risk_url` | URL points to a private/internal IP range | Critical |
| `urgency_language` | Email contains urgency or fear-based language patterns | Low–Medium |

---

## Project Structure

```
ContextShield/
├── addon/
│   ├── appsscript.json   — manifest, OAuth scopes
│   ├── Code.gs           — trigger entry point, payload builder
│   ├── Api.gs            — backend call with OIDC token
│   └── UI.gs             — Card Service UI builders
├── backend/
│   ├── main.py           — FastAPI app, routes, middleware
│   ├── auth.py           — OIDC verification, rate limiter
│   ├── sanitizer.py      — input cleaning pipeline
│   ├── heuristics.py     — deterministic signal extraction
│   ├── groq_client.py    — Groq wrapper, prompt injection defense
│   ├── analyzer.py       — orchestrates stages + fallback
│   ├── models.py         — Pydantic schemas
│   ├── Dockerfile        — non-root, multi-stage, minimal image
│   └── requirements.txt  — pinned dependencies
├── cloudbuild.yaml        — one-command Cloud Run deploy
└── README.md
```

---

## Setup & Deployment

### Prerequisites

- GCP project with Cloud Run, Secret Manager, and Cloud Build enabled
- Groq API key ([console.groq.com](https://console.groq.com))
- Node.js + `clasp` CLI for Apps Script deployment (`npm install -g @google/clasp`)

### 1. Store secrets in GCP Secret Manager

```bash
echo -n "your-groq-api-key" | gcloud secrets create groq-api-key --data-file=-
echo -n "your-script@your-project.iam.gserviceaccount.com" \
  | gcloud secrets create allowed-sa-emails --data-file=-
```

### 2. Deploy the backend

```bash
gcloud builds submit --config cloudbuild.yaml
```

After deploy, note the Cloud Run service URL (e.g. `https://contextshield-backend-xxxx-uc.a.run.app`).

Update `SERVICE_URL` in `cloudbuild.yaml` and redeploy, or set it directly:

```bash
gcloud run services update contextshield-backend \
  --set-env-vars SERVICE_URL=https://contextshield-backend-xxxx-uc.a.run.app
```

### 3. Deploy the add-on

```bash
cd addon
clasp login
clasp create --type standalone --title "ContextShield"
# Set the backend URL in Script Properties
clasp run 'PropertiesService.getScriptProperties().setProperty("BACKEND_URL", "https://contextshield-backend-xxxx-uc.a.run.app")'
clasp push
```

Then in the Apps Script editor: **Deploy → New deployment → Gmail Add-on**.

### 4. Install in Gmail

Go to **Google Workspace Marketplace** (or use developer mode in Gmail settings) and install the add-on on your account.

---

## Running Locally (for development)

```bash
cd backend
python -m venv .venv && source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
GROQ_API_KEY=your-key SERVICE_URL=http://localhost:8080 ALLOWED_SA_EMAILS="" \
  uvicorn main:app --reload --port 8080
```

The `ALLOWED_SA_EMAILS=""` empty string disables the subject allowlist for local dev.

Health check: `curl http://localhost:8080/health`

---

## Trade-offs & What I'd Do With More Time

**Trade-offs made:**
- **In-process rate limiter** — works for a single Cloud Run instance. A Redis-backed limiter would be correct for multi-instance deployments.
- **Groq / Llama 70B** — fast and free-tier friendly for demo purposes. A frontier model (Claude, GPT-4o) would catch subtler social engineering. The heuristic layer compensates significantly.
- **No attachment content scanning** — a hard security boundary for privacy. A production version would pass attachment hashes to a threat-intel API (VirusTotal) rather than scanning content.
- **`Authentication-Results` header parsing** — Apps Script doesn't expose raw MIME headers natively. The current approach parses what's available; a production version would use the Gmail API's full message resource for reliable header access.

**With more time:**
- VirusTotal integration for URL and attachment hash lookups
- Domain age lookup (WHOIS) for newly registered sender domains
- Redis rate limiter for multi-instance Cloud Run
- Historical per-sender scoring within a user's account
- Feedback loop: let users mark verdicts as wrong to improve accuracy
