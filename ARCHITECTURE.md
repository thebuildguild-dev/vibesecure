# VibeSecure — Architecture

> An AI Governance and Security platform combining a **multi-agent LangGraph swarm** (11 specialist AI agents, RAG-grounded) with an **ethical website vulnerability scanner**.

---

## 1. What VibeSecure Does

VibeSecure offers two independent analysis capabilities from a single dashboard:

| Domain | What it analyses | Key technology |
|---|---|---|
| **AI Governance** | Deepfake media, AI system ethics, threat exposure, privacy posture, digital assets | LangGraph swarm + Gemini + pgvector RAG |
| **Security Scanner** | Websites and APIs for OWASP-class vulnerabilities | Playwright + OWASP ZAP + 8 custom checkers |

Every AI Governance job is orchestrated by a **Supervisor agent** that reads the input, plans which specialist agents are needed, streams their results into a shared state graph, and synthesises a final report.

---

## 2. Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python 3.11) |
| Agent orchestration | LangGraph `StateGraph` |
| AI models | Google Gemini 2.5 Pro (brain), Gemini 2.5/2.0 Flash (agents), multimodal image support |
| Embeddings + RAG | `gemini-embedding-001` + PostgreSQL 15 + pgvector (cosine similarity, IVFFlat index) |
| Task queue | Celery + Redis |
| Authentication | Firebase Admin SDK — JWT verified on every request |
| Web scanning | Playwright (passive crawl + screenshots) + OWASP ZAP (active scan, consent-gated) |
| Frontend | React 18 + Vite + Tailwind CSS + Framer Motion |
| Database ORM | SQLModel (SQLAlchemy 2) |

---

## 3. LangGraph Agent Swarm

### Shared State

All agents read from and write to a single `AgentState` dict that flows through the graph. A `merge_dicts` reducer means each agent only touches its own key — no agent can overwrite another's results.

```
AgentState {
  job_id, service_type, input_data    — job identity and input
  active_agents, completed_agents     — planned vs finished
  results                             — per-agent output, merged via reducer
  governance_bundle                   — final synthesised report
  status                              — pending | running | completed | failed
}
```

### Graph Topology

```
START
  └─> supervisor_plan_node   ← Gemini 2.5 Pro decides which groups to activate
        └─> (router)
              ├─> run_deepfake_group    [keyframe_extractor → triage → forensic → ensemble_voter]
              ├─> run_threat_group      [threat_pattern → predictive_risk]
              ├─> run_responsible_group [responsible_ai_auditor → bias_fairness]
              ├─> run_privacy_group     [privacy_scanner → regulatory_mapper]
              └─> run_digital_group     [digital_asset_governance]
                    └─> synthesize_node  ← merges all results into final report
END
```

Each group runs sequentially so agent N can read agent N-1's results. Groups chain until all planned groups finish. Progress is streamed to the DB after each node so the frontend shows live status.

### Supervisor

**Planning** — inspects `service_type` and `input_data` keys (`file_path`, `url`, `content`, `api_endpoint`) to decide which groups run.

**Synthesis** — after all groups finish, produces: `executive_summary`, `overall_risk_level` (critical/high/medium/low), `confidence_score`, `key_findings`, `recommended_actions`.

---

## 4. RAG Knowledge Base

Five agents query a curated knowledge base before calling Gemini, grounding analysis in real regulatory text and research data rather than model memory.

### Infrastructure

- **Table**: `rag_documents` in PostgreSQL with `vector(768)` column
- **Embedding**: `gemini-embedding-001`, cosine similarity via `<=>` operator, IVFFlat index
- **Chunking**: 2,000-char max with 200-char overlap; SHA-256 content ID for idempotent upsert

### Knowledge Base Contents

| Category | Sources |
|---|---|
| `regulatory` | GDPR (Arts. 5–17), CCPA, India DPDP Act 2023, EU AI Act 2024 |
| `threat_intel` | MITRE ATLAS AI attack techniques, OWASP LLM Top 10 |
| `deepfake_research` | Celeb-DF v2, FaceForensics++, DFDC Challenge methodology |

### Agents that use RAG

| Agent | Category queried | How results are used |
|---|---|---|
| `ensemble_voter` | `deepfake_research` | Matches triage observations to known deepfake research; adds `rag_explanation` and `reference_datasets` |
| `threat_pattern` | `threat_intel` | Injects matching MITRE ATLAS / OWASP LLM entries into the Gemini prompt |
| `predictive_risk` | `threat_intel` | Grounds risk score predictions in known attack technique descriptions |
| `privacy_scanner` | `regulatory` | Injects relevant GDPR/CCPA article text before scanning a URL |
| `regulatory_mapper` | `regulatory` | Maps each detected violation to the exact article text from the knowledge base |

---

## 5. The Five AI Governance Services

### Service 1 — Deepfake Detection

**Input**: image (JPEG/PNG) or video (MP4) file upload  
**Agents**:

| Agent | What it does |
|---|---|
| Keyframe Extractor | OpenCV — extracts up to 10 evenly-spaced frames from video; images treated as single frame |
| Deepfake Triage | Gemini Flash — fast first-pass; looks for unnatural skin, lighting inconsistencies, blurred hair edges; returns `likely_real/likely_fake/suspicious/inconclusive` |
| Forensic Artifact | Gemini Flash (multimodal — actual image bytes sent) — deep analysis of compression artefacts, noise patterns, edge anomalies; separate audio waveform check for TTS/voice-clone signatures |
| Ensemble Voter | Combines 3 votes (triage + forensic + audio) by majority; ties go to `suspicious`; RAG-enriched with matching deepfake research |

**Final output**: `final_verdict`, `final_confidence`, per-agent vote breakdown, `rag_explanation`, `reference_datasets`

---

### Service 2 — Threat Intelligence

**Input**: text content or live AI API endpoint URL  
**Agents**:

| Agent | What it does |
|---|---|
| Threat Pattern | RAG-enriched Gemini analysis mapping threats to MITRE ATLAS technique IDs; live API probing when `api_endpoint` provided (prompt injection, model extraction, adversarial input probes) |
| Predictive Risk | Projects attack vectors for the next 6–12 months with impact/likelihood scores; produces a 2D risk matrix |

---

### Service 3 — Responsible AI Audit

**Input**: live AI model chat API endpoint (agent probes it directly)  
**What happens**: The auditor sends 8 adversarial probe prompts to the endpoint — training data leakage, prompt injection, PII exposure, demographic bias (loan/hiring), safety filter bypass, API key extraction, hallucination — then feeds all responses into a Gemini audit  
**Agents**:

| Agent | What it does |
|---|---|
| Responsible AI Auditor | Scores the system against NIST AI RMF 1.0 (Govern/Map/Measure/Manage) and Google SAIF (6 principles); produces a scorecard across 8 dimensions: transparency, fairness, accountability, safety, privacy, security, robustness, explainability |
| Bias and Fairness | Detects demographic bias, representation gaps, and output distribution skew; returns severity-rated findings with remediation steps |

---

### Service 4 — Privacy Compliance

**Input**: website URL  
**Agents**:

| Agent | What it does |
|---|---|
| Privacy Scanner | Fetches URL with httpx; parses HTML for consent banners (Cookiebot, OneTrust, six CSS class patterns), privacy policy links, and third-party trackers; sends page text to Gemini (RAG-enriched with GDPR/CCPA context) for PII category detection |
| Regulatory Mapper | For each violation, runs a targeted RAG query and maps it to the exact regulatory article; produces a GDPR/CCPA/DPDP/EU AI Act compliance grid |

---

### Service 5 — Digital Asset Governance

**Input**: digital asset description + optional verified domain URL  
**Agent**: Single `digital_asset_governance` agent — checks domain ownership and active scan consent in the DB, then runs all 8 Security Scanner checkers on the domain; separately analyses IP rights and licensing with Gemini

---

## 6. Security Scanner

Separate from the agent swarm — triggered via `/api/scans` directly.

**Preconditions**: (1) user must prove domain ownership via DNS TXT record, `.well-known` file, or response header; (2) explicit consent required for active ZAP scanning.

**Pipeline**:
```
POST /api/scans
  └─> Celery task
        ├─> Playwright: screenshot + link crawl + JS library inventory
        ├─> 8 checkers (sequence):
        │     header_checker      — CSP, HSTS, X-Frame-Options, Referrer-Policy
        │     https_checker       — HTTP→HTTPS redirect, HSTS presence
        │     tls_checker         — TLS 1.0/1.1 detection, weak ciphers, cert expiry
        │     cors_checker        — wildcard Access-Control-Allow-Origin
        │     directory_checker   — open listing on /backup, /.git/, /admin
        │     endpoint_checker    — exposed /admin, /debug, /.env, /api/keys
        │     reflection_checker  — reflected XSS probes with safe payloads
        │     library_checker     — outdated jQuery/Bootstrap/lodash with CVE mapping
        ├─> ZAP active scan (consent-gated)
        └─> Gemini: executive summary + remediation roadmap
```

Findings are severity-rated: `critical / high / medium / low / info`. Each finding includes title, description, evidence, and remediation.

---

## 7. End-to-End Flow

### AI Governance Job
```
Dashboard form  →  POST /api/governance/jobs  →  FastAPI (JWT verify)
  →  DB row (status: pending)  →  Celery task dispatched  →  { job_id } returned

Celery worker:
  AgentState initialised  →  LangGraph.stream()
    supervisor plans  →  agent groups run  →  RAG calls inline  →  synthesise
  DB updated: status=completed, results=governance_bundle

Frontend polls every 3 s  →  GovernanceDetail renders full report + RAG citations
```

### Security Scan
```
Dashboard  →  POST /api/scans  →  ownership + consent checked
  →  DB row (status: queued)  →  Celery task  →  { scan_id } returned

Celery worker: Playwright + 8 checkers + optional ZAP  →  Gemini summary  →  DB save

Frontend polls  →  ScanDetail renders findings, screenshots, PDF download
```

---

## 8. API Reference

All routes require Firebase Bearer token. Prefix: `/api`.

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/verify` | Verify Firebase token, create/update user |
| GET | `/api/auth/me` | Current user profile |
| GET/POST | `/api/domains` | List / add domains for verification |
| POST | `/api/domains/{id}/verify` | Check DNS/file/header verification |
| GET/POST | `/api/consent/{domain}` | Get or update scan consent |
| GET/POST | `/api/scans` | List scans / create new scan |
| GET | `/api/scans/{id}` | Scan result and findings |
| GET | `/api/scans/{id}/report` | PDF report download |
| GET/POST | `/api/governance/jobs` | List jobs / create new job |
| GET | `/api/governance/jobs/{id}` | Job status and results |
| POST | `/api/governance/upload` | Upload file for deepfake / asset analysis |
| GET | `/api/governance/jobs/{id}/rag-sources` | RAG citations used in the analysis |
| GET/POST | `/api/rag/search` `/api/rag/upsert` `/api/rag/stats` | Knowledge base dev/admin endpoints |

---

## Demo Website (TechFlow AI)

`demo-website/` is a deliberately vulnerable Vite app used to demonstrate both the Security Scanner and the Responsible AI Audit.

- **Port 5174** — Vite frontend (landing page with 19 intentional security flaws: missing CSP, outdated jQuery 1.12.4, reflected XSS, eval on URL param, hardcoded API keys, open redirect, etc.)
- **Port 5175** — `ai-api/server.js` — a Node.js chat API that intentionally leaks training data, yields to prompt injection, returns demographic bias, has no safety filters, exposes credentials in `/health`, and discloses its full system prompt on request. Used as a live target for the Responsible AI Audit service.

```bash
cd demo-website
npm run ai-api  # starts the vulnerable AI API on :5175
npm run dev     # starts the Vite site on :5174
```
