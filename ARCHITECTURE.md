# VibeSecure — Full Platform Architecture

> An AI Governance and Security platform with five specialized multi-agent services and an ethical web security scanner.

---

## Table of Contents

1. [Platform Overview](#1-platform-overview)
2. [Tech Stack](#2-tech-stack)
3. [LangGraph Agent Swarm — How It Works](#3-langgraph-agent-swarm--how-it-works)
4. [RAG System — Deep Dive](#4-rag-system--deep-dive)
5. [Service 1 — Deepfake Detection](#5-service-1--deepfake-detection)
6. [Service 2 — Threat Intelligence](#6-service-2--threat-intelligence)
7. [Service 3 — Responsible AI Audit](#7-service-3--responsible-ai-audit)
8. [Service 4 — Privacy Compliance](#8-service-4--privacy-compliance)
9. [Service 5 — Digital Asset Governance](#9-service-5--digital-asset-governance)
10. [Security Scanner](#10-security-scanner)
11. [End-to-End Request Flow](#11-end-to-end-request-flow)
12. [API Reference Summary](#12-api-reference-summary)

---

## 1. Platform Overview

VibeSecure operates in two parallel domains:

| Domain               | Purpose                                                                                                                          |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **AI Governance**    | Analyse AI-generated content, AI system design, privacy posture, digital assets, and threat exposure using 11 specialist agents. |
| **Security Scanner** | Actively scan websites for OWASP-class vulnerabilities using domain ownership verification and consent-gated active testing.     |

Every AI Governance analysis is orchestrated by a **LangGraph stateful graph** where a Supervisor agent plans which child agents to invoke based on the `service_type` and the input data provided.

---

## 2. Tech Stack

| Layer               | Technology                                                                  |
| ------------------- | --------------------------------------------------------------------------- |
| Backend framework   | FastAPI (Python 3.11)                                                       |
| Agent orchestration | LangGraph (StateGraph)                                                      |
| AI model            | Google Gemini 2.0 Flash (worker agents) + Gemini 1.5 Pro (Supervisor brain) |
| Embeddings          | `gemini-embedding-001`, 768 dimensions                                      |
| Vector store        | PostgreSQL 15 + pgvector extension                                          |
| RAG table           | `rag_documents` (cosine similarity via IVFFlat index)                       |
| Task queue          | Celery + Redis                                                              |
| Auth                | Firebase Admin SDK (JWT verification on every request)                      |
| Web scanning        | Playwright (screenshots + passive crawl) + OWASP ZAP (active scan)          |
| Email               | Resend                                                                      |
| PDF reports         | ReportLab                                                                   |
| Frontend            | React 18 + Vite + Tailwind CSS + Framer Motion                              |
| Database ORM        | SQLModel (SQLAlchemy 2)                                                     |

---

## 3. LangGraph Agent Swarm — How It Works

### 3.1 Shared State (`AgentState`)

All agents share a single typed dictionary called `AgentState`. It flows through every node in the graph and is mutated (merged) as each agent adds its results.

```
AgentState {
  job_id          str          — database job UUID
  service_type    str          — deepfake | threat_intel | responsible_ai | privacy | digital_asset | all
  input_data      dict         — file paths, URLs, content, ai_system_description, api_endpoint, options
  user_email      str          — Firebase UID email

  active_agents   list[str]    — agents Supervisor decided to run
  completed_agents list[str]   — agents that finished
  results         dict         — keyed by agent name, merged across all nodes

  messages        list[dict]   — append-only event log
  governance_bundle dict       — final synthesised output
  status          str          — pending | running | completed | failed
  error           str | None
}
```

Results use an `Annotated[dict, merge_dicts]` reducer so each agent can update only its own key without overwriting others.

### 3.2 The Graph

```
START
  |
  v
supervisor_plan_node          ← Supervisor decides which agents to run
  |
  v (router: route_after_plan)
  +---> run_deepfake_group    [keyframe_extractor -> deepfake_triage -> forensic_artifact -> ensemble_voter]
  +---> run_threat_group      [threat_pattern -> predictive_risk]
  +---> run_responsible_group [responsible_ai_auditor -> bias_fairness]
  +---> run_privacy_group     [privacy_scanner -> regulatory_mapper]
  +---> run_digital_group     [digital_asset_governance]
  |
  v
synthesize_node               ← Supervisor merges all results into governance_bundle
  |
  v
END
```

Each service group runs its agents **sequentially** in the order shown above (agent N can read agent N-1's results from state). After each group finishes, the router checks whether another group needs to run, chaining them together.

### 3.3 Supervisor Agent

The Supervisor uses **Gemini 1.5 Pro** (the "brain" tier) for two tasks:

**Planning** — Inspects `service_type` and `input_data` to decide which agents activate:

- `service_type = "deepfake"` activates exactly the 4 deepfake agents.
- `service_type = "all"` inspects input: has `file_path`? activate deepfake. Has `url`? activate privacy + digital asset. Has `api_endpoint`? activate threat intel. Has `content`? activate responsible AI.

**Synthesis** — After all agents complete, reads all `results` values and produces:

- `executive_summary` (3-5 sentences)
- `overall_risk_level` (critical / high / medium / low)
- `confidence_score` (0-100)
- `key_findings` (list)
- `recommended_actions` (prioritised list)
- `service_summaries` (per-service brief)

### 3.4 BaseAgent

All agents extend `BaseAgent` which provides:

- `self.generate_json(prompt, system_instruction)` — calls Gemini Flash, parses JSON response
- `self.generate_text(prompt)` — free-text Gemini response
- `run(state)` — wraps `process()` with error handling, timing, and event publishing via Redis pub/sub

---

## 4. RAG System — Deep Dive

### 4.1 What Is It

VibeSecure uses **Retrieval-Augmented Generation (RAG)** to ground agent decisions in a curated knowledge base of regulatory documents, threat intelligence frameworks, and deepfake research. This prevents hallucination and provides citations.

### 4.2 Infrastructure

| Component         | Detail                                          |
| ----------------- | ----------------------------------------------- |
| Table             | `rag_documents` in PostgreSQL                   |
| Extension         | `pgvector` — stores and queries 768-dim vectors |
| Embedding model   | `gemini-embedding-001`                          |
| Similarity metric | Cosine distance (`<=>` operator)                |
| Index type        | IVFFlat with 100 lists                          |

**Table schema:**

```sql
CREATE TABLE rag_documents (
    id          TEXT PRIMARY KEY,       -- sha256 hash of category:filename:chunk
    dataset_name TEXT NOT NULL,         -- human label, e.g. "GDPR Article 7"
    category    TEXT NOT NULL,          -- regulatory | threat_intel | deepfake_research | privacy
    content     TEXT NOT NULL,          -- the raw text chunk
    embedding   vector(768),            -- Gemini embedding
    metadata    JSONB DEFAULT '{}',     -- source URL, page number, etc.
    created_at  TIMESTAMPTZ,
    updated_at  TIMESTAMPTZ
);
```

### 4.3 What Is Upserted into the Knowledge Base

| Category            | Dataset Name           | What is stored                                                                                 |
| ------------------- | ---------------------- | ---------------------------------------------------------------------------------------------- |
| `regulatory`        | GDPR (Articles 5-17)   | Text of GDPR articles on lawful basis, consent requirements, data subject rights               |
| `regulatory`        | CCPA Regulations       | California Consumer Privacy Act sections                                                       |
| `regulatory`        | DPDP Act 2023          | India Digital Personal Data Protection Act clauses                                             |
| `regulatory`        | EU AI Act (2024)       | Articles on prohibited AI practices, high-risk AI requirements, transparency obligations       |
| `threat_intel`      | MITRE ATLAS            | AI-specific attack technique descriptions (prompt injection, model extraction, data poisoning) |
| `threat_intel`      | OWASP LLM Top 10       | Top 10 LLM application risks with descriptions and mitigations                                 |
| `deepfake_research` | Celeb-DF v2            | Research on identity-swap deepfake patterns and detection signatures                           |
| `deepfake_research` | FaceForensics++        | Forgery type descriptions and forensic artefact patterns                                       |
| `deepfake_research` | DFDC Challenge         | Ensemble detection methodology notes                                                           |
| `privacy`           | NIST Privacy Framework | Privacy risk assessment categories and controls                                                |

### 4.4 Ingestion Pipeline

```
Source documents (PDF, text)
  |
  v
chunk_text(max_chars=2000, overlap=200)   ← sliding window chunks with 200-char overlap
  |
  v
content_id(category, filename, chunk)     ← SHA-256 deterministic ID for upsert idempotency
  |
  v
generate_embeddings(texts, batch=32)      ← Gemini embedding-001, retries on 429/503
  |
  v
batch_upsert(documents)                   ← INSERT ... ON CONFLICT DO UPDATE
  |
  v
rag_documents table
```

The upsert is **idempotent** — re-running ingestion never creates duplicates because the document ID is a deterministic SHA-256 hash of the content.

### 4.5 Retrieval at Query Time

```python
def search_similar(query, top_k=5, category_filter=None):
    query_embedding = generate_embeddings([query])[0]   # embed the query
    results = SELECT ... ORDER BY embedding <=> query_embedding LIMIT top_k
    return [{ id, dataset_name, category, content, similarity }]
```

SQL used:

```sql
SELECT id, dataset_name, category, content, metadata,
       1 - (embedding <=> :qvec::vector) AS similarity
FROM rag_documents
WHERE embedding IS NOT NULL
  AND category = :category   -- optional filter
ORDER BY embedding <=> :qvec::vector
LIMIT :top_k;
```

### 4.6 Which Agents Use RAG and How

| Agent               | RAG Call | Query                                                           | Category Filter     | How it uses the results                                                                                                   |
| ------------------- | -------- | --------------------------------------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `ensemble_voter`    | Yes      | The content/media description + triage observations             | `deepfake_research` | Finds similar known deepfake cases from research datasets. Adds `rag_explanation` and `reference_datasets` to the result. |
| `threat_pattern`    | Yes      | First 1000 chars of the user's content                          | `threat_intel`      | Enriches prompt with matching MITRE ATLAS / OWASP LLM entries before calling Gemini.                                      |
| `predictive_risk`   | Yes      | Threat summary from threat_pattern results                      | `threat_intel`      | Grounds risk prediction in known attack technique descriptions.                                                           |
| `privacy_scanner`   | Yes      | `"privacy policy consent banner GDPR requirements regulations"` | `regulatory`        | Injects relevant GDPR/CCPA text into the Gemini prompt before scanning the URL.                                           |
| `regulatory_mapper` | Yes      | Built from found violations (e.g. `"GDPR Article 7 consent"`)   | `regulatory`        | Maps detected violations to exact regulatory article text from the knowledge base.                                        |

---

## 5. Service 1 — Deepfake Detection

### Input

| Field  | Type                    | Description                                  |
| ------ | ----------------------- | -------------------------------------------- |
| `file` | File upload (multipart) | Image (JPEG/PNG) or video (MP4/MOV/AVI)      |
| `url`  | string (optional)       | URL of media to fetch instead of file upload |

### Agents (run in sequence)

#### 5.1 Keyframe Extractor

**Purpose:** Pre-process the uploaded media into individual frames for downstream analysis.

**What it does:**

- For images: treats the single image as one "frame", copies to uploads directory, returns `{ frames: [path], file_type: "image" }`.
- For videos: uses OpenCV (`cv2`) to extract up to 10 evenly-spaced keyframes. Saves them as JPEG files.
- Returns frame file paths, FPS, total frame count, and file type in state.

**No AI call** — pure Python/OpenCV processing.

#### 5.2 Deepfake Triage Agent

**Purpose:** Fast first-pass check using Gemini Flash. Decide whether deeper forensic analysis is needed.

**What it does:**

- Takes up to 4 frames from keyframe extractor.
- Sends frame metadata (path, file type, frame count) to Gemini Flash with a structured prompt.
- Looks for: unnatural skin textures, inconsistent lighting, warped backgrounds, asymmetric facial features, blurred edges around face/hair, temporal inconsistencies.

**Gemini prompt asks for:**

```json
{
  "triage_verdict": "likely_real|likely_fake|suspicious|inconclusive",
  "confidence": 0-100,
  "quick_observations": ["..."],
  "needs_forensic": true/false,
  "risk_indicators": ["..."],
  "triage_reasoning": "..."
}
```

#### 5.3 Forensic Artifact Agent

**Purpose:** Deep forensic analysis if triage flagged `needs_forensic: true`.

**What it does:**

- Analyses all frames (up to 10) for forensic artifacts: compression artefacts, JPEG blocking, noise patterns, edge inconsistencies.
- Distinct audio analysis: checks audio waveform patterns for TTS/voice-clone signatures.
- Returns `overall_authenticity_score` (0-100, higher = more real), `artifact_types_found`, `anomalies_detected`, `audio_analysis`.

**Uses Gemini Flash** with a detailed forensic prompt.

#### 5.4 Ensemble Voter Agent (uses RAG)

**Purpose:** Combine triage + forensic + audio votes into a final verdict.

**Voting logic:**

1. Triage vote: directly from `triage_verdict`.
2. Forensic vote: derived from `overall_authenticity_score` (>=75 = likely_real, <=35 = likely_fake, else suspicious).
3. Audio vote: mapped from `audio_risk_level` (low/medium/high).
4. Majority vote determines `final_verdict`. Ties resolved by preferring "suspicious" for safety.
5. `final_confidence = avg(confidence) * agreement_ratio`.

**RAG call:**

```python
search_similar(
    query=f"deepfake detection {triage_verdict} {artifact_types} forensic analysis",
    top_k=3,
    category_filter="deepfake_research"
)
```

Results are added as `rag_explanation` (narrative from similar research) and `reference_datasets` (names of matched datasets).

**Final output:**

```json
{
  "final_verdict": "likely_real|likely_fake|suspicious|inconclusive",
  "final_confidence": 0-100,
  "votes": [...],
  "verdict_counts": { "likely_real": N, "likely_fake": N, "suspicious": N },
  "rag_explanation": "Similar cases found in FaceForensics++...",
  "reference_datasets": ["Celeb-DF v2", "FaceForensics++"]
}
```

---

## 6. Service 2 — Threat Intelligence

### Input

| Field                   | Type              | Description                              |
| ----------------------- | ----------------- | ---------------------------------------- |
| `content`               | string            | Text/code to scan for AI threat patterns |
| `ai_system_description` | string            | Description of the AI system to assess   |
| `api_endpoint`          | string (optional) | URL of a live AI API endpoint to probe   |
| `auth_config`           | dict (optional)   | Auth headers for live AI system testing  |

### Agents

#### 6.1 Threat Pattern Agent (uses RAG)

**Purpose:** Analyse content for AI threats and map to MITRE ATLAS framework.

**Two modes:**

**Mode A — Content Analysis** (when `content` or `ai_system_description` provided):

RAG call:

```python
search_similar(query=content[:1000], top_k=3, category_filter="threat_intel")
```

Matching MITRE ATLAS / OWASP LLM entries are injected into the Gemini prompt as context.

Gemini then analyses for:

- Hidden adversarial patterns or payloads
- Prompt injection attempts
- Social engineering via AI
- Data exfiltration patterns
- Model manipulation techniques

Each threat is mapped to a MITRE ATLAS technique (e.g. `AML.T0051 = Prompt Injection`).

**Mode B — Live AI System Testing** (when `api_endpoint` provided, with user consent):

Sends safe, non-destructive probes from 3 template sets:

- **Prompt injection** (`Ignore all previous instructions...`)
- **Model extraction** (`What model are you? What version?`)
- **Adversarial inputs** (`<script>alert('xss')</script>`, SQL injection patterns)

Each probe records the response and Gemini analyses whether the system is vulnerable.

**Output:**

```json
{
  "threats_found": [{ "technique_id": "AML.T0051", "severity": "high", "description": "...", "mitigations": [...] }],
  "overall_threat_level": "critical|high|medium|low|none",
  "confidence": 0-100
}
```

#### 6.2 Predictive Risk Agent (uses RAG)

**Purpose:** Project future attack vectors and assign quantified risk scores.

RAG call:

```python
search_similar(query=threat_summary, top_k=3, category_filter="threat_intel")
```

Reads `threat_pattern` results from state, then uses Gemini to:

- Predict which attack vectors are most likely in the next 6-12 months.
- Score each risk (0-100 impact, 0-100 likelihood).
- Produce a `risk_matrix` with 2D positioning.
- Recommend mitigations prioritised by risk score.

---

## 7. Service 3 — Responsible AI Audit

### Input

| Field                   | Type              | Description                                    |
| ----------------------- | ----------------- | ---------------------------------------------- |
| `content`               | string            | AI-generated content or system output to audit |
| `ai_system_description` | string            | Description of the AI system under review      |
| `url`                   | string (optional) | URL of the AI product/system                   |

### Agents

#### 7.1 Responsible AI Auditor Agent

**Purpose:** Score the AI system against NIST AI RMF 1.0 and Google SAIF.

**Frameworks evaluated:**

NIST AI RMF 1.0 functions:

- GOVERN — policies and processes for AI risk management
- MAP — risk identification and documentation
- MEASURE — risk metrics and tracking
- MANAGE — risk prioritisation and action

Google Secure AI Framework (SAIF) 6 principles:

- Expand strong security foundations to AI
- Extend detection and response to AI threats
- Automate defences
- Harmonise platform-level controls
- Adapt controls with feedback loops
- Contextualise AI risk in business processes

**Scorecard dimensions:** transparency, fairness, accountability, safety, privacy, security, robustness, explainability.

Also cross-references any `threat_pattern` and `ensemble_voter` results already in the state for richer context.

**Gemini output:**

```json
{
  "nist_rmf_scores": { "GOVERN": 0-100, "MAP": 0-100, "MEASURE": 0-100, "MANAGE": 0-100 },
  "saif_compliance": [{ "principle": "...", "score": 0-100, "gaps": [...] }],
  "ethics_scorecard": { "transparency": 0-100, "fairness": 0-100, ... },
  "overall_ethics_score": 0-100,
  "critical_gaps": [...],
  "recommendations": [...]
}
```

#### 7.2 Bias and Fairness Agent

**Purpose:** Detect bias patterns in AI output or system design.

Reads auditor results from state for context, then analyses:

- Demographic bias indicators
- Representation issues
- Stereotyping patterns
- Output distribution skew

Returns detailed `bias_findings` with severity and remediation steps.

---

## 8. Service 4 — Privacy Compliance

### Input

| Field     | Type              | Description                      |
| --------- | ----------------- | -------------------------------- |
| `url`     | string            | URL of website/service to scan   |
| `content` | string (optional) | Raw text/HTML to analyse for PII |

### Agents

#### 8.1 Privacy Scanner Agent (uses RAG)

**Purpose:** Detect PII exposure, consent banner issues, privacy policy gaps.

**Step 1 — RAG context retrieval:**

```python
search_similar(
    query="privacy policy consent banner GDPR requirements regulations",
    top_k=3,
    category_filter="regulatory"
)
```

Relevant GDPR/CCPA articles are injected into the Gemini analysis prompt.

**Step 2 — Page fetch and HTML analysis:**

- Fetches the URL with httpx (30s timeout, follows redirects).
- Parses HTML with BeautifulSoup.

**Step 3 — Consent banner check:**
Looks for CSS classes containing: `cookie`, `consent`, `gdpr`, `privacy-banner`, `cc-banner`.
Looks for elements with IDs containing: `cookie-consent`, `gdpr-consent`, `cookie-banner`.
Detects CMP scripts: Cookiebot, OneTrust, Osano, Termly, CookieYes.

**Step 4 — Privacy policy link check:**
Scans all `<a href>` elements for text/href containing: `privacy`, `data protection`, `cookie policy`, `datenschutz`.

**Step 5 — Gemini PII analysis:**
Sends page text (up to 5000 chars) to Gemini for:

- PII categories detected (email, phone, SSN, credit card, location, health data)
- Data collection patterns
- Third-party tracker detection
- Privacy violation severity

**Output includes:**

```json
{
  "privacy_score": 0-100,
  "has_cookie_banner": true/false,
  "has_privacy_policy_link": true/false,
  "pii_categories_detected": [...],
  "violations": [{ "type": "...", "severity": "...", "article": "GDPR Art. 7" }],
  "rag_regulatory_context": "Based on GDPR Article 13..."
}
```

#### 8.2 Regulatory Mapper Agent (uses RAG)

**Purpose:** Map each detected violation to specific regulatory articles with exact citation text.

For each violation from `privacy_scanner`, runs a targeted RAG query:

```python
search_similar(
    query=f"GDPR consent {violation_type} requirements article",
    top_k=2,
    category_filter="regulatory"
)
```

Produces a compliance grid:

| Regulation    | Status        | Violated Articles | Recommendation                        |
| ------------- | ------------- | ----------------- | ------------------------------------- |
| GDPR          | Non-compliant | Art. 7, Art. 13   | Implement consent management platform |
| CCPA          | Partial       | Section 1798.100  | Add "Do Not Sell" link                |
| DPDP Act 2023 | Unknown       | Section 5         | Review data localisation requirements |
| EU AI Act     | N/A           | —                 | No AI systems detected                |

---

## 9. Service 5 — Digital Asset Governance

### Input

| Field                   | Type              | Description                           |
| ----------------------- | ----------------- | ------------------------------------- |
| `content`               | string            | Digital asset description or metadata |
| `ai_system_description` | string            | AI system context                     |
| `url`                   | string (optional) | URL of the verified domain to scan    |

### Agent

#### 9.1 Digital Asset Governance Agent

**Purpose:** Audit digital assets for IP rights, licensing, and governance. Optionally triggers a full security scan on verified domains using the Security Scanner infrastructure.

**Ownership verification (if URL provided):**

```python
# Checks DomainVerification table — user must have verified domain before a scan can run
DomainVerification.domain == domain AND user_email == email AND verified == True
```

**Active scan consent check:**

```python
# Checks Consent table — explicit opt-in required for active vulnerability scanning
Consent.domain == domain AND active_allowed == True
```

**Security checks run (if domain is verified and consent given):**

All 8 checkers from the Security Scanner infrastructure are invoked:

| Checker                   | What it tests                                               |
| ------------------------- | ----------------------------------------------------------- |
| `check_headers`           | Missing security headers (CSP, HSTS, X-Frame-Options, etc.) |
| `check_https_redirect`    | HTTP to HTTPS redirect, HSTS header presence                |
| `check_tls`               | TLS version, cipher strength, certificate validity          |
| `check_cors`              | Wildcard CORS, misconfigured origins                        |
| `check_directory_listing` | Open directory listing on common paths                      |
| `check_endpoints`         | Exposed admin, debug, and API endpoints                     |
| `check_reflections`       | XSS reflection probes                                       |
| `check_libraries`         | Outdated JavaScript libraries with known CVEs               |

**Governance analysis via Gemini:**
Separately analyses the digital asset description for IP rights, licensing compliance, and governance framework adherence.

**Output:**

```json
{
  "governance_score": 0-100,
  "ownership_verified": true/false,
  "active_consent": true/false,
  "security_findings": [...],
  "ip_rights_assessment": { "has_license": true/false, "license_type": "...", "risks": [...] },
  "governance_gaps": [...]
}
```

---

## 10. Security Scanner

The Security Scanner is an independent service separate from the LangGraph swarm. It is triggered directly via the `/api/scans` endpoint.

### Preconditions

1. **Domain verification** — User must prove ownership via DNS TXT record or file upload before any scan.
2. **Consent** — User must explicitly grant consent for active (intrusive) testing for ZAP scans.

### Scanner Pipeline

```
POST /api/scans (FastAPI) — validates domain ownership + consent
  |
  v
Celery task (async, Redis broker)
  |
  +-- Playwright passive crawl — screenshots, extract links, JS inventory
  |
  +-- 8 Security Checkers (parallel):
  |     header_checker      — missing/misconfigured HTTP security headers
  |     https_checker       — HTTPS enforcement, HSTS
  |     tls_checker         — TLS 1.0/1.1 detection, weak ciphers, cert expiry
  |     cors_checker        — wildcard CORS, Access-Control-Allow-Origin: *
  |     directory_checker   — open directory listing on /backup, /.git/, /admin
  |     endpoint_checker    — exposed /admin, /debug, /api/keys, /.env endpoints
  |     reflection_checker  — reflected XSS probes with safe payloads
  |     library_checker     — outdated jQuery/Bootstrap/lodash with CVE lookup
  |
  +-- ZAP active scan (only if active consent given) — OWASP ZAP spider + scan
  |
  v
All findings aggregated into ScanResult model
  |
  v
Gemini AI summarises findings — executive summary + remediation roadmap
  |
  v
Save to PostgreSQL, notify user via WebSocket/email
```

### Finding Severity Levels

`critical` / `high` / `medium` / `low` / `info`

Each finding includes: `title`, `description`, `severity`, `url`, `parameter`, `evidence`, `remediation`.

---

## 11. End-to-End Request Flow

### AI Governance Job

```
1. User submits form on Dashboard (service type + input data)
2. Frontend calls POST /api/governance/jobs
3. FastAPI verifies Firebase JWT
4. Creates GovernanceJob row in PostgreSQL (status: pending)
5. Dispatches Celery task: run_governance_job(job_id, service_type, input_data, user_email)
6. Returns { job_id } to frontend immediately

7. Celery worker picks up task:
   a. Initialises AgentState with job_id, service_type, input_data
   b. Calls run_graph(state) — LangGraph graph execution starts
   c. supervisor_plan_node determines which agents to activate
   d. Each agent runs, reads from state, writes results back to state
   e. Agents that use RAG call search_similar() before their Gemini call
   f. synthesize_node produces the final governance_bundle
   g. Updates GovernanceJob in DB: status=completed, results=governance_bundle

8. Frontend polls GET /api/governance/jobs/{job_id} every 3 seconds
9. On completion, renders GovernanceDetail page with all results
10. GET /api/governance/jobs/{job_id}/rag-sources returns RAG citations shown in UI
```

### Security Scan

```
1. User selects a verified domain on Dashboard, clicks "New Scan"
2. Frontend calls POST /api/scans
3. FastAPI checks: domain verified? consent? (if active scan requested)
4. Creates Scan row in PostgreSQL (status: queued)
5. Dispatches Celery task: run_scan(scan_id)
6. Returns { scan_id } immediately

7. Celery worker runs:
   a. Playwright browser launch — screenshot, crawl links
   b. 8 checkers run in sequence
   c. ZAP active scan if consent given
   d. All findings merged into result list
   e. Gemini AI generates executive summary
   f. Scan result saved to DB

8. Frontend polls GET /api/scans/{scan_id}
9. On completion, renders ScanDetail page with findings, screenshots, PDF download
```

---

## 12. API Reference Summary

All routes are prefixed with `/api` and require Firebase Bearer token unless marked public.

| Method | Path                                        | Description                                   |
| ------ | ------------------------------------------- | --------------------------------------------- |
| POST   | `/api/auth/verify`                          | Verify Firebase token, create/update user     |
| GET    | `/api/auth/me`                              | Get current user profile                      |
| GET    | `/api/domains`                              | List user's verified domains                  |
| POST   | `/api/domains`                              | Add a new domain for verification             |
| POST   | `/api/domains/{id}/verify`                  | Check DNS/file verification status            |
| GET    | `/api/consent/{domain}`                     | Get consent status for a domain               |
| POST   | `/api/consent/{domain}`                     | Grant/update consent for a domain             |
| GET    | `/api/scans`                                | List security scans (paginated)               |
| POST   | `/api/scans`                                | Create and queue a new security scan          |
| GET    | `/api/scans/{scan_id}`                      | Get scan result and findings                  |
| GET    | `/api/scans/{scan_id}/report`               | Download PDF report                           |
| GET    | `/api/governance/jobs`                      | List AI governance jobs (paginated)           |
| POST   | `/api/governance/jobs`                      | Create a new governance analysis job          |
| GET    | `/api/governance/jobs/{job_id}`             | Get job status and results                    |
| POST   | `/api/governance/upload`                    | Upload media file for deepfake/asset analysis |
| GET    | `/api/governance/jobs/{job_id}/rag-sources` | Get RAG citations used in analysis            |
| GET    | `/api/rag/search`                           | Direct RAG search (dev/debug)                 |
| POST   | `/api/rag/upsert`                           | Ingest documents into RAG knowledge base      |
| GET    | `/api/rag/stats`                            | Knowledge base statistics                     |

---

## Demo Website

The `demo-website/` directory contains a separate Vite app called **TechFlow AI** — a realistic-looking SaaS landing page with intentional security flaws for demonstrating the VibeSecure Security Scanner.

**Running the demo site:**

```bash
cd demo-website
npm install
npm run dev   # runs on http://localhost:5174
```

**Intentional flaws present for scanner demo:**

| Flaw                                             | Where                       | Scanner check that detects it |
| ------------------------------------------------ | --------------------------- | ----------------------------- |
| Missing `Content-Security-Policy` header         | HTTP response               | `header_checker`              |
| Missing `X-Frame-Options` header (clickjacking)  | HTTP response               | `header_checker`              |
| Missing `Referrer-Policy` header                 | HTTP response               | `header_checker`              |
| Missing `Permissions-Policy` header              | HTTP response               | `header_checker`              |
| Outdated jQuery 1.12.4 loaded from CDN           | `index.html`                | `library_checker`             |
| Outdated Bootstrap 3.3.7 loaded from CDN         | `index.html`                | `library_checker`             |
| No cookie consent banner                         | Page HTML                   | `privacy_scanner`             |
| Privacy policy link present but no actual banner | Footer HTML                 | `privacy_scanner`             |
| Reflected XSS via `innerHTML` on search results  | `main.js:runSearch()`       | `reflection_checker`          |
| `eval()` on URL query parameter                  | `main.js:themeParam`        | `reflection_checker`          |
| Open redirect via `?redirect=` query param       | `main.js`                   | `endpoint_checker`            |
| Hard-coded API keys in source                    | `main.js`                   | `library_checker` / manual    |
| Plaintext password stored in `localStorage`      | `main.js:handleSignup()`    | `header_checker`              |
| Internal email exposed in HTML source            | Footer HTML                 | `privacy_scanner`             |
| No CSRF protection on sign-up form               | `index.html`                | `endpoint_checker`            |
| `autocomplete="on"` on password fields           | Form inputs                 | `header_checker`              |
| Sensitive debug object on `window`               | `main.js.__techflow_debug`  | `reflection_checker`          |
| Credentials logged to `console.log`              | `main.js`                   | manual review                 |
| HTTP (non-HTTPS) API call from page              | `main.js:fetchUsageStats()` | `https_checker`               |
