# VibeSecure API - Testing Guide

All 5 services share the same infrastructure: **Firebase Auth** for authentication,
**Celery + Redis** for async job processing, and the **11-agent LangGraph swarm** for
AI analysis. Every request requires a valid Firebase ID token in either the
`Authorization: Bearer <token>` header or the `vibesecure_token` cookie.

Base URL: `http://localhost:8000/api`

Interactive docs: `http://localhost:8000/docs`

---

## Prerequisites

```bash
# Start all services
docker compose up -d

# Verify health
curl http://localhost:8000/health
# Expected: {"status":"ok","app":"VibeSecure API","version":"2.0.0"}
```

**Get a Firebase token** (use your frontend login or the Firebase Admin SDK):

```bash
export TOKEN="your-firebase-id-token"
export AUTH="Authorization: Bearer $TOKEN"
```

---

## Service 1: Deepfake Detection

**Agents:** Keyframe Extractor, Deepfake Triage, Forensic Artifact, Ensemble Voter

### Upload a photo/video for analysis

```bash
curl -X POST http://localhost:8000/api/services/deepfake/upload \
  -H "$AUTH" \
  -F "file=@test_photo.jpg" \
  -F "content=Check this image for deepfakes"
```

### Analyse media at a public URL

```bash
curl -X POST http://localhost:8000/api/services/deepfake/analyze \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com/suspicious-video.mp4",
    "content": "This video looks suspicious"
  }'
```

### Check job status and results

```bash
# List your deepfake jobs
curl http://localhost:8000/api/services/deepfake \
  -H "$AUTH"

# Get full result (includes confidence score, verdict, frames analysed)
curl http://localhost:8000/api/services/deepfake/{job_id} \
  -H "$AUTH"

# Poll real-time agent events
curl "http://localhost:8000/api/services/deepfake/{job_id}/events?last_id=0-0" \
  -H "$AUTH"

# Get result from a specific agent
curl http://localhost:8000/api/services/deepfake/{job_id}/agent/ensemble_voter \
  -H "$AUTH"
```

### Response fields (GET /{job_id})

| Field                              | Type   | Description                                                |
| ---------------------------------- | ------ | ---------------------------------------------------------- |
| `confidence_score`                 | float  | 0-100 confidence the media is fake                         |
| `verdict`                          | string | `likely_real`, `likely_fake`, `suspicious`, `inconclusive` |
| `frames_analyzed`                  | int    | Number of keyframes extracted and analysed                 |
| `agent_results.keyframe_extractor` | object | Frame extraction details                                   |
| `agent_results.deepfake_triage`    | object | Fast triage pass                                           |
| `agent_results.forensic_artifact`  | object | Detailed forensic analysis with heatmap                    |
| `agent_results.ensemble_voter`     | object | Final weighted verdict                                     |

---

## Service 2: AI Threat Intelligence

**Agents:** Threat Pattern Agent, Predictive Risk Agent
**Special:** Can test your own AI system with safe probes (requires explicit consent)

### Analyse content for threats

```bash
curl -X POST http://localhost:8000/api/services/threat-intel/analyze \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Analyse this AI chatbot for prompt injection vulnerabilities",
    "ai_system_description": "Customer support chatbot using GPT-4"
  }'
```

### Test your own AI system (requires consent)

```bash
curl -X POST http://localhost:8000/api/services/threat-intel/analyze \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "ai_system_description": "My custom chatbot",
    "api_endpoint": "https://my-ai.example.com/api/chat",
    "ai_system_auth": {
      "type": "bearer",
      "token": "my-api-key"
    },
    "ai_system_consent": true
  }'
```

### Check job status and results

```bash
# List your threat intel jobs
curl http://localhost:8000/api/services/threat-intel \
  -H "$AUTH"

# Get full result (includes MITRE ATLAS mappings, risk score)
curl http://localhost:8000/api/services/threat-intel/{job_id} \
  -H "$AUTH"

# Poll agent events
curl "http://localhost:8000/api/services/threat-intel/{job_id}/events?last_id=0-0" \
  -H "$AUTH"

# Get specific agent result
curl http://localhost:8000/api/services/threat-intel/{job_id}/agent/threat_pattern \
  -H "$AUTH"
```

### Response fields (GET /{job_id})

| Field                           | Type   | Description                                          |
| ------------------------------- | ------ | ---------------------------------------------------- |
| `risk_score`                    | string | `Low`, `Medium`, `High`, `Critical`                  |
| `threats_found`                 | int    | Number of identified threats                         |
| `agent_results.threat_pattern`  | object | MITRE ATLAS mappings, attack patterns found          |
| `agent_results.predictive_risk` | object | Predicted attacks, threat actor profile, mitigations |

---

## Service 3: Responsible AI Frameworks

**Agents:** Responsible AI Auditor Agent, Bias & Fairness Agent

### Audit AI content or system

```bash
curl -X POST http://localhost:8000/api/services/responsible-ai/audit \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Our hiring algorithm uses facial analysis to rank candidates",
    "ai_system_description": "Automated resume screening with CV photo analysis"
  }'
```

### Audit a web application

```bash
curl -X POST http://localhost:8000/api/services/responsible-ai/audit \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://my-ai-app.example.com",
    "ai_system_description": "AI-powered content moderation platform"
  }'
```

### Check job status and results

```bash
# List your responsible AI audits
curl http://localhost:8000/api/services/responsible-ai \
  -H "$AUTH"

# Get full result (includes scorecard, NIST + SAIF assessments)
curl http://localhost:8000/api/services/responsible-ai/{job_id} \
  -H "$AUTH"

# Poll agent events
curl "http://localhost:8000/api/services/responsible-ai/{job_id}/events?last_id=0-0" \
  -H "$AUTH"

# Get specific agent result
curl http://localhost:8000/api/services/responsible-ai/{job_id}/agent/responsible_ai_auditor \
  -H "$AUTH"
```

### Response fields (GET /{job_id})

| Field                                  | Type   | Description                                                                                                                  |
| -------------------------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------- |
| `overall_grade`                        | string | A-F grade for overall AI responsibility                                                                                      |
| `scorecard`                            | object | Dimension scores: transparency, fairness, accountability, safety, privacy, security, robustness, explainability (each 0-100) |
| `agent_results.responsible_ai_auditor` | object | NIST AI RMF + Google SAIF assessments                                                                                        |
| `agent_results.bias_fairness`          | object | Bias analysis across 8 dimensions                                                                                            |

---

## Service 4: Data Privacy & Regulatory Compliance

**Agents:** Privacy Scanner Agent, Regulatory Mapper Agent

### Scan a website for privacy issues

```bash
curl -X POST http://localhost:8000/api/services/privacy/scan \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

### Scan text content for PII

```bash
curl -X POST http://localhost:8000/api/services/privacy/scan \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "content": "Contact John Smith at john.smith@company.com or call +1-555-0123. SSN: 123-45-6789"
  }'
```

### Check job status and results

```bash
# List your privacy scans
curl http://localhost:8000/api/services/privacy \
  -H "$AUTH"

# Get full result (includes PII findings, consent assessment, law references)
curl http://localhost:8000/api/services/privacy/{job_id} \
  -H "$AUTH"

# Poll agent events
curl "http://localhost:8000/api/services/privacy/{job_id}/events?last_id=0-0" \
  -H "$AUTH"

# Get specific agent result
curl http://localhost:8000/api/services/privacy/{job_id}/agent/regulatory_mapper \
  -H "$AUTH"
```

### Response fields (GET /{job_id})

| Field                             | Type   | Description                                                      |
| --------------------------------- | ------ | ---------------------------------------------------------------- |
| `overall_privacy_score`           | float  | 0-100 privacy health score                                       |
| `regulations_mapped`              | list   | Which regulations were mapped (GDPR, CCPA, DPDP, EU AI Act)      |
| `agent_results.privacy_scanner`   | object | PII findings, consent banner analysis, privacy policy assessment |
| `agent_results.regulatory_mapper` | object | Per-regulation mapping with exact article references             |

---

## Service 5: Digital Asset Governance (Website Security)

**Agents:** Digital Asset Governance Agent (+ optional Privacy Scanner)
**Prerequisite:** Domain must be verified before scanning.

### Step 1 - Verify your domain

```bash
# Request a verification token
curl -X POST http://localhost:8000/api/domains/verify/request \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Place the token on your site (file or meta tag), then verify
curl -X POST http://localhost:8000/api/domains/verify/check \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Step 2 - (Optional) Grant active scan consent

Required only if you want OWASP ZAP active scanning:

```bash
# Request consent
curl -X POST http://localhost:8000/api/consent/request \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'

# Place consent file, then verify
curl -X POST http://localhost:8000/api/consent/check \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Step 3 - Run the security scan

```bash
# Passive scan only
curl -X POST http://localhost:8000/api/services/digital-asset/scan \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'

# With active scanning (ZAP) + privacy co-scan
curl -X POST http://localhost:8000/api/services/digital-asset/scan \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com",
    "scan_options": {
      "allow_active": true,
      "run_privacy": true
    }
  }'
```

### Check job status and results

```bash
# List your digital asset scans
curl http://localhost:8000/api/services/digital-asset \
  -H "$AUTH"

# Get full result (includes findings, risk score, severity breakdown)
curl http://localhost:8000/api/services/digital-asset/{job_id} \
  -H "$AUTH"

# Poll agent events
curl "http://localhost:8000/api/services/digital-asset/{job_id}/events?last_id=0-0" \
  -H "$AUTH"

# Get specific agent result
curl http://localhost:8000/api/services/digital-asset/{job_id}/agent/digital_asset_governance \
  -H "$AUTH"
```

### Response fields (GET /{job_id})

| Field                                    | Type   | Description                                      |
| ---------------------------------------- | ------ | ------------------------------------------------ |
| `risk_score`                             | int    | 0-100 overall security risk score                |
| `findings_count`                         | int    | Total number of security findings                |
| `severity_counts`                        | object | Breakdown: `{critical, high, medium, low, info}` |
| `agent_results.digital_asset_governance` | object | Full findings, check errors, platform configs    |

---

## Generic Governance Endpoint (All Services)

The service-specific endpoints above are wrappers around the generic governance API.
You can also use the generic endpoint directly:

```bash
# Create a job for any service
curl -X POST http://localhost:8000/api/governance \
  -H "$AUTH" \
  -H "Content-Type: application/json" \
  -d '{
    "service_type": "deepfake",
    "url": "https://example.com/video.mp4"
  }'

# Valid service_type values: deepfake, threat_intel, responsible_ai, privacy, digital_asset, all
```

---

## Complete API Endpoint Reference

### Auth

| Method | Endpoint            | Description                                 |
| ------ | ------------------- | ------------------------------------------- |
| POST   | `/api/auth/login`   | Validate Firebase token, set session cookie |
| POST   | `/api/auth/logout`  | Clear session cookie                        |
| GET    | `/api/auth/profile` | Get current user profile                    |

### Deepfake Detection (`/api/services/deepfake`)

| Method | Endpoint                                       | Description                                 |
| ------ | ---------------------------------------------- | ------------------------------------------- |
| POST   | `/api/services/deepfake/upload`                | Upload photo/video for deepfake analysis    |
| POST   | `/api/services/deepfake/analyze`               | Analyse media at a URL                      |
| GET    | `/api/services/deepfake`                       | List deepfake jobs                          |
| GET    | `/api/services/deepfake/{job_id}`              | Get deepfake result with confidence/verdict |
| GET    | `/api/services/deepfake/{job_id}/events`       | Real-time agent events (poll)               |
| GET    | `/api/services/deepfake/{job_id}/agent/{name}` | Get specific agent result                   |

### AI Threat Intelligence (`/api/services/threat-intel`)

| Method | Endpoint                                           | Description                       |
| ------ | -------------------------------------------------- | --------------------------------- |
| POST   | `/api/services/threat-intel/analyze`               | Analyse content or test AI system |
| GET    | `/api/services/threat-intel`                       | List threat intel jobs            |
| GET    | `/api/services/threat-intel/{job_id}`              | Get threat analysis result        |
| GET    | `/api/services/threat-intel/{job_id}/events`       | Real-time agent events (poll)     |
| GET    | `/api/services/threat-intel/{job_id}/agent/{name}` | Get specific agent result         |

### Responsible AI Frameworks (`/api/services/responsible-ai`)

| Method | Endpoint                                             | Description                     |
| ------ | ---------------------------------------------------- | ------------------------------- |
| POST   | `/api/services/responsible-ai/audit`                 | Audit AI system or content      |
| GET    | `/api/services/responsible-ai`                       | List responsible AI audits      |
| GET    | `/api/services/responsible-ai/{job_id}`              | Get audit result with scorecard |
| GET    | `/api/services/responsible-ai/{job_id}/events`       | Real-time agent events (poll)   |
| GET    | `/api/services/responsible-ai/{job_id}/agent/{name}` | Get specific agent result       |

### Data Privacy & Regulatory (`/api/services/privacy`)

| Method | Endpoint                                      | Description                                 |
| ------ | --------------------------------------------- | ------------------------------------------- |
| POST   | `/api/services/privacy/scan`                  | Scan URL or content for PII and compliance  |
| GET    | `/api/services/privacy`                       | List privacy scan jobs                      |
| GET    | `/api/services/privacy/{job_id}`              | Get privacy result with regulation mappings |
| GET    | `/api/services/privacy/{job_id}/events`       | Real-time agent events (poll)               |
| GET    | `/api/services/privacy/{job_id}/agent/{name}` | Get specific agent result                   |

### Digital Asset Governance (`/api/services/digital-asset`)

| Method | Endpoint                                            | Description                               |
| ------ | --------------------------------------------------- | ----------------------------------------- |
| POST   | `/api/services/digital-asset/scan`                  | Scan verified website for security issues |
| GET    | `/api/services/digital-asset`                       | List digital asset jobs                   |
| GET    | `/api/services/digital-asset/{job_id}`              | Get scan result with severity counts      |
| GET    | `/api/services/digital-asset/{job_id}/events`       | Real-time agent events (poll)             |
| GET    | `/api/services/digital-asset/{job_id}/agent/{name}` | Get specific agent result                 |

### Domain Verification (`/api/domains`)

| Method | Endpoint                       | Description                         |
| ------ | ------------------------------ | ----------------------------------- |
| POST   | `/api/domains/verify/request`  | Get verification token for a domain |
| DELETE | `/api/domains/verify/request`  | Cancel pending verification         |
| POST   | `/api/domains/verify/check`    | Check if domain token is placed     |
| GET    | `/api/domains/{domain}/status` | Get verification status             |
| GET    | `/api/domains/list`            | List all verified domains           |

### Active Scan Consent (`/api/consent`)

| Method | Endpoint                       | Description                              |
| ------ | ------------------------------ | ---------------------------------------- |
| POST   | `/api/consent/request`         | Request active scan consent for a domain |
| POST   | `/api/consent/check`           | Verify consent file placement            |
| GET    | `/api/consent/{domain}/status` | Get consent status                       |
| GET    | `/api/consent/list`            | List all consents                        |

### Legacy Scans (`/api/scans`)

| Method | Endpoint                          | Description                        |
| ------ | --------------------------------- | ---------------------------------- |
| POST   | `/api/scans`                      | Create security scan (legacy V1)   |
| GET    | `/api/scans`                      | List scans                         |
| GET    | `/api/scans/{scan_id}`            | Get scan details                   |
| GET    | `/api/scans/{scan_id}/findings`   | Get scan findings                  |
| GET    | `/api/scans/{scan_id}/report`     | Download JSON/PDF report           |
| GET    | `/api/scans/{scan_id}/ai-summary` | AI-generated fix checklist         |
| GET    | `/api/scans/{scan_id}/fix-config` | Platform-specific security configs |

### Generic Governance (`/api/governance`)

| Method | Endpoint                                | Description                         |
| ------ | --------------------------------------- | ----------------------------------- |
| POST   | `/api/governance`                       | Create governance job (any service) |
| POST   | `/api/governance/upload`                | Create job with file upload         |
| GET    | `/api/governance`                       | List governance jobs                |
| GET    | `/api/governance/{job_id}`              | Get job details                     |
| GET    | `/api/governance/{job_id}/events`       | Real-time agent events              |
| GET    | `/api/governance/{job_id}/bundle`       | Get final governance bundle         |
| GET    | `/api/governance/{job_id}/agent/{name}` | Get specific agent result           |

---

## Agent Model Tiers

| Tier      | Models (tried in order)                                                | Used by                                                                                                    |
| --------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **BRAIN** | `gemini-3.1-pro-preview` then `gemini-2.5-pro` then `gemini-2.5-flash` | Supervisor, Forensic Artifact, Ensemble Voter, Threat Pattern, Predictive Risk, Auditor, Regulatory Mapper |
| **AGENT** | `gemini-3-flash-preview` then `gemini-2.5-flash`                       | Keyframe Extractor, Deepfake Triage, Bias & Fairness, Privacy Scanner, Digital Asset Governance            |

Each agent tries models in order. If the first model fails or is rate-limited, it
automatically falls back to the next one.

---

## Real-time Event Polling

All services expose `/{job_id}/events?last_id=0-0` for near-real-time updates.
Poll this endpoint to track agent progress:

```javascript
async function pollEvents(serviceBase, jobId, token) {
  let lastId = "0-0";
  while (true) {
    const res = await fetch(
      `${serviceBase}/${jobId}/events?last_id=${lastId}`,
      { headers: { Authorization: `Bearer ${token}` } },
    );
    const data = await res.json();
    for (const event of data.events) {
      console.log(`[${event.agent}] ${event.event_type}: ${event.message}`);
      lastId = event.id;
    }
    if (data.events.some((e) => e.event_type === "job_complete")) break;
    await new Promise((r) => setTimeout(r, 2000));
  }
}
```

---

## Error Codes

| Code | Meaning                                                           |
| ---- | ----------------------------------------------------------------- |
| 400  | Invalid input (missing fields, bad URL format)                    |
| 401  | Not authenticated (missing or invalid Firebase token)             |
| 403  | Not authorized (job belongs to another user, domain not verified) |
| 404  | Job or agent result not found                                     |
| 413  | File too large (max 100 MB)                                       |
| 429  | Rate limited                                                      |
