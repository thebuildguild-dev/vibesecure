# VibeSecure Frontend API Guide

Complete API reference for building the VibeSecure frontend. All endpoints are authenticated via Firebase token.

## Base URL

```
http://localhost:8000/api  (development)
https://api.vibesecure.io/api  (production)
```

---

## 1. Authentication

### Login

```http
POST /auth/login
Content-Type: application/json

{
  "firebase_token": "..."
}

Response:
{
  "user_email": "user@example.com",
  "access_token": "...",
  "token_type": "bearer"
}
```

### Get Profile

```http
GET /auth/profile
Authorization: Bearer {token}

Response:
{
  "email": "user@example.com",
  "firebase_uid": "...",
  "created_at": "2025-01-15T10:30:00Z"
}
```

### Logout

```http
POST /auth/logout
Authorization: Bearer {token}
```

**Frontend Client Usage:**

```javascript
import { auth } from "./api/client.js";

// Login
const result = await auth.login(firebaseToken);

// Get profile
const profile = await auth.getProfile();

// Logout
await auth.logout();
```

---

## 2. Domain Verification (3-step process)

### Step 1: Request Verification Token

```http
POST /domains/verify/request
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com"
}

Response:
{
  "domain": "example.com",
  "token": "vibesecure_verify_...",
  "instructions": {
    "file": {
      "path": "/.well-known/vibesecure-verification.txt",
      "content": "vibesecure-verify=vibesecure_verify_..."
    },
    "meta": "<meta name='vibesecure-verify' content='vibesecure_verify_...' />",
    "header": {
      "name": "X-VibeSecure-Verify",
      "value": "vibesecure_verify_..."
    }
  },
  "expires_at": "2025-02-15T10:30:00Z",
  "message": "Place the token using one of the methods below..."
}
```

### Step 2: User Places Token (3 methods)

Choose one:

- **File method**: Upload verification file to `/.well-known/vibesecure-verification.txt`
- **Meta tag method**: Add `<meta name="vibesecure-verify" content="..." />` to `<head>`
- **Header method**: Add `X-VibeSecure-Verify: ...` HTTP header to your server responses

### Step 3: Check Verification Status

```http
POST /domains/verify/check
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com"
}

or use specific verification_id:
{
  "verification_id": "..."
}

Response (verified):
{
  "domain": "example.com",
  "verified": true,
  "method": "file",
  "details": "Domain ownership verified",
  "verified_at": "2025-01-15T11:00:00Z"
}

Response (not verified):
{
  "domain": "example.com",
  "verified": false,
  "method": null,
  "details": "Token not found on domain"
}
```

### Get Domain Verification Status

```http
GET /domains/{domain}/status
Authorization: Bearer {token}

Response:
{
  "domain": "example.com",
  "verified": true,
  "verified_at": "2025-01-15T11:00:00Z",
  "verified_by_method": "file",
  "expires_at": "2025-02-15T10:30:00Z"
}
```

### List All Verified Domains

```http
GET /domains/list
Authorization: Bearer {token}

Response:
[
  {
    "domain": "example.com",
    "verified": true,
    "verified_at": "2025-01-15T11:00:00Z",
    "verified_by_method": "file",
    "expires_at": "2025-02-15T10:30:00Z"
  }
]
```

**Frontend Client Usage:**

```javascript
import { domains } from "./api/client.js";

// Request token
const { token, instructions } =
  await domains.requestVerification("example.com");

// User places token manually...

// Check verification status
const status = await domains.checkVerification("example.com");

// Get status
const domainStatus = await domains.getStatus("example.com");

// List all
const allDomains = await domains.list();
```

---

## 3. Active Scan Consent (2-step process)

**Prerequisites:** Domain must be verified first.

### Step 1: Request Consent File

```http
POST /consent/request
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com"
}

Response:
{
  "domain": "example.com",
  "user_email": "user@example.com",
  "instructions": {
    "path": "/.well-known/vibesecure-consent.txt",
    "content": "domain=example.com\nuser=user@example.com\nimestamp=..."
  },
  "message": "Place the consent file at the specified path..."
}
```

### Step 2: Check Consent Status

```http
POST /consent/check
Authorization: Bearer {token}
Content-Type: application/json

{
  "domain": "example.com"
}

Response (consented):
{
  "domain": "example.com",
  "active_consent_verified": true,
  "verified_at": "2025-01-15T11:30:00Z",
  "message": "Active scan consent verified for example.com..."
}

Response (not consented):
{
  "domain": "example.com",
  "active_consent_verified": false,
  "verified_at": null,
  "message": "Active scan consent NOT found..."
}
```

### Get Consent Status

```http
GET /consent/{domain}/status
Authorization: Bearer {token}

Response:
{
  "domain": "example.com",
  "active_allowed": true,
  "active_consent_verified": true,
  "verified_at": "2025-01-15T11:30:00Z",
  "method": "well-known",
  "created_at": "2025-01-15T11:30:00Z"
}
```

**Frontend Client Usage:**

```javascript
import { consent } from "./api/client.js";

// Request consent file
const { instructions } = await consent.request("example.com");

// User places file...

// Check consent
const status = await consent.check("example.com");

// Get status
const consentStatus = await consent.getStatus("example.com");
```

---

## 4. Security Scanning (Passive)

### Create a Scan

```http
POST /scans
Authorization: Bearer {token}
Content-Type: application/json

{
  "url": "https://example.com",
  "description": "Security scan for Q1",
  "options": {
    "allow_active": false,
    "depth": 2,
    "rate_limit_secs": 1.0
  }
}

Response:
{
  "id": "scan_abc123...",
  "status": "queued"
}
```

**Note:** If domain not verified, returns 403 with instructions to verify first.

### List Scans

```http
GET /scans?skip=0&limit=20
Authorization: Bearer {token}

Response:
[
  {
    "id": "scan_abc123...",
    "url": "https://example.com",
    "description": "Q1 scan",
    "status": "done",
    "created_at": "2025-01-15T10:00:00Z",
    "started_at": "2025-01-15T10:01:00Z",
    "finished_at": "2025-01-15T10:05:00Z",
    "risk_score": 35,
    "risk_label": "Medium",
    "scan_confidence": "High"
  }
]
```

### Get Scan Details

```http
GET /scans/{scan_id}
Authorization: Bearer {token}

Response:
{
  "id": "scan_abc123...",
  "url": "https://example.com",
  "status": "done",
  "created_at": "2025-01-15T10:00:00Z",
  "risk_score": 35,
  "risk_label": "Medium",
  "findings": [
    {
      "id": "finding_...",
      "scan_id": "scan_...",
      "title": "Missing HSTS Header",
      "severity": "high",
      "remediation": "Add Strict-Transport-Security header",
      "confidence": 95,
      "path": "/",
      "created_at": "2025-01-15T10:01:00Z"
    }
  ],
  "result": { ... }
}
```

### Get Scan Findings

```http
GET /scans/{scan_id}/findings
Authorization: Bearer {token}

Response:
[
  {
    "id": "finding_...",
    "scan_id": "scan_...",
    "title": "Missing HSTS Header",
    "severity": "high",
    "remediation": "Add header to server config",
    "confidence": 95,
    "path": "/",
    "created_at": "2025-01-15T10:01:00Z"
  }
]
```

### Get Scan Report

```http
GET /scans/{scan_id}/report?format=json
Authorization: Bearer {token}

Response: Full scan report JSON

GET /scans/{scan_id}/report?format=pdf
Authorization: Bearer {token}

Response: Binary PDF file
```

### Get AI Summary

```http
GET /scans/{scan_id}/ai-summary
Authorization: Bearer {token}

Response:
{
  "scan_id": "scan_...",
  "summary": "This website has 5 high-severity findings...",
  "top_issues": ["HSTS missing", "No CSP"],
  "recommendations": ["Add HSTS header", "Configure CSP"]
}
```

**Frontend Client Usage:**

```javascript
import { scans } from "./api/client.js";

// Create
const scan = await scans.create("https://example.com", "Q1 scan");

// List
const list = await scans.list(0, 20);

// Get details
const details = await scans.get("scan_abc123...");

// Get findings
const findings = await scans.getFindings("scan_abc123...");

// Get report
const jsonReport = await scans.getReport("scan_abc123...", "json");
const pdfBlob = await scans.getReport("scan_abc123...", "pdf");

// AI summary
const summary = await scans.getAISummary("scan_abc123...");
```

---

## 5. Governance & AI Auditing (Agent Swarm)

### Create Governance Job

#### Governance Job Types

- **deepfake**: Analyze images/videos for deepfake artifacts
- **threat_intel**: Analyze text/content for threats + test AI systems
- **responsible_ai**: Evaluate AI systems against NIST/Google frameworks
- **privacy**: Scan websites for PII + consent mechanisms
- **digital_asset**: Full website security scanning
- **all**: Run all applicable agents based on input

### Option A: Text/URL Input

```http
POST /governance
Authorization: Bearer {token}
Content-Type: application/json

{
  "service_type": "all",
  "url": "https://example.com",
  "content": "Optional text to analyze",
  "ai_system_description": "ChatGPT wrapper for customer support",
  "api_endpoint": "https://api.example.com/chat",
  "ai_system_auth": {
    "type": "bearer",
    "token": "..."
  },
  "ai_system_consent": true,
  "scan_options": {}
}

Response:
{
  "id": "job_abc123...",
  "service_type": "all",
  "status": "pending",
  "created_at": "2025-01-15T12:00:00Z",
  "agents_planned": ["keyframe_extractor", "threat_pattern", ...],
  "agents_completed": [],
  "error": null
}
```

### Option B: File Upload (for deepfake detection)

```http
POST /governance/upload
Authorization: Bearer {token}
Content-Type: multipart/form-data

file: <image.jpg or video.mp4> (max 100MB)
service_type: "deepfake"
content: "<optional description>"
ai_system_description: "<optional AI system description>"

Response: Same as above
```

### List Governance Jobs

```http
GET /governance?skip=0&limit=20&service_type=deepfake
Authorization: Bearer {token}

Response:
[
  {
    "id": "job_abc123...",
    "service_type": "deepfake",
    "status": "completed",
    "created_at": "2025-01-15T12:00:00Z",
    "agents_planned": [...],
    "agents_completed": [...],
    "error": null
  }
]
```

### Get Job Status

```http
GET /governance/{job_id}
Authorization: Bearer {token}

Response:
{
  "id": "job_abc123...",
  "service_type": "deepfake",
  "status": "completed",
  "created_at": "2025-01-15T12:00:00Z",
  "started_at": "2025-01-15T12:01:00Z",
  "finished_at": "2025-01-15T12:15:00Z",
  "agents_planned": ["keyframe_extractor", "deepfake_triage", "forensic_artifact", "ensemble_voter"],
  "agents_completed": ["keyframe_extractor", "deepfake_triage", "forensic_artifact", "ensemble_voter"],
  "error": null
}
```

### Get Final Governance Bundle

```http
GET /governance/{job_id}/bundle
Authorization: Bearer {token}

Response:
{
  "job_id": "job_abc123...",
  "service_type": "deepfake",
  "governance_bundle": {
    "executive_summary": "The analyzed media shows signs of...",
    "overall_risk_level": "high",
    "confidence_score": 87,
    "key_findings": [...],
    "recommended_actions": [...],
    "service_summaries": {
      "deepfake": { ... }
    }
  },
  "agents_completed": [...],
  "completed_at": "2025-01-15T12:15:00Z"
}
```

### Get Specific Agent Result

```http
GET /governance/{job_id}/agent/{agent_name}
Authorization: Bearer {token}

agent_name values:
- keyframe_extractor
- deepfake_triage
- forensic_artifact
- ensemble_voter
- threat_pattern
- predictive_risk
- responsible_ai_auditor
- bias_fairness
- privacy_scanner
- regulatory_mapper
- digital_asset_governance

Response:
{
  "job_id": "job_abc123...",
  "agent_name": "ensemble_voter",
  "result": {
    "status": "success",
    "final_verdict": "likely_fake",
    "confidence_score": 87,
    "real_percentage": 13,
    "fake_percentage": 87,
    "rag_analysis": {
      "dataset_matches": [
        {
          "dataset": "Celeb-DF v2",
          "similarity": 92,
          "technique": "Face Swap",
          "notes": "High consistency with Face Swap artifacts"
        }
      ],
      "plain_english_explanation": "The video exhibits...",
      "heatmap_regions": ["face"],
      "generation_technique_guess": "Face Swap"
    }
  }
}
```

### Get RAG Sources & Citations

```http
GET /governance/{job_id}/rag-sources
Authorization: Bearer {token}

Response:
{
  "job_id": "job_abc123...",
  "sources": {
    "deepfake": [
      {
        "agent": "ensemble_voter",
        "dataset": "Celeb-DF v2",
        "technique": "Face Swap",
        "similarity": 92,
        "notes": "High consistency..."
      }
    ],
    "threat_intel": [
      {
        "agent": "threat_pattern",
        "technique_id": "AML.T0051",
        "technique_name": "Prompt Injection",
        "severity": "high"
      }
    ],
    "regulatory": [
      {
        "agent": "regulatory_mapper",
        "regulation": "GDPR",
        "article": "Art. 25",
        "title": "Data protection by design and default",
        "status": "non_compliant"
      }
    ]
  },
  "summary": "Found 12 knowledge base references across all analyses"
}
```

### Real-time Job Events (Server-Sent Events)

```http
GET /governance/{job_id}/events?last_id=0-0
Authorization: Bearer {token}

Response:
{
  "job_id": "job_abc123...",
  "events": [
    {
      "timestamp": "2025-01-15T12:01:00Z",
      "agent": "keyframe_extractor",
      "event": "started",
      "data": {}
    },
    {
      "timestamp": "2025-01-15T12:02:00Z",
      "agent": "keyframe_extractor",
      "event": "completed",
      "data": { "duration_seconds": 60 }
    }
  ],
  "count": 2
}
```

**Frontend Client Usage:**

```javascript
import { governance } from "./api/client.js";

// Create job
const job = await governance.create({
  service_type: "deepfake",
  url: "https://example.com",
});

// Or upload file
const uploadedJob = await governance.uploadFile(fileInput.files[0], "deepfake");

// List jobs
const jobs = await governance.list(0, 20, "deepfake");

// Get status
const status = await governance.get(job.id);

// Get final bundle (when completed)
const bundle = await governance.getBundle(job.id);

// Get agent result
const agentResult = await governance.getAgentResult(job.id, "ensemble_voter");

// Get RAG sources
const sources = await governance.getRagSources(job.id);

// Stream real-time events
const events = await governance.getEvents(job.id);
```

---

## 6. RAG Knowledge Base API

### Search Knowledge Base

```http
POST /rag/search
Authorization: Bearer {token}
Content-Type: application/json

{
  "query": "face swap detection artifacts",
  "top_k": 5,
  "category": "deepfake",
  "dataset": null
}

Response:
{
  "query": "face swap detection artifacts",
  "results": [
    {
      "id": "deepfake:face_swap:1a2b3c...",
      "dataset_name": "Celeb-DF",
      "category": "deepfake",
      "content": "Face swap deepfakes show blending artifacts at the boundaries...",
      "metadata": { "type": "detection_method", "dataset": "Celeb-DF" },
      "similarity": 0.92
    }
  ],
  "count": 5
}

Categories: "deepfake", "threat_intel", "regulatory"
Datasets: "Celeb-DF", "FaceForensics++", "MITRE-ATLAS", "GDPR", etc.
```

### Initialize RAG Database

```http
POST /rag/init
Authorization: Bearer {token}

Response:
{
  "status": "ok",
  "message": "rag_documents table ready"
}
```

### Upsert RAG Data

```http
POST /rag/upsert
Authorization: Bearer {token}
Content-Type: application/json

{
  "categories": ["deepfake", "threat_intel", "regulatory"]
}

Response:
{
  "status": "ok",
  "documents_upserted": 487,
  "message": "Upserted 487 documents for categories: [...]"
}
```

### Get RAG Stats

```http
GET /rag/stats
Authorization: Bearer {token}

Response:
{
  "total_documents": 487,
  "by_dataset": [
    {
      "category": "deepfake",
      "dataset_name": "Celeb-DF",
      "doc_count": 45,
      "embedded_count": 45
    },
    {
      "category": "regulatory",
      "dataset_name": "GDPR",
      "doc_count": 120,
      "embedded_count": 120
    }
  ]
}
```

**Frontend Client Usage:**

```javascript
import { rag } from "./api/client.js";

// Search
const results = await rag.search("face swap artifacts", 5, "deepfake");

// Initialize
await rag.init();

// Upsert seed data
await rag.upsert(["deepfake", "threat_intel", "regulatory"]);

// Get stats
const stats = await rag.stats();
```

---

## Error Handling

All endpoints return standard error responses:

```json
{
  "detail": "Error message here"
}
```

Special error types (403 Forbidden):

### Domain Verification Required

```json
{
  "detail": {
    "error": "domain_verification_required",
    "message": "You must verify ownership before scanning",
    "verification": {
      "domain": "example.com",
      "token": "...",
      "instructions": { ... },
      "expires_at": "2025-02-15T..."
    }
  }
}
```

### Active Consent Required

```json
{
  "detail": {
    "error": "active_consent_required",
    "message": "Domain requires consent for active scanning",
    "consent": {
      "domain": "example.com",
      "instructions": { ... }
    }
  }
}
```

**Frontend Error Handling:**

```javascript
import { APIError } from "./api/client.js";

try {
  await scans.create("https://example.com");
} catch (error) {
  if (error instanceof APIError) {
    if (error.status === 403) {
      const details = error.message;
      if (details.includes("verification")) {
        // Handle domain verification
      } else if (details.includes("consent")) {
        // Handle consent requirement
      }
    }
  }
}
```

---

## Status Values

### Scan Status

- `queued`: Waiting to start
- `running`: Currently scanning
- `done`: Successfully completed
- `failed`: Encountered error

### Governance Job Status

- `pending`: Job created, not started
- `running`: Agent swarm executing
- `completed`: All agents finished
- `failed`: Job encountered fatal error

### Finding Severity

- `critical`: Immediate action required
- `high`: Should fix soon
- `medium`: Should address
- `low`: Nice to fix
- `info`: Informational

### Risk Level

- `critical`: 81-100% risk
- `high`: 61-80% risk
- `medium`: 41-60% risk
- `low`: 1-40% risk

---

## Pagination

All list endpoints support pagination:

```
GET /endpoint?skip=0&limit=20
```

- `skip`: Number of items to skip (default 0)
- `limit`: Max items to return (default 20, max 100)

---

## Rate Limiting

- General API: 100 requests per minute per user
- Domain verification requests: 3 per domain per day, 5 per user per day
- Active scans: Requires explicit consent

---

## Example Frontend Flow

### Complete Workflow

```javascript
import { auth, domains, consent, scans, governance } from "./api/client.js";

// 1. Authenticate
const profile = await auth.login(firebaseToken);

// 2. Verify domain
const { token, instructions } =
  await domains.requestVerification("example.com");
// User places token...
await domains.checkVerification("example.com");

// 3. Verify active scan consent (for active scans)
if (needsActiveScan) {
  const { instructions } = await consent.request("example.com");
  // User places consent file...
  await consent.check("example.com");
}

// 4. Create job with governance (advanced AI analysis)
const job = await governance.create({
  service_type: "all",
  url: "https://example.com",
});

// 5. Poll for completion
let status = await governance.get(job.id);
while (status.status === "pending" || status.status === "running") {
  await new Promise((r) => setTimeout(r, 2000));
  status = await governance.get(job.id);
}

// 6. Get results
const bundle = await governance.getBundle(job.id);
const sources = await governance.getRagSources(job.id);

// Display results to user
```

---

## API Documentation URLs

- **Swagger/OpenAPI**: `/docs`
- **ReDoc**: `/redoc`
- **Health Check**: `GET /health`
