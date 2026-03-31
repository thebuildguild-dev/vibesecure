import { useState, useEffect, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Shield,
  AlertTriangle,
  Brain,
  Lock,
  Database,
  CheckCircle,
  AlertCircle,
  Clock,
  Activity,
  ChevronDown,
  ChevronUp,
  BookOpen,
  FileText,
} from "lucide-react";
import { governance as governanceAPI } from "../api/client";
import { MainLayout } from "../components/layout";
import { Card, Badge, SectionTitle } from "../components/ui";

// ── Config ──────────────────────────────────────────────────────────────────

const SERVICE_CONFIG = {
  deepfake: {
    label: "Deepfake Detection",
    icon: Shield,
    color: "var(--accent-info)",
  },
  threat_intel: {
    label: "Threat Intelligence",
    icon: AlertTriangle,
    color: "var(--accent-error)",
  },
  responsible_ai: {
    label: "Responsible AI Audit",
    icon: Brain,
    color: "var(--accent-warning)",
  },
  privacy: {
    label: "Privacy & Compliance",
    icon: Lock,
    color: "var(--accent-verified)",
  },
  digital_asset: {
    label: "Digital Asset Governance",
    icon: Database,
    color: "#9b59b6",
  },
  all: {
    label: "Full AI Governance",
    icon: Brain,
    color: "var(--accent-info)",
  },
};

const AGENT_LABELS = {
  keyframe_extractor: "Keyframe Extractor",
  deepfake_triage: "Deepfake Triage",
  forensic_artifact: "Forensic Artifact Analyzer",
  ensemble_voter: "Ensemble Voter",
  threat_pattern: "Threat Pattern Analysis",
  predictive_risk: "Predictive Risk Forecaster",
  responsible_ai_auditor: "Responsible AI Auditor",
  bias_fairness: "Bias & Fairness Checker",
  privacy_scanner: "Privacy Scanner",
  regulatory_mapper: "Regulatory Mapper",
  digital_asset_governance: "Digital Asset Governance",
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function ScoreBar({ score, max = 100 }) {
  const pct = Math.min(100, Math.round((score / max) * 100));
  const color =
    pct >= 70
      ? "var(--accent-verified)"
      : pct >= 40
        ? "var(--accent-warning)"
        : "var(--accent-error)";
  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-[var(--bg-elevated)] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <span
        className="font-mono text-sm font-bold w-14 text-right"
        style={{ color }}
      >
        {score}/{max}
      </span>
    </div>
  );
}

// ── Smart result renderer (no raw JSON) ──────────────────────────────────────

const SKIP_KEYS = new Set(["status", "error"]);

function renderValue(value, depth = 0) {
  if (value === null || value === undefined)
    return <span className="text-[var(--text-tertiary)]">—</span>;
  if (typeof value === "boolean")
    return (
      <span
        className={
          value ? "text-[var(--accent-verified)]" : "text-[var(--accent-error)]"
        }
      >
        {value ? "Yes" : "No"}
      </span>
    );
  if (typeof value === "number")
    return <span className="text-[var(--accent-info)] font-mono">{value}</span>;
  if (typeof value === "string")
    return <span className="text-[var(--text-secondary)]">{value}</span>;

  if (Array.isArray(value)) {
    if (value.length === 0)
      return <span className="text-[var(--text-tertiary)]">None</span>;
    return (
      <ul className="space-y-1 mt-1">
        {value.slice(0, 10).map((item, i) => (
          <li key={i} className="flex items-start gap-2">
            <span className="text-[var(--accent-info)] font-mono text-xs mt-0.5 flex-shrink-0">
              ›
            </span>
            <span className="text-sm text-[var(--text-secondary)]">
              {typeof item === "string" || typeof item === "number"
                ? item
                : renderValue(item, depth + 1)}
            </span>
          </li>
        ))}
        {value.length > 10 && (
          <li className="text-xs text-[var(--text-tertiary)] font-mono">
            ... and {value.length - 10} more
          </li>
        )}
      </ul>
    );
  }

  if (typeof value === "object") {
    if (depth > 2)
      return (
        <span className="text-[var(--text-tertiary)] text-xs font-mono">
          [nested object]
        </span>
      );
    const entries = Object.entries(value).filter(([k]) => !SKIP_KEYS.has(k));
    if (entries.length === 0)
      return <span className="text-[var(--text-tertiary)]">—</span>;
    return (
      <div
        className={`space-y-1.5 ${depth > 0 ? "pl-3 border-l border-slate-700/50 mt-1" : ""}`}
      >
        {entries.map(([k, v]) => (
          <div key={k}>
            <span className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-wide">
              {k.replace(/_/g, " ")}
            </span>
            <div className="mt-0.5">{renderValue(v, depth + 1)}</div>
          </div>
        ))}
      </div>
    );
  }
  return null;
}

function AgentAccordion({ agentName, result }) {
  const [open, setOpen] = useState(false);

  // Determine a quick status badge
  const statusColor =
    result?.status === "success"
      ? "text-[var(--accent-verified)]"
      : result?.status === "error" || result?.error
        ? "text-[var(--accent-error)]"
        : "text-[var(--text-tertiary)]";

  const entries = result
    ? Object.entries(result).filter(([k]) => !SKIP_KEYS.has(k))
    : [];

  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-3 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-colors text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-sm font-semibold truncate">
            {AGENT_LABELS[agentName] || agentName}
          </span>
          {result?.status && (
            <span className={`text-xs font-mono flex-shrink-0 ${statusColor}`}>
              {result.status}
            </span>
          )}
          {result?.error && (
            <span className="text-xs text-[var(--accent-error)] font-mono flex-shrink-0 truncate max-w-48">
              {result.error}
            </span>
          )}
        </div>
        {open ? (
          <ChevronUp className="w-4 h-4 text-[var(--text-tertiary)] flex-shrink-0 ml-2" />
        ) : (
          <ChevronDown className="w-4 h-4 text-[var(--text-tertiary)] flex-shrink-0 ml-2" />
        )}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden"
          >
            <div className="p-4 border-t border-slate-700 space-y-3">
              {result?.error && (
                <div className="p-2 rounded bg-[var(--accent-error)]/10 border border-[var(--accent-error)]/20 text-sm text-[var(--accent-error)] font-mono">
                  {result.error}
                </div>
              )}
              {entries.length === 0 && !result?.error && (
                <p className="text-sm text-[var(--text-tertiary)] font-mono">
                  No data available.
                </p>
              )}
              {entries.map(([k, v]) => (
                <div key={k} className="space-y-0.5">
                  <div className="text-xs font-mono font-semibold text-[var(--text-tertiary)] uppercase tracking-wider">
                    {k.replace(/_/g, " ")}
                  </div>
                  <div className="text-sm">{renderValue(v, 0)}</div>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Result Renderers ─────────────────────────────────────────────────────────

function DeepfakeResults({ agentResults }) {
  const voter = agentResults?.ensemble_voter;
  const triage = agentResults?.deepfake_triage;
  const forensic = agentResults?.forensic_artifact;

  if (!voter && !triage && !forensic) {
    return (
      <p className="text-[var(--text-tertiary)] text-sm font-mono">
        No deepfake results available yet.
      </p>
    );
  }

  const verdict = voter?.final_verdict;
  const verdictColor = {
    likely_fake: "var(--accent-error)",
    suspicious: "var(--accent-warning)",
    likely_real: "var(--accent-verified)",
  }[verdict];
  const verdictLabel = verdict
    ? verdict.replace(/_/g, " ").toUpperCase()
    : "ANALYZING";
  // confidence_score is already 0-100; clamp just in case
  const confidence =
    voter?.confidence_score != null
      ? Math.min(100, voter.confidence_score)
      : null;

  return (
    <div className="space-y-4">
      {voter && (
        <div
          className="text-center p-6 rounded-xl border"
          style={{
            borderColor: `${verdictColor}50`,
            backgroundColor: `${verdictColor}10`,
          }}
        >
          <div className="text-xs font-mono text-[var(--text-secondary)] mb-2 tracking-widest">
            VERDICT
          </div>
          <div
            className="text-3xl font-mono font-bold mb-2 text-shadow-glow"
            style={{ color: verdictColor }}
          >
            {verdictLabel}
          </div>
          {confidence != null && (
            <div className="text-sm text-[var(--text-secondary)] font-mono">
              {confidence}% confidence
            </div>
          )}
          {voter.fake_percentage != null && voter.real_percentage != null && (
            <div className="flex justify-center gap-8 mt-4 text-sm font-mono">
              <div style={{ color: "var(--accent-error)" }}>
                Fake: {voter.fake_percentage.toFixed(1)}%
              </div>
              <div style={{ color: "var(--accent-verified)" }}>
                Real: {voter.real_percentage.toFixed(1)}%
              </div>
            </div>
          )}
        </div>
      )}

      {voter?.rag_analysis?.plain_english_explanation && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="flex items-center gap-2 mb-2">
            <BookOpen className="w-4 h-4 text-[var(--accent-info)]" />
            <span className="text-xs font-mono font-semibold text-[var(--accent-info)] tracking-wider">
              KNOWLEDGE BASE ANALYSIS
            </span>
          </div>
          <p className="text-sm text-[var(--text-secondary)]">
            {voter.rag_analysis.plain_english_explanation}
          </p>
        </div>
      )}

      {triage?.indicators?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Triage Indicators
          </h4>
          <div className="flex flex-wrap gap-2">
            {triage.indicators.map((ind, i) => (
              <Badge key={i} variant="warning" size="sm">
                {ind}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {forensic?.artifacts?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Forensic Artifacts
          </h4>
          <div className="space-y-2">
            {forensic.artifacts.slice(0, 5).map((a, i) => (
              <div
                key={i}
                className="p-2 rounded bg-[var(--bg-tertiary)] text-sm font-mono text-[var(--text-secondary)]"
              >
                {typeof a === "string" ? a : a.description || JSON.stringify(a)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ThreatIntelResults({ agentResults }) {
  const pattern = agentResults?.threat_pattern;
  const risk = agentResults?.predictive_risk;

  if (!pattern && !risk) {
    return (
      <p className="text-[var(--text-tertiary)] text-sm font-mono">
        No threat intelligence results available yet.
      </p>
    );
  }

  const levelColor = {
    critical: "var(--severity-critical)",
    high: "var(--severity-high)",
    medium: "var(--severity-medium)",
    low: "var(--severity-low)",
  }[pattern?.overall_threat_level?.toLowerCase()];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {pattern?.overall_threat_level && (
          <div
            className="p-4 rounded-lg bg-[var(--bg-tertiary)] border"
            style={{ borderColor: `${levelColor}50` }}
          >
            <div className="text-xs font-mono text-[var(--text-tertiary)] mb-1 tracking-wider">
              THREAT LEVEL
            </div>
            <div
              className="text-2xl font-mono font-bold"
              style={{ color: levelColor }}
            >
              {pattern.overall_threat_level.toUpperCase()}
            </div>
            {pattern.confidence != null && (
              <div className="text-xs text-[var(--text-tertiary)] mt-1 font-mono">
                Confidence:{" "}
                {Math.round(
                  pattern.confidence > 1
                    ? pattern.confidence
                    : pattern.confidence * 100,
                )}
                %
              </div>
            )}
          </div>
        )}

        {risk?.risk_score != null && (
          <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
            <div className="text-xs font-mono text-[var(--text-tertiary)] mb-2 tracking-wider">
              RISK SCORE
            </div>
            <ScoreBar score={risk.risk_score} />
            {risk.risk_trajectory && (
              <div className="text-xs font-mono text-[var(--text-tertiary)] mt-2">
                Trajectory: {risk.risk_trajectory}
              </div>
            )}
          </div>
        )}
      </div>

      {risk?.executive_summary && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Executive Summary
          </div>
          <p className="text-sm text-[var(--text-secondary)]">
            {risk.executive_summary}
          </p>
        </div>
      )}

      {pattern?.threats_found?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-3 tracking-wider">
            Threats Identified ({pattern.threats_found.length})
          </h4>
          <div className="space-y-3">
            {pattern.threats_found.map((threat, i) => {
              const sev = threat.severity?.toLowerCase();
              const sevColor = {
                critical: "var(--severity-critical)",
                high: "var(--severity-high)",
                medium: "var(--severity-medium)",
                low: "var(--severity-low)",
              }[sev];
              return (
                <div
                  key={i}
                  className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700"
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      {threat.technique_id && (
                        <span className="font-mono text-xs text-[var(--accent-info)] mr-2">
                          {threat.technique_id}
                        </span>
                      )}
                      <span className="font-mono text-sm font-semibold">
                        {threat.technique_name ||
                          threat.name ||
                          "Unknown Technique"}
                      </span>
                    </div>
                    {sev && (
                      <span
                        className="badge text-xs font-mono px-2 py-0.5 rounded-full flex-shrink-0"
                        style={{
                          backgroundColor: `${sevColor}30`,
                          color: sevColor,
                          border: `1px solid ${sevColor}50`,
                        }}
                      >
                        {sev}
                      </span>
                    )}
                  </div>
                  {threat.mitigations?.length > 0 && (
                    <div className="space-y-1 mt-2">
                      {threat.mitigations.slice(0, 3).map((m, j) => (
                        <div
                          key={j}
                          className="text-xs text-[var(--text-secondary)] flex items-start gap-1.5"
                        >
                          <span className="text-[var(--accent-verified)] mt-0.5 flex-shrink-0">
                            ›
                          </span>
                          {typeof m === "string"
                            ? m
                            : m.description || JSON.stringify(m)}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {risk?.priority_mitigations?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Priority Mitigations
          </h4>
          <div className="space-y-1">
            {risk.priority_mitigations.slice(0, 5).map((m, i) => (
              <div
                key={i}
                className="text-sm text-[var(--text-secondary)] flex items-start gap-2 p-2 rounded bg-[var(--bg-tertiary)]"
              >
                <span className="text-[var(--accent-verified)] font-mono text-xs mt-0.5 flex-shrink-0">
                  {i + 1}.
                </span>
                {typeof m === "string" ? m : m.description || JSON.stringify(m)}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function PrivacyResults({ agentResults }) {
  const scanner = agentResults?.privacy_scanner;
  const mapper = agentResults?.regulatory_mapper;

  if (!scanner && !mapper) {
    return (
      <p className="text-[var(--text-tertiary)] text-sm font-mono">
        No privacy results available yet.
      </p>
    );
  }

  const REGS = [
    { key: "gdpr_mapping", label: "GDPR" },
    { key: "ccpa_mapping", label: "CCPA" },
    { key: "dpdp_mapping", label: "DPDP Act" },
    { key: "eu_ai_act_mapping", label: "EU AI Act" },
  ];

  return (
    <div className="space-y-4">
      {/* Scores Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {scanner?.overall_privacy_score != null && (
          <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
            <div className="text-xs font-mono text-[var(--text-tertiary)] mb-2 tracking-wider">
              PRIVACY SCORE
            </div>
            <ScoreBar score={scanner.overall_privacy_score} />
            {scanner?.consent_assessment?.grade && (
              <div className="text-xs font-mono text-[var(--text-secondary)] mt-2">
                Consent Grade:{" "}
                <span className="font-bold text-[var(--text-primary)]">
                  {scanner.consent_assessment.grade}
                </span>
              </div>
            )}
          </div>
        )}
        {mapper?.overall_compliance_score != null && (
          <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
            <div className="text-xs font-mono text-[var(--text-tertiary)] mb-2 tracking-wider">
              COMPLIANCE SCORE
            </div>
            <ScoreBar score={mapper.overall_compliance_score} />
            {mapper?.overall_compliance_grade && (
              <div className="text-xs font-mono text-[var(--text-secondary)] mt-2">
                Grade:{" "}
                <span className="font-bold text-[var(--text-primary)]">
                  {mapper.overall_compliance_grade}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Regulation Breakdown */}
      {mapper && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {REGS.map(({ key, label }) => {
            const m = mapper[key];
            if (!m) return null;
            const score = m.compliance_score ?? null;
            const color =
              score == null
                ? "var(--text-tertiary)"
                : score >= 70
                  ? "var(--accent-verified)"
                  : score >= 40
                    ? "var(--accent-warning)"
                    : "var(--accent-error)";
            return (
              <div
                key={key}
                className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700 text-center"
              >
                <div className="text-xs font-mono text-[var(--text-tertiary)] mb-1">
                  {label}
                </div>
                <div className="text-xl font-mono font-bold" style={{ color }}>
                  {score ?? "N/A"}
                </div>
                {m.violations?.length > 0 && (
                  <div className="text-xs font-mono text-[var(--accent-error)] mt-1">
                    {m.violations.length} violation
                    {m.violations.length !== 1 ? "s" : ""}
                  </div>
                )}
              </div>
            );
          }).filter(Boolean)}
        </div>
      )}

      {/* PII Findings */}
      {scanner?.pii_findings?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            PII Findings ({scanner.pii_findings.length})
          </h4>
          <div className="space-y-1">
            {scanner.pii_findings.slice(0, 6).map((f, i) => (
              <div
                key={i}
                className="p-2 rounded bg-[var(--bg-tertiary)] text-sm text-[var(--text-secondary)] font-mono"
              >
                {typeof f === "string"
                  ? f
                  : f.type || f.description || JSON.stringify(f)}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Violations per regulation */}
      {["gdpr_mapping", "ccpa_mapping", "dpdp_mapping"].map((regKey) => {
        const reg = mapper?.[regKey];
        if (!reg?.violations?.length) return null;
        const labels = {
          gdpr_mapping: "GDPR",
          ccpa_mapping: "CCPA",
          dpdp_mapping: "DPDP Act",
        };
        return (
          <div key={regKey}>
            <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
              {labels[regKey]} Violations
            </h4>
            <div className="space-y-2">
              {reg.violations.slice(0, 5).map((v, i) => (
                <div
                  key={i}
                  className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--accent-error)]/20 space-y-1"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-xs font-mono font-bold text-[var(--accent-error)]">
                      {typeof v === "string" ? v : v.article || v.section}
                    </span>
                    {v.title && (
                      <span className="text-xs font-mono text-[var(--text-secondary)]">
                        — {v.title}
                      </span>
                    )}
                    {v.priority && (
                      <span className="ml-auto text-xs font-mono uppercase px-1.5 py-0.5 rounded bg-[var(--accent-error)]/10 text-[var(--accent-error)]">
                        {v.priority}
                      </span>
                    )}
                  </div>
                  {v.finding && (
                    <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
                      {v.finding}
                    </p>
                  )}
                  {v.required_action && (
                    <p className="text-xs text-[var(--accent-warning)] leading-relaxed">
                      Action: {v.required_action}
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        );
      })}

      {/* EU AI Act obligations */}
      {mapper?.eu_ai_act_mapping?.obligations?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            EU AI Act Obligations
          </h4>
          <div className="space-y-2">
            {mapper.eu_ai_act_mapping.obligations.slice(0, 4).map((o, i) => (
              <div
                key={i}
                className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-[var(--accent-warning)]/20 space-y-1"
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-[var(--text-primary)]">
                    {o.obligation}
                  </span>
                  {o.status && (
                    <span
                      className={`ml-auto text-xs font-mono uppercase px-1.5 py-0.5 rounded ${o.status === "met" ? "bg-[var(--accent-verified)]/10 text-[var(--accent-verified)]" : "bg-[var(--accent-warning)]/10 text-[var(--accent-warning)]"}`}
                    >
                      {o.status}
                    </span>
                  )}
                </div>
                {o.required_action && (
                  <p className="text-xs text-[var(--accent-warning)] leading-relaxed">
                    Action: {o.required_action}
                  </p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Executive Summary */}
      {mapper?.executive_summary && (
        <div className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Executive Summary
          </h4>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
            {mapper.executive_summary}
          </p>
        </div>
      )}

      {/* Recommendations from any regulation */}
      {(() => {
        const recs = [
          ...(mapper?.gdpr_mapping?.recommendations || []),
          ...(mapper?.ccpa_mapping?.recommendations || []),
          ...(mapper?.dpdp_mapping?.recommendations || []),
          ...(mapper?.eu_ai_act_mapping?.recommendations || []),
        ].slice(0, 6);
        if (!recs.length) return null;
        return (
          <div>
            <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
              Key Recommendations
            </h4>
            <div className="space-y-1">
              {recs.map((r, i) => (
                <div
                  key={i}
                  className="text-sm text-[var(--text-secondary)] flex items-start gap-2 p-2 rounded bg-[var(--bg-tertiary)]"
                >
                  <span className="text-[var(--accent-info)] font-mono text-xs mt-0.5 flex-shrink-0">
                    {i + 1}.
                  </span>
                  {typeof r === "string" ? r : r.description || String(r)}
                </div>
              ))}
            </div>
          </div>
        );
      })()}
    </div>
  );
}

const SCORECARD_DIMENSION_LABELS = {
  transparency: "Transparency",
  fairness: "Fairness",
  accountability: "Accountability",
  safety: "Safety",
  privacy: "Privacy",
  security: "Security",
  robustness: "Robustness",
  explainability: "Explainability",
};

const NIST_PILLAR_LABELS = {
  govern: "Govern",
  map: "Map",
  measure: "Measure",
  manage: "Manage",
};

const COMPLIANCE_COLORS = {
  compliant: "var(--accent-verified)",
  partial: "var(--accent-warning)",
  non_compliant: "var(--accent-error)",
  not_addressed: "var(--accent-error)",
};

const NIST_RATING_COLORS = {
  addressed: "var(--accent-verified)",
  partially_addressed: "var(--accent-warning)",
  not_addressed: "var(--accent-error)",
};

function ResponsibleAIResults({ agentResults }) {
  const auditor = agentResults?.responsible_ai_auditor;
  const bias = agentResults?.bias_fairness;
  const [traceOpen, setTraceOpen] = useState(false);

  if (!auditor && !bias) {
    return (
      <p className="text-[var(--text-tertiary)] text-sm font-mono">
        No Responsible AI results available yet.
      </p>
    );
  }

  const scorecard = auditor?.scorecard || {};
  const nist = auditor?.nist_assessment || {};
  const saif = auditor?.saif_assessment || [];
  const topRecs =
    auditor?.top_recommendations || auditor?.recommendations || [];
  const reasoningTrace = auditor?.reasoning_trace;
  const summary =
    auditor?.plain_english_summary ||
    auditor?.summary ||
    auditor?.executive_summary;
  const grade = auditor?.overall_grade;

  return (
    <div className="space-y-5">
      {/* Score + Grade row */}
      {auditor?.overall_score != null && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="flex items-center justify-between mb-2">
            <div className="text-xs font-mono text-[var(--text-tertiary)] tracking-wider uppercase">
              AI Ethics Score
            </div>
            {grade && (
              <span
                className="font-mono text-xl font-bold px-3 py-0.5 rounded"
                style={{
                  color:
                    grade === "A"
                      ? "var(--accent-verified)"
                      : grade === "B" || grade === "C"
                        ? "var(--accent-warning)"
                        : "var(--accent-error)",
                  backgroundColor:
                    grade === "A"
                      ? "rgba(var(--accent-verified-rgb,34,197,94),0.1)"
                      : grade === "B" || grade === "C"
                        ? "rgba(var(--accent-warning-rgb,234,179,8),0.1)"
                        : "rgba(var(--accent-error-rgb,239,68,68),0.1)",
                }}
              >
                {grade}
              </span>
            )}
          </div>
          <ScoreBar score={auditor.overall_score} />
        </div>
      )}

      {/* Plain-English Summary */}
      {summary && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Audit Summary
          </div>
          <p className="text-sm text-[var(--text-secondary)] leading-relaxed">
            {summary}
          </p>
        </div>
      )}

      {/* Scorecard dimensions */}
      {Object.keys(scorecard).length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-3 tracking-wider">
            Ethics Scorecard ({Object.keys(scorecard).length} dimensions)
          </h4>
          <div className="space-y-3">
            {Object.entries(scorecard).map(([dim, data]) => {
              const label =
                SCORECARD_DIMENSION_LABELS[dim] ||
                dim.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
              const score = data?.score;
              const findings = data?.findings;
              const recs = data?.recommendations || [];
              return (
                <div
                  key={dim}
                  className="rounded-lg bg-[var(--bg-tertiary)] border border-slate-700 overflow-hidden"
                >
                  <div className="px-4 py-3 flex items-center gap-4">
                    <div className="w-28 shrink-0 text-sm font-mono font-semibold text-[var(--text-primary)]">
                      {label}
                    </div>
                    {score != null ? (
                      <div className="flex-1">
                        <ScoreBar score={score} />
                      </div>
                    ) : (
                      <div className="flex-1" />
                    )}
                  </div>
                  {findings && (
                    <div className="px-4 pb-3 text-xs text-[var(--text-secondary)] leading-relaxed border-t border-slate-700 pt-2">
                      {findings}
                    </div>
                  )}
                  {recs.length > 0 && (
                    <div className="px-4 pb-3 space-y-1">
                      {recs.map((r, i) => (
                        <div
                          key={i}
                          className="text-xs text-[var(--text-tertiary)] flex items-start gap-1.5"
                        >
                          <span className="text-[var(--accent-info)] mt-0.5 shrink-0">
                            ›
                          </span>
                          {r}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Bias findings */}
      {bias?.bias_findings?.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Bias Findings
            {bias.bias_score != null && (
              <span className="ml-2 text-[var(--accent-error)]">
                — Bias Score {bias.bias_score}/100
              </span>
            )}
          </h4>
          <div className="space-y-2">
            {bias.bias_findings.map((f, i) => (
              <div
                key={i}
                className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700 text-sm text-[var(--text-secondary)] flex items-start gap-2"
              >
                <span className="text-[var(--accent-error)] shrink-0 mt-0.5">
                  ⚠
                </span>
                {typeof f === "string"
                  ? f
                  : f.description || f.finding || JSON.stringify(f)}
              </div>
            ))}
          </div>
          {bias.affected_groups?.length > 0 && (
            <div className="mt-2 flex flex-wrap gap-2">
              {bias.affected_groups.map((g, i) => (
                <span
                  key={i}
                  className="text-xs font-mono px-2 py-0.5 rounded-full border"
                  style={{
                    color: "var(--accent-error)",
                    borderColor: "rgba(239,68,68,0.4)",
                    backgroundColor: "rgba(239,68,68,0.08)",
                  }}
                >
                  {g}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* NIST AI RMF Assessment */}
      {Object.keys(nist).length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-3 tracking-wider">
            NIST AI Risk Management Framework
          </h4>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {Object.entries(nist).map(([pillar, data]) => {
              const label =
                NIST_PILLAR_LABELS[pillar] ||
                pillar
                  .replace(/_/g, " ")
                  .replace(/\b\w/g, (c) => c.toUpperCase());
              const rating = data?.rating || data?.status || "";
              const notes =
                data?.notes || (typeof data === "string" ? data : "");
              const ratingColor =
                NIST_RATING_COLORS[rating] || "var(--text-tertiary)";
              return (
                <div
                  key={pillar}
                  className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700"
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                      {label}
                    </span>
                    <span
                      className="text-xs font-mono px-2 py-0.5 rounded-full border"
                      style={{
                        color: ratingColor,
                        borderColor: `${ratingColor}50`,
                        backgroundColor: `${ratingColor}15`,
                      }}
                    >
                      {rating.replace(/_/g, " ")}
                    </span>
                  </div>
                  {notes && (
                    <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                      {notes}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* SAIF Assessment */}
      {saif.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-3 tracking-wider">
            Google SAIF Compliance
          </h4>
          <div className="space-y-2">
            {saif.map((item, i) => {
              const compliance = item?.compliance || "";
              const compColor =
                COMPLIANCE_COLORS[compliance] || "var(--text-tertiary)";
              return (
                <div
                  key={i}
                  className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700"
                >
                  <div className="flex items-start justify-between gap-3 mb-1">
                    <span className="text-xs text-[var(--text-primary)] leading-snug">
                      {item.principle}
                    </span>
                    <span
                      className="text-xs font-mono px-2 py-0.5 rounded-full border shrink-0"
                      style={{
                        color: compColor,
                        borderColor: `${compColor}50`,
                        backgroundColor: `${compColor}15`,
                      }}
                    >
                      {compliance.replace(/_/g, " ")}
                    </span>
                  </div>
                  {item.notes && (
                    <p className="text-xs text-[var(--text-tertiary)] leading-relaxed">
                      {item.notes}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Top Recommendations */}
      {topRecs.length > 0 && (
        <div>
          <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Top Recommendations
          </h4>
          <div className="space-y-1">
            {topRecs.slice(0, 5).map((rec, i) => (
              <div
                key={i}
                className="text-sm text-[var(--text-secondary)] flex items-start gap-2 p-2 rounded bg-[var(--bg-tertiary)]"
              >
                <span className="text-[var(--accent-info)] font-mono text-xs mt-0.5 shrink-0">
                  {i + 1}.
                </span>
                {typeof rec === "string"
                  ? rec
                  : rec.description || JSON.stringify(rec)}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Reasoning Trace (collapsible) */}
      {reasoningTrace && (
        <div className="rounded-lg border border-slate-700 overflow-hidden">
          <button
            className="w-full flex items-center justify-between px-4 py-2 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-colors text-left"
            onClick={() => setTraceOpen((o) => !o)}
          >
            <span className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-wider">
              Agent Reasoning Trace
            </span>
            {traceOpen ? (
              <ChevronUp className="w-4 h-4 text-[var(--text-tertiary)]" />
            ) : (
              <ChevronDown className="w-4 h-4 text-[var(--text-tertiary)]" />
            )}
          </button>
          {traceOpen && (
            <pre className="px-4 py-3 text-xs font-mono text-[var(--text-secondary)] whitespace-pre-wrap leading-relaxed bg-[var(--bg-primary)]">
              {reasoningTrace}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}

function DigitalAssetResults({ agentResults }) {
  const gov = agentResults?.digital_asset_governance;

  if (!gov) {
    return (
      <p className="text-[var(--text-tertiary)] text-sm font-mono">
        No digital asset results available yet.
      </p>
    );
  }

  return (
    <div className="space-y-4">
      {gov.governance_score != null && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="text-xs font-mono text-[var(--text-tertiary)] mb-2 tracking-wider">
            GOVERNANCE SCORE
          </div>
          <ScoreBar score={gov.governance_score} />
        </div>
      )}

      {(gov.summary || gov.executive_summary) && (
        <div className="p-4 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700">
          <div className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
            Asset Assessment
          </div>
          <p className="text-sm text-[var(--text-secondary)]">
            {gov.summary || gov.executive_summary}
          </p>
        </div>
      )}

      {Object.entries(gov)
        .filter(
          ([k]) =>
            !["governance_score", "summary", "executive_summary"].includes(k),
        )
        .map(([k, v]) => {
          if (!v || (Array.isArray(v) && v.length === 0)) return null;
          return (
            <div key={k}>
              <h4 className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
                {k.replace(/_/g, " ")}
              </h4>
              {Array.isArray(v) ? (
                <div className="space-y-1">
                  {v.slice(0, 5).map((item, i) => (
                    <div
                      key={i}
                      className="text-sm text-[var(--text-secondary)] p-2 rounded bg-[var(--bg-tertiary)]"
                    >
                      {typeof item === "string" ? item : JSON.stringify(item)}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="p-3 rounded-lg bg-[var(--bg-tertiary)] border border-slate-700 text-sm text-[var(--text-secondary)]">
                  {typeof v === "object"
                    ? JSON.stringify(v, null, 2)
                    : String(v)}
                </div>
              )}
            </div>
          );
        })}
    </div>
  );
}

// ── Main Component ───────────────────────────────────────────────────────────

export default function GovernanceDetail() {
  const { jobId } = useParams();
  const navigate = useNavigate();

  const [job, setJob] = useState(null);
  const [ragSources, setRagSources] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const pollingRef = useRef(null);

  useEffect(() => {
    loadJob();
    return () => {
      if (pollingRef.current) clearInterval(pollingRef.current);
    };
  }, [jobId]);

  const loadJob = async () => {
    try {
      const data = await governanceAPI.get(jobId);
      setJob(data);
      if (data.status === "completed") {
        governanceAPI
          .getRagSources(jobId)
          .then(setRagSources)
          .catch(() => {});
      }
      if (data.status === "running" || data.status === "pending") {
        startPolling();
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const startPolling = () => {
    pollingRef.current = setInterval(async () => {
      try {
        const data = await governanceAPI.get(jobId);
        setJob(data);
        if (data.status === "completed" || data.status === "failed") {
          clearInterval(pollingRef.current);
          if (data.status === "completed") {
            governanceAPI
              .getRagSources(jobId)
              .then(setRagSources)
              .catch(() => {});
          }
        }
      } catch (err) {
        console.error("Polling error:", err);
      }
    }, 3000);
  };

  // ── Loaders ──

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center py-24">
          <div className="spinner w-8 h-8" />
        </div>
      </MainLayout>
    );
  }

  if (error) {
    return (
      <MainLayout>
        <div className="text-center py-24">
          <AlertCircle className="w-12 h-12 text-[var(--accent-error)] mx-auto mb-3" />
          <p className="font-mono text-[var(--accent-error)] mb-4">{error}</p>
          <button
            onClick={() => navigate("/dashboard")}
            className="btn-secondary"
          >
            Back to Dashboard
          </button>
        </div>
      </MainLayout>
    );
  }

  const svcConfig = SERVICE_CONFIG[job.service_type] || SERVICE_CONFIG.deepfake;
  const Icon = svcConfig.icon;
  const agentResults = job.agent_results || {};
  const hasResults = Object.keys(agentResults).length > 0;
  const isRunning = job.status === "running" || job.status === "pending";

  // ── Service result routing ──

  const renderServiceResults = () => {
    const type = job.service_type;
    if (type === "deepfake")
      return <DeepfakeResults agentResults={agentResults} />;
    if (type === "threat_intel")
      return <ThreatIntelResults agentResults={agentResults} />;
    if (type === "privacy")
      return <PrivacyResults agentResults={agentResults} />;
    if (type === "responsible_ai")
      return <ResponsibleAIResults agentResults={agentResults} />;
    if (type === "digital_asset")
      return <DigitalAssetResults agentResults={agentResults} />;
    if (type === "all") {
      return (
        <div className="space-y-6">
          {[
            {
              key: "deepfake",
              Component: DeepfakeResults,
            },
            {
              key: "threat_intel",
              Component: ThreatIntelResults,
            },
            {
              key: "responsible_ai",
              Component: ResponsibleAIResults,
            },
            { key: "privacy", Component: PrivacyResults },
            {
              key: "digital_asset",
              Component: DigitalAssetResults,
            },
          ].map(({ key, Component }) => {
            const cfg = SERVICE_CONFIG[key];
            const SvcIcon = cfg.icon;
            return (
              <Card key={key}>
                <div className="flex items-center gap-2 mb-4">
                  <SvcIcon style={{ color: cfg.color }} className="w-5 h-5" />
                  <SectionTitle>{cfg.label}</SectionTitle>
                </div>
                <Component agentResults={agentResults} />
              </Card>
            );
          })}
        </div>
      );
    }
    return null;
  };

  // ── RAG Sources ──

  const renderRagSources = () => {
    if (!ragSources) return null;
    const src = ragSources.sources || ragSources;
    const deepfake = src.deepfake || [];
    const threat = src.threat_intel || [];
    const regulatory = src.regulatory || [];
    const total = deepfake.length + threat.length + regulatory.length;
    if (total === 0) return null;

    return (
      <Card className="mt-4">
        <div className="flex items-center gap-2 mb-3">
          <BookOpen className="w-4 h-4 text-[var(--accent-info)]" />
          <SectionTitle>Knowledge Base Sources ({total})</SectionTitle>
        </div>
        {[
          { data: deepfake, label: "Deepfake Database" },
          { data: threat, label: "Threat Intelligence" },
          { data: regulatory, label: "Regulatory References" },
        ]
          .filter((s) => s.data.length > 0)
          .map(({ data, label }) => (
            <div key={label} className="mb-3 last:mb-0">
              <div className="text-xs font-mono text-[var(--text-tertiary)] uppercase mb-2 tracking-wider">
                {label}
              </div>
              <div className="space-y-2">
                {data.map((src, i) => (
                  <div
                    key={i}
                    className="p-2 rounded bg-[var(--bg-tertiary)] border border-slate-700/50"
                  >
                    <div className="text-xs font-mono text-[var(--text-primary)]">
                      {src.dataset || src.technique || src.article || "Source"}
                    </div>
                    {src.notes && (
                      <div className="text-xs text-[var(--text-tertiary)] mt-0.5 font-mono">
                        {src.notes}
                      </div>
                    )}
                    {src.similarity != null && (
                      <div className="text-xs text-[var(--accent-info)] mt-0.5 font-mono">
                        Similarity: {(src.similarity * 100).toFixed(0)}%
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
      </Card>
    );
  };

  // ── Render ──

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <button
            onClick={() => navigate("/dashboard")}
            className="p-2 rounded-lg hover:bg-[var(--bg-elevated)] transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <Icon style={{ color: svcConfig.color }} className="w-6 h-6" />
          <div className="flex-1 min-w-0">
            <h1 className="font-mono text-lg font-bold">{svcConfig.label}</h1>
            <div className="text-xs text-[var(--text-tertiary)] font-mono">
              {jobId.slice(0, 8)}
              {"\u2026"} &bull;{" "}
              {new Date(
                job.created_at.endsWith("Z") || job.created_at.includes("+")
                  ? job.created_at
                  : job.created_at + "Z",
              ).toLocaleString()}
            </div>
          </div>
          <Badge
            variant={
              {
                pending: "warning",
                running: "info",
                completed: "verified",
                failed: "error",
              }[job.status] || "default"
            }
            size="md"
          >
            {job.status}
          </Badge>
        </div>

        {/* Live progress for pending/running */}
        {isRunning && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="mb-6"
          >
            <Card>
              <div className="flex items-center gap-2 mb-3">
                <Activity className="w-4 h-4 text-[var(--accent-info)] animate-pulse" />
                <SectionTitle>Analysis in Progress</SectionTitle>
              </div>
              <div className="space-y-2">
                {(job.agents_planned || []).map((agent) => {
                  const done = (job.agents_completed || []).includes(agent);
                  return (
                    <div
                      key={agent}
                      className="flex items-center gap-3 p-2 rounded bg-[var(--bg-tertiary)]"
                    >
                      {done ? (
                        <CheckCircle className="w-4 h-4 text-[var(--accent-verified)] flex-shrink-0" />
                      ) : (
                        <Clock className="w-4 h-4 text-[var(--accent-warning)] animate-pulse flex-shrink-0" />
                      )}
                      <span className="font-mono text-sm">
                        {AGENT_LABELS[agent] || agent}
                      </span>
                      {done && (
                        <span className="text-xs text-[var(--accent-verified)] ml-auto font-mono">
                          Done
                        </span>
                      )}
                    </div>
                  );
                })}
                {!job.agents_planned?.length && (
                  <div className="flex items-center gap-2 py-2 text-sm text-[var(--text-secondary)] font-mono">
                    <div className="spinner w-4 h-4" />
                    Initializing agents...
                  </div>
                )}
              </div>
            </Card>
          </motion.div>
        )}

        {/* Error */}
        {job.status === "failed" && job.error && (
          <Card className="mb-6 border-[var(--accent-error)]/30 bg-[var(--accent-error)]/5">
            <div className="flex items-center gap-2 mb-2">
              <AlertCircle className="w-5 h-5 text-[var(--accent-error)]" />
              <span className="font-mono font-semibold text-[var(--accent-error)]">
                Analysis Failed
              </span>
            </div>
            <p className="text-sm text-[var(--text-secondary)] font-mono">
              {job.error}
            </p>
          </Card>
        )}

        {/* Input Summary */}
        {job.input_data && (
          <details className="terminal-panel mb-4 cursor-pointer group">
            <summary className="flex items-center gap-2 font-mono text-sm text-[var(--text-secondary)] select-none list-none">
              <FileText className="w-4 h-4 flex-shrink-0" />
              <span>Input Summary</span>
              <ChevronDown className="w-3 h-3 ml-auto group-open:hidden" />
              <ChevronUp className="w-3 h-3 ml-auto hidden group-open:block" />
            </summary>
            <div className="mt-3 space-y-2 text-xs font-mono">
              {job.input_data.url && (
                <div className="text-[var(--accent-info)]">
                  URL: {job.input_data.url}
                </div>
              )}
              {job.input_data.file_name && (
                <div className="text-[var(--accent-warning)]">
                  File: {job.input_data.file_name} ({job.input_data.file_type})
                </div>
              )}
              {job.input_data.ai_system_description && (
                <div className="text-[var(--text-secondary)] bg-black/30 p-2 rounded max-h-20 overflow-y-auto scrollbar-thin">
                  AI System: {job.input_data.ai_system_description}
                </div>
              )}
              {job.input_data.content && (
                <div className="text-[var(--text-secondary)] bg-black/30 p-2 rounded max-h-20 overflow-y-auto scrollbar-thin">
                  {job.input_data.content}
                </div>
              )}
            </div>
          </details>
        )}

        {/* Service Results — shown as soon as any agent is done */}
        {hasResults && (
          <motion.div
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            className="mb-4"
          >
            {job.service_type === "all" ? (
              renderServiceResults()
            ) : (
              <Card>{renderServiceResults()}</Card>
            )}
          </motion.div>
        )}

        {/* RAG Sources */}
        {renderRagSources()}

        {/* Agent Raw Breakdown */}
        {hasResults && (
          <Card className="mt-4">
            <SectionTitle className="mb-3">Agent Breakdown</SectionTitle>
            <div className="space-y-2">
              {Object.entries(agentResults).map(([name, result]) => (
                <AgentAccordion key={name} agentName={name} result={result} />
              ))}
            </div>
          </Card>
        )}
      </div>
    </MainLayout>
  );
}
