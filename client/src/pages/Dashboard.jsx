import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Lock,
  ScanLine,
  Clock,
  CheckCircle,
  AlertCircle,
  ChevronRight,
  Shield,
  AlertTriangle,
  Brain,
  Database,
  Plus,
  X,
  Activity,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import ScanForm from "../components/ScanForm";
import { MainLayout } from "../components/layout";
import { Card, Badge, SectionTitle } from "../components/ui";
import {
  governance as governanceAPI,
  domains as domainsAPI,
  scans as scansAPI,
} from "../api/client";

const SERVICE_CONFIG = {
  deepfake: {
    label: "Deepfake Detection",
    description: "Detect AI-generated fakes in images, videos & audio",
    icon: Shield,
    color: "var(--accent-info)",
    borderClass:
      "border-[var(--accent-info)]/30 hover:border-[var(--accent-info)]/60",
  },
  threat_intel: {
    label: "Threat Intelligence",
    description: "Identify MITRE ATLAS patterns and predict AI attacks",
    icon: AlertTriangle,
    color: "var(--accent-error)",
    borderClass:
      "border-[var(--accent-error)]/30 hover:border-[var(--accent-error)]/60",
  },
  responsible_ai: {
    label: "Responsible AI Audit",
    description: "Audit AI systems for bias, fairness & ethical alignment",
    icon: Brain,
    color: "var(--accent-warning)",
    borderClass:
      "border-[var(--accent-warning)]/30 hover:border-[var(--accent-warning)]/60",
  },
  privacy: {
    label: "Privacy & Compliance",
    description: "GDPR / CCPA / DPDP compliance scans & PII detection",
    icon: Lock,
    color: "var(--accent-verified)",
    borderClass:
      "border-[var(--accent-verified)]/30 hover:border-[var(--accent-verified)]/60",
  },
  digital_asset: {
    label: "Digital Asset Governance",
    description: "Assess AI assets for licensing, provenance & governance",
    icon: Database,
    color: "#9b59b6",
    borderClass: "border-purple-500/30 hover:border-purple-500/60",
  },
};

const JOB_STATUS = {
  pending: {
    label: "Pending",
    dot: "status-dot-pending",
    textClass: "text-[var(--accent-warning)]",
  },
  running: {
    label: "Running",
    dot: "status-dot-pending",
    textClass: "text-[var(--accent-info)]",
  },
  completed: {
    label: "Completed",
    dot: "status-dot-verified",
    textClass: "text-[var(--accent-verified)]",
  },
  failed: {
    label: "Failed",
    dot: "status-dot-error",
    textClass: "text-[var(--accent-error)]",
  },
};

export default function Dashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [activeTab, setActiveTab] = useState("governance");
  const [governanceJobs, setGovernanceJobs] = useState([]);
  const [scans, setScans] = useState([]);
  const [domains, setDomains] = useState([]);
  const [loading, setLoading] = useState(true);

  // Create form state
  const [showCreate, setShowCreate] = useState(false);
  const [selectedService, setSelectedService] = useState(null);
  const [filterService, setFilterService] = useState(null);
  const [formContent, setFormContent] = useState("");
  const [formUrl, setFormUrl] = useState("");
  const [formAiDesc, setFormAiDesc] = useState("");
  const [formFile, setFormFile] = useState(null);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    const [jobsRes, scansRes, domsRes] = await Promise.allSettled([
      governanceAPI.list(0, 30),
      scansAPI.list(0, 10),
      domainsAPI.list(),
    ]);
    if (jobsRes.status === "fulfilled")
      setGovernanceJobs(Array.isArray(jobsRes.value) ? jobsRes.value : []);
    if (scansRes.status === "fulfilled") {
      const s = Array.isArray(scansRes.value) ? scansRes.value : [];
      s.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
      setScans(s);
    }
    if (domsRes.status === "fulfilled")
      setDomains(Array.isArray(domsRes.value) ? domsRes.value : []);
    setLoading(false);
  };

  const resetForm = () => {
    setSelectedService(null);
    setFormContent("");
    setFormUrl("");
    setFormAiDesc("");
    setFormFile(null);
    setCreateError(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setCreateError(null);
    setCreating(true);
    try {
      let job;
      if (formFile && selectedService === "deepfake") {
        job = await governanceAPI.uploadFile(formFile, selectedService);
      } else {
        const body = { service_type: selectedService };
        if (formUrl) body.url = formUrl;
        if (formContent) body.content = formContent;
        if (formAiDesc) body.ai_system_description = formAiDesc;
        job = await governanceAPI.create(body);
      }
      navigate(`/governance/${job.id}`);
    } catch (err) {
      setCreateError(err.message || "Failed to create analysis job");
    } finally {
      setCreating(false);
    }
  };

  const filteredJobs = filterService
    ? governanceJobs.filter((j) => j.service_type === filterService)
    : governanceJobs;

  const activeJobs = governanceJobs.filter(
    (j) => j.status === "running" || j.status === "pending",
  ).length;

  return (
    <MainLayout>
      {/* Stats Row */}
      <motion.div
        initial={{ opacity: 0, y: -10 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6"
      >
        {[
          {
            label: "Verified Domains",
            value: domains.length,
            icon: Lock,
            color: "var(--accent-verified)",
          },
          {
            label: "Total AI Analyses",
            value: governanceJobs.length,
            icon: Brain,
            color: "var(--accent-info)",
          },
          {
            label: "Active Jobs",
            value: activeJobs,
            icon: Activity,
            color: "var(--accent-warning)",
          },
          {
            label: "Security Scans",
            value: scans.length,
            icon: ScanLine,
            color: "var(--accent-error)",
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="terminal-panel flex flex-col gap-2 p-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-[var(--text-tertiary)] uppercase tracking-wider">
                {label}
              </span>
              <Icon style={{ color }} className="w-4 h-4 opacity-70" />
            </div>
            <div className="text-3xl font-mono font-bold" style={{ color }}>
              {loading ? "—" : value}
            </div>
          </div>
        ))}
      </motion.div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 border-b border-slate-700/50">
        {[
          { id: "governance", label: "AI Governance", icon: Brain },
          { id: "scanner", label: "Security Scanner", icon: ScanLine },
        ].map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 font-mono text-sm transition-all border-b-2 -mb-px ${
              activeTab === id
                ? "border-[var(--accent-verified)] text-[var(--accent-verified)]"
                : "border-transparent text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
          </button>
        ))}
      </div>

      {/* ── AI Governance Tab ── */}
      {activeTab === "governance" && (
        <div>
          {/* Toolbar */}
          <div className="flex items-center justify-between mb-4">
            <p className="text-xs font-mono text-[var(--text-tertiary)]">
              {filteredJobs.length} job
              {filteredJobs.length !== 1 ? "s" : ""}
              {filterService
                ? ` · ${SERVICE_CONFIG[filterService]?.label}`
                : ""}
            </p>
            <button
              onClick={() => {
                setShowCreate(!showCreate);
                resetForm();
              }}
              className="btn-primary flex items-center gap-2 text-sm py-2 px-4"
            >
              <Plus className="w-4 h-4" />
              New Analysis
            </button>
          </div>

          {/* Create Form */}
          <AnimatePresence>
            {showCreate && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
                className="mb-6"
              >
                <Card className="border-[var(--accent-verified)]/20">
                  <div className="flex items-center justify-between mb-5">
                    <SectionTitle icon={<Brain className="w-4 h-4" />}>
                      New AI Governance Analysis
                    </SectionTitle>
                    <button
                      onClick={() => {
                        setShowCreate(false);
                        resetForm();
                      }}
                      className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-colors"
                    >
                      <X className="w-5 h-5" />
                    </button>
                  </div>

                  {/* Step 1 — Select service */}
                  {!selectedService ? (
                    <div>
                      <p className="text-xs font-mono text-[var(--text-secondary)] mb-3">
                        Select a service:
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                        {Object.entries(SERVICE_CONFIG).map(([key, svc]) => {
                          const Icon = svc.icon;
                          return (
                            <button
                              key={key}
                              onClick={() => setSelectedService(key)}
                              className={`text-left p-4 rounded-lg border bg-[var(--bg-tertiary)] transition-all card-hover ${svc.borderClass}`}
                            >
                              <Icon
                                style={{ color: svc.color }}
                                className="w-5 h-5 mb-2"
                              />
                              <div className="font-mono font-semibold text-sm mb-1">
                                {svc.label}
                              </div>
                              <div className="text-xs text-[var(--text-tertiary)]">
                                {svc.description}
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  ) : (
                    /* Step 2 — Fill inputs */
                    <form onSubmit={handleSubmit}>
                      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-slate-700/50">
                        {(() => {
                          const Icon = SERVICE_CONFIG[selectedService].icon;
                          return (
                            <Icon
                              style={{
                                color: SERVICE_CONFIG[selectedService].color,
                              }}
                              className="w-5 h-5"
                            />
                          );
                        })()}
                        <span className="font-mono font-semibold text-sm">
                          {SERVICE_CONFIG[selectedService].label}
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            setSelectedService(null);
                            setCreateError(null);
                          }}
                          className="ml-auto text-xs text-[var(--accent-info)] font-mono hover:underline"
                        >
                          Change
                        </button>
                      </div>

                      {/* Deepfake */}
                      {selectedService === "deepfake" && (
                        <div className="space-y-3">
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Upload Image or Video
                            </label>
                            <input
                              type="file"
                              accept="image/jpeg,image/png,image/webp,image/gif,video/mp4,video/webm,video/quicktime"
                              onChange={(e) =>
                                setFormFile(e.target.files?.[0] || null)
                              }
                              className="input-field text-sm"
                            />
                            {formFile && (
                              <p className="text-xs text-[var(--accent-info)] mt-1 font-mono">
                                {formFile.name}
                              </p>
                            )}
                          </div>
                          <div className="text-center text-xs text-[var(--text-tertiary)] font-mono">
                            — or —
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Media URL
                            </label>
                            <input
                              type="url"
                              value={formUrl}
                              onChange={(e) => setFormUrl(e.target.value)}
                              placeholder="https://example.com/video.mp4"
                              className="input-field text-sm"
                              disabled={!!formFile}
                            />
                          </div>
                        </div>
                      )}

                      {/* Threat Intel */}
                      {selectedService === "threat_intel" && (
                        <div className="space-y-3">
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Content to Analyze{" "}
                              <span className="text-[var(--accent-error)]">
                                *
                              </span>
                            </label>
                            <textarea
                              value={formContent}
                              onChange={(e) => setFormContent(e.target.value)}
                              placeholder="Paste AI system outputs, prompts, model responses, or describe the suspected threat pattern..."
                              className="input-field text-sm min-h-[100px] resize-y"
                              required
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              AI System Description (optional)
                            </label>
                            <input
                              type="text"
                              value={formAiDesc}
                              onChange={(e) => setFormAiDesc(e.target.value)}
                              placeholder="e.g. LLM-powered customer service chatbot with RAG"
                              className="input-field text-sm"
                            />
                          </div>
                        </div>
                      )}

                      {/* Responsible AI */}
                      {selectedService === "responsible_ai" && (
                        <div className="space-y-3">
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              AI System Description{" "}
                              <span className="text-[var(--accent-error)]">
                                *
                              </span>
                            </label>
                            <textarea
                              value={formAiDesc}
                              onChange={(e) => setFormAiDesc(e.target.value)}
                              placeholder="Describe the AI system to audit: its purpose, training data, decision-making scope, affected user groups, and deployment context..."
                              className="input-field text-sm min-h-[110px] resize-y"
                              required
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Additional Content (optional)
                            </label>
                            <textarea
                              value={formContent}
                              onChange={(e) => setFormContent(e.target.value)}
                              placeholder="Paste model cards, bias test results, AI outputs, or evaluation reports..."
                              className="input-field text-sm min-h-[80px] resize-y"
                            />
                          </div>
                        </div>
                      )}

                      {/* Privacy */}
                      {selectedService === "privacy" && (
                        <div className="space-y-3">
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Website URL
                            </label>
                            <input
                              type="url"
                              value={formUrl}
                              onChange={(e) => setFormUrl(e.target.value)}
                              placeholder="https://example.com"
                              className="input-field text-sm"
                            />
                          </div>
                          <div className="text-center text-xs text-[var(--text-tertiary)] font-mono">
                            — or paste content —
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Privacy Policy / Content
                            </label>
                            <textarea
                              value={formContent}
                              onChange={(e) => setFormContent(e.target.value)}
                              placeholder="Paste privacy policy, cookie policy, or data processing description..."
                              className="input-field text-sm min-h-[90px] resize-y"
                            />
                          </div>
                        </div>
                      )}

                      {/* Digital Asset */}
                      {selectedService === "digital_asset" && (
                        <div className="space-y-3">
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              Asset Description{" "}
                              <span className="text-[var(--accent-error)]">
                                *
                              </span>
                            </label>
                            <textarea
                              value={formContent}
                              onChange={(e) => setFormContent(e.target.value)}
                              placeholder="Describe the AI digital asset: its type, origin, licensing terms, training data sources, provenance, and intended use..."
                              className="input-field text-sm min-h-[100px] resize-y"
                              required
                            />
                          </div>
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1.5">
                              AI System Context (optional)
                            </label>
                            <input
                              type="text"
                              value={formAiDesc}
                              onChange={(e) => setFormAiDesc(e.target.value)}
                              placeholder="e.g. Open-source LLM fine-tuned on proprietary customer data"
                              className="input-field text-sm"
                            />
                          </div>
                        </div>
                      )}

                      {createError && (
                        <div className="mt-3 p-3 rounded-lg bg-[var(--accent-error)]/10 border border-[var(--accent-error)]/30 text-sm text-[var(--accent-error)] font-mono">
                          {createError}
                        </div>
                      )}

                      <div className="flex gap-3 mt-5">
                        <button
                          type="submit"
                          disabled={creating}
                          className="btn-primary flex-1 flex items-center justify-center gap-2 text-sm py-2.5"
                        >
                          {creating ? (
                            <>
                              <div className="spinner w-4 h-4" />
                              Submitting...
                            </>
                          ) : (
                            "Start Analysis"
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setShowCreate(false);
                            resetForm();
                          }}
                          className="btn-secondary text-sm py-2.5 px-4"
                        >
                          Cancel
                        </button>
                      </div>
                    </form>
                  )}
                </Card>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Filter Pills */}
          <div className="flex flex-wrap gap-2 mb-4">
            <button
              onClick={() => setFilterService(null)}
              className={`px-3 py-1 rounded-full text-xs font-mono border transition-all ${
                !filterService
                  ? "bg-[var(--accent-verified)]/20 border-[var(--accent-verified)]/50 text-[var(--accent-verified)]"
                  : "border-slate-700 text-[var(--text-secondary)] hover:border-slate-500"
              }`}
            >
              All services
            </button>
            {Object.entries(SERVICE_CONFIG).map(([key, svc]) => {
              const Icon = svc.icon;
              const active = filterService === key;
              return (
                <button
                  key={key}
                  onClick={() => setFilterService(active ? null : key)}
                  style={
                    active
                      ? {
                          color: svc.color,
                          borderColor: svc.color,
                          backgroundColor: `${svc.color}20`,
                        }
                      : {}
                  }
                  className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono border transition-all ${
                    active
                      ? ""
                      : "border-slate-700 text-[var(--text-secondary)] hover:border-slate-500"
                  }`}
                >
                  <Icon className="w-3 h-3" />
                  {svc.label}
                </button>
              );
            })}
          </div>

          {/* Jobs List */}
          {loading ? (
            <div className="text-center py-16">
              <div className="spinner mx-auto" />
            </div>
          ) : filteredJobs.length === 0 ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="terminal-panel text-center py-16"
            >
              <Brain className="w-12 h-12 text-[var(--text-tertiary)] mx-auto mb-3" />
              <p className="font-mono text-[var(--text-secondary)]">
                No governance jobs yet
              </p>
              <p className="text-sm text-[var(--text-tertiary)] mt-1">
                Run your first AI analysis using{" "}
                <button
                  onClick={() => setShowCreate(true)}
                  className="text-[var(--accent-info)] hover:underline"
                >
                  New Analysis
                </button>
              </p>
            </motion.div>
          ) : (
            <div className="space-y-3">
              {filteredJobs.map((job, i) => {
                const svc = SERVICE_CONFIG[job.service_type] || {};
                const Icon = svc.icon || Brain;
                const statusInfo = JOB_STATUS[job.status] || JOB_STATUS.pending;
                return (
                  <motion.button
                    key={job.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: i * 0.04 }}
                    onClick={() => navigate(`/governance/${job.id}`)}
                    className="w-full text-left p-4 rounded-lg bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-all border border-transparent hover:border-slate-600 card-hover"
                  >
                    <div className="flex items-center gap-3">
                      <Icon
                        style={{ color: svc.color }}
                        className="w-5 h-5 flex-shrink-0"
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex flex-wrap items-center gap-2 mb-0.5">
                          <span className="font-mono text-sm font-semibold">
                            {svc.label || job.service_type}
                          </span>
                          <span
                            className={`flex items-center gap-1.5 text-xs font-mono ${statusInfo.textClass}`}
                          >
                            <span className={`status-dot ${statusInfo.dot}`} />
                            {statusInfo.label}
                          </span>
                        </div>
                        <div className="text-xs text-[var(--text-tertiary)] font-mono">
                          {new Date(job.created_at).toLocaleString()}
                          {job.agents_completed?.length > 0 && (
                            <span className="ml-3">
                              {job.agents_completed.length} agent
                              {job.agents_completed.length !== 1 ? "s" : ""} run
                            </span>
                          )}
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-[var(--text-tertiary)] flex-shrink-0" />
                    </div>
                  </motion.button>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ── Security Scanner Tab ── */}
      {activeTab === "scanner" && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-6">
          <motion.aside
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.1 }}
            className="lg:col-span-3 space-y-4"
          >
            <Card>
              <SectionTitle
                icon={<Lock className="w-4 h-4" />}
                className="mb-3"
              >
                Verified Domains
              </SectionTitle>
              {loading ? (
                <div className="text-center py-4">
                  <div className="spinner mx-auto" />
                </div>
              ) : domains.length === 0 ? (
                <p className="text-xs text-[var(--text-tertiary)]">
                  No verified domains yet
                </p>
              ) : (
                <div className="space-y-2">
                  {domains.map((d) => (
                    <div
                      key={d.domain}
                      className="flex items-center gap-2 p-2 rounded bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-colors"
                    >
                      <span className="status-dot status-dot-verified" />
                      <span className="text-xs font-mono flex-1 truncate">
                        {d.domain}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </Card>

            {!loading && scans.length > 0 && (
              <Card className="hidden lg:block">
                <SectionTitle
                  icon={<ScanLine className="w-4 h-4" />}
                  className="mb-3"
                >
                  Recent Scans
                </SectionTitle>
                <div className="space-y-2">
                  {scans.slice(0, 5).map((scan) => (
                    <button
                      key={scan.id}
                      onClick={() => navigate(`/scan/${scan.id}`)}
                      className="w-full text-left p-2 rounded bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-colors flex items-center gap-2 group"
                    >
                      {scan.status === "done" ? (
                        <CheckCircle className="w-3.5 h-3.5 text-[var(--accent-verified)] flex-shrink-0" />
                      ) : scan.status === "running" ? (
                        <Clock className="w-3.5 h-3.5 text-[var(--accent-info)] animate-pulse flex-shrink-0" />
                      ) : scan.status === "failed" ? (
                        <AlertCircle className="w-3.5 h-3.5 text-[var(--accent-error)] flex-shrink-0" />
                      ) : (
                        <Clock className="w-3.5 h-3.5 text-[var(--text-tertiary)] flex-shrink-0" />
                      )}
                      <span className="text-xs font-mono flex-1 truncate text-[var(--text-secondary)] group-hover:text-[var(--text-primary)]">
                        {(() => {
                          try {
                            return new URL(scan.url).hostname;
                          } catch {
                            return scan.url;
                          }
                        })()}
                      </span>
                      <ChevronRight className="w-3 h-3 text-[var(--text-tertiary)] group-hover:text-[var(--accent-verified)]" />
                    </button>
                  ))}
                </div>
              </Card>
            )}
          </motion.aside>

          <main className="lg:col-span-9">
            <ScanForm
              onScanCreated={(scan) => {
                if (scan === false) {
                  loadData();
                  return;
                }
                navigate(`/scan/${scan.id}`);
              }}
            />

            {!loading && scans.length > 0 && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.3 }}
                className="mt-6"
              >
                <Card>
                  <SectionTitle className="mb-4">All Scans</SectionTitle>
                  <div className="space-y-3">
                    {scans.map((scan, i) => (
                      <motion.button
                        key={scan.id}
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        transition={{ delay: 0.3 + i * 0.04 }}
                        onClick={() => navigate(`/scan/${scan.id}`)}
                        className="w-full text-left p-3 rounded-lg bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-all border border-transparent hover:border-slate-600 card-hover"
                      >
                        <div className="flex flex-col sm:flex-row items-start justify-between gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="font-mono font-semibold text-sm break-all mb-1">
                              {scan.url}
                            </div>
                            <div className="text-xs text-[var(--text-tertiary)] font-mono">
                              {new Date(
                                scan.created_at.endsWith("Z")
                                  ? scan.created_at
                                  : scan.created_at + "Z",
                              ).toLocaleString()}
                              {scan.risk_label && (
                                <span className="ml-2 text-[var(--accent-info)]">
                                  {scan.risk_label}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-3 flex-shrink-0">
                            {scan.risk_score != null && (
                              <span
                                className={`font-mono font-bold text-xl ${
                                  scan.risk_score >= 70
                                    ? "text-[var(--severity-critical)]"
                                    : scan.risk_score >= 40
                                      ? "text-[var(--severity-medium)]"
                                      : "text-[var(--accent-verified)]"
                                }`}
                              >
                                {scan.risk_score}
                              </span>
                            )}
                            <Badge
                              variant={
                                {
                                  done: "verified",
                                  running: "info",
                                  failed: "error",
                                  queued: "warning",
                                }[scan.status] || "default"
                              }
                              size="sm"
                            >
                              {scan.status}
                            </Badge>
                          </div>
                        </div>
                      </motion.button>
                    ))}
                  </div>
                </Card>
              </motion.div>
            )}
          </main>
        </div>
      )}
    </MainLayout>
  );
}
