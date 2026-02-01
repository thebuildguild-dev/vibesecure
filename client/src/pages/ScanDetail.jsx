import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useParams, useNavigate } from "react-router-dom";
import {
  Radar,
  Clock,
  CheckCircle,
  AlertCircle,
  XCircle,
  ChevronDown,
  ChevronUp,
  Download,
  Sparkles,
  FileCode,
  Copy,
  Check,
  ArrowLeft,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { MainLayout } from "../components/layout";
import { Card, Badge, Button, SectionTitle } from "../components/ui";

export default function ScanDetail() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [expandedFindings, setExpandedFindings] = useState(new Set());
  const [showExport, setShowExport] = useState(false);
  const [aiSummary, setAiSummary] = useState(null);
  const [loadingAiSummary, setLoadingAiSummary] = useState(false);
  const [fixConfig, setFixConfig] = useState(null);
  const [selectedPlatform, setSelectedPlatform] = useState("vercel");
  const [loadingFix, setLoadingFix] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    window.scrollTo(0, 0);

    loadScanDetail();
    const interval = setInterval(() => {
      if (scan?.status === "running" || scan?.status === "queued") {
        loadScanDetail();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [scanId, scan?.status]);

  const loadScanDetail = async () => {
    try {
      const { scans } = await import("../api/client");
      const [scanData, findingsData] = await Promise.all([
        scans.get(scanId),
        scans.getFindings(scanId).catch(() => []),
      ]);
      setScan(scanData);
      setFindings(findingsData);

      if (scanData.status === "done" && !aiSummary && !loadingAiSummary) {
        setLoadingAiSummary(true);
        scans
          .getAISummary(scanId)
          .then((data) => {
            setAiSummary(data);
            setLoadingAiSummary(false);
          })
          .catch((err) => {
            console.error("AI Summary error:", err);
            setLoadingAiSummary(false);
          });
      }
    } catch (err) {
      console.error("Failed to load scan:", err);
    } finally {
      setLoading(false);
    }
  };

  const toggleFinding = (findingId) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(findingId)) {
      newExpanded.delete(findingId);
    } else {
      newExpanded.add(findingId);
    }
    setExpandedFindings(newExpanded);
  };

  useEffect(() => {
    if (scan?.status === "done") {
      const fetchConfig = async () => {
        setLoadingFix(true);
        try {
          const { scans } = await import("../api/client");
          const config = await scans.getFixConfig(scanId, selectedPlatform);
          setFixConfig(config);
        } catch (err) {
          console.error("Failed to load fix config:", err);
        } finally {
          setLoadingFix(false);
        }
      };
      fetchConfig();
    }
  }, [scanId, selectedPlatform, scan?.status]);

  const getSeverityBadge = (severity) => {
    return severity;
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case "critical":
      case "high":
        return <XCircle className="w-3 h-3 sm:w-4 sm:h-4" />;
      case "medium":
        return <AlertCircle className="w-3 h-3 sm:w-4 sm:h-4" />;
      default:
        return <CheckCircle className="w-3 h-3 sm:w-4 sm:h-4" />;
    }
  };

  const groupFindingsBySeverity = () => {
    const grouped = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: [],
    };
    findings.forEach((f) => {
      grouped[f.severity]?.push(f);
    });
    return grouped;
  };

  const downloadReport = async (format) => {
    try {
      const { scans } = await import("../api/client");
      const report = await scans.getReport(scanId, format);

      let blob;
      if (format === "pdf") {
        blob = report;
      } else {
        blob = new Blob([JSON.stringify(report, null, 2)], {
          type: "application/json",
        });
      }

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vibesecure-scan-${scanId}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error("Failed to download report:", err);
    }
  };

  if (loading) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center min-h-[50vh]">
          <div className="text-center">
            <div className="spinner mx-auto mb-4"></div>
            <p className="text-[var(--text-secondary)] font-mono text-sm sm:text-base">
              Loading scan data...
            </p>
          </div>
        </div>
      </MainLayout>
    );
  }

  if (!scan) {
    return (
      <MainLayout>
        <div className="flex items-center justify-center min-h-[50vh]">
          <div className="text-center">
            <XCircle className="w-12 h-12 sm:w-16 sm:h-16 text-[var(--accent-error)] mx-auto mb-4" />
            <p className="text-[var(--text-secondary)] text-sm sm:text-base">
              Scan not found
            </p>
            <Button
              onClick={() => navigate("/dashboard")}
              variant="primary"
              className="mt-4"
            >
              Back to Dashboard
            </Button>
          </div>
        </div>
      </MainLayout>
    );
  }

  const groupedFindings = groupFindingsBySeverity();
  const totalFindings = findings.length;

  return (
    <MainLayout showProfile={true}>
      {/* Custom header with back button and export */}
      <div className="mb-4 sm:mb-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 sm:gap-4">
          <div className="flex items-center gap-3 sm:gap-4">
            <button
              onClick={() => navigate("/dashboard")}
              className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors flex-shrink-0"
              aria-label="Back to dashboard"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
            <div className="min-w-0">
              <h1 className="text-lg sm:text-xl lg:text-2xl font-mono font-bold break-words">
                Security Scan Report
              </h1>
              <p className="text-xs sm:text-sm text-[var(--text-tertiary)] font-mono truncate">
                {scan.url}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2 relative w-full sm:w-auto">
            <Button
              onClick={() => setShowExport(!showExport)}
              variant="secondary"
              size="sm"
              icon={<Download className="w-4 h-4" />}
              fullWidth
              className="sm:w-auto"
            >
              Export
            </Button>
            <AnimatePresence>
              {showExport && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  className="absolute right-0 top-full mt-2 w-32 bg-[var(--bg-tertiary)] border border-slate-700 rounded-lg shadow-xl z-50 overflow-hidden"
                >
                  <button
                    onClick={() => {
                      downloadReport("json");
                      setShowExport(false);
                    }}
                    className="w-full text-left px-4 py-2 text-sm font-mono hover:bg-[var(--bg-elevated)] transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  >
                    JSON
                  </button>
                  <button
                    onClick={() => {
                      downloadReport("pdf");
                      setShowExport(false);
                    }}
                    className="w-full text-left px-4 py-2 text-sm font-mono hover:bg-[var(--bg-elevated)] transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  >
                    PDF
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
      {/* Status and Risk Score */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-1 md:grid-cols-3 gap-4 sm:gap-6 mb-6 sm:mb-8"
      >
        {/* Status */}
        <Card>
          <div className="flex items-center gap-2 mb-2 sm:mb-3">
            {scan.status === "done" && (
              <CheckCircle className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-verified)]" />
            )}
            {scan.status === "running" && (
              <Clock className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-info)] animate-pulse" />
            )}
            {scan.status === "failed" && (
              <XCircle className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-error)]" />
            )}
            <span className="text-xs sm:text-sm font-mono text-[var(--text-secondary)] uppercase">
              Status
            </span>
          </div>
          <Badge
            variant={
              scan.status === "done"
                ? "verified"
                : scan.status === "failed"
                  ? "error"
                  : "info"
            }
            size="md"
          >
            {scan.status}
          </Badge>
        </Card>

        {/* Risk Score Gauge */}
        <Card className="md:col-span-2">
          <div className="flex items-center justify-between mb-3 sm:mb-4">
            <span className="text-xs sm:text-sm font-mono text-[var(--text-secondary)] uppercase">
              Risk Assessment
            </span>
            {scan.risk_label && (
              <Badge variant="warning" size="sm">
                {scan.risk_label}
              </Badge>
            )}
          </div>
          {scan.risk_score !== null ? (
            <div className="relative">
              <div className="h-3 sm:h-4 bg-[var(--bg-tertiary)] rounded-full overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${scan.risk_score}%` }}
                  transition={{ duration: 1, ease: "easeOut" }}
                  className="h-full rounded-full"
                  style={{
                    backgroundColor:
                      scan.risk_score >= 70
                        ? "var(--severity-critical)"
                        : scan.risk_score >= 40
                          ? "var(--severity-medium)"
                          : "var(--accent-verified)",
                    boxShadow: `0 0 20px ${
                      scan.risk_score >= 70
                        ? "var(--accent-error-glow)"
                        : scan.risk_score >= 40
                          ? "var(--accent-warning-glow)"
                          : "var(--accent-verified-glow)"
                    }`,
                  }}
                />
              </div>
              <div className="flex items-baseline justify-between mt-2">
                <span className="text-2xl sm:text-3xl font-mono font-bold">
                  <span
                    style={{
                      color:
                        scan.risk_score >= 70
                          ? "var(--severity-critical)"
                          : scan.risk_score >= 40
                            ? "var(--severity-medium)"
                            : "var(--accent-verified)",
                    }}
                  >
                    {scan.risk_score}
                  </span>
                  <span className="text-base sm:text-lg text-[var(--text-tertiary)]">
                    /100
                  </span>
                </span>
                <span className="text-xs text-[var(--text-tertiary)]">
                  {totalFindings} finding{totalFindings !== 1 ? "s" : ""}
                </span>
              </div>
            </div>
          ) : (
            <p className="text-xs sm:text-sm text-[var(--text-tertiary)]">
              Risk score calculating...
            </p>
          )}
        </Card>
      </motion.div>

      {/* Scan metadata */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="mb-6 sm:mb-8"
      >
        <Card>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 text-xs sm:text-sm">
            <div>
              <span className="text-[var(--text-tertiary)] block mb-1">
                Created
              </span>
              <span className="font-mono text-xs sm:text-sm break-words">
                {new Date(
                  scan.created_at.endsWith("Z")
                    ? scan.created_at
                    : scan.created_at + "Z",
                ).toLocaleString()}
              </span>
            </div>
            {scan.started_at && (
              <div>
                <span className="text-[var(--text-tertiary)] block mb-1">
                  Started
                </span>
                <span className="font-mono text-xs sm:text-sm break-words">
                  {new Date(
                    scan.started_at.endsWith("Z")
                      ? scan.started_at
                      : scan.started_at + "Z",
                  ).toLocaleString()}
                </span>
              </div>
            )}
            {scan.finished_at && (
              <div>
                <span className="text-[var(--text-tertiary)] block mb-1">
                  Finished
                </span>
                <span className="font-mono text-xs sm:text-sm break-words">
                  {new Date(
                    scan.finished_at.endsWith("Z")
                      ? scan.finished_at
                      : scan.finished_at + "Z",
                  ).toLocaleString()}
                </span>
              </div>
            )}
            {scan.scan_confidence && (
              <div>
                <span className="text-[var(--text-tertiary)] block mb-1">
                  Confidence
                </span>
                <span className="font-mono text-xs sm:text-sm">
                  {scan.scan_confidence}
                </span>
              </div>
            )}
          </div>
          {scan.description && (
            <div className="mt-3 sm:mt-4 pt-3 sm:pt-4 border-t border-slate-700">
              <span className="text-[var(--text-tertiary)] block mb-1 text-xs sm:text-sm">
                Description
              </span>
              <p className="text-xs sm:text-sm break-words">
                {scan.description}
              </p>
            </div>
          )}
        </Card>
      </motion.div>

      {/* AI Summary */}
      {(loadingAiSummary || aiSummary) && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 sm:mb-8"
        >
          <Card>
            <SectionTitle
              icon={<Sparkles className="w-4 h-4 sm:w-5 sm:h-5" />}
              className="mb-3 sm:mb-4"
            >
              <span className="text-base sm:text-lg">
                AI Vulnerability Analysis
              </span>
            </SectionTitle>
            {loadingAiSummary ? (
              <div className="flex flex-col items-center justify-center py-8 sm:py-12">
                <div className="spinner mb-4"></div>
                <p className="text-sm sm:text-base text-[var(--text-secondary)] font-mono">
                  Loading AI analysis...
                </p>
              </div>
            ) : (
              <>
                <p className="text-xs sm:text-sm text-[var(--text-secondary)] mb-4 sm:mb-6 leading-relaxed">
                  {aiSummary.summary}
                </p>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 sm:gap-6">
                  {aiSummary.checklist && aiSummary.checklist.length > 0 && (
                    <div>
                      <h4 className="text-xs font-mono font-semibold text-[var(--text-tertiary)] uppercase mb-3">
                        Security Checklist
                      </h4>
                      <ul className="space-y-3">
                        {aiSummary.checklist.map((item, i) => (
                          <li
                            key={i}
                            className="flex items-start gap-2 text-sm"
                          >
                            <CheckCircle className="w-4 h-4 text-[var(--accent-verified)] flex-shrink-0 mt-0.5" />
                            <div>
                              <span className="text-[var(--text-primary)] font-medium block">
                                {item.title || item.item || item}
                              </span>
                              {item.priority && (
                                <span
                                  className={`text-[10px] uppercase font-mono px-1.5 py-0.5 rounded border mr-2
                                  ${
                                    item.priority === "Critical"
                                      ? "border-red-500/50 text-red-500 bg-red-500/10"
                                      : item.priority === "High"
                                        ? "border-orange-500/50 text-orange-500 bg-orange-500/10"
                                        : "border-slate-600 text-slate-400"
                                  }`}
                                >
                                  {item.priority}
                                </span>
                              )}
                              {item.action && (
                                <span className="text-[var(--text-tertiary)] text-xs">
                                  {item.action}
                                </span>
                              )}
                            </div>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {aiSummary.recommendations &&
                    aiSummary.recommendations.length > 0 && (
                      <div>
                        <h4 className="text-xs font-mono font-semibold text-[var(--text-tertiary)] uppercase mb-3">
                          Key Recommendations
                        </h4>
                        <ul className="space-y-2">
                          {aiSummary.recommendations.map((rec, i) => (
                            <li
                              key={i}
                              className="flex items-start gap-2 text-sm"
                            >
                              <div className="w-1.5 h-1.5 rounded-full bg-[var(--accent-info)] mt-1.5 flex-shrink-0" />
                              <span className="text-[var(--text-secondary)]">
                                {rec}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                </div>
              </>
            )}
          </Card>
        </motion.div>
      )}

      {/* Platform Fix Configuration */}
      {scan?.status === "done" && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-6 sm:mb-8"
        >
          <Card>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 sm:gap-4 mb-4 sm:mb-6">
              <SectionTitle
                icon={<FileCode className="w-4 h-4 sm:w-5 sm:h-5" />}
                className="mb-0"
              >
                <span className="text-base sm:text-lg">
                  Platform Configuration
                </span>
              </SectionTitle>
              <div className="flex flex-wrap gap-2 w-full sm:w-auto">
                {["vercel", "netlify", "nginx", "apache"].map((platform) => (
                  <button
                    key={platform}
                    onClick={() => setSelectedPlatform(platform)}
                    className={`px-2.5 sm:px-3 py-1 sm:py-1.5 rounded text-xs font-mono uppercase transition-colors
                      ${
                        selectedPlatform === platform
                          ? "bg-[var(--accent-info)] text-[var(--bg-primary)] font-bold"
                          : "bg-[var(--bg-tertiary)] text-[var(--text-secondary)] hover:bg-[var(--bg-elevated)]"
                      }`}
                  >
                    {platform}
                  </button>
                ))}
              </div>
            </div>

            {loadingFix ? (
              <div className="text-center py-6 sm:py-8">
                <div className="spinner mx-auto" />
              </div>
            ) : fixConfig ? (
              <div className="space-y-4">
                <p className="text-sm text-[var(--text-secondary)]">
                  {fixConfig.instructions}
                </p>
                <div className="relative group">
                  <pre
                    className="bg-[var(--bg-primary)] p-4 rounded-lg overflow-x-auto text-xs font-mono border border-slate-700 text-[var(--text-secondary)]"
                    style={{ whiteSpace: "pre-wrap" }}
                  >
                    {fixConfig.config}
                  </pre>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(fixConfig.config);
                      setCopied(true);
                      setTimeout(() => setCopied(false), 2000);
                    }}
                    className="absolute top-2 right-2 p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                    title="Copy to clipboard"
                  >
                    {copied ? (
                      <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <div className="flex items-center justify-between text-xs text-[var(--text-tertiary)] font-mono">
                  <span>
                    Filename:{" "}
                    <span className="text-[var(--text-primary)]">
                      {fixConfig.filename}
                    </span>
                  </span>
                </div>
              </div>
            ) : (
              <div className="text-center py-6 sm:py-8 text-[var(--text-tertiary)] text-xs sm:text-sm">
                Select a platform to generate configuration
              </div>
            )}
          </Card>
        </motion.div>
      )}

      {/* Findings */}
      {totalFindings > 0 ? (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="space-y-4 sm:space-y-6"
        >
          <SectionTitle icon={<Radar className="w-5 h-5 sm:w-6 sm:h-6" />}>
            <span className="text-xl sm:text-2xl">Security Findings</span>
          </SectionTitle>

          {Object.entries(groupedFindings).map(
            ([severity, items], sectionIdx) =>
              items.length > 0 && (
                <motion.div
                  key={severity}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: 0.2 + sectionIdx * 0.1 }}
                >
                  <Card>
                    <div className="flex items-center gap-2 sm:gap-3 mb-3 sm:mb-4 pb-2 border-b border-slate-700">
                      <Badge variant={getSeverityBadge(severity)} size="md">
                        {severity.toUpperCase()}
                      </Badge>
                      <span className="text-xs sm:text-sm text-[var(--text-tertiary)]">
                        {items.length} finding{items.length !== 1 ? "s" : ""}
                      </span>
                    </div>

                    <div className="space-y-2 sm:space-y-3">
                      {items.map((finding, idx) => (
                        <motion.div
                          key={finding.id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{ opacity: 1, x: 0 }}
                          transition={{
                            delay: 0.3 + sectionIdx * 0.1 + idx * 0.05,
                          }}
                          className="bg-[var(--bg-tertiary)] rounded-lg border border-slate-700 overflow-hidden"
                        >
                          <button
                            onClick={() => toggleFinding(finding.id)}
                            className="w-full p-3 sm:p-4 flex items-start gap-2 sm:gap-3 hover:bg-[var(--bg-elevated)] transition-colors text-left"
                          >
                            <div className="pt-0.5 sm:pt-1 flex-shrink-0">
                              {getSeverityIcon(finding.severity)}
                            </div>
                            <div className="flex-1 min-w-0">
                              <h4 className="font-mono font-semibold mb-1 text-sm sm:text-base break-words">
                                {finding.title}
                              </h4>
                              {finding.path && (
                                <p className="text-xs sm:text-sm text-[var(--text-tertiary)] font-mono break-all">
                                  {finding.path}
                                </p>
                              )}
                            </div>
                            <div className="flex items-center gap-2 flex-shrink-0">
                              {finding.confidence && (
                                <span className="text-xs text-[var(--text-tertiary)] hidden sm:inline">
                                  {finding.confidence}%
                                </span>
                              )}
                              {expandedFindings.has(finding.id) ? (
                                <ChevronUp className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-verified)]" />
                              ) : (
                                <ChevronDown className="w-4 h-4 sm:w-5 sm:h-5" />
                              )}
                            </div>
                          </button>

                          <AnimatePresence>
                            {expandedFindings.has(finding.id) && (
                              <motion.div
                                initial={{ height: 0, opacity: 0 }}
                                animate={{ height: "auto", opacity: 1 }}
                                exit={{ height: 0, opacity: 0 }}
                                transition={{
                                  duration: 0.2,
                                  ease: "easeInOut",
                                }}
                                className="border-t border-slate-700 bg-black/20 overflow-hidden"
                              >
                                <div className="p-3 sm:p-4">
                                  <h5 className="text-xs sm:text-sm font-mono font-semibold text-[var(--accent-verified)] mb-2 uppercase">
                                    Remediation
                                  </h5>
                                  <p className="text-xs sm:text-sm text-[var(--text-secondary)] leading-relaxed whitespace-pre-wrap break-words">
                                    {finding.remediation ||
                                      finding.description ||
                                      "No specific remediation details available."}
                                  </p>
                                </div>
                              </motion.div>
                            )}
                          </AnimatePresence>
                        </motion.div>
                      ))}
                    </div>
                  </Card>
                </motion.div>
              ),
          )}
        </motion.div>
      ) : (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="text-center py-8 sm:py-12"
        >
          <Card>
            <CheckCircle className="w-12 h-12 sm:w-16 sm:h-16 text-[var(--accent-verified)] mx-auto mb-3 sm:mb-4" />
            <h3 className="text-lg sm:text-xl font-mono font-bold mb-2">
              No Findings Detected
            </h3>
            <p className="text-xs sm:text-sm text-[var(--text-secondary)]">
              {scan.status === "done"
                ? "This scan completed without detecting any security issues."
                : "Scan is still in progress. Findings will appear as they are discovered."}
            </p>
          </Card>
        </motion.div>
      )}
    </MainLayout>
  );
}
