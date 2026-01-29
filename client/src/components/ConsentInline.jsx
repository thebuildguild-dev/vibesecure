import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Copy,
  Check,
  Shield,
  FileText,
  AlertTriangle,
  AlertCircle,
  X,
} from "lucide-react";

export default function ConsentInline({ domain, onConsentVerified, onCancel }) {
  const [consentData, setConsentData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);
  const [consentSuccess, setConsentSuccess] = useState(false);

  const requestConsent = async () => {
    setLoading(true);
    setError(null);
    try {
      const { consent } = await import("../api/client");
      const data = await consent.request(domain);
      setConsentData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyConsent = async () => {
    setVerifying(true);
    setError(null);
    try {
      const { consent } = await import("../api/client");
      const result = await consent.check(domain);

      if (result.active_consent_verified) {
        setConsentSuccess(true);
        setTimeout(() => {
          onConsentVerified && onConsentVerified();
        }, 1500);
      } else {
        setError(
          result.message ||
            "Consent file not found or invalid. Please check file placement.",
        );
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  useEffect(() => {
    if (!consentData) {
      requestConsent();
    }
  }, []);

  if (consentSuccess) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="terminal-panel-elevated text-center py-12"
      >
        <Shield className="w-24 h-24 text-[var(--accent-warning)] mx-auto mb-6" />
        <h2 className="text-3xl font-mono font-bold text-[var(--accent-warning)] mb-2">
          Consent Verified!
        </h2>
        <p className="text-[var(--text-secondary)]">
          Active scanning authorized
        </p>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.95 }}
      animate={{ opacity: 1, scale: 1 }}
      className="terminal-panel-elevated"
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-6 border-b border-slate-700 pb-4">
        <div>
          <h2 className="text-2xl font-mono font-bold text-[var(--accent-warning)] mb-2">
            Active Scan Consent Required
          </h2>
          <p className="text-[var(--text-secondary)]">
            Authorization needed for{" "}
            <span className="text-[var(--accent-info)] font-mono">
              {domain}
            </span>
          </p>
        </div>
        <button
          onClick={onCancel}
          className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors"
        >
          <X className="w-5 h-5" />
        </button>
      </div>

      {/* Warning banner */}
      <div className="bg-[var(--accent-warning)]/10 border-l-4 border-l-[var(--accent-warning)] p-4 mb-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-[var(--accent-warning)] flex-shrink-0 mt-0.5" />
          <div>
            <h3 className="font-mono font-semibold text-[var(--accent-warning)] mb-1">
              Active Scanning Notice
            </h3>
            <p className="text-sm text-[var(--text-secondary)]">
              Active scanning sends potentially malicious payloads to test for
              vulnerabilities (SQL injection, XSS, etc.). Only authorize if you
              have legal permission and understand the risks.
            </p>
          </div>
        </div>
      </div>

      {/* Content */}
      {loading && (
        <div className="text-center py-12">
          <div className="spinner mx-auto mb-4"></div>
          <p className="text-[var(--text-secondary)]">
            Generating consent instructions...
          </p>
        </div>
      )}

      {consentData && (
        <div className="space-y-6">
          {/* Instructions */}
          <div className="terminal-panel border-l-4 border-l-[var(--accent-warning)]">
            <div className="flex items-start gap-3 mb-4">
              <FileText className="w-6 h-6 text-[var(--accent-warning)] flex-shrink-0 mt-1" />
              <div className="flex-1">
                <h3 className="text-lg font-mono font-semibold mb-2">
                  Consent File Setup
                </h3>
                <p className="text-sm text-[var(--text-secondary)] mb-4">
                  Create a consent file at the following location:
                </p>

                <div className="code-block mb-4">
                  {consentData.instructions.path}
                </div>

                <p className="text-sm text-[var(--text-secondary)] mb-2">
                  With the following content:
                </p>

                <div className="relative">
                  <pre className="code-block overflow-x-auto whitespace-pre text-xs leading-relaxed">
                    {consentData.instructions.content}
                  </pre>
                  <button
                    onClick={() =>
                      copyToClipboard(consentData.instructions.content)
                    }
                    className="absolute top-2 right-2 p-2 bg-[var(--bg-primary)] hover:bg-[var(--bg-tertiary)] rounded transition-colors"
                    title="Copy to clipboard"
                  >
                    {copied ? (
                      <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* User info */}
          <div className="terminal-panel bg-[var(--bg-tertiary)]">
            <h4 className="text-sm font-mono text-[var(--text-secondary)] mb-3 uppercase tracking-wider">
              Request Details
            </h4>
            <div className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-[var(--text-tertiary)]">Domain:</span>
                <span className="font-mono text-[var(--accent-info)]">
                  {consentData.domain}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[var(--text-tertiary)]">
                  Requested by:
                </span>
                <span className="font-mono">{consentData.user_email}</span>
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex flex-col md:flex-row gap-4 pt-4 border-t border-slate-700">
            <button
              onClick={verifyConsent}
              disabled={verifying}
              className="btn-primary flex-1 flex items-center justify-center gap-2"
            >
              {verifying ? (
                <>
                  <div className="spinner"></div>
                  Checking...
                </>
              ) : (
                <>
                  <Shield className="w-5 h-5" />
                  Check Consent File
                </>
              )}
            </button>
            <button onClick={onCancel} className="btn-secondary">
              Cancel
            </button>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-[var(--accent-error)]/10 border border-[var(--accent-error)] rounded-lg p-4 mt-6 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-[var(--accent-error)] flex-shrink-0" />
          <p className="text-[var(--accent-error)] text-sm">{error}</p>
        </div>
      )}
    </motion.div>
  );
}
