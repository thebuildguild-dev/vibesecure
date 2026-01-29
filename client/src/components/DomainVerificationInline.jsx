import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Copy,
  Check,
  Lock,
  FileText,
  Code,
  Globe,
  AlertCircle,
  CheckCircle,
} from "lucide-react";

export default function DomainVerificationInline({
  domain,
  onVerified,
  onCancel,
}) {
  const [verificationData, setVerificationData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState(null);
  const [copiedField, setCopiedField] = useState(null);
  const [verificationSuccess, setVerificationSuccess] = useState(false);
  const [showDeleteOption, setShowDeleteOption] = useState(false);

  const requestToken = async () => {
    setLoading(true);
    setError(null);
    try {
      const { domains } = await import("../api/client");
      const data = await domains.requestVerification(domain);
      setVerificationData(data);
    } catch (err) {
      if (err.status === 409 && err.errorType === "token_exists") {
        setShowDeleteOption(true);
      } else {
        setError(err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const verifyToken = async () => {
    setVerifying(true);
    setError(null);
    setShowDeleteOption(false);
    try {
      const { domains } = await import("../api/client");
      const result = await domains.checkVerification(domain);

      if (result.verified) {
        setVerificationSuccess(true);
        setTimeout(() => {
          onVerified && onVerified();
        }, 1500);
      } else {
        setError(
          result.details ||
            "Verification failed. Please check token placement.",
        );
        setShowDeleteOption(true);
      }
    } catch (err) {
      setError(err.message);
      setShowDeleteOption(true);
    } finally {
      setVerifying(false);
    }
  };

  const deleteAndRequestNew = async () => {
    setDeleting(true);
    setError(null);
    try {
      const { domains } = await import("../api/client");
      await domains.deleteVerificationRequest(domain);

      setVerificationData(null);
      setShowDeleteOption(false);

      await requestToken();
    } catch (err) {
      setError(err.message || "Failed to delete old verification request");
    } finally {
      setDeleting(false);
    }
  };

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  useEffect(() => {
    if (!verificationData) {
      requestToken();
    }
  }, []);

  if (verificationSuccess) {
    return (
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="terminal-panel-elevated bg-[var(--accent-verified)]/10 border-2 border-[var(--accent-verified)]"
      >
        <div className="text-center py-8">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ type: "spring", damping: 15 }}
          >
            <CheckCircle className="w-16 h-16 text-[var(--accent-verified)] mx-auto mb-4" />
            <h3 className="text-2xl font-mono font-bold text-[var(--accent-verified)] mb-2">
              Domain Verified!
            </h3>
            <p className="text-[var(--text-secondary)]">
              Authorization granted for{" "}
              <span className="text-[var(--accent-info)] font-mono">
                {domain}
              </span>
            </p>
          </motion.div>
        </div>
      </motion.div>
    );
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="terminal-panel-elevated"
    >
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <Lock className="w-6 h-6 text-[var(--accent-warning)]" />
          <h3 className="text-xl font-mono font-bold text-[var(--accent-warning)]">
            Domain Ownership Verification Required
          </h3>
        </div>
        <p className="text-[var(--text-secondary)]">
          Prove ownership of{" "}
          <span className="text-[var(--accent-info)] font-mono">{domain}</span>
        </p>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="text-center py-8">
          <div className="spinner mx-auto mb-4"></div>
          <p className="text-[var(--text-secondary)]">
            Generating verification token...
          </p>
        </div>
      )}

      {/* Info message when token exists */}
      {!verificationData && showDeleteOption && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="bg-[var(--accent-info)]/10 border border-[var(--accent-info)] rounded-lg p-4 mb-6"
        >
          <div className="flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-[var(--accent-info)] flex-shrink-0 mt-0.5" />
            <p className="text-[var(--accent-info)] text-sm">
              A verification token already exists for this domain. Click
              "Request New Token" below to delete the old one and generate a
              fresh token.
            </p>
          </div>
        </motion.div>
      )}

      {/* Request New Token button when no verification data */}
      {!verificationData && showDeleteOption && (
        <div className="flex gap-3">
          <button
            onClick={deleteAndRequestNew}
            disabled={deleting}
            className="px-6 py-3 bg-[var(--accent-warning)]/20 hover:bg-[var(--accent-warning)]/30 border border-[var(--accent-warning)] text-[var(--accent-warning)] rounded-lg font-mono transition-colors"
          >
            {deleting ? (
              <span className="flex items-center justify-center gap-2">
                <div className="spinner"></div>
                Requesting...
              </span>
            ) : (
              "Request New Token"
            )}
          </button>

          {onCancel && (
            <button
              onClick={onCancel}
              disabled={deleting}
              className="px-6 py-3 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] rounded-lg font-mono transition-colors"
            >
              Cancel
            </button>
          )}
        </div>
      )}

      {/* Verification instructions */}
      {verificationData && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="space-y-6"
        >
          {/* Token display */}
          <div className="terminal-panel bg-[var(--bg-tertiary)]">
            <h4 className="text-sm font-mono text-[var(--text-secondary)] mb-2 uppercase tracking-wider">
              Your Verification Token
            </h4>
            <div className="flex items-center gap-2 mb-2">
              <code className="flex-1 bg-black/40 px-3 py-2 rounded text-[var(--accent-verified)] font-mono text-sm break-all">
                {verificationData.token}
              </code>
              <button
                onClick={() => copyToClipboard(verificationData.token, "token")}
                className="p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors flex-shrink-0"
                title="Copy token"
              >
                {copiedField === "token" ? (
                  <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
            <p className="text-xs text-[var(--text-tertiary)]">
              Expires: {new Date(verificationData.expires_at).toLocaleString()}
            </p>
          </div>

          {/* Verification methods */}
          <div className="space-y-4">
            <h4 className="text-lg font-mono font-semibold flex items-center gap-2">
              <FileText className="w-5 h-5 text-[var(--accent-info)]" />
              Choose Verification Method
            </h4>

            {/* Method 1: File */}
            <div className="terminal-panel bg-[var(--bg-tertiary)] border-l-4 border-l-[var(--accent-verified)]">
              <div className="flex items-start gap-3 mb-3">
                <FileText className="w-5 h-5 text-[var(--accent-verified)] flex-shrink-0 mt-1" />
                <div className="flex-1">
                  <h5 className="font-mono font-semibold mb-1 text-[var(--accent-verified)]">
                    Method 1: File Verification (Recommended)
                  </h5>
                  <p className="text-sm text-[var(--text-secondary)] mb-3">
                    Create a file at the following path:
                  </p>
                  <div className="bg-black/40 rounded p-3 mb-2">
                    <div className="flex items-center gap-2 mb-2">
                      <code className="flex-1 text-[var(--accent-info)] font-mono text-xs break-all">
                        {verificationData.instructions.file.path}
                      </code>
                      <button
                        onClick={() =>
                          copyToClipboard(
                            verificationData.instructions.file.path,
                            "file-path",
                          )
                        }
                        className="p-1 hover:bg-[var(--bg-tertiary)] rounded transition-colors flex-shrink-0"
                        title="Copy path"
                      >
                        {copiedField === "file-path" ? (
                          <Check className="w-3 h-3 text-[var(--accent-verified)]" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                    <div className="border-t border-slate-700 pt-2">
                      <div className="flex items-start gap-2">
                        <code className="flex-1 text-[var(--text-primary)] font-mono text-xs break-all">
                          {verificationData.instructions.file.content}
                        </code>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              verificationData.instructions.file.content,
                              "file-content",
                            )
                          }
                          className="p-1 hover:bg-[var(--bg-tertiary)] rounded transition-colors flex-shrink-0"
                          title="Copy content"
                        >
                          {copiedField === "file-content" ? (
                            <Check className="w-3 h-3 text-[var(--accent-verified)]" />
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Method 2: HTML Meta Tag */}
            <div className="terminal-panel bg-[var(--bg-tertiary)]">
              <div className="flex items-start gap-3 mb-3">
                <Code className="w-5 h-5 text-[var(--accent-info)] flex-shrink-0 mt-1" />
                <div className="flex-1">
                  <h5 className="font-mono font-semibold mb-1">
                    Method 2: HTML Meta Tag
                  </h5>
                  <p className="text-sm text-[var(--text-secondary)] mb-3">
                    Add this meta tag to your HTML {`<head>`}:
                  </p>
                  <div className="bg-black/40 rounded p-3">
                    <div className="flex items-start gap-2">
                      <code className="flex-1 text-[var(--text-primary)] font-mono text-xs break-all">
                        {verificationData.instructions.meta}
                      </code>
                      <button
                        onClick={() =>
                          copyToClipboard(
                            verificationData.instructions.meta,
                            "meta",
                          )
                        }
                        className="p-1 hover:bg-[var(--bg-tertiary)] rounded transition-colors flex-shrink-0"
                        title="Copy meta tag"
                      >
                        {copiedField === "meta" ? (
                          <Check className="w-3 h-3 text-[var(--accent-verified)]" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Method 3: HTTP Header */}
            <div className="terminal-panel bg-[var(--bg-tertiary)]">
              <div className="flex items-start gap-3 mb-3">
                <Globe className="w-5 h-5 text-[var(--accent-info)] flex-shrink-0 mt-1" />
                <div className="flex-1">
                  <h5 className="font-mono font-semibold mb-1">
                    Method 3: HTTP Response Header
                  </h5>
                  <p className="text-sm text-[var(--text-secondary)] mb-3">
                    Add this header to your server responses:
                  </p>
                  <div className="bg-black/40 rounded p-3">
                    <div className="flex items-start gap-2">
                      <code className="flex-1 text-[var(--text-primary)] font-mono text-xs break-all">
                        {verificationData.instructions.header.name}:{" "}
                        {verificationData.instructions.header.value}
                      </code>
                      <button
                        onClick={() =>
                          copyToClipboard(
                            `${verificationData.instructions.header.name}: ${verificationData.instructions.header.value}`,
                            "header",
                          )
                        }
                        className="p-1 hover:bg-[var(--bg-tertiary)] rounded transition-colors flex-shrink-0"
                        title="Copy header"
                      >
                        {copiedField === "header" ? (
                          <Check className="w-3 h-3 text-[var(--accent-verified)]" />
                        ) : (
                          <Copy className="w-3 h-3" />
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-3 pt-4">
            <button
              onClick={verifyToken}
              disabled={verifying || deleting}
              className="btn-primary flex-1"
            >
              {verifying ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="spinner"></div>
                  Verifying...
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <Lock className="w-5 h-5" />
                  Verify Domain Ownership
                </span>
              )}
            </button>

            {showDeleteOption && (
              <button
                onClick={deleteAndRequestNew}
                disabled={deleting || verifying}
                className="px-6 py-3 bg-[var(--accent-warning)]/20 hover:bg-[var(--accent-warning)]/30 border border-[var(--accent-warning)] text-[var(--accent-warning)] rounded-lg font-mono transition-colors"
              >
                {deleting ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="spinner"></div>
                    Requesting...
                  </span>
                ) : (
                  "Request New Token"
                )}
              </button>
            )}

            {onCancel && (
              <button
                onClick={onCancel}
                disabled={verifying || deleting}
                className="px-6 py-3 bg-[var(--bg-tertiary)] hover:bg-[var(--bg-secondary)] rounded-lg font-mono transition-colors"
              >
                Cancel
              </button>
            )}
          </div>

          <div className="flex items-start gap-2 text-xs text-[var(--text-tertiary)] bg-[var(--bg-tertiary)] rounded p-3">
            <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
            <p>
              After deploying the token using any method above, click "Verify
              Domain Ownership" to complete the verification process.
            </p>
          </div>
        </motion.div>
      )}

      {/* Error display at bottom */}
      {error && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="bg-[var(--accent-error)]/10 border border-[var(--accent-error)] rounded-lg p-4 mt-6"
        >
          <div className="flex items-start gap-2">
            <AlertCircle className="w-5 h-5 text-[var(--accent-error)] flex-shrink-0 mt-0.5" />
            <p className="text-[var(--accent-error)] text-sm">{error}</p>
          </div>
        </motion.div>
      )}
    </motion.div>
  );
}
