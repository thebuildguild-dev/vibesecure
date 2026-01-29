import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Copy, Check, Lock, FileText, Code, Globe } from "lucide-react";

export default function DomainVerificationModal({
  domain,
  onClose,
  onVerified,
}) {
  const [verificationData, setVerificationData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState(null);
  const [copiedField, setCopiedField] = useState(null);
  const [verificationSuccess, setVerificationSuccess] = useState(false);

  const requestToken = async () => {
    setLoading(true);
    setError(null);
    try {
      const { domains } = await import("../api/client");
      const data = await domains.requestVerification(domain);
      setVerificationData(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const verifyToken = async () => {
    setVerifying(true);
    setError(null);
    try {
      const { domains } = await import("../api/client");
      const result = await domains.checkVerification(domain);

      if (result.verified) {
        setVerificationSuccess(true);
        setTimeout(() => {
          onVerified && onVerified();
          onClose();
        }, 2000);
      } else {
        setError(
          result.details ||
            "Verification failed. Please check token placement.",
        );
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setVerifying(false);
    }
  };

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  useState(() => {
    if (!verificationData) {
      requestToken();
    }
  }, []);

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="modal-backdrop"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0, y: 20 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.9, opacity: 0, y: 20 }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="modal-content"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Success overlay */}
          {verificationSuccess && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="absolute inset-0 bg-[var(--accent-verified)]/10 backdrop-blur-sm z-50 flex items-center justify-center rounded-lg"
            >
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", damping: 15 }}
                className="text-center"
              >
                <Lock className="w-24 h-24 text-[var(--accent-verified)] mx-auto mb-4" />
                <h2 className="text-3xl font-mono font-bold text-[var(--accent-verified)] mb-2">
                  Domain Verified!
                </h2>
                <p className="text-[var(--text-secondary)]">
                  Authorization granted
                </p>
              </motion.div>
            </motion.div>
          )}

          {/* Header */}
          <div className="flex items-start justify-between mb-6 border-b border-slate-700 pb-4">
            <div>
              <h2 className="text-2xl font-mono font-bold text-[var(--accent-verified)] mb-2">
                Domain Ownership Verification
              </h2>
              <p className="text-[var(--text-secondary)] text-sm">
                Prove ownership of{" "}
                <span className="text-[var(--accent-info)] font-mono">
                  {domain}
                </span>
              </p>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-[var(--bg-tertiary)] rounded-lg transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Content */}
          {loading && (
            <div className="text-center py-12">
              <div className="spinner mx-auto mb-4"></div>
              <p className="text-[var(--text-secondary)]">
                Generating verification token...
              </p>
            </div>
          )}

          {error && (
            <div className="bg-[var(--accent-error)]/10 border border-[var(--accent-error)] rounded-lg p-4 mb-6">
              <p className="text-[var(--accent-error)] text-sm">{error}</p>
            </div>
          )}

          {verificationData && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="space-y-6"
            >
              {/* Token display */}
              <div className="terminal-panel">
                <h3 className="text-sm font-mono text-[var(--text-secondary)] mb-2 uppercase tracking-wider">
                  Your Verification Token
                </h3>
                <div className="flex items-center gap-2 mb-2">
                  <code className="flex-1 bg-black/40 px-3 py-2 rounded text-[var(--accent-verified)] font-mono text-sm">
                    {verificationData.token}
                  </code>
                  <button
                    onClick={() =>
                      copyToClipboard(verificationData.token, "token")
                    }
                    className="p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors"
                  >
                    {copiedField === "token" ? (
                      <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
                <p className="text-xs text-[var(--text-tertiary)]">
                  Expires:{" "}
                  {new Date(verificationData.expires_at).toLocaleString()}
                </p>
              </div>

              {/* Verification methods */}
              <div className="space-y-4">
                <h3 className="text-lg font-mono font-semibold">
                  Choose Verification Method
                </h3>

                {/* Method 1: File */}
                <motion.div
                  whileHover={{ scale: 1.01 }}
                  className="terminal-panel border-l-4 border-l-[var(--accent-verified)]"
                >
                  <div className="flex items-start gap-3 mb-3">
                    <FileText className="w-5 h-5 text-[var(--accent-verified)] flex-shrink-0 mt-1" />
                    <div className="flex-1">
                      <h4 className="font-mono font-semibold mb-1">
                        Method 1: File Verification (Recommended)
                      </h4>
                      <p className="text-sm text-[var(--text-secondary)] mb-3">
                        Create a file at the following path:
                      </p>
                      <div className="code-block mb-2">
                        {verificationData.instructions.file.path}
                      </div>
                      <p className="text-sm text-[var(--text-secondary)] mb-2">
                        With content:
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 bg-black/40 px-3 py-2 rounded text-[var(--accent-verified)] font-mono text-xs">
                          {verificationData.instructions.file.content}
                        </code>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              verificationData.instructions.file.content,
                              "file",
                            )
                          }
                          className="p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors"
                        >
                          {copiedField === "file" ? (
                            <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>

                {/* Method 2: Meta tag */}
                <motion.div
                  whileHover={{ scale: 1.01 }}
                  className="terminal-panel border-l-4 border-l-[var(--accent-info)]"
                >
                  <div className="flex items-start gap-3 mb-3">
                    <Code className="w-5 h-5 text-[var(--accent-info)] flex-shrink-0 mt-1" />
                    <div className="flex-1">
                      <h4 className="font-mono font-semibold mb-1">
                        Method 2: HTML Meta Tag
                      </h4>
                      <p className="text-sm text-[var(--text-secondary)] mb-3">
                        Add this meta tag to your HTML {"<head>"}:
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 bg-black/40 px-3 py-2 rounded text-[var(--accent-info)] font-mono text-xs overflow-x-auto">
                          {verificationData.instructions.meta}
                        </code>
                        <button
                          onClick={() =>
                            copyToClipboard(
                              verificationData.instructions.meta,
                              "meta",
                            )
                          }
                          className="p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors"
                        >
                          {copiedField === "meta" ? (
                            <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>

                {/* Method 3: Header */}
                <motion.div
                  whileHover={{ scale: 1.01 }}
                  className="terminal-panel border-l-4 border-l-[var(--accent-warning)]"
                >
                  <div className="flex items-start gap-3 mb-3">
                    <Globe className="w-5 h-5 text-[var(--accent-warning)] flex-shrink-0 mt-1" />
                    <div className="flex-1">
                      <h4 className="font-mono font-semibold mb-1">
                        Method 3: HTTP Header
                      </h4>
                      <p className="text-sm text-[var(--text-secondary)] mb-3">
                        Add this response header to your server:
                      </p>
                      <div className="flex items-center gap-2 mb-2">
                        <code className="flex-1 bg-black/40 px-3 py-2 rounded text-[var(--accent-warning)] font-mono text-xs">
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
                          className="p-2 hover:bg-[var(--bg-tertiary)] rounded transition-colors"
                        >
                          {copiedField === "header" ? (
                            <Check className="w-4 h-4 text-[var(--accent-verified)]" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  </div>
                </motion.div>
              </div>

              {/* Action buttons */}
              <div className="flex gap-3 pt-4 border-t border-slate-700">
                <button
                  onClick={verifyToken}
                  disabled={verifying}
                  className="btn-primary flex-1 flex items-center justify-center gap-2"
                >
                  {verifying ? (
                    <>
                      <div className="spinner"></div>
                      Verifying...
                    </>
                  ) : (
                    <>
                      <Lock className="w-5 h-5" />
                      Verify Now
                    </>
                  )}
                </button>
                <button onClick={onClose} className="btn-secondary">
                  Cancel
                </button>
              </div>
            </motion.div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
