import { useState } from "react";
import { motion } from "framer-motion";
import {
  Target,
  Lock,
  Shield,
  AlertCircle,
  ChevronDown,
  ChevronUp,
  Settings,
} from "lucide-react";
import DomainVerificationInline from "./DomainVerificationInline";
import ConsentInline from "./ConsentInline";

export default function ScanForm({ onScanCreated }) {
  const [url, setUrl] = useState("");
  const [description, setDescription] = useState("");
  const [allowActive, setAllowActive] = useState(false);
  const [ignoreRobots, setIgnoreRobots] = useState(false);
  const [renderJs, setRenderJs] = useState(false);
  const [checkReflections, setCheckReflections] = useState(false);
  const [wordlistProfile, setWordlistProfile] = useState("default");
  const [useAuth, setUseAuth] = useState(false);
  const [authType, setAuthType] = useState("bearer");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authToken, setAuthToken] = useState("");
  const [authCookie, setAuthCookie] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showVerification, setShowVerification] = useState(false);
  const [showConsentModal, setShowConsentModal] = useState(false);
  const [pendingDomain, setPendingDomain] = useState(null);

  const extractDomain = (urlString) => {
    try {
      const urlObj = new URL(
        urlString.startsWith("http") ? urlString : `https://${urlString}`,
      );
      if (urlObj.port) {
        return `${urlObj.hostname}:${urlObj.port}`;
      }
      return urlObj.hostname;
    } catch {
      return null;
    }
  };

  const checkDomainVerification = async (domain) => {
    const { domains, APIError } = await import("../api/client");
    try {
      const status = await domains.getStatus(domain);
      return status.verified;
    } catch (err) {
      if (
        err instanceof APIError &&
        err.errorType === "domain_verification_required"
      ) {
        return false;
      }
      throw err;
    }
  };

  const checkActiveConsent = async (domain) => {
    const { consent, APIError } = await import("../api/client");
    try {
      const status = await consent.getStatus(domain);
      return status.active_consent_verified;
    } catch (err) {
      if (
        err instanceof APIError &&
        err.errorType === "active_consent_required"
      ) {
        return false;
      }
      throw err;
    }
  };

  const handleActiveScanToggle = async (checked) => {
    if (!checked) {
      setAllowActive(false);
      return;
    }

    const domain = extractDomain(url);
    if (!domain) {
      setError("Please enter a valid URL first");
      return;
    }

    setError(null);
    setLoading(true);

    try {
      const isVerified = await checkDomainVerification(domain);
      if (!isVerified) {
        setError("Domain must be verified before enabling active scanning");
        setLoading(false);
        return;
      }

      const hasConsent = await checkActiveConsent(domain);
      if (!hasConsent) {
        setPendingDomain(domain);
        setShowConsentModal(true);
      } else {
        setAllowActive(true);
      }
    } catch (err) {
      setError(err.message || "Failed to verify domain");
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);

    const domain = extractDomain(url);
    if (!domain) {
      setError("Please enter a valid URL");
      return;
    }

    setLoading(true);

    try {
      const isVerified = await checkDomainVerification(domain);
      if (!isVerified) {
        setPendingDomain(domain);
        setShowVerification(true);
        setLoading(false);
        return;
      }

      if (allowActive) {
        const hasConsent = await checkActiveConsent(domain);
        if (!hasConsent) {
          setPendingDomain(domain);
          setShowConsentModal(true);
          setLoading(false);
          return;
        }
      }

      const options = {};

      if (allowActive) options.allow_active = true;
      if (ignoreRobots) options.ignore_robots = true;
      if (renderJs) options.render_js = true;
      if (checkReflections) options.check_reflections = true;
      if (wordlistProfile !== "default")
        options.wordlist_profile = wordlistProfile;

      if (useAuth) {
        options.auth = { type: authType };
        if (authType === "basic") {
          options.auth.username = authUsername;
          options.auth.password = authPassword;
        } else if (authType === "bearer") {
          options.auth.token = authToken;
        } else if (authType === "cookie") {
          options.auth.cookie = authCookie;
        }
      }

      const { scans } = await import("../api/client");
      const scan = await scans.create(
        url,
        description || null,
        Object.keys(options).length > 0 ? options : null,
      );

      setUrl("");
      setDescription("");
      setAllowActive(false);
      setIgnoreRobots(false);
      setRenderJs(false);
      setCheckReflections(false);
      setWordlistProfile("default");
      setUseAuth(false);
      setAuthType("bearer");
      setAuthUsername("");
      setAuthPassword("");
      setAuthToken("");
      setAuthCookie("");
      setShowAdvanced(false);

      if (onScanCreated) {
        onScanCreated(scan);
      }
    } catch (err) {
      setError(err.message || "Failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      {/* Domain Verification Section */}
      {showVerification && pendingDomain && (
        <DomainVerificationInline
          domain={pendingDomain}
          onVerified={() => {
            setShowVerification(false);
            setTimeout(() => {
              handleSubmit({ preventDefault: () => {} });
              if (onScanCreated) {
                onScanCreated(false);
              }
            }, 500);
          }}
          onCancel={() => {
            setShowVerification(false);
            setPendingDomain(null);
            setLoading(false);
          }}
        />
      )}

      {/* Active Consent Section */}
      {showConsentModal && pendingDomain && (
        <ConsentInline
          domain={pendingDomain}
          onConsentVerified={() => {
            setShowConsentModal(false);
            setAllowActive(true);
          }}
          onCancel={() => {
            setShowConsentModal(false);
            setPendingDomain(null);
            setAllowActive(false);
            setLoading(false);
          }}
        />
      )}

      {/* Scan Form */}
      {!showVerification && !showConsentModal && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="terminal-panel-elevated"
        >
          <div className="mb-6">
            <div className="flex items-center gap-3 mb-2">
              <Target className="w-6 h-6 text-[var(--accent-verified)]" />
              <h2 className="text-2xl font-mono font-bold">
                Initialize Security Scan
              </h2>
            </div>
            <p className="text-sm text-[var(--text-secondary)]">
              Enter a target URL to begin comprehensive security analysis
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* URL Input */}
            <div>
              <label className="block text-sm font-mono text-[var(--text-secondary)] mb-2 uppercase tracking-wider">
                Target URL
              </label>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="https://example.com"
                className="input-field"
                required
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-mono text-[var(--text-secondary)] mb-2 uppercase tracking-wider">
                Description (Optional)
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Production security audit"
                className="input-field"
              />
            </div>

            {/* Scan Options Header */}
            <div className="border-t border-slate-700 pt-6">
              <button
                type="button"
                onClick={() => setShowAdvanced(!showAdvanced)}
                className="flex items-center justify-between w-full mb-4 text-left hover:text-[var(--accent-info)] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Settings className="w-5 h-5 text-[var(--accent-info)]" />
                  <h3 className="text-lg font-mono font-semibold">
                    Scan Options
                  </h3>
                </div>
                {showAdvanced ? (
                  <ChevronUp className="w-5 h-5" />
                ) : (
                  <ChevronDown className="w-5 h-5" />
                )}
              </button>

              {showAdvanced && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  className="space-y-4"
                >
                  {/* Active Scanning */}
                  <div className="p-4 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                    <div className="flex items-start gap-4">
                      <input
                        type="checkbox"
                        id="allowActive"
                        checked={allowActive}
                        onChange={(e) =>
                          handleActiveScanToggle(e.target.checked)
                        }
                        disabled={loading}
                        className="mt-1 w-5 h-5 appearance-none rounded-sm bg-[var(--bg-primary)] border border-[var(--accent-warning)] 
                               checked:bg-[var(--accent-warning)] checked:shadow-[0_0_8px_var(--accent-warning-glow)] transition-all cursor-pointer"
                      />
                      <div className="flex-1">
                        <label
                          htmlFor="allowActive"
                          className="font-mono font-semibold text-[var(--accent-warning)] cursor-pointer flex items-center gap-2 mb-1"
                        >
                          <Shield className="w-4 h-4" />
                          Enable Active Scanning (OWASP ZAP)
                        </label>
                        <p className="text-xs text-[var(--text-tertiary)]">
                          Performs invasive vulnerability testing (XSS, SQL
                          injection, etc.). Requires explicit consent.
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Other Options */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Render JS */}
                    <div className="flex items-start gap-3 p-3 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                      <input
                        type="checkbox"
                        id="renderJs"
                        checked={renderJs}
                        onChange={(e) => setRenderJs(e.target.checked)}
                        className="mt-1 w-4 h-4 appearance-none rounded-sm bg-[var(--bg-primary)] border border-slate-600 checked:bg-[var(--accent-verified)] checked:shadow-[0_0_5px_var(--accent-verified-glow)] transition-all cursor-pointer"
                      />
                      <div className="flex-1">
                        <label
                          htmlFor="renderJs"
                          className="font-mono font-semibold text-sm cursor-pointer"
                        >
                          JavaScript Rendering
                        </label>
                        <p className="text-xs text-[var(--text-tertiary)] mt-1">
                          Use headless browser (Playwright) for SPA apps
                        </p>
                      </div>
                    </div>

                    {/* Check Reflections */}
                    <div className="flex items-start gap-3 p-3 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                      <input
                        type="checkbox"
                        id="checkReflections"
                        checked={checkReflections}
                        onChange={(e) => setCheckReflections(e.target.checked)}
                        className="mt-1 w-4 h-4 appearance-none rounded-sm bg-[var(--bg-primary)] border border-slate-600 checked:bg-[var(--accent-verified)] checked:shadow-[0_0_5px_var(--accent-verified-glow)] transition-all cursor-pointer"
                      />
                      <div className="flex-1">
                        <label
                          htmlFor="checkReflections"
                          className="font-mono font-semibold text-sm cursor-pointer"
                        >
                          Parameter Reflection
                        </label>
                        <p className="text-xs text-[var(--text-tertiary)] mt-1">
                          Detect potential XSS via parameter reflection
                        </p>
                      </div>
                    </div>

                    {/* Ignore Robots */}
                    <div className="flex items-start gap-3 p-3 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                      <input
                        type="checkbox"
                        id="ignoreRobots"
                        checked={ignoreRobots}
                        onChange={(e) => setIgnoreRobots(e.target.checked)}
                        className="mt-1 w-4 h-4 appearance-none rounded-sm bg-[var(--bg-primary)] border border-slate-600 checked:bg-[var(--accent-verified)] checked:shadow-[0_0_5px_var(--accent-verified-glow)] transition-all cursor-pointer"
                      />
                      <div className="flex-1">
                        <label
                          htmlFor="ignoreRobots"
                          className="font-mono font-semibold text-sm cursor-pointer"
                        >
                          Ignore robots.txt
                        </label>
                        <p className="text-xs text-[var(--text-tertiary)] mt-1">
                          Bypass robots.txt restrictions
                        </p>
                      </div>
                    </div>

                    {/* Wordlist Profile */}
                    <div className="p-3 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                      <label
                        htmlFor="wordlistProfile"
                        className="font-mono font-semibold text-sm block mb-2"
                      >
                        Discovery Profile
                      </label>
                      <select
                        id="wordlistProfile"
                        value={wordlistProfile}
                        onChange={(e) => setWordlistProfile(e.target.value)}
                        className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] border border-slate-600 rounded-sm px-3 py-2 text-sm font-mono focus:border-[var(--accent-info)] focus:outline-none transition-colors"
                      >
                        <option value="minimal">Minimal (4 paths)</option>
                        <option value="default">Default (10 paths)</option>
                        <option value="deep">Deep (18+ paths)</option>
                      </select>
                      <p className="text-xs text-[var(--text-tertiary)] mt-1">
                        Hidden file and endpoint discovery intensity
                      </p>
                    </div>
                  </div>

                  {/* Authentication Options */}
                  <div className="p-4 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                    <div className="flex items-center gap-3 mb-4">
                      <input
                        type="checkbox"
                        id="useAuth"
                        checked={useAuth}
                        onChange={(e) => setUseAuth(e.target.checked)}
                        className="w-5 h-5 appearance-none rounded-sm bg-[var(--bg-primary)] border border-slate-600 checked:bg-[var(--accent-verified)] checked:shadow-[0_0_5px_var(--accent-verified-glow)] transition-all cursor-pointer"
                      />
                      <label
                        htmlFor="useAuth"
                        className="font-mono font-semibold cursor-pointer"
                      >
                        Authentication
                      </label>
                    </div>

                    {useAuth && (
                      <motion.div
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: "auto" }}
                        className="space-y-3 pl-7"
                      >
                        <div>
                          <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1">
                            Auth Type
                          </label>
                          <select
                            value={authType}
                            onChange={(e) => setAuthType(e.target.value)}
                            className="w-full bg-[var(--bg-tertiary)] text-[var(--text-primary)] border border-slate-600 rounded-sm px-3 py-2 text-sm font-mono focus:border-[var(--accent-info)] focus:outline-none transition-colors"
                          >
                            <option value="bearer">Bearer Token</option>
                            <option value="basic">HTTP Basic Auth</option>
                            <option value="cookie">Cookie-Based</option>
                          </select>
                        </div>

                        {authType === "basic" && (
                          <>
                            <div>
                              <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1">
                                Username
                              </label>
                              <input
                                type="text"
                                value={authUsername}
                                onChange={(e) =>
                                  setAuthUsername(e.target.value)
                                }
                                className="input-field text-sm"
                                placeholder="admin"
                              />
                            </div>
                            <div>
                              <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1">
                                Password
                              </label>
                              <input
                                type="password"
                                value={authPassword}
                                onChange={(e) =>
                                  setAuthPassword(e.target.value)
                                }
                                className="input-field text-sm"
                                placeholder="••••••••"
                              />
                            </div>
                          </>
                        )}

                        {authType === "bearer" && (
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1">
                              Bearer Token
                            </label>
                            <input
                              type="text"
                              value={authToken}
                              onChange={(e) => setAuthToken(e.target.value)}
                              className="input-field text-sm font-mono"
                              placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6..."
                            />
                          </div>
                        )}

                        {authType === "cookie" && (
                          <div>
                            <label className="block text-xs font-mono text-[var(--text-secondary)] mb-1">
                              Cookie String
                            </label>
                            <input
                              type="text"
                              value={authCookie}
                              onChange={(e) => setAuthCookie(e.target.value)}
                              className="input-field text-sm font-mono"
                              placeholder="session=abc123; token=xyz789"
                            />
                          </div>
                        )}
                      </motion.div>
                    )}
                  </div>
                </motion.div>
              )}
            </div>

            {/* Submit button */}
            <button
              type="submit"
              disabled={loading || !url}
              className="btn-primary w-full"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="spinner"></div>
                  Initializing...
                </span>
              ) : (
                <span className="flex items-center justify-center gap-2">
                  <Lock className="w-5 h-5" />
                  Start Authorized Scan
                </span>
              )}
            </button>

            {/* Error */}
            {error && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                className="bg-[var(--accent-error)]/10 border border-[var(--accent-error)] rounded-lg p-4 mt-4"
              >
                <div className="flex items-start gap-2">
                  <AlertCircle className="w-5 h-5 text-[var(--accent-error)] flex-shrink-0 mt-0.5" />
                  <p className="text-[var(--accent-error)] text-sm">{error}</p>
                </div>
              </motion.div>
            )}
          </form>

          {/* Authorization info */}
          <div className="mt-6 pt-6 border-t border-slate-700">
            <div className="flex items-start gap-2 text-xs text-[var(--text-tertiary)]">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <p>
                All scans require domain ownership verification. Active scans
                require additional explicit consent. Verification will appear
                inline if needed.
              </p>
            </div>
          </div>
        </motion.div>
      )}
    </>
  );
}
