import { useState } from "react";
import { motion } from "framer-motion";
import { Radar, Lock, Zap, Eye, AlertTriangle } from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { Card, Badge } from "../components/ui";
import Footer from "../components/layout/Footer";

export default function Landing() {
  const { signInWithGoogle, loading, error } = useAuth();
  const [isSigningIn, setIsSigningIn] = useState(false);

  const handleGoogleSignIn = async () => {
    setIsSigningIn(true);
    try {
      await signInWithGoogle();
    } catch (err) {
      console.error("Sign-in failed:", err);
    } finally {
      setIsSigningIn(false);
    }
  };

  const features = [
    {
      icon: Radar,
      title: "Domain Verification Required",
      description: "Prove ownership before scanning with DNS/file verification",
      color: "var(--accent-verified)",
    },
    {
      icon: Lock,
      title: "Consent-Based Active Testing",
      description:
        "Explicit opt-in required for intrusive vulnerability checks",
      color: "var(--accent-warning)",
    },
    {
      icon: Zap,
      title: "AI-Powered Analysis",
      description:
        "Google Gemini AI provides intelligent vulnerability summaries",
      color: "var(--accent-info)",
    },
    {
      icon: Eye,
      title: "Actionable Security Reports",
      description: "Detailed findings with step-by-step remediation guidance",
      color: "var(--text-link)",
    },
  ];

  return (
    <div className="min-h-screen bg-[var(--bg-primary)] relative overflow-hidden">
      {/* Grid overlay */}
      <div className="grid-overlay" />

      {/* Radial bloom */}
      <div className="radial-bloom" />

      {/* Main content */}
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-4 sm:px-6 lg:px-8 py-8 sm:py-12">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="max-w-5xl mx-auto text-center w-full"
        >
          {/* Logo + Title */}
          <motion.div
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="mb-6 sm:mb-8"
          >
            <div className="flex items-center justify-center gap-2 sm:gap-3 mb-3 sm:mb-4">
              <Radar
                className="w-12 h-12 sm:w-14 sm:h-14 lg:w-16 lg:h-16 text-[var(--accent-verified)]"
                strokeWidth={1.5}
              />
            </div>
            <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold font-display text-[var(--text-primary)] mb-2 sm:mb-3 tracking-tight">
              Vibe<span className="text-[var(--accent-verified)]">Secure</span>
            </h1>
            <p className="text-base sm:text-lg lg:text-xl text-[var(--text-secondary)] font-mono px-4">
              Owner-authorized web security scanner with ethical constraints
            </p>
          </motion.div>

          {/* Security badge */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.3 }}
            className="mb-8 sm:mb-12 flex justify-center"
          >
            <Badge
              variant="verified"
              size="lg"
              className="text-xs sm:text-sm gap-2"
            >
              <Lock className="w-3 h-3 sm:w-4 sm:h-4" />
              <span className="hidden sm:inline">
                Domain verification required • Consent-gated active scans
              </span>
              <span className="sm:hidden">Verified & Ethical</span>
            </Badge>
          </motion.div>
          {/* Sign-in button */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="mb-12 sm:mb-16"
          >
            <button
              onClick={handleGoogleSignIn}
              disabled={isSigningIn || loading}
              className="group relative overflow-hidden mx-auto w-full sm:w-auto
                       border-2 border-[var(--accent-verified)] rounded-xl
                       transform hover:scale-[1.02] transition-all duration-300
                       disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100
                       shadow-[0_0_30px_rgba(0,255,136,0.3)] hover:shadow-[0_0_50px_rgba(0,255,136,0.5)]"
            >
              {/* Animated gradient background */}
              <div
                className="absolute inset-0 bg-gradient-to-r from-[var(--accent-verified)] via-[var(--accent-info)] to-[var(--accent-verified)] 
                            bg-[length:200%_100%] animate-[shimmer_3s_ease-in-out_infinite]
                            opacity-20 group-hover:opacity-30 transition-opacity"
              />

              {/* Glow effect */}
              <div
                className="absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity duration-500
                            bg-[radial-gradient(circle_at_center,_var(--accent-verified)_0%,_transparent_70%)]
                            blur-xl scale-150"
              />

              {/* Button content */}
              <div
                className="relative px-6 sm:px-10 py-4 sm:py-5 flex items-center justify-center gap-3 sm:gap-4 
                            bg-gradient-to-br from-slate-900 to-slate-800"
              >
                {/* Google icon with animated border */}
                <div className="relative flex-shrink-0">
                  <div className="absolute inset-0 bg-white rounded-full blur-sm opacity-50 group-hover:opacity-75 transition-opacity" />
                  <div className="relative bg-white rounded-full p-1.5 sm:p-2">
                    <svg className="w-5 h-5 sm:w-6 sm:h-6" viewBox="0 0 24 24">
                      <path
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                        fill="#4285F4"
                      />
                      <path
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                        fill="#34A853"
                      />
                      <path
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                        fill="#FBBC05"
                      />
                      <path
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                        fill="#EA4335"
                      />
                    </svg>
                  </div>
                </div>

                {/* Text */}
                <span
                  className="text-base sm:text-lg lg:text-xl font-bold tracking-wide text-white font-mono
                               group-hover:text-[var(--accent-verified)] transition-colors duration-300"
                >
                  {isSigningIn ? (
                    <span className="inline-flex items-center gap-1">
                      <span className="inline-block animate-pulse">
                        Authenticating
                      </span>
                      <span className="inline-block animate-[pulse_1s_ease-in-out_0.2s_infinite]">
                        .
                      </span>
                      <span className="inline-block animate-[pulse_1s_ease-in-out_0.4s_infinite]">
                        .
                      </span>
                      <span className="inline-block animate-[pulse_1s_ease-in-out_0.6s_infinite]">
                        .
                      </span>
                    </span>
                  ) : (
                    <>
                      <span className="hidden sm:inline">
                        Launch Security Console
                      </span>
                      <span className="sm:hidden">Get Started</span>
                    </>
                  )}
                </span>

                {/* Arrow indicator */}
                {!isSigningIn && (
                  <motion.div
                    className="text-[var(--accent-verified)] hidden sm:block"
                    animate={{ x: [0, 5, 0] }}
                    transition={{
                      duration: 1.5,
                      repeat: Infinity,
                      ease: "easeInOut",
                    }}
                  >
                    <svg width="20" height="20" viewBox="0 0 20 20" fill="none">
                      <path
                        d="M4 10h12m-6-6l6 6-6 6"
                        stroke="currentColor"
                        strokeWidth="2"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                      />
                    </svg>
                  </motion.div>
                )}
              </div>
            </button>

            {/* Subtitle */}
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.6 }}
              className="mt-3 sm:mt-4 text-xs sm:text-sm text-[var(--text-tertiary)] font-mono flex items-center justify-center gap-2 px-4"
            >
              <Lock className="w-3 h-3 sm:w-4 sm:h-4 flex-shrink-0 mt-0.5 sm:mt-0" />
              <span className="text-center sm:text-left">
                <span className="hidden sm:inline">
                  Authenticate with Google to access the scanner
                </span>
                <span className="sm:hidden">Authenticate with Google</span>
              </span>
            </motion.p>

            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mt-4 mx-4 sm:mx-0 px-4 py-3 bg-red-500/10 border border-red-500/30 
                         rounded-lg text-red-400 text-sm font-mono"
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  <span className="break-words">{error}</span>
                </div>
              </motion.div>
            )}
          </motion.div>

          {/* Features grid */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.5 }}
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6 mb-12 sm:mb-16 px-2"
          >
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.6 + index * 0.1 }}
              >
                <Card hover className="text-left h-full">
                  <feature.icon
                    className="w-7 h-7 sm:w-8 sm:h-8 mb-3 sm:mb-4"
                    style={{ color: feature.color }}
                    strokeWidth={1.5}
                  />
                  <h3 className="text-base sm:text-lg font-semibold text-[var(--text-primary)] mb-2 font-display">
                    {feature.title}
                  </h3>
                  <p className="text-xs sm:text-sm text-[var(--text-tertiary)] font-mono leading-relaxed">
                    {feature.description}
                  </p>
                </Card>
              </motion.div>
            ))}
          </motion.div>

          {/* Footer info */}
        </motion.div>
      </div>

      {/* Footer */}
      <Footer />
    </div>
  );
}
