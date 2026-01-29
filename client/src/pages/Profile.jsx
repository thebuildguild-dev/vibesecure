import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  User,
  Mail,
  CheckCircle,
  XCircle,
  Key,
  LogOut,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { auth as authAPI } from "../api/client";
import { MainLayout } from "../components/layout";
import { Card, Button, Badge, SectionTitle } from "../components/ui";

export default function Profile() {
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const [imageLoaded, setImageLoaded] = useState(false);
  const [imageError, setImageError] = useState(false);

  return (
    <MainLayout>
      <div className="max-w-4xl mx-auto">
        {/* Profile Card */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
        >
          <Card variant="elevated">
            <div className="flex flex-col sm:flex-row items-start gap-4 sm:gap-6">
              {/* Profile Picture */}
              <div className="flex-shrink-0 mx-auto sm:mx-0">
                {!imageError && user?.photoURL ? (
                  <img
                    src={user?.photoURL}
                    alt={user?.displayName || "User"}
                    onLoad={() => setImageLoaded(true)}
                    onError={() => {
                      setImageError(true);
                      setImageLoaded(true);
                    }}
                    loading="eager"
                    referrerPolicy="no-referrer"
                    crossOrigin="anonymous"
                    className={`w-24 h-24 sm:w-32 sm:h-32 rounded-full border-4 border-[var(--accent-verified)] 
                           shadow-[0_0_30px_rgba(0,255,136,0.3)] ${!imageLoaded ? "opacity-0" : "opacity-100"} transition-opacity`}
                  />
                ) : null}
                <div
                  className={`fallback-avatar w-24 h-24 sm:w-32 sm:h-32 rounded-full border-4 border-[var(--accent-verified)] 
                              bg-[var(--bg-tertiary)] items-center justify-center ${
                                !imageError && user?.photoURL
                                  ? "hidden"
                                  : "flex"
                              }`}
                >
                  <User className="w-12 h-12 sm:w-16 sm:h-16 text-[var(--text-tertiary)]" />
                </div>
              </div>

              {/* Profile Info */}
              <div className="flex-1 w-full space-y-4 sm:space-y-6">
                <div>
                  <SectionTitle className="mb-2">
                    <span className="text-xl sm:text-2xl lg:text-3xl">
                      Profile
                    </span>
                  </SectionTitle>
                  <p className="text-[var(--text-tertiary)] font-mono text-xs sm:text-sm">
                    Your VibeSecure account information
                  </p>
                </div>

                {/* Details Grid */}
                <div className="space-y-3 sm:space-y-4">
                  {/* Name */}
                  <div className="flex items-start gap-3 sm:gap-4 p-3 sm:p-4 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                    <User className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-info)] mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-[var(--text-tertiary)] font-mono mb-1">
                        DISPLAY NAME
                      </div>
                      <div className="text-[var(--text-primary)] font-mono text-sm sm:text-base break-words">
                        {user?.displayName || "Not provided"}
                      </div>
                    </div>
                  </div>

                  {/* Email */}
                  <div className="flex items-start gap-3 sm:gap-4 p-3 sm:p-4 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                    <Mail className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-info)] mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-[var(--text-tertiary)] font-mono mb-1">
                        EMAIL ADDRESS
                      </div>
                      <div className="text-[var(--text-primary)] font-mono text-sm sm:text-base break-all flex flex-col sm:flex-row sm:items-center gap-2">
                        <span>{user?.email}</span>
                        {user?.emailVerified ? (
                          <Badge variant="verified" size="sm">
                            <CheckCircle className="w-3 h-3" />
                            Verified
                          </Badge>
                        ) : (
                          <Badge variant="warning" size="sm">
                            <XCircle className="w-3 h-3" />
                            Not Verified
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* User ID */}
                  <div className="flex items-start gap-3 sm:gap-4 p-3 sm:p-4 bg-[var(--bg-tertiary)] rounded-lg border border-slate-700">
                    <Key className="w-4 h-4 sm:w-5 sm:h-5 text-[var(--accent-info)] mt-0.5 flex-shrink-0" />
                    <div className="flex-1 min-w-0">
                      <div className="text-xs text-[var(--text-tertiary)] font-mono mb-1">
                        USER ID
                      </div>
                      <div className="text-[var(--text-primary)] font-mono text-xs sm:text-sm break-all">
                        {user?.uid}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex flex-col sm:flex-row gap-3 pt-2 sm:pt-4">
                  <Button
                    onClick={() => navigate("/dashboard")}
                    variant="primary"
                    icon={<Shield className="w-4 h-4" />}
                    fullWidth
                    className="sm:flex-1"
                  >
                    <span className="hidden sm:inline">Back to Dashboard</span>
                    <span className="sm:hidden">Dashboard</span>
                  </Button>
                  <Button
                    onClick={() => signOut()}
                    variant="secondary"
                    icon={<LogOut className="w-4 h-4" />}
                    fullWidth
                    className="sm:flex-1"
                  >
                    Sign Out
                  </Button>
                </div>
              </div>
            </div>
          </Card>
        </motion.div>

        {/* Security Info */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="mt-4 sm:mt-6"
        >
          <Card>
            <div className="flex flex-col sm:flex-row items-start gap-3 sm:gap-4">
              <Shield className="w-5 h-5 text-[var(--accent-verified)] mt-1 flex-shrink-0" />
              <div className="flex-1">
                <h3 className="text-base sm:text-lg font-semibold text-[var(--text-primary)] mb-2 font-display">
                  Authentication Provider
                </h3>
                <p className="text-xs sm:text-sm text-[var(--text-tertiary)] font-mono mb-3 sm:mb-4">
                  Your account is secured with Google Firebase Authentication.
                  All tokens are automatically refreshed and secured.
                </p>
                <div className="flex items-center gap-2 text-xs text-[var(--text-tertiary)] font-mono">
                  <CheckCircle className="w-4 h-4 text-[var(--accent-verified)] flex-shrink-0" />
                  <span>End-to-end encrypted authentication</span>
                </div>
              </div>
            </div>
          </Card>
        </motion.div>
      </div>
    </MainLayout>
  );
}
