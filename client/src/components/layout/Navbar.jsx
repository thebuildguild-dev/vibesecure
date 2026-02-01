import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { useNavigate } from "react-router-dom";
import { Radar, LogOut, User, Menu, X } from "lucide-react";
import { useAuth } from "../../context/AuthContext";

export default function Navbar({ showProfile = true }) {
  const navigate = useNavigate();
  const { user, signOut } = useAuth();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  return (
    <motion.header
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-[var(--bg-secondary)]/80 backdrop-blur-sm border-b border-slate-700 sticky top-0 z-30"
    >
      <nav className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 sm:h-20">
          {/* Logo */}
          <button
            onClick={() => navigate("/dashboard")}
            className="flex items-center gap-2 sm:gap-3 hover:opacity-80 transition-opacity"
          >
            <Radar className="w-6 h-6 sm:w-8 sm:h-8 text-[var(--accent-verified)]" />
            <h1 className="text-xl sm:text-2xl lg:text-3xl font-mono font-bold tracking-wider">
              VIBE
              <span className="text-[var(--accent-verified)]">SECURE</span>
            </h1>
          </button>

          {/* Desktop Navigation */}
          {showProfile && user && (
            <div className="hidden sm:flex items-center gap-4">
              {/* Profile Button */}
              <button
                onClick={() => navigate("/profile")}
                className="flex items-center gap-3 px-4 py-2 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || user.email}
                    loading="lazy"
                    referrerPolicy="no-referrer"
                    crossOrigin="anonymous"
                    onError={(e) => {
                      e.target.onerror = null;
                      e.target.style.display = "none";
                      e.target.nextElementSibling.style.display = "flex";
                    }}
                    className="w-8 h-8 sm:w-10 sm:h-10 rounded-full border-2 border-[var(--accent-verified)]"
                  />
                ) : null}
                <div
                  className={`w-8 h-8 sm:w-10 sm:h-10 rounded-full border-2 border-[var(--accent-verified)] bg-[var(--bg-tertiary)] items-center justify-center ${user.photoURL ? "hidden" : "flex"}`}
                >
                  <User className="w-5 h-5 text-[var(--text-tertiary)]" />
                </div>
                <span className="hidden md:block text-sm font-mono text-[var(--text-secondary)]">
                  {user.displayName || user.email}
                </span>
              </button>

              {/* Sign Out Button */}
              <button
                onClick={handleSignOut}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[var(--bg-tertiary)] hover:bg-[var(--accent-error)]/20 hover:text-[var(--accent-error)] transition-colors border border-slate-600 hover:border-[var(--accent-error)]"
              >
                <LogOut className="w-4 h-4" />
                <span className="hidden lg:inline font-mono text-sm">
                  Sign Out
                </span>
              </button>
            </div>
          )}

          {/* Mobile Menu Button */}
          {showProfile && user && (
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="sm:hidden p-2 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
            >
              {mobileMenuOpen ? (
                <X className="w-6 h-6" />
              ) : (
                <Menu className="w-6 h-6" />
              )}
            </button>
          )}
        </div>

        {/* Mobile Menu */}
        <AnimatePresence>
          {mobileMenuOpen && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="sm:hidden border-t border-slate-700 py-4 space-y-3"
            >
              {/* Profile */}
              <button
                onClick={() => {
                  navigate("/profile");
                  setMobileMenuOpen(false);
                }}
                className="w-full flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-[var(--bg-tertiary)] transition-colors"
              >
                {user.photoURL ? (
                  <img
                    src={user.photoURL}
                    alt={user.displayName || user.email}
                    loading="lazy"
                    referrerPolicy="no-referrer"
                    crossOrigin="anonymous"
                    onError={(e) => {
                      e.target.onerror = null;
                      e.target.style.display = "none";
                      e.target.nextElementSibling.style.display = "flex";
                    }}
                    className="w-10 h-10 rounded-full border-2 border-[var(--accent-verified)]"
                  />
                ) : null}
                <div
                  className={`w-10 h-10 rounded-full border-2 border-[var(--accent-verified)] bg-[var(--bg-tertiary)] items-center justify-center ${user.photoURL ? "hidden" : "flex"}`}
                >
                  <User className="w-5 h-5 text-[var(--text-tertiary)]" />
                </div>
                <div className="flex-1 text-left">
                  <div className="text-sm font-mono font-semibold text-[var(--text-primary)]">
                    {user.displayName || "User"}
                  </div>
                  <div className="text-xs font-mono text-[var(--text-tertiary)]">
                    View Profile
                  </div>
                </div>
              </button>

              {/* Sign Out */}
              <button
                onClick={() => {
                  handleSignOut();
                  setMobileMenuOpen(false);
                }}
                className="w-full flex items-center gap-3 px-4 py-3 rounded-lg bg-[var(--accent-error)]/10 text-[var(--accent-error)] hover:bg-[var(--accent-error)]/20 transition-colors border border-[var(--accent-error)]/30"
              >
                <LogOut className="w-5 h-5" />
                <span className="font-mono text-sm font-semibold">
                  Sign Out
                </span>
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </nav>
    </motion.header>
  );
}
