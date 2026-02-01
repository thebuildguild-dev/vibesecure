import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  Lock,
  ScanLine,
  Clock,
  CheckCircle,
  AlertCircle,
  ChevronRight,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import ScanForm from "../components/ScanForm";
import { MainLayout } from "../components/layout";
import { Card, Badge, SectionTitle } from "../components/ui";

export default function Dashboard() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [domains, setDomains] = useState([]);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      const { domains: domainsAPI, scans: scansAPI } =
        await import("../api/client");
      const [domainsData, scansData] = await Promise.all([
        domainsAPI.list(),
        scansAPI.list(0, 10),
      ]);
      if (Array.isArray(scansData)) {
        scansData.sort(
          (a, b) => new Date(b.created_at) - new Date(a.created_at),
        );
      }
      setDomains(domainsData);
      setScans(scansData);
    } catch (err) {
      console.error("Failed to load dashboard:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleScanCreated = (scan) => {
    if (scan === false) {
      loadDashboardData();
      return;
    }
    navigate(`/scan/${scan.id}`);
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case "done":
        return (
          <CheckCircle className="w-4 h-4 text-[var(--accent-verified)]" />
        );
      case "running":
        return (
          <Clock className="w-4 h-4 text-[var(--accent-info)] animate-pulse" />
        );
      case "failed":
        return <AlertCircle className="w-4 h-4 text-[var(--accent-error)]" />;
      default:
        return <Clock className="w-4 h-4 text-[var(--text-tertiary)]" />;
    }
  };

  const getStatusBadge = (status) => {
    const statusMap = {
      done: "verified",
      running: "info",
      failed: "error",
      queued: "warning",
    };
    return statusMap[status] || "default";
  };

  return (
    <MainLayout>
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-6">
        {/* Sidebar */}
        <motion.aside
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.1 }}
          className="lg:col-span-3 space-y-4 sm:space-y-6"
        >
          {/* Verified Domains */}
          <Card>
            <SectionTitle
              icon={<Lock className="w-4 h-4 sm:w-5 sm:h-5" />}
              className="mb-3 sm:mb-4"
              titleSize="text-sm sm:text-base"
            >
              Verified Domains
            </SectionTitle>

            {loading ? (
              <div className="text-center py-4">
                <div className="spinner mx-auto"></div>
              </div>
            ) : domains.length === 0 ? (
              <p className="text-xs sm:text-sm text-[var(--text-tertiary)]">
                No verified domains yet
              </p>
            ) : (
              <div className="space-y-2">
                {domains.map((domain, i) => (
                  <motion.div
                    key={domain.domain}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="flex items-center gap-2 p-2 rounded bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] transition-colors"
                  >
                    <span className="status-dot status-dot-verified"></span>
                    <span className="text-xs sm:text-sm font-mono flex-1 truncate">
                      {domain.domain}
                    </span>
                  </motion.div>
                ))}
              </div>
            )}
          </Card>

          {/* Recent Scans */}
          <Card className="hidden lg:block">
            <SectionTitle
              icon={<ScanLine className="w-4 h-4 sm:w-5 sm:h-5" />}
              className="mb-3 sm:mb-4"
              titleSize="text-sm sm:text-base"
            >
              Recent Scans
            </SectionTitle>

            {loading ? (
              <div className="text-center py-4">
                <div className="spinner mx-auto"></div>
              </div>
            ) : scans.length === 0 ? (
              <p className="text-xs sm:text-sm text-[var(--text-tertiary)]">
                No scans yet
              </p>
            ) : (
              <div className="space-y-2">
                {scans.slice(0, 5).map((scan, i) => (
                  <motion.button
                    key={scan.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    onClick={() => navigate(`/scan/${scan.id}`)}
                    className="w-full text-left p-2 sm:p-3 rounded bg-[var(--bg-tertiary)] hover:bg-[var(--bg-elevated)] 
                             transition-all border border-transparent hover:border-slate-600 group"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      {getStatusIcon(scan.status)}
                      <span className="text-xs font-mono text-[var(--text-secondary)] flex-1 truncate">
                        {new URL(scan.url).hostname}
                      </span>
                      <ChevronRight className="w-3 h-3 text-[var(--text-tertiary)] group-hover:text-[var(--accent-verified)] transition-colors" />
                    </div>
                  </motion.button>
                ))}
              </div>
            )}
          </Card>
        </motion.aside>

        {/* Main Content */}
        <main className="lg:col-span-9">
          <ScanForm onScanCreated={handleScanCreated} />

          {/* All Scans List */}
          {!loading && scans.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3 }}
              className="mt-6 sm:mt-8"
            >
              <Card>
                <SectionTitle className="mb-4 sm:mb-6">
                  <span className="text-lg sm:text-xl">All Scans</span>
                </SectionTitle>
                <div className="space-y-3">
                  {scans.map((scan, i) => (
                    <motion.button
                      key={scan.id}
                      initial={{ opacity: 0, y: 10 }}
                      animate={{ opacity: 1, y: 0 }}
                      transition={{ delay: 0.3 + i * 0.05 }}
                      onClick={() => navigate(`/scan/${scan.id}`)}
                      className="w-full text-left p-3 sm:p-4 rounded-lg bg-[var(--bg-tertiary)] 
                               hover:bg-[var(--bg-elevated)] transition-all border border-transparent 
                               hover:border-slate-600 card-hover"
                    >
                      <div className="flex flex-col sm:flex-row items-start justify-between gap-3 sm:gap-4">
                        <div className="flex-1 w-full sm:w-auto">
                          <div className="flex items-center gap-2 mb-2">
                            {getStatusIcon(scan.status)}
                            <span className="font-mono font-semibold text-sm sm:text-base break-all">
                              {scan.url}
                            </span>
                          </div>
                          {scan.description && (
                            <p className="text-xs sm:text-sm text-[var(--text-secondary)] mb-2">
                              {scan.description}
                            </p>
                          )}
                          <div className="flex flex-wrap items-center gap-2 sm:gap-3 text-xs text-[var(--text-tertiary)]">
                            <span className="font-mono">
                              {new Date(
                                scan.created_at.endsWith("Z")
                                  ? scan.created_at
                                  : scan.created_at + "Z",
                              ).toLocaleString()}
                            </span>
                            {scan.risk_label && (
                              <Badge variant="info" size="sm">
                                {scan.risk_label}
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex sm:flex-col items-center sm:items-end gap-3 sm:gap-2 w-full sm:w-auto justify-between sm:justify-start">
                          <Badge
                            variant={getStatusBadge(scan.status)}
                            size="md"
                          >
                            {scan.status}
                          </Badge>
                          {scan.risk_score !== null && (
                            <div className="text-xl sm:text-2xl font-mono font-bold">
                              <span
                                className={
                                  scan.risk_score >= 70
                                    ? "text-[var(--severity-critical)]"
                                    : scan.risk_score >= 40
                                      ? "text-[var(--severity-medium)]"
                                      : "text-[var(--accent-verified)]"
                                }
                              >
                                {scan.risk_score}
                              </span>
                              <span className="text-xs sm:text-sm text-[var(--text-tertiary)]">
                                /100
                              </span>
                            </div>
                          )}
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
    </MainLayout>
  );
}
