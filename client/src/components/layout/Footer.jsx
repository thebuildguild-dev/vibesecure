import { Shield, Github, Mail } from "lucide-react";

export default function Footer() {
  const currentYear = new Date().getFullYear();

  return (
    <footer className="bg-[var(--bg-secondary)] border-t border-slate-700 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 sm:gap-8">
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Shield className="w-6 h-6 text-[var(--accent-verified)]" />
              <span className="text-lg sm:text-xl font-mono font-bold">
                VIBE
                <span className="text-[var(--accent-verified)]">SECURE</span>
              </span>
            </div>
            <p className="text-xs sm:text-sm text-[var(--text-tertiary)] font-mono">
              Ethical web security scanner with owner verification and
              consent-gated testing.
            </p>
          </div>

          {/* Resources */}
          <div className="space-y-3">
            <h3 className="text-sm font-mono font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Resources
            </h3>
            <ul className="space-y-2 text-xs sm:text-sm font-mono">
              <li>
                <a
                  href="https://owasp.org/www-project-zap/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  OWASP ZAP
                </a>
              </li>
              <li>
                <a
                  href="https://firebase.google.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Firebase
                </a>
              </li>
              <li>
                <a
                  href="https://redis.io/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Redis
                </a>
              </li>
              <li>
                <a
                  href="https://playwright.dev/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Playwright
                </a>
              </li>
              <li>
                <a
                  href="https://ai.google.dev/gemini-api"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Google Gemini AI
                </a>
              </li>
              <li>
                <a
                  href="https://fastapi.tiangolo.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  FastAPI
                </a>
              </li>
              <li>
                <a
                  href="https://www.postgresql.org/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  PostgreSQL
                </a>
              </li>
              <li>
                <a
                  href="https://docs.celeryq.dev/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Celery
                </a>
              </li>
              <li>
                <a
                  href="https://react.dev/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  React
                </a>
              </li>
              <li>
                <a
                  href="https://vitejs.dev/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Vite
                </a>
              </li>
              <li>
                <a
                  href="https://tailwindcss.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Tailwind CSS
                </a>
              </li>
              <li>
                <a
                  href="https://resend.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  Resend
                </a>
              </li>
              <li>
                <a
                  href="https://www.reportlab.com/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                >
                  ReportLab
                </a>
              </li>
            </ul>
          </div>

          {/* Powered By */}
          <div className="space-y-3">
            <h3 className="text-sm font-mono font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Powered By
            </h3>
            <ul className="space-y-2 text-xs sm:text-sm font-mono text-[var(--text-tertiary)]">
              <li>Google Gemini AI</li>
              <li>FastAPI</li>
              <li>PostgreSQL</li>
              <li>Celery</li>
              <li>React + Vite</li>
              <li>Tailwind CSS</li>
              <li>Resend (Email)</li>
              <li>ReportLab (PDF)</li>
            </ul>
          </div>

          {/* Contact */}
          <div className="space-y-3">
            <h3 className="text-sm font-mono font-semibold text-[var(--text-secondary)] uppercase tracking-wider">
              Connect
            </h3>
            <div className="flex gap-4">
              <a
                href="https://github.com/thebuildguild-dev/vibesecure"
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                aria-label="GitHub"
              >
                <Github className="w-5 h-5" />
              </a>
              <a
                href="mailto:info@thebuildguild.dev"
                className="text-[var(--text-tertiary)] hover:text-[var(--accent-verified)] transition-colors"
                aria-label="Email"
              >
                <Mail className="w-5 h-5" />
              </a>
            </div>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="mt-6 sm:mt-8 pt-6 border-t border-slate-700">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-3 sm:gap-0">
            <p className="text-xs text-[var(--text-tertiary)] font-mono text-center sm:text-left">
              © {currentYear} VibeSecure. Ethical security testing platform.
            </p>
            <p className="text-xs text-[var(--text-tertiary)] font-mono text-center sm:text-right">
              Built with ❤️ by The Build Guild
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}
