import { motion } from "framer-motion";

export default function Button({
  children,
  variant = "primary",
  size = "md",
  disabled = false,
  loading = false,
  fullWidth = false,
  icon,
  onClick,
  type = "button",
  className = "",
  ...props
}) {
  const baseClasses =
    "inline-flex items-center justify-center gap-2 font-mono font-semibold transition-all duration-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[var(--bg-primary)] disabled:opacity-50 disabled:cursor-not-allowed";

  const variants = {
    primary:
      "bg-[var(--accent-verified)] text-slate-900 hover:bg-[var(--accent-verified)]/90 focus:ring-[var(--accent-verified)] shadow-[0_0_20px_rgba(0,255,136,0.3)] hover:shadow-[0_0_30px_rgba(0,255,136,0.5)]",
    secondary:
      "bg-[var(--bg-tertiary)] text-[var(--text-primary)] hover:bg-[var(--bg-elevated)] border border-slate-600 hover:border-[var(--accent-verified)]",
    danger:
      "bg-[var(--accent-error)] text-white hover:bg-[var(--accent-error)]/90 focus:ring-[var(--accent-error)] shadow-[0_0_20px_rgba(255,71,87,0.3)]",
    ghost:
      "bg-transparent text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)]",
    info: "bg-[var(--accent-info)] text-slate-900 hover:bg-[var(--accent-info)]/90 focus:ring-[var(--accent-info)] shadow-[0_0_20px_rgba(0,212,255,0.3)]",
  };

  const sizes = {
    sm: "px-3 py-1.5 text-sm",
    md: "px-4 py-2 text-base",
    lg: "px-6 py-3 text-lg",
  };

  const widthClass = fullWidth ? "w-full" : "";

  return (
    <motion.button
      type={type}
      disabled={disabled || loading}
      onClick={onClick}
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${widthClass} ${className}`}
      whileHover={disabled || loading ? {} : { scale: 1.02 }}
      whileTap={disabled || loading ? {} : { scale: 0.98 }}
      {...props}
    >
      {loading ? (
        <>
          <span className="inline-block w-4 h-4 border-2 border-current border-t-transparent rounded-full animate-spin" />
          <span>Loading...</span>
        </>
      ) : (
        <>
          {icon && <span className="flex-shrink-0">{icon}</span>}
          {children}
        </>
      )}
    </motion.button>
  );
}
