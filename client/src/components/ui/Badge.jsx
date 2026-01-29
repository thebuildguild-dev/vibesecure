export default function Badge({
  children,
  variant = "default",
  size = "md",
  className = "",
}) {
  const baseClasses =
    "inline-flex items-center justify-center font-mono font-semibold rounded-full uppercase tracking-wide whitespace-nowrap";

  const variants = {
    default: "bg-[var(--bg-tertiary)] text-[var(--text-secondary)]",
    verified:
      "bg-[var(--accent-verified)]/10 text-[var(--accent-verified)] border border-[var(--accent-verified)]/30",
    warning:
      "bg-[var(--accent-warning)]/10 text-[var(--accent-warning)] border border-[var(--accent-warning)]/30",
    error:
      "bg-[var(--accent-error)]/10 text-[var(--accent-error)] border border-[var(--accent-error)]/30",
    info: "bg-[var(--accent-info)]/10 text-[var(--accent-info)] border border-[var(--accent-info)]/30",
    success:
      "bg-[var(--accent-verified)]/10 text-[var(--accent-verified)] border border-[var(--accent-verified)]/30",
    critical:
      "bg-[var(--severity-critical)]/10 text-[var(--severity-critical)] border border-[var(--severity-critical)]/30",
    high: "bg-[var(--severity-high)]/10 text-[var(--severity-high)] border border-[var(--severity-high)]/30",
    medium:
      "bg-[var(--severity-medium)]/10 text-[var(--severity-medium)] border border-[var(--severity-medium)]/30",
    low: "bg-[var(--severity-low)]/10 text-[var(--severity-low)] border border-[var(--severity-low)]/30",
  };

  const sizes = {
    sm: "px-2 py-0.5 text-[10px]",
    md: "px-2.5 py-1 text-xs",
    lg: "px-3 py-1.5 text-sm",
  };

  return (
    <span
      className={`${baseClasses} ${variants[variant]} ${sizes[size]} ${className}`}
    >
      {children}
    </span>
  );
}
