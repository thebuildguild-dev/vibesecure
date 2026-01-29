export default function SectionTitle({
  children,
  icon,
  subtitle,
  className = "",
}) {
  return (
    <div className={`mb-4 sm:mb-6 ${className}`}>
      <div className="flex items-center gap-2 sm:gap-3">
        {icon && (
          <span className="text-[var(--accent-verified)] flex-shrink-0">
            {icon}
          </span>
        )}
        <h2 className="text-xl sm:text-2xl lg:text-3xl font-bold font-display text-[var(--text-primary)]">
          {children}
        </h2>
      </div>
      {subtitle && (
        <p className="mt-2 text-sm sm:text-base text-[var(--text-secondary)] font-mono">
          {subtitle}
        </p>
      )}
    </div>
  );
}
