export default function SectionTitle({
  children,
  icon,
  subtitle,
  className = "",
  titleSize = "text-xl sm:text-2xl lg:text-3xl",
}) {
  return (
    <div className={`mb-4 sm:mb-6 ${className}`}>
      <div className="flex items-center gap-2 sm:gap-3 leading-none">
        {icon && (
          <span className="text-[var(--accent-verified)] flex-shrink-0 flex items-center justify-center">
            {icon}
          </span>
        )}
        <h2
          className={`font-bold font-display text-[var(--text-primary)] ${titleSize}`}
        >
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
