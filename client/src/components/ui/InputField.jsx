export default function InputField({
  label,
  type = "text",
  placeholder,
  value,
  onChange,
  error,
  disabled = false,
  required = false,
  icon,
  className = "",
  ...props
}) {
  return (
    <div className={`w-full ${className}`}>
      {label && (
        <label className="block text-sm font-mono font-semibold text-[var(--text-secondary)] mb-2">
          {label}
          {required && (
            <span className="text-[var(--accent-error)] ml-1">*</span>
          )}
        </label>
      )}
      <div className="relative">
        {icon && (
          <div className="absolute left-3 top-1/2 -translate-y-1/2 text-[var(--text-tertiary)]">
            {icon}
          </div>
        )}
        <input
          type={type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          disabled={disabled}
          required={required}
          className={`
            w-full px-4 py-2.5 sm:py-3
            ${icon ? "pl-10" : ""}
            bg-[var(--bg-tertiary)] 
            border border-slate-600 
            rounded-lg 
            text-[var(--text-primary)] 
            placeholder-[var(--text-tertiary)]
            font-mono text-sm sm:text-base
            focus:outline-none 
            focus:border-[var(--accent-verified)] 
            focus:ring-2 
            focus:ring-[var(--accent-verified)]/20
            disabled:opacity-50 
            disabled:cursor-not-allowed
            transition-all duration-200
          `}
          {...props}
        />
      </div>
      {error && (
        <p className="mt-2 text-sm text-[var(--accent-error)] font-mono">
          {error}
        </p>
      )}
    </div>
  );
}
