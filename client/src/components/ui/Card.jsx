import { motion } from "framer-motion";

export default function Card({
  children,
  variant = "default",
  hover = false,
  onClick,
  className = "",
  ...props
}) {
  const baseClasses =
    "rounded-lg border border-slate-700 bg-[var(--bg-secondary)] transition-all duration-200";

  const variants = {
    default: "p-4 sm:p-6",
    elevated:
      "p-4 sm:p-6 shadow-[0_0_30px_rgba(0,255,136,0.1)] border-[var(--accent-verified)]/20",
    interactive:
      "p-4 sm:p-5 cursor-pointer hover:bg-[var(--bg-tertiary)] hover:border-slate-600",
  };

  const hoverClass =
    hover && !onClick
      ? "hover:shadow-[0_0_30px_rgba(0,255,136,0.15)] hover:border-[var(--accent-verified)]/30"
      : "";

  const clickableClass = onClick ? "cursor-pointer" : "";

  const Component = onClick ? motion.button : motion.div;

  return (
    <Component
      className={`${baseClasses} ${variants[variant]} ${hoverClass} ${clickableClass} ${className}`}
      onClick={onClick}
      initial={false}
      whileHover={hover || onClick ? { y: -2 } : {}}
      {...props}
    >
      {children}
    </Component>
  );
}
