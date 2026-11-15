import type { ComponentPropsWithoutRef } from "react";

type Props = ComponentPropsWithoutRef<"button"> & {
  variant?: "primary" | "secondary" | "quiet";
};

const variants = {
  primary:
    "bg-brand-600 text-white hover:bg-brand-700",
  secondary:
    "border border-line bg-surface text-fg hover:bg-hover",
  quiet:
    "text-fg-muted hover:bg-hover"
};

export function Button({ variant = "secondary", className = "", type = "button", ...props }: Props) {
  return (
    <button
      type={type}
      className={`rounded-md px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 focus-visible:ring-offset-surface-muted disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    />
  );
}
