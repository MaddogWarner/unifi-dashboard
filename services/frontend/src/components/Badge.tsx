import type { ReactNode } from "react";

type Props = {
  tone?: "neutral" | "success" | "warning" | "danger";
  children: ReactNode;
};

const tones = {
  neutral: "bg-hover text-fg-muted",
  success: "bg-success-bg text-success-fg",
  warning: "bg-warning-bg text-warning-fg",
  danger: "bg-danger-bg text-danger-fg"
};

export function Badge({ tone = "neutral", children }: Props) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${tones[tone]}`}>
      {children}
    </span>
  );
}
