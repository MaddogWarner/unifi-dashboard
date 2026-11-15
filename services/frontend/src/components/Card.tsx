import type { ReactNode } from "react";

type Props = {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
};

export function Card({ title, action, children, className = "" }: Props) {
  return (
    <section className={`rounded-lg border border-line bg-surface shadow-sm ${className}`}>
      {title ? (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 p-4">
            <h2 className="text-base font-semibold text-fg">{title}</h2>
            {action ? <div className="shrink-0">{action}</div> : null}
          </div>
          <div className="p-4 pt-0">{children}</div>
        </>
      ) : (
        <div className="p-4">{children}</div>
      )}
    </section>
  );
}
