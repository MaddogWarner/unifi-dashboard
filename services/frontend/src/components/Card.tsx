import type { ReactNode } from "react";

type Props = {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
};

export function Card({ title, action, children, className = "" }: Props) {
  return (
    <section className={`rounded-lg border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900 ${className}`}>
      {title ? (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3 p-4">
            <h2 className="text-base font-semibold text-slate-950 dark:text-slate-50">{title}</h2>
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
