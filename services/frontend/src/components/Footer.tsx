import { ExternalLink, Github } from "lucide-react";

export function Footer() {
  const version = import.meta.env.VITE_APP_VERSION;

  return (
    <footer className="border-t border-slate-200 bg-white dark:border-slate-800 dark:bg-slate-900">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 text-sm text-slate-500 dark:text-slate-400">
        <span>© 2025 MadDog Warner{version ? ` · v${version}` : ""}</span>
        <div className="flex items-center gap-4">
          <a
            href="https://maddogwarner.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-brand-700 dark:hover:text-brand-300"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            maddogwarner.com
          </a>
          <a
            href="https://github.com/MaddogWarner"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-brand-700 dark:hover:text-brand-300"
          >
            <Github className="h-3.5 w-3.5" />
            MaddogWarner
          </a>
        </div>
      </div>
    </footer>
  );
}
