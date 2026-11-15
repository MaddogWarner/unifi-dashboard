import { ExternalLink } from "lucide-react";
import { GithubIcon } from "./icons/GithubIcon";

export function Footer() {
  const version = import.meta.env.VITE_APP_VERSION;

  return (
    <footer className="border-t border-line bg-surface">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 text-sm text-fg-muted">
        <span>© 2025 MadDog Warner{version ? ` · v${version}` : ""}</span>
        <div className="flex items-center gap-4">
          <a
            href="https://maddogwarner.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-brand-ink"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            maddogwarner.com
          </a>
          <a
            href="https://github.com/MaddogWarner"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-brand-ink"
          >
            <GithubIcon className="h-3.5 w-3.5" />
            MaddogWarner
          </a>
        </div>
      </div>
    </footer>
  );
}
