import { ExternalLink, Github } from "lucide-react";

export function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 px-4 py-3 text-sm text-slate-500">
        <span>© 2025 MadDog Warner</span>
        <div className="flex items-center gap-4">
          <a
            href="https://maddogwarner.com"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-slate-700"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            maddogwarner.com
          </a>
          <a
            href="https://github.com/MaddogWarner"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 hover:text-slate-700"
          >
            <Github className="h-3.5 w-3.5" />
            MaddogWarner
          </a>
        </div>
      </div>
    </footer>
  );
}
