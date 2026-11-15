import { CopyButton } from "../../components/CopyButton";

type Props = {
  ip: string | null;
  port: number | null;
  role: "source" | "destination";
  onFilter: (ip: string) => void;
};

export function IpCell({ ip, port, role, onFilter }: Props) {
  if (!ip) return <span className="text-fg-muted">Unknown</span>;
  return (
    <span className="inline-flex items-center gap-1">
      <button
        type="button"
        onClick={(event) => {
          event.stopPropagation();
          onFilter(ip);
        }}
        title={`Filter by ${role} ${ip}`}
        className="rounded font-mono text-xs text-brand-ink hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
      >
        {ip}
      </button>
      {port ? <span className="font-mono text-xs text-fg-muted">:{port}</span> : null}
      <CopyButton value={ip} label={`Copy ${role} IP ${ip}`} />
    </span>
  );
}
