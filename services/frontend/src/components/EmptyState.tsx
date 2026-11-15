type Props = {
  title: string;
  detail?: string;
};

export function EmptyState({ title, detail }: Props) {
  return (
    <div className="rounded-md border border-dashed border-line px-4 py-8 text-center">
      <p className="text-sm font-medium text-fg">{title}</p>
      {detail ? <p className="mt-1 text-sm text-fg-muted">{detail}</p> : null}
    </div>
  );
}
