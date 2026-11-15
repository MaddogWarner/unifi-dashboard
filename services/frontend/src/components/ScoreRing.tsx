type Props = {
  score: number | null;
};

const RADIUS = 52;
const CIRCUMFERENCE = 2 * Math.PI * RADIUS;

function toneClass(score: number) {
  if (score >= 80) return "stroke-success-fg";
  if (score >= 50) return "stroke-warning-fg";
  return "stroke-danger-fg";
}

export function ScoreRing({ score }: Props) {
  const clamped = score === null ? 0 : Math.min(100, Math.max(0, score));
  return (
    <div className="relative h-32 w-32 shrink-0">
      <svg
        viewBox="0 0 120 120"
        role="img"
        aria-label={score === null ? "Security score unavailable" : `Security score ${clamped} out of 100`}
        className="h-full w-full -rotate-90"
      >
        <circle cx="60" cy="60" r={RADIUS} fill="none" strokeWidth="10" className="stroke-hover" />
        {score === null ? null : (
          <circle
            cx="60"
            cy="60"
            r={RADIUS}
            fill="none"
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={CIRCUMFERENCE}
            strokeDashoffset={CIRCUMFERENCE * (1 - clamped / 100)}
            className={toneClass(clamped)}
          />
        )}
      </svg>
      <span
        aria-hidden
        className="absolute inset-0 flex items-center justify-center text-3xl font-semibold tabular-nums text-fg"
      >
        {score === null ? "–" : clamped}
      </span>
    </div>
  );
}
