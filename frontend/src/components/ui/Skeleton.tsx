/**
 * Loading-state placeholders. `Skeleton` is the primitive block; `GraphSkeleton`
 * is the map-shaped loader shown while pod data is in flight — pulsing node
 * cards wired by faint edges, so the canvas reads as "assembling the graph"
 * instead of a bare spinner on an empty screen. Honors prefers-reduced-motion
 * via the global CSS reset (which neutralizes `animate-pulse`).
 */
export function Skeleton({ className = '' }: { className?: string }) {
  return <div className={`animate-pulse rounded-control bg-hubble-hover ${className}`} />;
}

function SkeletonNode({ className = '' }: { className?: string }) {
  return (
    <div
      className={`absolute w-[168px] rounded-surface border border-hubble-border bg-hubble-card px-4 py-3 ${className}`}
    >
      <div className="flex items-center gap-2">
        <Skeleton className="w-5 h-5 rounded-full" />
        <Skeleton className="h-3 flex-1" />
      </div>
      <Skeleton className="mt-2.5 h-2 w-2/3" />
    </div>
  );
}

export function GraphSkeleton() {
  return (
    <div className="relative w-full h-full overflow-hidden" aria-hidden>
      {/* Faint connective lines behind the node cards (0–100 canvas). */}
      <svg className="absolute inset-0 w-full h-full" viewBox="0 0 100 100" preserveAspectRatio="none">
        <g stroke="var(--color-hubble-border)" strokeWidth="0.4" fill="none">
          <path d="M 22 30 C 34 30, 34 52, 50 52" />
          <path d="M 22 30 C 34 30, 40 22, 74 22" />
          <path d="M 50 52 C 62 52, 62 74, 74 74" />
          <path d="M 50 52 C 62 52, 62 40, 74 40" />
        </g>
      </svg>
      <SkeletonNode className="left-[14%] top-[26%]" />
      <SkeletonNode className="left-[42%] top-[48%]" />
      <SkeletonNode className="left-[66%] top-[18%]" />
      <SkeletonNode className="left-[66%] top-[70%]" />
      <SkeletonNode className="left-[66%] top-[36%]" />
    </div>
  );
}
