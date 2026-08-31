interface BrandMarkProps {
  size?: number;
  className?: string;
}

/**
 * The kguardian mark: an indigo hexagon with a padlock — the product's one
 * genuinely-owned visual. Previously it lived only in the favicon while the app
 * wore a stock lucide Shield; this promotes it into the product so "lock =
 * kguardian" reads everywhere. Fixed brand colors (mark, not an icon).
 */
export function BrandMark({ size = 24, className = '' }: BrandMarkProps) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      role="img"
      aria-label="kguardian"
    >
      <polygon
        points="12,1.2 21.4,6.6 21.4,17.4 12,22.8 2.6,17.4 2.6,6.6"
        fill="#4e3ad9"
        stroke="#4e3ad9"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <path
        d="M8.6 11.2 V9.2 a3.4 3.4 0 0 1 6.8 0 v2"
        stroke="#ffffff"
        strokeWidth="2.1"
        strokeLinecap="round"
        fill="none"
      />
      <path
        d="M7.2 12.9 q0 -1.6 1.6 -1.6 h6.4 q1.6 0 1.6 1.6 v3.1 q0 1.3 -1 2.1 l-2.9 2.2 q-0.9 0.7 -1.8 0 l-2.9 -2.2 q-1 -0.8 -1 -2.1 z"
        fill="#ffffff"
      />
      <circle cx="12" cy="14.9" r="1.15" fill="#4e3ad9" />
      <rect x="11.55" y="15.5" width="0.9" height="2.1" rx="0.45" fill="#4e3ad9" />
    </svg>
  );
}
