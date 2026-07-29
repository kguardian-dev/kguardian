import { forwardRef } from 'react';
import type { ButtonHTMLAttributes } from 'react';
import type { LucideIcon } from 'lucide-react';

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger' | 'success';
export type ButtonSize = 'sm' | 'md';

// One base, one radius, one transition — every button in the app routes through
// here so heights and paddings can never drift again (they did: ~14 distinct
// inline signatures across 101 buttons before this).
const BASE =
  'inline-flex items-center justify-center gap-1.5 font-medium rounded-control border ' +
  'transition-colors select-none whitespace-nowrap ' +
  'disabled:opacity-50 disabled:pointer-events-none';

const SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-xs',
  md: 'h-9 px-4 text-sm',
};

const ICON_ONLY_SIZES: Record<ButtonSize, string> = {
  sm: 'h-8 w-8 px-0',
  md: 'h-9 w-9 px-0',
};

const VARIANTS: Record<ButtonVariant, string> = {
  primary: 'bg-hubble-accent hover:bg-hubble-accent-hover text-white border-transparent',
  secondary: 'bg-hubble-card hover:bg-hubble-hover text-primary border-hubble-border',
  ghost: 'bg-transparent hover:bg-hubble-hover text-secondary hover:text-primary border-transparent',
  success: 'bg-hubble-success hover:bg-hubble-success-hover text-white border-transparent',
  danger: 'bg-hubble-error hover:bg-hubble-error-hover text-white border-transparent',
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  leftIcon?: LucideIcon;
  rightIcon?: LucideIcon;
  /** Square, content-free icon button (padding collapses to a fixed square). */
  iconOnly?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = 'secondary', size = 'md', leftIcon: LeftIcon, rightIcon: RightIcon, iconOnly = false, className = '', children, type = 'button', ...props },
  ref,
) {
  const iconPx = size === 'sm' ? 14 : 16;
  const sizing = iconOnly ? ICON_ONLY_SIZES[size] : SIZES[size];
  return (
    <button ref={ref} type={type} className={`${BASE} ${sizing} ${VARIANTS[variant]} ${className}`} {...props}>
      {LeftIcon && <LeftIcon size={iconPx} className="shrink-0" />}
      {children}
      {RightIcon && <RightIcon size={iconPx} className="shrink-0" />}
    </button>
  );
});
