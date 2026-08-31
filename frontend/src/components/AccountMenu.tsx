import { useState, useRef } from 'react';
import { User, Settings as SettingsIcon, Sun, Moon, LogOut, ShieldCheck, ChevronsUpDown } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../contexts/ThemeContext';
import { useDismissable } from '../hooks/useDismissable';

interface AccountMenuProps {
  collapsed?: boolean;
  onOpenSettings: () => void;
}

/**
 * Account control in the rail footer. Reflects the real auth state: local /
 * no-auth by default (shown honestly, no fake login), or the signed-in user
 * once SSO is enabled (AuthContext). Hosts Settings + the theme toggle.
 */
export function AccountMenu({ collapsed = false, onOpenSettings }: AccountMenuProps) {
  const { mode, user, signOut } = useAuth();
  const { theme, toggleTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useDismissable(open, () => setOpen(false), ref);

  const primaryLabel = user?.name ?? 'Local access';
  const secondaryLabel = user?.email ?? (mode === 'oidc' ? 'Signed in' : 'SSO not configured');
  const initials = (user?.name ?? 'L').trim().slice(0, 1).toUpperCase();

  return (
    <div ref={ref} className="relative flex-1 min-w-0">
      <button
        onClick={() => setOpen((o) => !o)}
        title={collapsed ? primaryLabel : undefined}
        className={`w-full flex items-center h-9 rounded-control hover:bg-hubble-hover transition-colors ${
          collapsed ? 'justify-center px-0' : 'gap-2 px-1.5'
        }`}
      >
        <span className="grid place-items-center w-7 h-7 shrink-0 rounded-full bg-hubble-accent/15 text-hubble-accent text-xs font-semibold">
          {user ? initials : <User size={15} />}
        </span>
        {!collapsed && (
          <>
            <span className="flex-1 min-w-0 text-left">
              <span className="block text-xs font-medium text-primary truncate leading-tight">{primaryLabel}</span>
              <span className="block text-[10px] text-tertiary truncate leading-tight">{secondaryLabel}</span>
            </span>
            <ChevronsUpDown size={14} className="shrink-0 text-tertiary" />
          </>
        )}
      </button>

      {open && (
        <div className="absolute bottom-full mb-1 left-0 right-0 z-30 min-w-[200px] rounded-control border border-hubble-border bg-hubble-card shadow-xl py-1">
          <div className="px-3 py-2 border-b border-hubble-border">
            <div className="text-xs font-medium text-primary truncate">{primaryLabel}</div>
            <div className="mt-0.5 flex items-center gap-1 text-[10px] text-tertiary">
              <ShieldCheck size={11} className={mode === 'oidc' ? 'text-hubble-success' : 'text-tertiary'} />
              <span>{mode === 'oidc' ? 'SSO session' : 'Local access · SSO not configured'}</span>
            </div>
          </div>

          <button
            onClick={() => { onOpenSettings(); setOpen(false); }}
            className="w-full flex items-center gap-2.5 px-3 h-9 text-sm text-secondary hover:bg-hubble-hover hover:text-primary transition-colors"
          >
            <SettingsIcon size={15} className="shrink-0" />
            <span>Settings</span>
          </button>

          <button
            onClick={toggleTheme}
            className="w-full flex items-center gap-2.5 px-3 h-9 text-sm text-secondary hover:bg-hubble-hover hover:text-primary transition-colors"
          >
            {theme === 'dark' ? <Sun size={15} className="shrink-0" /> : <Moon size={15} className="shrink-0" />}
            <span>{theme === 'dark' ? 'Light theme' : 'Dark theme'}</span>
          </button>

          {mode === 'oidc' && (
            <>
              <div className="my-1 border-t border-hubble-border" />
              <button
                onClick={() => { signOut(); setOpen(false); }}
                className="w-full flex items-center gap-2.5 px-3 h-9 text-sm text-hubble-error hover:bg-hubble-error/10 transition-colors"
              >
                <LogOut size={15} className="shrink-0" />
                <span>Sign out</span>
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}
