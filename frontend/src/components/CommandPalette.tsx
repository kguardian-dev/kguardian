import { useMemo, useState } from 'react';
import type { LucideIcon } from 'lucide-react';
import { Search, CornerDownLeft } from 'lucide-react';
import { Modal } from './ui/Modal';

export interface Command {
  id: string;
  label: string;
  /** Secondary text (e.g. namespace). */
  hint?: string;
  group: string;
  icon: LucideIcon;
  /** Extra terms to match on beyond the label. */
  keywords?: string;
  run: () => void;
}

interface CommandPaletteProps {
  onClose: () => void;
  commands: Command[];
}

// Fixed group order so results read predictably regardless of input order.
const GROUP_ORDER = ['Views', 'Tools', 'Namespaces', 'Workloads'];

/** Subsequence match (fuzzy) — "qbt" matches "qbittorrent". */
function fuzzy(haystack: string, needle: string): boolean {
  if (!needle) return true;
  let i = 0;
  for (const ch of haystack) {
    if (ch === needle[i]) i++;
    if (i === needle.length) return true;
  }
  return false;
}

/**
 * ⌘K command palette — one keyboard-first surface to jump anywhere: switch
 * views, open tools, change namespace, or select a workload. Turns navigation
 * that otherwise means hunting the rail or the graph into two keystrokes, and
 * keeps every destination discoverable without adding chrome.
 */
export function CommandPalette({ onClose, commands }: CommandPaletteProps) {
  const [query, setQuery] = useState('');
  const [active, setActive] = useState(0);

  const results = useMemo(() => {
    const q = query.trim().toLowerCase();
    const matched = commands.filter((c) => {
      const hay = `${c.label} ${c.hint ?? ''} ${c.keywords ?? ''} ${c.group}`.toLowerCase();
      return q ? hay.includes(q) || fuzzy(c.label.toLowerCase(), q) : true;
    });
    // Cap workloads/namespaces so a huge cluster doesn't flood the list.
    const capped: Command[] = [];
    const perGroup: Record<string, number> = {};
    for (const g of GROUP_ORDER) {
      for (const c of matched.filter((m) => m.group === g)) {
        perGroup[g] = (perGroup[g] ?? 0) + 1;
        if (perGroup[g] <= (g === 'Views' || g === 'Tools' ? 99 : 8)) capped.push(c);
      }
    }
    // Any groups not in GROUP_ORDER, appended.
    for (const c of matched.filter((m) => !GROUP_ORDER.includes(m.group))) capped.push(c);
    return capped;
  }, [commands, query]);

  const activeIdx = Math.min(active, Math.max(0, results.length - 1));

  const run = (cmd: Command | undefined) => {
    if (!cmd) return;
    cmd.run();
    onClose();
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive((a) => Math.min(a + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive((a) => Math.max(a - 1, 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      run(results[activeIdx]);
    }
  };

  // Render results grouped, but keep a flat index for keyboard nav.
  let flatIndex = -1;
  const groups = GROUP_ORDER.map((g) => ({ group: g, items: results.filter((r) => r.group === g) })).filter(
    (g) => g.items.length > 0,
  );

  return (
    <Modal isOpen onClose={onClose} hideHeader size="lg" align="top" contentClassName="flex flex-col">
      <div className="flex items-center gap-2 h-12 px-4 border-b border-hubble-border shrink-0">
        <Search className="w-4 h-4 text-tertiary shrink-0" />
        <input
          autoFocus
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setActive(0);
          }}
          onKeyDown={onKeyDown}
          placeholder="Jump to a view, tool, namespace, or workload…"
          className="flex-1 bg-transparent text-sm text-primary placeholder:text-tertiary focus:outline-none"
        />
        <kbd className="hidden sm:inline text-[10px] font-mono text-tertiary border border-hubble-border rounded px-1.5 py-0.5">
          ESC
        </kbd>
      </div>

      <div className="max-h-[52vh] overflow-y-auto py-2">
        {results.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-tertiary">No matches for “{query}”.</div>
        ) : (
          groups.map(({ group, items }) => (
            <div key={group} className="mb-1">
              <div className="px-4 pt-2 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">
                {group}
              </div>
              {items.map((cmd) => {
                flatIndex += 1;
                const idx = flatIndex;
                const Icon = cmd.icon;
                return (
                  <button
                    key={cmd.id}
                    onClick={() => run(cmd)}
                    onMouseEnter={() => setActive(idx)}
                    className={`w-full flex items-center gap-3 px-4 py-2 text-left transition-colors ${
                      idx === activeIdx ? 'bg-hubble-accent/15' : 'hover:bg-hubble-hover'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${idx === activeIdx ? 'text-hubble-accent' : 'text-tertiary'}`} />
                    <span className="flex-1 min-w-0 text-sm text-primary truncate">{cmd.label}</span>
                    {cmd.hint && <span className="text-[11px] text-tertiary font-mono truncate max-w-[40%]">{cmd.hint}</span>}
                    {idx === activeIdx && <CornerDownLeft className="w-3.5 h-3.5 shrink-0 text-tertiary" />}
                  </button>
                );
              })}
            </div>
          ))
        )}
      </div>
    </Modal>
  );
}
