import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { copyText } from '../../utils/clipboard';
import { Button } from './Button';

interface CopyButtonProps {
  text: string;
  /** Visible label; defaults to "Copy". */
  label?: string;
  /** Accessible name when the label alone is ambiguous on the page. */
  ariaLabel?: string;
}

type CopyState = 'idle' | 'copied' | 'failed';

/**
 * Copies `text` and says so, in words and to screen readers (aria-live), for
 * two seconds. A failed copy says that too instead of pretending it worked.
 */
export function CopyButton({ text, label = 'Copy', ariaLabel }: CopyButtonProps) {
  const [state, setState] = useState<CopyState>('idle');
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);

  const onClick = async () => {
    const ok = await copyText(text);
    setState(ok ? 'copied' : 'failed');
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setState('idle'), 2000);
  };

  return (
    <span className="inline-flex items-center gap-2">
      <Button variant="secondary" size="sm" leftIcon={state === 'copied' ? Check : Copy} onClick={onClick} aria-label={ariaLabel}>
        {state === 'copied' ? 'Copied' : label}
      </Button>
      <span aria-live="polite" className="text-[11px] text-tertiary">
        {state === 'failed' ? 'Copy failed — select the text and copy it manually' : ''}
      </span>
    </span>
  );
}
