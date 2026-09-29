import React, { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { X, Send, Square, ArrowRight, Minimize2, Maximize2, ChevronRight, ChevronLeft, Copy, Check } from 'lucide-react';
import { streamChatMessage, type HistoryMessage } from '../services/aiApi';
import { UI_DIMENSIONS } from '../constants/ui';
import { initialViewMode, storeViewMode, type AssistantViewMode } from '../utils/assistantViewMode';
import { useMediaQuery } from '../hooks/useMediaQuery';
import { Button } from './ui/Button';
import { Modal } from './ui/Modal';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
  // Transient UI state while a streamed assistant reply is in flight.
  activity?: string;   // e.g. "Looking up policy verdicts…" or "Thinking…"
  streaming?: boolean; // true until the terminal done/error event
}

// Map an MCP tool name to a short human phrase for the activity indicator.
function describeTool(name: string): string {
  const map: Record<string, string> = {
    get_pod_network_traffic: 'pod network traffic',
    get_pod_syscalls: 'pod syscalls',
    get_pod_details: 'pod details',
    get_pod_details_by_name: 'pod details',
    get_service_details: 'service details',
    list_services: 'service inventory',
    get_cluster_traffic: 'cluster traffic',
    get_cluster_pods: 'cluster pods',
    get_pods_on_node: 'pods on node',
    get_audit_verdicts: 'policy verdicts',
    generate_network_policy: 'network policy',
    generate_seccomp_profile: 'seccomp profile',
  };
  return map[name] || name.replace(/^(get|list|generate)_/, '').replace(/_/g, ' ');
}

// Activity line for a tool call — generation tools read better as "Generating…".
function toolActivity(name: string): string {
  const what = describeTool(name);
  return name.startsWith('generate_') ? `Generating ${what}…` : `Looking up ${what}…`;
}

const EXAMPLE_PROMPTS = [
  'What pods have the most network traffic?',
  'Show me any suspicious system calls',
  'Summarize security events in the last hour',
];

// A reply that has shown no progress for this long says how long it has been.
const SLOW_REPLY_AFTER_S = 5;

// Docked, the panel takes 448px next to the 224px rail; the map needs about
// 600px for its toolbar and summary to fit on one row. Below this the
// assistant opens as a modal and the stored preference is kept for wider screens.
const DOCK_MIN_WIDTH_PX = 1280;

// The conversation outlives the panel for the tab's session: the app unmounts
// the panel on close, and a reply that took a minute to arrive should not go
// with it. Replies still in flight are stored as far as they got.
const CONVERSATION_KEY = 'kguardian.ai-assistant.conversation';
// Older turns go first, also when the browser refuses the write for size.
const MAX_STORED_MESSAGES = 50;

interface StoredMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
}

function isStoredMessage(m: unknown): m is StoredMessage {
  if (!m || typeof m !== 'object') return false;
  const r = m as Record<string, unknown>;
  return (
    typeof r.id === 'string' &&
    (r.role === 'user' || r.role === 'assistant') &&
    typeof r.content === 'string' &&
    typeof r.timestamp === 'string' &&
    !Number.isNaN(Date.parse(r.timestamp))
  );
}

function readConversation(): Message[] {
  try {
    const parsed: unknown = JSON.parse(sessionStorage.getItem(CONVERSATION_KEY) ?? '[]');
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter(isStoredMessage)
      .slice(-MAX_STORED_MESSAGES)
      .map((m) => ({ ...m, timestamp: new Date(m.timestamp) }));
  } catch {
    return [];
  }
}

function storeConversation(messages: Message[]): void {
  try {
    let stored: StoredMessage[] = messages
      .filter((m) => m.content)
      .slice(-MAX_STORED_MESSAGES)
      .map(({ id, role, content, timestamp }) => ({ id, role, content, timestamp: timestamp.toISOString() }));
    if (stored.length === 0) {
      sessionStorage.removeItem(CONVERSATION_KEY);
      return;
    }
    for (;;) {
      try {
        sessionStorage.setItem(CONVERSATION_KEY, JSON.stringify(stored));
        return;
      } catch (e) {
        // Over quota: keep the newest half and try again.
        if (stored.length <= 1) throw e;
        stored = stored.slice(Math.ceil(stored.length / 2));
      }
    }
  } catch {
    /* storage blocked: the conversation lasts while the panel is mounted */
  }
}

// Renders a fenced markdown code block with a Copy button. Used as the custom
// `pre` renderer for assistant markdown so generated NetworkPolicy/seccomp
// (and any other code) can be copied to the clipboard in one click.
const CodeBlock: React.FC<{ children?: React.ReactNode }> = ({ children }) => {
  const preRef = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    const text = preRef.current?.innerText ?? '';
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable (e.g. non-secure context) — silently ignore.
    }
  };

  return (
    <div className="relative group">
      <button
        type="button"
        onClick={handleCopy}
        className="absolute right-2 top-2 flex items-center gap-1 rounded bg-hubble-dark/80 px-2 py-1 text-xs text-tertiary opacity-0 transition-opacity group-hover:opacity-100 hover:text-primary"
        aria-label="Copy code"
      >
        {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
        {copied ? 'Copied' : 'Copy'}
      </button>
      <pre ref={preRef}>{children}</pre>
    </div>
  );
};

// Replies carry text the model read from tool results, which an attacker can
// shape (pod names, DNS names, CVE text). An image would be fetched as soon as
// it rendered, carrying whatever the injected text put in its URL, so an image
// shows as its alt text only, or `[image]` so the reader knows one was left
// out. Links need a click and open in a new tab without a referrer or a
// handle back to this page.
const ReplyImage: React.FC<{ alt?: string }> = ({ alt }) => <span>{alt ? `[image: ${alt}]` : '[image]'}</span>;

// Whether the browser would take `href` to another origin. It decides, not a
// pattern: `https:evil.example` and backslash forms leave the page too.
function leavesOrigin(href: string): boolean {
  try {
    return new URL(href, window.location.href).origin !== window.location.origin;
  } catch {
    return true;
  }
}

const ReplyLink: React.FC<{ href?: string; children?: React.ReactNode }> = ({ href, children }) =>
  href && leavesOrigin(href) ? (
    <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
  ) : (
    <a href={href}>{children}</a>
  );

const REPLY_COMPONENTS = { pre: CodeBlock, img: ReplyImage, a: ReplyLink };

// Notes this panel adds to a reply that did not finish. They are for the
// reader, not the model, and are taken off again before a reply is sent back
// as history.
const STOPPED_NOTE = '\n\n_Stopped._';
const STOPPED_EMPTY = '_Stopped before an answer arrived._';
const FAILED_PREFIX = 'Error: ';
const errorNote = (error: string) => `\n\n_Error: ${error}_`;
const ERROR_NOTE = /\n\n_Error: [^\n]*_$/;

/** What a reply adds to the history, or null for one with no answer in it. */
function replyForHistory(content: string): string | null {
  if (content.startsWith(FAILED_PREFIX) || content === STOPPED_EMPTY) return null;
  const text = content.endsWith(STOPPED_NOTE) ? content.slice(0, -STOPPED_NOTE.length) : content.replace(ERROR_NOTE, '');
  return text.trim() ? text : null;
}

/**
 * The conversation as history for the next message: each question with the
 * answer it got. A question whose reply failed, was stopped before any text or
 * came back empty is left out with it, so the history alternates user and
 * assistant turns and carries no empty messages. aiApi trims it to what the
 * bridge accepts.
 */
function conversationHistory(messages: Message[]): HistoryMessage[] {
  const history: HistoryMessage[] = [];
  for (let i = 0; i + 1 < messages.length; i++) {
    const question = messages[i];
    const reply = messages[i + 1];
    if (question.role !== 'user' || reply.role !== 'assistant') continue;
    i++;
    const answer = replyForHistory(reply.content);
    if (answer) history.push({ role: 'user', content: question.content }, { role: 'assistant', content: answer });
  }
  return history;
}

// ---------------------------------------------------------------------------
// Shared chrome for both layouts (modal and side panel). The two views render
// identical header/messages/input markup — only the layout-toggle buttons in
// the header and one empty-state container class differ, so those are props.
// ---------------------------------------------------------------------------

const ChatHeader: React.FC<{
  showClear: boolean;
  onClear: () => void;
  onClose: () => void;
  /** Layout-toggle buttons rendered between Clear and Close. */
  children: React.ReactNode;
}> = ({ showClear, onClear, onClose, children }) => (
  <div className="flex items-center justify-between h-14 px-5 border-b border-hubble-border shrink-0">
    <div className="min-w-0">
      <h2 className="text-sm font-semibold text-primary">AI Assistant</h2>
      <p className="text-xs text-tertiary truncate">Grounded in live cluster telemetry</p>
    </div>
    <div className="flex items-center gap-1">
      {showClear && (
        <Button variant="ghost" size="sm" onClick={onClear}>Clear</Button>
      )}
      {children}
      <Button variant="ghost" size="sm" iconOnly leftIcon={X} onClick={onClose} aria-label="Close AI Assistant" />
    </div>
  </div>
);

const ChatMessages: React.FC<{
  messages: Message[];
  isTyping: boolean;
  onPromptClick: (prompt: string) => void;
  messagesEndRef: React.RefObject<HTMLDivElement | null>;
  /** The side panel constrains the example-prompt list; the modal doesn't. */
  examplesClassName: string;
  /** Shown after the activity line once a reply has been a while coming. */
  slowHint?: string;
}> = ({ messages, isTyping, onPromptClick, messagesEndRef, examplesClassName, slowHint }) => (
  <div className="flex-1 overflow-y-auto px-5 py-5 space-y-6">
    {messages.length === 0 ? (
      <div className={`h-full flex flex-col justify-center ${examplesClassName}`}>
        <h3 className="text-sm font-semibold text-primary">Ask about your cluster</h3>
        <p className="mt-1.5 text-sm text-secondary leading-relaxed">
          Query live traffic, syscalls, and audit verdicts, or generate a NetworkPolicy or seccomp
          profile — every answer is grounded in what kguardian actually observed.
        </p>
        <div className="mt-5">
          <p className="mb-1 px-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">Try asking</p>
          {EXAMPLE_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              onClick={() => onPromptClick(prompt)}
              className="group w-full flex items-center gap-2.5 text-left px-3 h-9 rounded-control text-sm text-secondary hover:bg-hubble-hover hover:text-primary transition-colors"
            >
              <ArrowRight size={14} className="shrink-0 text-tertiary group-hover:text-hubble-accent transition-colors" />
              <span className="truncate">{prompt}</span>
            </button>
          ))}
        </div>
      </div>
    ) : (
      <>
        {messages.map((message) => (
          <div key={message.id} className="space-y-1.5">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">
              {message.role === 'user' ? 'You' : 'Assistant'}
            </div>
            {message.role === 'assistant' ? (
              <div className="text-sm text-primary prose prose-sm dark:prose-invert max-w-none prose-p:my-1.5 prose-headings:mt-3 prose-headings:mb-1.5 prose-ul:my-1.5 prose-ol:my-1.5 prose-li:my-0.5 prose-pre:my-2 prose-pre:bg-hubble-darker prose-pre:border prose-pre:border-hubble-border prose-table:my-2 prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1 prose-code:text-hubble-accent prose-a:text-hubble-accent">
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={REPLY_COMPONENTS}>{message.content}</ReactMarkdown>
              </div>
            ) : (
              <p className="text-sm text-primary whitespace-pre-wrap">{message.content}</p>
            )}
            {message.role === 'assistant' && message.activity && (
              <div className="flex items-center gap-2 pt-0.5 text-xs text-tertiary">
                <span className="flex gap-1">
                  <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                  <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                  <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                </span>
                <span>{message.activity}</span>
                {message.streaming && slowHint && <span>· {slowHint}</span>}
              </div>
            )}
          </div>
        ))}
        {isTyping && !messages.some(m => m.streaming) && (
          <div className="space-y-1.5">
            <div className="text-[10px] font-semibold uppercase tracking-[0.12em] text-tertiary">Assistant</div>
            <div className="flex gap-1 py-1">
              <span className="w-1.5 h-1.5 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
              <span className="w-1.5 h-1.5 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
              <span className="w-1.5 h-1.5 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </>
    )}
  </div>
);

const ChatInput: React.FC<{
  inputRef: React.RefObject<HTMLTextAreaElement | null>;
  /** The Send/Stop button, so a stream that ends while it holds focus can hand focus on. */
  sendRef: React.RefObject<HTMLButtonElement | null>;
  inputValue: string;
  onInputChange: (value: string) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void;
  onSend: () => void;
  /** Cancels the reply in flight. The one button reads Stop while a reply is
   *  in flight, so a keyboard user's focus is not lost to a swapped element. */
  onStop: () => void;
  isTyping: boolean;
}> = ({ inputRef, sendRef, inputValue, onInputChange, onKeyDown, onSend, onStop, isTyping }) => (
  <div className="border-t border-hubble-border p-3 shrink-0">
    <div className="flex items-end gap-2">
      <textarea
        ref={inputRef}
        value={inputValue}
        onChange={(e) => onInputChange(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder="Ask about traffic, syscalls, or policies…"
        className="flex-1 bg-hubble-darker text-primary placeholder-tertiary text-sm px-3 py-2.5 rounded-control border border-hubble-border
                   focus:outline-none focus:border-hubble-accent resize-none min-h-[60px] max-h-[140px]"
        rows={2}
      />
      <Button
        ref={sendRef}
        variant={isTyping ? 'secondary' : 'primary'}
        leftIcon={isTyping ? Square : Send}
        onClick={isTyping ? onStop : onSend}
        disabled={!isTyping && !inputValue.trim()}
        aria-label={isTyping ? 'Stop generating' : 'Send message'}
      >
        <span className="hidden sm:inline">{isTyping ? 'Stop' : 'Send'}</span>
      </Button>
    </div>
    <p className="mt-2 text-[11px] text-tertiary">
      Enter to send · Shift+Enter for a new line
    </p>
  </div>
);

interface AIAssistantProps {
  isOpen: boolean;
  onClose: () => void;
  onLayoutChange?: (isSidePanel: boolean, isCollapsed: boolean, width?: number) => void;
  namespace?: string;
  podNames?: string[];
  /**
   * Context handed over by a view ("Ask AI" on a CVE): placed in the input,
   * visible and editable, never sent on the user's behalf. A new `nonce`
   * re-applies the same text.
   */
  prefill?: { text: string; nonce: number };
}

type ViewMode = AssistantViewMode;

const AIAssistant: React.FC<AIAssistantProps> = ({ isOpen, onClose, onLayoutChange, namespace, podNames, prefill }) => {
  const [messages, setMessages] = useState<Message[]>(readConversation);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  // Seconds since the reply in flight was sent, for the slow-reply hint.
  const [elapsed, setElapsed] = useState(0);
  const [viewMode, setViewMode] = useState<ViewMode>(initialViewMode);
  const tooNarrowToDock = useMediaQuery(`(max-width: ${DOCK_MIN_WIDTH_PX - 1}px)`);
  const mode: ViewMode = tooNarrowToDock ? 'modal' : viewMode;
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [panelWidth, setPanelWidth] = useState<number>(UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH);
  const [isResizing, setIsResizing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const sendRef = useRef<HTMLButtonElement>(null);

  // Docked, the panel is a landmark, not a Modal, so nothing returned focus
  // when it closed. The opener is read while rendering the mount, before
  // commit: an effect would run again under StrictMode after the input below
  // has taken focus and record the textarea. The rail item is the fallback.
  const [opener] = useState<HTMLElement | null>(() => {
    const el = document.activeElement;
    return el instanceof HTMLElement && el !== document.body ? el : null;
  });
  const closeDocked = () => {
    (opener?.isConnected ? opener : document.querySelector<HTMLElement>('nav button[data-nav-id="assistant"]'))?.focus();
    onClose();
  };

  // A view's "Ask AI" context lands in the input for the user to review.
  const prefillNonce = prefill?.nonce;
  const prefillText = prefill?.text;
  useEffect(() => {
    if (prefillNonce === undefined || prefillText === undefined) return;
    // Apply a handed-over prompt once per nonce.
    setInputValue(prefillText);
    inputRef.current?.focus();
  }, [prefillNonce, prefillText]);
  // Aborts the in-flight streaming request so the model stream (and its
  // server-side tool calls / token spend) is cancelled when the user closes,
  // clears, navigates away, or sends a new message mid-stream.
  const abortRef = useRef<AbortController | null>(null);

  // Abort any in-flight stream on unmount.
  useEffect(() => () => abortRef.current?.abort(), []);

  // Abort the in-flight stream when the panel is closed.
  useEffect(() => {
    if (!isOpen) abortRef.current?.abort();
  }, [isOpen]);

  // Notify parent of layout changes
  useEffect(() => {
    if (onLayoutChange && isOpen) {
      onLayoutChange(mode === 'side-panel', isCollapsed, panelWidth);
    }
  }, [mode, isCollapsed, panelWidth, onLayoutChange, isOpen]);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Stored once a turn settles rather than on every streamed delta, and on
  // unmount so a reply cut off by closing the panel keeps what had arrived.
  const latestMessages = useRef(messages);
  useEffect(() => {
    latestMessages.current = messages;
    if (!messages.some((m) => m.streaming)) storeConversation(messages);
  }, [messages]);
  useEffect(() => () => storeConversation(latestMessages.current), []);

  useEffect(() => {
    if (!isTyping) return;
    const started = Date.now();
    const tick = setInterval(() => setElapsed(Math.round((Date.now() - started) / 1000)), 1000);
    return () => clearInterval(tick);
  }, [isTyping]);

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen) {
      inputRef.current?.focus();
    }
  }, [isOpen]);

  const handleSendMessage = async () => {
    if (!inputValue.trim()) return;

    const userMessage: Message = {
      id: crypto.randomUUID(),
      role: 'user',
      content: inputValue,
      timestamp: new Date(),
    };

    // Conversation history (exclude the in-flight turn) before we mutate state.
    const history = conversationHistory(messages);

    // Streaming placeholder the deltas accumulate into.
    const assistantId = crypto.randomUUID();
    const assistantPlaceholder: Message = {
      id: assistantId,
      role: 'assistant',
      content: '',
      timestamp: new Date(),
      activity: 'Thinking…',
      streaming: true,
    };

    setMessages(prev => [...prev, userMessage, assistantPlaceholder]);
    const currentMessage = inputValue;
    setInputValue('');
    setElapsed(0);
    setIsTyping(true);

    // Immutably patch the in-flight assistant message by id.
    const patchAssistant = (patch: (m: Message) => Message) =>
      setMessages(prev => prev.map(m => (m.id === assistantId ? patch(m) : m)));

    // Build structured context for every message
    const context = JSON.stringify({
      namespace: namespace || undefined,
      // Cap at 20 to match the bridge's getSystemPrompt truncation — sending
      // more just gets dropped server-side.
      podNames: podNames?.slice(0, 20),
    });

    // Cancel any prior in-flight stream, then start a fresh abortable one.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      await streamChatMessage(currentMessage, history, context, {
        onText: (delta) =>
          patchAssistant(m => ({ ...m, content: m.content + delta, activity: undefined })),
        onToolUse: (name) =>
          patchAssistant(m => ({ ...m, activity: toolActivity(name) })),
        onToolResult: () =>
          patchAssistant(m => ({ ...m, activity: 'Analyzing…' })),
        onThinking: () =>
          // Only surface a "thinking" hint while no answer text has arrived yet.
          patchAssistant(m => (m.content ? m : { ...m, activity: 'Thinking…' })),
        onDone: () =>
          patchAssistant(m => ({ ...m, streaming: false, activity: undefined })),
        onError: (error) =>
          patchAssistant(m => ({
            ...m,
            streaming: false,
            activity: undefined,
            content: m.content
              ? `${m.content}${errorNote(error)}`
              : `${FAILED_PREFIX}${error}`,
          })),
      }, { signal: controller.signal });
    } catch (error) {
      patchAssistant(m => ({
        ...m,
        streaming: false,
        activity: undefined,
        content: `${FAILED_PREFIX}${error instanceof Error ? error.message : 'Failed to get AI response. Please check that your API keys are configured.'}`,
      }));
    } finally {
      // Finalize the placeholder in every termination case — including an
      // aborted stream, where neither onDone nor onError fires — so no bubble
      // is left stuck in the streaming state with a spinning activity line.
      patchAssistant(m => (m.streaming ? { ...m, streaming: false, activity: undefined } : m));
      // Ending on the Stop button would leave a disabled Send holding focus,
      // which drops it to the body; the textarea takes it instead.
      if (sendRef.current && document.activeElement === sendRef.current) inputRef.current?.focus();
      setIsTyping(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      // Ignore Enter while a response is streaming — the Send button is already
      // disabled on isTyping; this guards the keyboard path too, so a second
      // turn can't start mid-stream (which would feed a partial answer back as
      // history and run two concurrent streams).
      if (isTyping) return;
      handleSendMessage();
    }
  };

  const handleClearChat = () => {
    // Abort any in-flight stream so it doesn't keep patching a cleared message.
    abortRef.current?.abort();
    setMessages([]);
  };

  const handleStop = () => {
    abortRef.current?.abort();
    // The button becomes a disabled Send once the turn ends and would drop focus.
    inputRef.current?.focus();
    // The stream's finally clears the in-flight state; the bubble says why it ends here.
    setMessages(prev =>
      prev.map(m =>
        m.streaming
          ? { ...m, streaming: false, activity: undefined, content: m.content ? `${m.content}${STOPPED_NOTE}` : STOPPED_EMPTY }
          : m,
      ),
    );
  };

  // Docked, the panel is a landmark, not a dialog, so it has no Modal to close
  // it on Escape; Escape from inside it closes it like every other overlay.
  const onDockedKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== 'Escape') return;
    e.stopPropagation();
    closeDocked();
  };

  const toggleViewMode = () => {
    const next: ViewMode = viewMode === 'modal' ? 'side-panel' : 'modal';
    storeViewMode(next);
    setViewMode(next);
    // Reset collapse state when switching to modal
    if (viewMode === 'side-panel') {
      setIsCollapsed(false);
    }
  };

  const toggleCollapse = () => {
    setIsCollapsed(prev => !prev);
  };

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!isResizing) return;

    const windowWidth = window.innerWidth;
    // Calculate width from right edge
    const newWidth = windowWidth - e.clientX;

    // Constrain between min and max widths
    const maxWidth = windowWidth * UI_DIMENSIONS.AI_PANEL_MAX_WIDTH_RATIO;
    const constrainedWidth = Math.max(
      UI_DIMENSIONS.AI_PANEL_MIN_WIDTH,
      Math.min(maxWidth, newWidth)
    );

    setPanelWidth(constrainedWidth);
  }, [isResizing]);

  const handleMouseUp = useCallback(() => {
    setIsResizing(false);
  }, []);

  // Effect to manage resize listeners
  useEffect(() => {
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'ew-resize';
    } else {
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    }

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      document.body.style.userSelect = '';
      document.body.style.cursor = '';
    };
  }, [isResizing, handleMouseMove, handleMouseUp]);

  if (!isOpen) return null;

  const chatMessages = (examplesClassName: string) => (
    <ChatMessages
      messages={messages}
      isTyping={isTyping}
      onPromptClick={setInputValue}
      messagesEndRef={messagesEndRef}
      examplesClassName={examplesClassName}
      slowHint={isTyping && elapsed >= SLOW_REPLY_AFTER_S ? `still working, ${elapsed}s` : undefined}
    />
  );

  const chatInput = (
    <ChatInput
      inputRef={inputRef}
      sendRef={sendRef}
      inputValue={inputValue}
      onInputChange={setInputValue}
      onKeyDown={handleKeyDown}
      onSend={handleSendMessage}
      onStop={handleStop}
      isTyping={isTyping}
    />
  );

  // Modal view (centered, with backdrop)
  if (mode === 'modal') {
    return (
      <Modal
        isOpen
        onClose={onClose}
        hideHeader
        ariaLabel="AI Assistant"
        className="w-full max-w-3xl h-[600px]"
        contentClassName="flex-1 min-h-0 flex flex-col"
      >
        <ChatHeader showClear={messages.length > 0} onClear={handleClearChat} onClose={onClose}>
          {!tooNarrowToDock && <Button variant="ghost" size="sm" iconOnly leftIcon={Minimize2} onClick={toggleViewMode} aria-label="Dock to side" title="Dock to side" />}
        </ChatHeader>
        {chatMessages('max-w-md mx-auto w-full')}
        {chatInput}
      </Modal>
    );
  }

  // Side panel view (docked to right, no backdrop)
  // Collapsed state - show just a thin vertical bar
  if (isCollapsed) {
    return (
      <div
        role="complementary"
        aria-label="AI Assistant"
        onKeyDown={onDockedKeyDown}
        className="fixed top-0 right-0 bottom-0 z-50 w-12 flex flex-col bg-hubble-card border-l border-hubble-border shadow-2xl items-center justify-center"
      >
        <Button variant="ghost" iconOnly leftIcon={ChevronLeft} onClick={toggleCollapse} aria-label="Expand AI Assistant" title="Expand AI Assistant" />
        <div className="flex-1 flex items-center justify-center">
          <div className="transform -rotate-90 whitespace-nowrap text-sm text-tertiary font-medium">
            AI Assistant
          </div>
        </div>
        {messages.length > 0 && (
          <div className="mb-4 flex items-center justify-center w-6 h-6 rounded-full bg-hubble-accent text-white text-xs">
            {messages.filter(m => m.role === 'assistant').length}
          </div>
        )}
      </div>
    );
  }

  // Expanded side panel
  return (
    <div
      role="complementary"
      aria-label="AI Assistant"
      onKeyDown={onDockedKeyDown}
      className="fixed top-0 right-0 bottom-0 z-50 flex flex-col bg-hubble-card border-l border-hubble-border shadow-2xl"
      style={{ width: `${panelWidth}px` }}
    >
      {/* Resize Handle */}
      <div
        onMouseDown={handleMouseDown}
        className={`absolute left-0 top-0 bottom-0 w-1 cursor-ew-resize hover:bg-hubble-accent/50 transition-colors ${
          isResizing ? 'bg-hubble-accent' : 'bg-transparent'
        }`}
        title="Drag to resize"
      >
        {/* Visual indicator */}
        <div className="absolute inset-y-0 left-1/2 -translate-x-1/2 flex flex-col justify-center opacity-0 hover:opacity-100 transition-opacity">
          <div className="flex flex-col gap-1">
            <div className="w-0.5 h-8 bg-hubble-accent rounded-full"></div>
          </div>
        </div>
      </div>

      <ChatHeader showClear={messages.length > 0} onClear={handleClearChat} onClose={closeDocked}>
        <Button variant="ghost" size="sm" iconOnly leftIcon={ChevronRight} onClick={toggleCollapse} aria-label="Collapse panel" title="Collapse panel" />
        <Button variant="ghost" size="sm" iconOnly leftIcon={Maximize2} onClick={toggleViewMode} aria-label="Expand to center" title="Expand to center" />
      </ChatHeader>
      {chatMessages('max-w-sm w-full')}
      {chatInput}
    </div>
  );
};

export default AIAssistant;
