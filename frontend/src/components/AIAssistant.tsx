import React, { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { X, Send, ArrowRight, Minimize2, Maximize2, ChevronRight, ChevronLeft, Copy, Check } from 'lucide-react';
import { streamChatMessage, type HistoryMessage } from '../services/aiApi';
import { UI_DIMENSIONS } from '../constants/ui';
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
}> = ({ messages, isTyping, onPromptClick, messagesEndRef, examplesClassName }) => (
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
                <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ pre: CodeBlock }}>{message.content}</ReactMarkdown>
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
  inputValue: string;
  onInputChange: (value: string) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void;
  onSend: () => void;
  isTyping: boolean;
}> = ({ inputRef, inputValue, onInputChange, onKeyDown, onSend, isTyping }) => (
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
      <Button variant="primary" leftIcon={Send} onClick={onSend} disabled={!inputValue.trim() || isTyping} aria-label="Send message">
        <span className="hidden sm:inline">Send</span>
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
}

type ViewMode = 'modal' | 'side-panel';

const AIAssistant: React.FC<AIAssistantProps> = ({ isOpen, onClose, onLayoutChange, namespace, podNames }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('modal');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [panelWidth, setPanelWidth] = useState<number>(UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH);
  const [isResizing, setIsResizing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
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
      onLayoutChange(viewMode === 'side-panel', isCollapsed, panelWidth);
    }
  }, [viewMode, isCollapsed, panelWidth, onLayoutChange, isOpen]);

  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

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
    const history: HistoryMessage[] = messages.map(msg => ({
      role: msg.role,
      content: msg.content,
    }));

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
              ? `${m.content}\n\n_Error: ${error}_`
              : `Error: ${error}`,
          })),
      }, { signal: controller.signal });
    } catch (error) {
      patchAssistant(m => ({
        ...m,
        streaming: false,
        activity: undefined,
        content: `Error: ${error instanceof Error ? error.message : 'Failed to get AI response. Please check that your API keys are configured.'}`,
      }));
    } finally {
      // Finalize the placeholder in every termination case — including an
      // aborted stream, where neither onDone nor onError fires — so no bubble
      // is left stuck in the streaming state with a spinning activity line.
      patchAssistant(m => (m.streaming ? { ...m, streaming: false, activity: undefined } : m));
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

  const toggleViewMode = () => {
    setViewMode(prev => prev === 'modal' ? 'side-panel' : 'modal');
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
    />
  );

  const chatInput = (
    <ChatInput
      inputRef={inputRef}
      inputValue={inputValue}
      onInputChange={setInputValue}
      onKeyDown={handleKeyDown}
      onSend={handleSendMessage}
      isTyping={isTyping}
    />
  );

  // Modal view (centered, with backdrop)
  if (viewMode === 'modal') {
    return (
      <Modal
        isOpen
        onClose={onClose}
        hideHeader
        className="w-full max-w-3xl h-[600px]"
        contentClassName="flex-1 min-h-0 flex flex-col"
      >
        <ChatHeader showClear={messages.length > 0} onClear={handleClearChat} onClose={onClose}>
          <Button variant="ghost" size="sm" iconOnly leftIcon={Minimize2} onClick={toggleViewMode} aria-label="Dock to side" title="Dock to side" />
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
      <div className="fixed top-0 right-0 bottom-0 z-50 w-12 flex flex-col bg-hubble-card border-l border-hubble-border shadow-2xl items-center justify-center">
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

      <ChatHeader showClear={messages.length > 0} onClear={handleClearChat} onClose={onClose}>
        <Button variant="ghost" size="sm" iconOnly leftIcon={ChevronRight} onClick={toggleCollapse} aria-label="Collapse panel" title="Collapse panel" />
        <Button variant="ghost" size="sm" iconOnly leftIcon={Maximize2} onClick={toggleViewMode} aria-label="Expand to center" title="Expand to center" />
      </ChatHeader>
      {chatMessages('max-w-sm w-full')}
      {chatInput}
    </div>
  );
};

export default AIAssistant;
