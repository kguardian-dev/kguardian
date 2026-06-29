import React, { useState, useRef, useEffect, useCallback } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { X, Send, Sparkles, Bot, User, Minimize2, Maximize2, ChevronRight, ChevronLeft, Copy, Check } from 'lucide-react';
import { streamChatMessage, type HistoryMessage } from '../services/aiApi';
import { UI_DIMENSIONS } from '../constants/ui';

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
      podNames: podNames?.slice(0, 30),
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

  // Modal view (centered, with backdrop)
  if (viewMode === 'modal') {
    return (
      <>
        {/* Backdrop */}
        <div
          className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 transition-opacity"
          onClick={onClose}
        />

        {/* Modal */}
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none">
          <div
            className="bg-hubble-card border border-hubble-border rounded-lg shadow-2xl w-full max-w-3xl h-[600px] flex flex-col pointer-events-auto"
            onClick={(e) => e.stopPropagation()}
          >
          {/* Header */}
          <div className="flex items-center justify-between px-6 py-4 border-b border-hubble-border">
            <div className="flex items-center gap-3">
              <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-hubble-accent/20">
                <Sparkles className="w-5 h-5 text-hubble-accent" />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-primary">AI Assistant</h2>
                <p className="text-xs text-tertiary">Ask questions about your cluster</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {messages.length > 0 && (
                <button
                  onClick={handleClearChat}
                  className="px-3 py-1.5 text-xs text-tertiary hover:text-secondary transition-colors"
                >
                  Clear
                </button>
              )}
              <button
                onClick={toggleViewMode}
                className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
                aria-label="Dock to side"
                title="Dock to side"
              >
                <Minimize2 className="w-5 h-5" />
              </button>
              <button
                onClick={onClose}
                className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
                aria-label="Close AI Assistant"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {messages.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-center">
                <div className="flex items-center justify-center w-16 h-16 rounded-full bg-hubble-accent/10 mb-4">
                  <Sparkles className="w-8 h-8 text-hubble-accent" />
                </div>
                <h3 className="text-lg font-semibold text-primary mb-2">
                  Welcome to AI Assistant
                </h3>
                <p className="text-sm text-tertiary max-w-md">
                  Ask me anything about your Kubernetes cluster, network traffic, security events, or system calls.
                </p>
                <div className="mt-6 space-y-2 text-left">
                  <p className="text-xs text-tertiary font-medium">Example prompts:</p>
                  <button
                    onClick={() => setInputValue('What pods have the most network traffic?')}
                    className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
                  >
                    "What pods have the most network traffic?"
                  </button>
                  <button
                    onClick={() => setInputValue('Show me any suspicious system calls')}
                    className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
                  >
                    "Show me any suspicious system calls"
                  </button>
                  <button
                    onClick={() => setInputValue('Summarize security events in the last hour')}
                    className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
                  >
                    "Summarize security events in the last hour"
                  </button>
                </div>
              </div>
            ) : (
              <>
                {messages.map((message) => (
                  <div
                    key={message.id}
                    className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    {message.role === 'assistant' && (
                      <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-accent/20 flex items-center justify-center">
                        <Bot className="w-5 h-5 text-hubble-accent" />
                      </div>
                    )}
                    <div
                      className={`max-w-[70%] rounded-lg px-4 py-3 ${
                        message.role === 'user'
                          ? 'bg-hubble-accent text-white'
                          : 'bg-hubble-dark text-primary'
                      }`}
                    >
                      {message.role === 'assistant' ? (
                        <div className="text-sm prose prose-sm dark:prose-invert max-w-none prose-p:my-1 prose-headings:my-2 prose-ul:my-1 prose-ol:my-1 prose-li:my-0.5 prose-pre:my-2 prose-table:my-2 prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1 prose-code:text-hubble-accent prose-a:text-hubble-accent">
                          <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ pre: CodeBlock }}>{message.content}</ReactMarkdown>
                        </div>
                      ) : (
                        <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                      )}
                      {message.role === 'assistant' && message.activity && (
                        <div className="flex items-center gap-2 mt-1 text-xs text-tertiary italic">
                          <span className="flex gap-1">
                            <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                            <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                            <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                          </span>
                          <span>{message.activity}</span>
                        </div>
                      )}
                      <p
                        className={`text-xs mt-1 ${
                          message.role === 'user' ? 'text-blue-100' : 'text-tertiary'
                        }`}
                      >
                        {message.timestamp.toLocaleTimeString()}
                      </p>
                    </div>
                    {message.role === 'user' && (
                      <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-success/20 flex items-center justify-center">
                        <User className="w-5 h-5 text-hubble-success" />
                      </div>
                    )}
                  </div>
                ))}
                {isTyping && !messages.some(m => m.streaming) && (
                  <div className="flex gap-3 justify-start">
                    <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-accent/20 flex items-center justify-center">
                      <Bot className="w-5 h-5 text-hubble-accent" />
                    </div>
                    <div className="bg-hubble-dark rounded-lg px-4 py-3">
                      <div className="flex gap-1">
                        <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                        <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                        <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                      </div>
                    </div>
                  </div>
                )}
                <div ref={messagesEndRef} />
              </>
            )}
          </div>

          {/* Input */}
          <div className="border-t border-hubble-border p-4">
            <div className="flex gap-3">
              <textarea
                ref={inputRef}
                value={inputValue}
                onChange={(e) => setInputValue(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask a question... (Shift+Enter for new line)"
                className="flex-1 bg-hubble-dark text-primary placeholder-tertiary px-4 py-3 rounded-lg border border-hubble-border
                           focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent
                           resize-none min-h-[60px] max-h-[120px]"
                rows={2}
              />
              <button
                onClick={handleSendMessage}
                disabled={!inputValue.trim() || isTyping}
                className="px-6 py-3 bg-hubble-accent text-white rounded-lg hover:bg-blue-600
                           transition-colors disabled:opacity-50 disabled:cursor-not-allowed
                           flex items-center gap-2"
              >
                <Send className="w-4 h-4" />
                <span className="hidden sm:inline">Send</span>
              </button>
            </div>
            <p className="text-xs text-tertiary mt-2">
              AI Assistant uses your configured LLM provider (OpenAI, Anthropic, Gemini, or GitHub Copilot). Configure API keys in Helm values.
            </p>
          </div>
        </div>
      </div>
    </>
    );
  }

  // Side panel view (docked to right, no backdrop)
  // Collapsed state - show just a thin vertical bar
  if (isCollapsed) {
    return (
      <div className="fixed top-0 right-0 bottom-0 z-50 w-12 flex flex-col bg-hubble-card border-l border-hubble-border shadow-2xl items-center justify-center">
        <button
          onClick={toggleCollapse}
          className="p-3 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
          aria-label="Expand AI Assistant"
          title="Expand AI Assistant"
        >
          <ChevronLeft className="w-5 h-5" />
        </button>
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

      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-hubble-border">
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-10 h-10 rounded-lg bg-hubble-accent/20">
            <Sparkles className="w-5 h-5 text-hubble-accent" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-primary">AI Assistant</h2>
            <p className="text-xs text-tertiary">Ask questions about your cluster</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {messages.length > 0 && (
            <button
              onClick={handleClearChat}
              className="px-3 py-1.5 text-xs text-tertiary hover:text-secondary transition-colors"
            >
              Clear
            </button>
          )}
          <button
            onClick={toggleCollapse}
            className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
            aria-label="Collapse panel"
            title="Collapse panel"
          >
            <ChevronRight className="w-5 h-5" />
          </button>
          <button
            onClick={toggleViewMode}
            className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
            aria-label="Expand to center"
            title="Expand to center"
          >
            <Maximize2 className="w-5 h-5" />
          </button>
          <button
            onClick={onClose}
            className="p-2 text-tertiary hover:text-primary hover:bg-hubble-dark rounded-lg transition-colors"
            aria-label="Close AI Assistant"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-6 space-y-4">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <div className="flex items-center justify-center w-16 h-16 rounded-full bg-hubble-accent/10 mb-4">
              <Sparkles className="w-8 h-8 text-hubble-accent" />
            </div>
            <h3 className="text-lg font-semibold text-primary mb-2">
              Welcome to AI Assistant
            </h3>
            <p className="text-sm text-tertiary max-w-md">
              Ask me anything about your Kubernetes cluster, network traffic, security events, or system calls.
            </p>
            <div className="mt-6 space-y-2 text-left w-full max-w-sm">
              <p className="text-xs text-tertiary font-medium">Example prompts:</p>
              <button
                onClick={() => setInputValue('What pods have the most network traffic?')}
                className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
              >
                "What pods have the most network traffic?"
              </button>
              <button
                onClick={() => setInputValue('Show me any suspicious system calls')}
                className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
              >
                "Show me any suspicious system calls"
              </button>
              <button
                onClick={() => setInputValue('Summarize security events in the last hour')}
                className="block w-full text-left px-4 py-2 text-sm text-secondary bg-hubble-dark hover:bg-hubble-darker rounded-lg transition-colors"
              >
                "Summarize security events in the last hour"
              </button>
            </div>
          </div>
        ) : (
          <>
            {messages.map((message) => (
              <div
                key={message.id}
                className={`flex gap-3 ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
              >
                {message.role === 'assistant' && (
                  <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-accent/20 flex items-center justify-center">
                    <Bot className="w-5 h-5 text-hubble-accent" />
                  </div>
                )}
                <div
                  className={`max-w-[70%] rounded-lg px-4 py-3 ${
                    message.role === 'user'
                      ? 'bg-hubble-accent text-white'
                      : 'bg-hubble-dark text-primary'
                  }`}
                >
                  {message.role === 'assistant' ? (
                    <div className="text-sm prose prose-sm dark:prose-invert max-w-none prose-p:my-1 prose-headings:my-2 prose-ul:my-1 prose-ol:my-1 prose-li:my-0.5 prose-pre:my-2 prose-table:my-2 prose-th:px-2 prose-th:py-1 prose-td:px-2 prose-td:py-1 prose-code:text-hubble-accent prose-a:text-hubble-accent">
                      <ReactMarkdown remarkPlugins={[remarkGfm]} components={{ pre: CodeBlock }}>{message.content}</ReactMarkdown>
                    </div>
                  ) : (
                    <p className="text-sm whitespace-pre-wrap">{message.content}</p>
                  )}
                  {message.role === 'assistant' && message.activity && (
                    <div className="flex items-center gap-2 mt-1 text-xs text-tertiary italic">
                      <span className="flex gap-1">
                        <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                        <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                        <span className="w-1.5 h-1.5 bg-hubble-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                      </span>
                      <span>{message.activity}</span>
                    </div>
                  )}
                  <p
                    className={`text-xs mt-1 ${
                      message.role === 'user' ? 'text-blue-100' : 'text-tertiary'
                    }`}
                  >
                    {message.timestamp.toLocaleTimeString()}
                  </p>
                </div>
                {message.role === 'user' && (
                  <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-success/20 flex items-center justify-center">
                    <User className="w-5 h-5 text-hubble-success" />
                  </div>
                )}
              </div>
            ))}
            {isTyping && !messages.some(m => m.streaming) && (
              <div className="flex gap-3 justify-start">
                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-hubble-accent/20 flex items-center justify-center">
                  <Bot className="w-5 h-5 text-hubble-accent" />
                </div>
                <div className="bg-hubble-dark rounded-lg px-4 py-3">
                  <div className="flex gap-1">
                    <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                    <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                    <div className="w-2 h-2 bg-tertiary rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </>
        )}
      </div>

      {/* Input */}
      <div className="border-t border-hubble-border p-4">
        <div className="flex gap-3">
          <textarea
            ref={inputRef}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask a question... (Shift+Enter for new line)"
            className="flex-1 bg-hubble-dark text-primary placeholder-tertiary px-4 py-3 rounded-lg border border-hubble-border
                       focus:outline-none focus:ring-2 focus:ring-hubble-accent focus:border-transparent
                       resize-none min-h-[60px] max-h-[120px]"
            rows={2}
          />
          <button
            onClick={handleSendMessage}
            disabled={!inputValue.trim() || isTyping}
            className="px-6 py-3 bg-hubble-accent text-white rounded-lg hover:bg-blue-600
                       transition-colors disabled:opacity-50 disabled:cursor-not-allowed
                       flex items-center gap-2"
          >
            <Send className="w-4 h-4" />
            <span className="hidden sm:inline">Send</span>
          </button>
        </div>
        <p className="text-xs text-tertiary mt-2">
          AI Assistant uses your configured LLM provider (OpenAI, Anthropic, Gemini, or GitHub Copilot). Configure API keys in Helm values.
        </p>
      </div>
    </div>
  );
};

export default AIAssistant;
