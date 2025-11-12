import React, { useState, useRef, useEffect, useCallback } from 'react';
import { X, Send, Sparkles, Bot, User, Minimize2, Maximize2, ChevronRight, ChevronLeft } from 'lucide-react';
import { sendChatMessage, type HistoryMessage } from '../services/aiApi';

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

interface AIAssistantProps {
  isOpen: boolean;
  onClose: () => void;
  onLayoutChange?: (isSidePanel: boolean, isCollapsed: boolean, width?: number) => void;
}

type ViewMode = 'modal' | 'side-panel';

const AIAssistant: React.FC<AIAssistantProps> = ({ isOpen, onClose, onLayoutChange }) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [viewMode, setViewMode] = useState<ViewMode>('modal');
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [panelWidth, setPanelWidth] = useState(448); // Default 448px (max-w-md)
  const [isResizing, setIsResizing] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

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
      id: Date.now().toString(),
      role: 'user',
      content: inputValue,
      timestamp: new Date(),
    };

    setMessages(prev => [...prev, userMessage]);
    const currentMessage = inputValue;
    setInputValue('');
    setIsTyping(true);

    try {
      // Build conversation history (exclude system messages)
      const history: HistoryMessage[] = messages.map(msg => ({
        role: msg.role,
        content: msg.content,
      }));

      // Call the real AI API with conversation history
      const response = await sendChatMessage(currentMessage, history);

      const assistantMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: response.message,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, assistantMessage]);
    } catch (error) {
      const errorMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: 'assistant',
        content: `Error: ${error instanceof Error ? error.message : 'Failed to get AI response. Please check that your API keys are configured.'}`,
        timestamp: new Date(),
      };
      setMessages(prev => [...prev, errorMessage]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleClearChat = () => {
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

    // Constrain between 300px and 80% of window width
    const minWidth = 300;
    const maxWidth = windowWidth * 0.8;
    const constrainedWidth = Math.max(minWidth, Math.min(maxWidth, newWidth));

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
                      <p className="text-sm whitespace-pre-wrap">{message.content}</p>
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
                {isTyping && (
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
                  <p className="text-sm whitespace-pre-wrap">{message.content}</p>
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
            {isTyping && (
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
