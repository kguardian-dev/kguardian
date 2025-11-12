import { useState, useCallback, useEffect } from 'react';
import { RefreshCw, Shield, Sparkles } from 'lucide-react';
import NetworkGraph from './components/NetworkGraph';
import NamespaceSelector from './components/NamespaceSelector';
import DataTable from './components/DataTable';
import ThemeToggle from './components/ThemeToggle';
import AIAssistant from './components/AIAssistant';
import NetworkPolicyEditor from './components/NetworkPolicyEditor';
import { usePodData } from './hooks/usePodData';
import { useNamespaces } from './hooks/useNamespaces';
import type { PodNodeData } from './types';
import { UI_DIMENSIONS } from './constants/ui';

function App() {
  const [namespace, setNamespace] = useState('default');
  const [selectedPod, setSelectedPod] = useState<PodNodeData | null>(null);
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isPolicyEditorOpen, setIsPolicyEditorOpen] = useState(false);
  const [policyEditorPod, setPolicyEditorPod] = useState<PodNodeData | null>(null);
  const [aiSidePanel, setAISidePanel] = useState<{
    isSidePanel: boolean;
    isCollapsed: boolean;
    width: number;
  }>({
    isSidePanel: false,
    isCollapsed: false,
    width: UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH
  });
  const [tableHeight, setTableHeight] = useState<number>(UI_DIMENSIONS.TABLE_DEFAULT_HEIGHT);
  const [isResizing, setIsResizing] = useState(false);

  const { namespaces } = useNamespaces();
  const { pods, loading, error, togglePodExpansion, refreshData } = usePodData(namespace);

  // Calculate the right padding for content when AI panel is docked (in pixels)
  const contentPaddingRightPx = aiSidePanel.isSidePanel
    ? (aiSidePanel.isCollapsed ? UI_DIMENSIONS.AI_PANEL_COLLAPSED_WIDTH : aiSidePanel.width)
    : 0;

  const handlePodSelect = (pod: PodNodeData | null) => {
    setSelectedPod(pod);
  };

  const handleBuildPolicy = (pod: PodNodeData) => {
    setPolicyEditorPod(pod);
    setIsPolicyEditorOpen(true);
  };

  const handleAILayoutChange = useCallback((isSidePanel: boolean, isCollapsed: boolean, width?: number) => {
    setAISidePanel({ isSidePanel, isCollapsed, width: width ?? UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH });
  }, []);

  const handleAIClose = useCallback(() => {
    setIsAIAssistantOpen(false);
    // Reset layout when closing to remove padding
    setAISidePanel({
      isSidePanel: false,
      isCollapsed: false,
      width: UI_DIMENSIONS.AI_PANEL_DEFAULT_WIDTH
    });
  }, []);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  }, []);

  const handleMouseMove = useCallback((e: MouseEvent) => {
    if (!isResizing) return;

    const windowHeight = window.innerHeight;
    const availableHeight = windowHeight - UI_DIMENSIONS.HEADER_HEIGHT - UI_DIMENSIONS.FOOTER_HEIGHT;

    // Calculate height from bottom
    const newHeight = windowHeight - e.clientY - UI_DIMENSIONS.FOOTER_HEIGHT;

    // Constrain between min and max heights
    const maxHeight = availableHeight * UI_DIMENSIONS.TABLE_MAX_HEIGHT_RATIO;
    const constrainedHeight = Math.max(
      UI_DIMENSIONS.TABLE_MIN_HEIGHT,
      Math.min(maxHeight, newHeight)
    );

    setTableHeight(constrainedHeight);
  }, [isResizing]);

  const handleMouseUp = useCallback(() => {
    setIsResizing(false);
  }, []);

  // Effect to manage resize listeners
  useEffect(() => {
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove);
      document.addEventListener('mouseup', handleMouseUp);
      // Prevent text selection during resize
      document.body.style.userSelect = 'none';
      document.body.style.cursor = 'ns-resize';
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

  return (
    <div
      className="flex flex-col h-screen bg-hubble-darker transition-all duration-300"
      style={{ paddingRight: `${contentPaddingRightPx}px` }}
    >
      {/* Header */}
      <header className="bg-hubble-dark border-b border-hubble-border px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-hubble-accent" />
            <div>
              <h1 className="text-2xl font-bold text-primary">
                kguardian
              </h1>
              <p className="text-sm text-tertiary">
                Network Traffic & Security Monitoring
              </p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <button
              onClick={() => setIsAIAssistantOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-hubble-accent/10 border border-hubble-accent/30
                         rounded-lg text-hubble-accent hover:bg-hubble-accent/20 hover:border-hubble-accent
                         transition-all"
              title="Open AI Assistant"
            >
              <Sparkles className="w-4 h-4" />
              <span className="hidden sm:inline font-medium">AI</span>
            </button>

            <NamespaceSelector
              selectedNamespace={namespace}
              onNamespaceChange={setNamespace}
              namespaces={namespaces}
            />

            <ThemeToggle />

            <button
              onClick={refreshData}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 bg-hubble-card border border-hubble-border
                         rounded-lg text-secondary hover:bg-hubble-dark hover:border-hubble-accent
                         transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              title="Refresh data"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {error && (
          <div className="bg-hubble-error/20 border border-hubble-error text-hubble-error px-6 py-3">
            <p className="text-sm">Error: {error}</p>
          </div>
        )}

        {loading && pods.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <RefreshCw className="w-8 h-8 text-hubble-accent animate-spin mx-auto mb-4" />
              <p className="text-secondary">Loading pod data...</p>
            </div>
          </div>
        ) : (
          <>
            {/* Network Visualization */}
            <div className="flex-1 min-h-0">
              <NetworkGraph
                pods={pods}
                onPodToggle={togglePodExpansion}
                onPodSelect={handlePodSelect}
                selectedPodId={selectedPod?.id || null}
                onBuildPolicy={handleBuildPolicy}
              />
            </div>

            {/* Resize Handle */}
            <div
              onMouseDown={handleMouseDown}
              className={`h-1 border-t border-hubble-border cursor-ns-resize hover:bg-hubble-accent/50 transition-colors relative group ${
                isResizing ? 'bg-hubble-accent' : 'bg-hubble-border'
              }`}
              title="Drag to resize"
            >
              {/* Visual indicator */}
              <div className="absolute inset-x-0 top-1/2 -translate-y-1/2 flex justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                <div className="flex gap-1">
                  <div className="w-8 h-0.5 bg-hubble-accent rounded-full"></div>
                </div>
              </div>
            </div>

            {/* Data Table */}
            <div
              className="border-t border-hubble-border bg-hubble-dark overflow-hidden"
              style={{ height: `${tableHeight}px` }}
            >
              <DataTable selectedPod={selectedPod} allPods={pods} />
            </div>
          </>
        )}
      </div>

      {/* Footer */}
      <footer className="bg-hubble-dark border-t border-hubble-border px-6 py-2 text-center text-xs text-tertiary">
        <p>Kube Guardian v0.1.0 | Namespace: {namespace} | Pods: {pods.length}</p>
      </footer>

      {/* AI Assistant Modal */}
      <AIAssistant
        isOpen={isAIAssistantOpen}
        onClose={handleAIClose}
        onLayoutChange={handleAILayoutChange}
      />

      {/* Network Policy Editor Modal */}
      <NetworkPolicyEditor
        isOpen={isPolicyEditorOpen}
        onClose={() => setIsPolicyEditorOpen(false)}
        pod={policyEditorPod}
        allPods={pods}
      />
    </div>
  );
}

export default App;
