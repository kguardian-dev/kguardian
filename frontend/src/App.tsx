import { useState, useCallback, useEffect, lazy, Suspense } from 'react';
import { Bot, RefreshCw, Share2, ShieldAlert, LayoutDashboard } from 'lucide-react';
import NetworkGraph from './components/NetworkGraph';
import { FindingsView } from './components/FindingsView';
import { useHashRoute } from './hooks/useHashRoute';
import NamespaceSelector from './components/NamespaceSelector';
import DataTable from './components/DataTable';
import { Sidebar, type NavItem } from './components/Sidebar';
import { ClusterSwitcher } from './components/ClusterSwitcher';
import { AccountMenu } from './components/AccountMenu';
import { SettingsPanel } from './components/SettingsPanel';
import { useSettings } from './contexts/SettingsContext';
import { useCluster } from './contexts/ClusterContext';

// Heavy surfaces — lazy so they stay out of the initial bundle and only load
// when first opened (the NetworkPolicyEditor alone is ~2k lines).
const AIAssistant = lazy(() => import('./components/AIAssistant'));
const AuditVerdictsPanel = lazy(() => import('./components/AuditVerdictsPanel'));
const NetworkPolicyEditor = lazy(() => import('./components/NetworkPolicyEditor'));
import { Button } from './components/ui/Button';
import { EmptyState } from './components/ui/EmptyState';
import { GraphSkeleton } from './components/ui/Skeleton';
import { Server } from 'lucide-react';
import { usePodData } from './hooks/usePodData';
import { useNamespaces } from './hooks/useNamespaces';
import type { PodNodeData } from './types';
import { UI_DIMENSIONS } from './constants/ui';

const ROUTES = ['map', 'findings'] as const;

function App() {
  const { settings, updateSettings } = useSettings();
  const { activeCluster } = useCluster();
  // Namespace selection is remembered per cluster, so switching clusters
  // restores that cluster's own namespace rather than carrying one across.
  const [nsByCluster, setNsByCluster] = useState<Record<string, string>>({});
  const namespace = nsByCluster[activeCluster.id] ?? settings.defaultNamespace ?? 'default';
  const setNamespace = useCallback(
    (ns: string) => setNsByCluster((prev) => ({ ...prev, [activeCluster.id]: ns })),
    [activeCluster.id],
  );
  const [selectedPod, setSelectedPod] = useState<PodNodeData | null>(null);
  const [view, setView] = useHashRoute<(typeof ROUTES)[number]>('map', ROUTES);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isAuditPanelOpen, setIsAuditPanelOpen] = useState(false);
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
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => localStorage.getItem('kg-rail-collapsed') === '1');

  const { namespaces } = useNamespaces();
  // If the current selection isn't a namespace that actually has monitored pods
  // (the hardcoded 'default' usually isn't), resolve to the first real one so
  // the graph isn't empty on first paint. Derived rather than synced via an
  // effect — no extra render, and it can't loop.
  const effectiveNamespace =
    namespaces.length > 0 && !namespaces.includes(namespace) ? namespaces[0] : namespace;
  const { pods, allPodsLookup, services, loading, error, togglePodExpansion, refreshData } = usePodData(effectiveNamespace);

  const toggleRail = useCallback(() => {
    setRailCollapsed((c) => {
      localStorage.setItem('kg-rail-collapsed', c ? '0' : '1');
      return !c;
    });
  }, []);

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

  // Jump from a finding straight to that workload on the map.
  const handleFindingSelect = useCallback((pod: PodNodeData) => {
    setSelectedPod(pod);
    setView('map');
  }, [setView]);

  const navItems: NavItem[] = [
    {
      id: 'findings', label: 'Findings', icon: LayoutDashboard, group: 'Views',
      hint: 'Prioritized runtime-security signals',
      active: view === 'findings', onClick: () => setView('findings'),
    },
    {
      id: 'map', label: 'Network Map', icon: Share2, group: 'Views', hint: 'Live pod traffic graph',
      active: view === 'map',
      onClick: () => setView('map'),
    },
    {
      id: 'audit', label: 'Audit Verdicts', icon: ShieldAlert, group: 'Tools',
      hint: 'Flows an AuditNetworkPolicy would deny',
      active: isAuditPanelOpen, onClick: () => setIsAuditPanelOpen(true),
    },
    {
      id: 'assistant', label: 'AI Assistant', icon: Bot, group: 'Tools',
      hint: 'Ask about cluster traffic & policies',
      active: isAIAssistantOpen, onClick: () => setIsAIAssistantOpen(true),
    },
  ];

  const sectionTitle = view === 'findings' ? 'Findings' : 'Network Map';
  const sectionSubtitle =
    view === 'findings'
      ? `Namespace ${effectiveNamespace}`
      : `Namespace ${effectiveNamespace} · ${pods.length} pods`;

  return (
    <div className="flex h-screen bg-hubble-darker">
      <Sidebar
        items={navItems}
        version={__APP_VERSION__}
        topSlot={<ClusterSwitcher collapsed={railCollapsed} />}
        footer={<AccountMenu collapsed={railCollapsed} onOpenSettings={() => setSettingsOpen(true)} />}
        collapsed={railCollapsed}
        onToggleCollapse={toggleRail}
      />

      <div
        className="flex-1 flex flex-col min-w-0 transition-all duration-300"
        style={{ paddingRight: `${contentPaddingRightPx}px` }}
      >
        {/* Top bar */}
        <header className="h-14 shrink-0 flex items-center justify-between gap-4 px-5 border-b border-hubble-border bg-hubble-dark">
          <div className="min-w-0">
            <h1 className="text-sm font-semibold text-primary truncate">{sectionTitle}</h1>
            <p className="text-xs text-tertiary truncate">{sectionSubtitle}</p>
          </div>

          <div className="flex items-center gap-2">
            <NamespaceSelector
              selectedNamespace={effectiveNamespace}
              onNamespaceChange={setNamespace}
              namespaces={namespaces}
            />
            <Button
              variant="secondary"
              leftIcon={RefreshCw}
              onClick={refreshData}
              disabled={loading}
              className={loading ? '[&_svg]:animate-spin' : ''}
            >
              Refresh
            </Button>
          </div>
        </header>

        {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {view === 'findings' ? (
          <FindingsView
            pods={pods}
            namespace={effectiveNamespace}
            onSelectPod={handleFindingSelect}
            onBuildPolicy={handleBuildPolicy}
            onOpenAudit={() => setIsAuditPanelOpen(true)}
          />
        ) : (
        <>
        {error && (
          <div className="bg-hubble-error/20 border border-hubble-error text-hubble-error px-6 py-3">
            <p className="text-sm">Error: {error}</p>
          </div>
        )}

        {loading && pods.length === 0 ? (
          <div className="flex-1 min-h-0">
            <GraphSkeleton />
          </div>
        ) : !error && pods.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <EmptyState
              icon={Server}
              title={`No workloads in ${effectiveNamespace}`}
              description="This namespace has no observed pods yet. Switch namespaces from the header, or wait for the controller to report traffic from workloads here."
              action={
                <Button variant="secondary" size="sm" leftIcon={RefreshCw} onClick={refreshData}>
                  Refresh
                </Button>
              }
            />
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
                allPodsLookup={allPodsLookup}
                services={services}
                showExternalNodes={settings.showExternalNodes}
                onToggleExternalNodes={() => updateSettings({ showExternalNodes: !settings.showExternalNodes })}
                showTraffic={settings.showTraffic}
                onToggleTraffic={() => updateSettings({ showTraffic: !settings.showTraffic })}
                layoutDirection={settings.layoutDirection}
                onToggleLayoutDirection={() => updateSettings({ layoutDirection: settings.layoutDirection === 'LR' ? 'TB' : 'LR' })}
              />
            </div>

            {/* Collapsible Bottom Panel: Resize Handle + Data Table */}
            <div
              className="overflow-hidden transition-all duration-300 ease-in-out"
              style={{
                height: selectedPod ? `${tableHeight + 4}px` : '0px',
                opacity: selectedPod ? 1 : 0,
              }}
            >
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
                <DataTable selectedPod={selectedPod} allPodsLookup={allPodsLookup} services={services} />
              </div>
            </div>
          </>
        )}
        </>
        )}
      </div>

      </div>

      {/* Heavy surfaces: mounted (and their chunk fetched) only while open. */}
      {isAIAssistantOpen && (
        <Suspense fallback={null}>
          <AIAssistant
            isOpen
            onClose={handleAIClose}
            onLayoutChange={handleAILayoutChange}
            namespace={effectiveNamespace}
            podNames={pods.map(p => p.label)}
          />
        </Suspense>
      )}

      {isPolicyEditorOpen && (
        <Suspense fallback={null}>
          <NetworkPolicyEditor
            isOpen
            onClose={() => setIsPolicyEditorOpen(false)}
            pod={policyEditorPod}
            allPods={pods}
          />
        </Suspense>
      )}

      {isAuditPanelOpen && (
        <Suspense fallback={null}>
          <AuditVerdictsPanel isOpen onClose={() => setIsAuditPanelOpen(false)} />
        </Suspense>
      )}

      <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} namespaces={namespaces} />
    </div>
  );
}

export default App;
