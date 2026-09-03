import { useState, useCallback, useEffect, useMemo, useRef, lazy, Suspense } from 'react';
import { Bot, RefreshCw, Share2, ShieldAlert, LayoutDashboard, FileCode, Boxes, Search, Lock } from 'lucide-react';
import NetworkGraph from './components/NetworkGraph';
import { FindingsView } from './components/FindingsView';
import { CommandPalette, type Command } from './components/CommandPalette';
import { useHashLocation } from './hooks/useHashLocation';
import NamespaceSelector from './components/NamespaceSelector';
import DataTable from './components/DataTable';
import { Sidebar, type NavItem } from './components/Sidebar';
import { ClusterSwitcher } from './components/ClusterSwitcher';
import { AccountMenu } from './components/AccountMenu';
import { SettingsPanel } from './components/SettingsPanel';
import { useSettings } from './contexts/SettingsContext';
import { useClusterEnvironment } from './hooks/useClusterEnvironment';
import { policyTypeForFinding, type FindingKind } from './utils/findingPolicyType';
import type { PolicyType } from './hooks/policyEditor';
import { useCluster } from './contexts/ClusterContext';

// Heavy surfaces — lazy so they stay out of the initial bundle and only load
// when first opened (the NetworkPolicyEditor alone is ~2k lines).
const AIAssistant = lazy(() => import('./components/AIAssistant'));
const AuditVerdictsPanel = lazy(() => import('./components/AuditVerdictsPanel'));
const PolicyBuilderModal = lazy(() =>
  import('./components/PolicyBuilderModal').then((m) => ({ default: m.PolicyBuilderModal })),
);
const SeccompProfilesView = lazy(() => import('./components/SeccompProfilesView'));
import { Button } from './components/ui/Button';
import { EmptyState } from './components/ui/EmptyState';
import { GraphSkeleton } from './components/ui/Skeleton';
import { Server } from 'lucide-react';
import { usePodData } from './hooks/usePodData';
import { useNamespaces } from './hooks/useNamespaces';
import type { PodNodeData } from './types';
import { UI_DIMENSIONS } from './constants/ui';

const ROUTES = ['map', 'findings', 'seccomp'] as const;

function App() {
  const { settings, updateSettings, toggleSetting } = useSettings();
  const toggleDaemonSetNodes = useCallback(() => toggleSetting('showDaemonSetNodes'), [toggleSetting]);
  const { activeCluster } = useCluster();

  // The whole location — view, namespace, selected workload — lives in the URL
  // hash so it's shareable and refreshable. Namespace is also remembered per
  // cluster (below) as the fallback when the URL carries none.
  const { loc, navigate } = useHashLocation();
  const view: (typeof ROUTES)[number] = (ROUTES as readonly string[]).includes(loc.view)
    ? (loc.view as (typeof ROUTES)[number])
    : 'map';

  // Namespace remembered per cluster — seeded from a deep-linked ns on first load.
  const [nsByCluster, setNsByCluster] = useState<Record<string, string>>(() => {
    const ns = new URLSearchParams(window.location.hash.split('?')[1] ?? '').get('ns');
    return ns ? { [activeCluster.id]: ns } : {};
  });
  const namespace = loc.params.ns ?? nsByCluster[activeCluster.id] ?? settings.defaultNamespace ?? 'default';

  // Map-only params (selected workload, focused node) travel with the map view
  // and are dropped when leaving it.
  const setView = useCallback(
    (v: (typeof ROUTES)[number]) =>
      navigate(v, { ns: loc.params.ns, pod: v === 'map' ? loc.params.pod : undefined, focus: v === 'map' ? loc.params.focus : undefined }),
    [navigate, loc.params.ns, loc.params.pod, loc.params.focus],
  );
  const setNamespace = useCallback(
    (ns: string) => {
      setNsByCluster((prev) => ({ ...prev, [activeCluster.id]: ns }));
      navigate(view, { ns, pod: undefined, focus: undefined }); // namespace change clears the workload + focus
    },
    [navigate, view, activeCluster.id],
  );
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [isAIAssistantOpen, setIsAIAssistantOpen] = useState(false);
  const [isAuditPanelOpen, setIsAuditPanelOpen] = useState(false);
  const [isPolicyBuilderOpen, setIsPolicyBuilderOpen] = useState(false);
  const [policyBuilderInitialPod, setPolicyBuilderInitialPod] = useState<PodNodeData | null>(null);
  const [policyBuilderInitialType, setPolicyBuilderInitialType] = useState<PolicyType>('network');
  const { cni } = useClusterEnvironment();
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

  // Selected workload is derived from the URL (`?pod=<id>`) and resolved against
  // the loaded pods — so a deep link opens straight to that workload once data
  // arrives, and back/forward restores it.
  const selectedPodId = loc.params.pod ?? null;
  const selectedPod = useMemo(
    () => (selectedPodId ? pods.find((p) => p.id === selectedPodId) ?? null : null),
    [pods, selectedPodId],
  );
  const selectPod = useCallback(
    (pod: PodNodeData | null) => navigate('map', { ns: loc.params.ns, pod: pod?.id, focus: loc.params.focus }, { replace: true }),
    [navigate, loc.params.ns, loc.params.focus],
  );

  // Graph focus mode is URL state (`?focus=<node id>`) so a focused view can
  // be copied and shared; the graph restores it once data arrives and clears
  // it if the node disappears.
  const focusedNodeId = loc.params.focus ?? null;
  const setFocusedNodeId = useCallback(
    (id: string | null) => navigate('map', { ns: loc.params.ns, pod: loc.params.pod, focus: id ?? undefined }, { replace: true }),
    [navigate, loc.params.ns, loc.params.pod],
  );

  // On cluster switch, point the URL at the new cluster's remembered namespace
  // (and clear the workload) so the per-cluster memory wins over a stale URL ns.
  const prevCluster = useRef(activeCluster.id);
  useEffect(() => {
    if (prevCluster.current === activeCluster.id) return;
    prevCluster.current = activeCluster.id;
    navigate(view, { ns: nsByCluster[activeCluster.id], pod: undefined, focus: undefined }, { replace: true });
  }, [activeCluster.id, nsByCluster, view, navigate]);

  // Keep the resolved namespace in the URL so the link is always shareable,
  // even before the user has explicitly picked one.
  useEffect(() => {
    if (!loc.params.ns && namespaces.length > 0) {
      navigate(view, { ns: effectiveNamespace, pod: loc.params.pod, focus: loc.params.focus }, { replace: true });
    }
  }, [loc.params.ns, loc.params.pod, loc.params.focus, namespaces.length, effectiveNamespace, view, navigate]);

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
    selectPod(pod);
  };

  const handleBuildPolicy = (pod: PodNodeData) => {
    setPolicyBuilderInitialPod(pod);
    setPolicyBuilderInitialType('network');
    setIsPolicyBuilderOpen(true);
  };

  // A finding's "Policy" action opens the tab relevant to that finding —
  // seccomp for sensitive syscalls, network (Cilium on a Cilium cluster) for
  // the traffic findings — not the default tab.
  const handleBuildPolicyForFinding = useCallback((pod: PodNodeData, kind: FindingKind) => {
    setPolicyBuilderInitialPod(pod);
    setPolicyBuilderInitialType(policyTypeForFinding(kind, cni));
    setIsPolicyBuilderOpen(true);
  }, [cni]);

  // Rail entry: open the builder with the current workload if one is selected,
  // otherwise with no pod so it shows the workload picker.
  const openPolicyBuilder = useCallback(() => {
    setPolicyBuilderInitialPod(selectedPod && !selectedPod.isExternal ? selectedPod : null);
    setPolicyBuilderInitialType('network');
    setIsPolicyBuilderOpen(true);
  }, [selectedPod]);

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

  // Jump from a finding straight to that workload on the map (one history entry).
  const handleFindingSelect = useCallback((pod: PodNodeData) => {
    navigate('map', { ns: loc.params.ns, pod: pod.id });
  }, [navigate, loc.params.ns]);

  // ⌘K / Ctrl-K opens the command palette from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  // Everything the command palette can jump to.
  const commands: Command[] = useMemo(() => {
    const list: Command[] = [
      { id: 'view-map', group: 'Views', label: 'Network Map', icon: Share2, keywords: 'graph traffic', run: () => setView('map') },
      { id: 'view-findings', group: 'Views', label: 'Findings', icon: LayoutDashboard, keywords: 'risk signals triage', run: () => setView('findings') },
      { id: 'view-seccomp', group: 'Views', label: 'Seccomp Profiles', icon: Lock, keywords: 'syscall publish enforce capture', run: () => setView('seccomp') },
      { id: 'tool-policy', group: 'Tools', label: 'Policy Builder', icon: FileCode, keywords: 'networkpolicy seccomp cilium generate', run: openPolicyBuilder },
      { id: 'tool-audit', group: 'Tools', label: 'Audit Verdicts', icon: ShieldAlert, keywords: 'would deny', run: () => setIsAuditPanelOpen(true) },
      { id: 'tool-ai', group: 'Tools', label: 'AI Assistant', icon: Bot, keywords: 'chat ask', run: () => setIsAIAssistantOpen(true) },
    ];
    namespaces.forEach((ns) =>
      list.push({ id: `ns-${ns}`, group: 'Namespaces', label: ns, icon: Boxes, keywords: 'namespace switch', run: () => setNamespace(ns) }),
    );
    pods
      .filter((p) => !p.isExternal)
      .forEach((p) =>
        list.push({
          id: `pod-${p.id}`,
          group: 'Workloads',
          label: p.label || p.pod.pod_identity || p.pod.pod_name,
          hint: p.pod.pod_namespace ?? undefined,
          icon: Server,
          run: () => handleFindingSelect(p),
        }),
      );
    return list;
  }, [namespaces, pods, setView, openPolicyBuilder, setNamespace, handleFindingSelect]);

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
      id: 'seccomp', label: 'Seccomp Profiles', icon: Lock, group: 'Views',
      hint: 'Publish, enforce, and edit per-workload seccomp profiles',
      active: view === 'seccomp', onClick: () => setView('seccomp'),
    },
    {
      id: 'policy', label: 'Policy Builder', icon: FileCode, group: 'Tools',
      hint: 'Generate a NetworkPolicy or Seccomp profile for a workload',
      active: isPolicyBuilderOpen, onClick: openPolicyBuilder,
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

  const cmdKey = useMemo(
    () => (typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K'),
    [],
  );

  const sectionTitle = view === 'findings' ? 'Findings' : view === 'seccomp' ? 'Seccomp Profiles' : 'Network Map';
  const sectionSubtitle =
    view === 'map'
      ? `Namespace ${effectiveNamespace} · ${pods.length} pods`
      : `Namespace ${effectiveNamespace}`;

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
            <button
              onClick={() => setPaletteOpen(true)}
              title="Search & commands"
              className="hidden md:flex items-center gap-2 h-8 pl-2.5 pr-1.5 rounded-control border border-hubble-border bg-hubble-card text-tertiary hover:text-secondary hover:border-hubble-border-strong transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span className="text-xs">Search</span>
              <kbd className="text-[10px] font-mono border border-hubble-border rounded px-1 py-0.5 leading-none">{cmdKey}</kbd>
            </button>
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
        {view === 'seccomp' ? (
          <Suspense fallback={null}>
            <SeccompProfilesView namespace={effectiveNamespace} />
          </Suspense>
        ) : view === 'findings' ? (
          <FindingsView
            pods={pods}
            namespace={effectiveNamespace}
            onSelectPod={handleFindingSelect}
            onBuildPolicy={handleBuildPolicyForFinding}
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
                focusedNodeId={focusedNodeId}
                onFocusChange={setFocusedNodeId}
                allPodsLookup={allPodsLookup}
                services={services}
                showExternalNodes={settings.showExternalNodes}
                onToggleExternalNodes={() => updateSettings({ showExternalNodes: !settings.showExternalNodes })}
                showDaemonSetNodes={settings.showDaemonSetNodes}
                onToggleDaemonSetNodes={toggleDaemonSetNodes}
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

      {isPolicyBuilderOpen && (
        <Suspense fallback={null}>
          <PolicyBuilderModal
            onClose={() => setIsPolicyBuilderOpen(false)}
            workloads={pods.filter((p) => !p.isExternal)}
            initialPod={policyBuilderInitialPod}
            initialPolicyType={policyBuilderInitialType}
          />
        </Suspense>
      )}

      {isAuditPanelOpen && (
        <Suspense fallback={null}>
          <AuditVerdictsPanel isOpen onClose={() => setIsAuditPanelOpen(false)} />
        </Suspense>
      )}

      <SettingsPanel isOpen={settingsOpen} onClose={() => setSettingsOpen(false)} namespaces={namespaces} />

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} commands={commands} />}
    </div>
  );
}

export default App;
