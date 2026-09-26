import { useState, useCallback, useEffect, useMemo, useRef, Suspense } from 'react';
import { lazyRetry } from './utils/lazyRetry';
import { Bot, RefreshCw, Share2, ShieldAlert, FileCode, Boxes, Search, Lock, Layers, TriangleAlert } from 'lucide-react';
import NetworkGraph from './components/NetworkGraph';
import { RisksRoute } from './components/RisksView';
import { ScopeChip } from './components/ScopeChip';
import { CommandPalette, type Command } from './components/CommandPalette';
import { useHashLocation } from './hooks/useHashLocation';
import { NARROW_QUERY, useMediaQuery } from './hooks/useMediaQuery';
import { useDialogFocus } from './hooks/useDialogFocus';
import NamespaceSelector from './components/NamespaceSelector';
import DataTable from './components/DataTable';
import { Sidebar, type NavItem } from './components/Sidebar';
import { ClusterSwitcher } from './components/ClusterSwitcher';
import { AccountMenu } from './components/AccountMenu';
import { SettingsPanel } from './components/SettingsPanel';
import { useSettings } from './contexts/SettingsContext';
import { useClusterEnvironment } from './hooks/useClusterEnvironment';
import { findingAction, policyTypeForFinding, type FindingKind } from './utils/findingPolicyType';
import { recommendedPolicyType } from './utils/cniPolicySupport';
import type { PolicyType } from './hooks/policyEditor';
import { useCluster } from './contexts/ClusterContext';
import { paramsForSelection } from './utils/mapSelection';
import { CLUSTER_SCOPED_VIEWS, isAllNamespaces, resolveRoute, workloadsBackParams, type View } from './utils/routes';

// Heavy surfaces — lazy so they stay out of the initial bundle and only load
// when first opened (the NetworkPolicyEditor alone is ~2k lines).
const AIAssistant = lazyRetry(() => import('./components/AIAssistant'));
const AuditVerdictsPanel = lazyRetry(() => import('./components/AuditVerdictsPanel'));
const PolicyBuilderModal = lazyRetry(() =>
  import('./components/PolicyBuilderModal').then((m) => ({ default: m.PolicyBuilderModal })),
);
const WorkloadsView = lazyRetry(() => import('./components/WorkloadsView'));
const WorkloadView = lazyRetry(() => import('./components/WorkloadView'));
import { Button } from './components/ui/Button';
import { EmptyState } from './components/ui/EmptyState';
import { GraphSkeleton } from './components/ui/Skeleton';
import { Server } from 'lucide-react';
import { usePodData } from './hooks/usePodData';
import { useNamespaces } from './hooks/useNamespaces';
import type { PodNodeData } from './types';
import { UI_DIMENSIONS } from './constants/ui';

function App() {
  const { settings, updateSettings, toggleSetting } = useSettings();
  const toggleDaemonSetNodes = useCallback(() => toggleSetting('showDaemonSetNodes'), [toggleSetting]);
  const toggleContention = useCallback(() => toggleSetting('showContention'), [toggleSetting]);
  const { activeCluster } = useCluster();

  // The whole location — view, namespace, selected workload — lives in the URL
  // hash so it's shareable and refreshable. Namespace is also remembered per
  // cluster (below) as the fallback when the URL carries none.
  const { loc, navigate } = useHashLocation();
  const route = resolveRoute(loc);
  const view = route.view;

  // Renamed routes (#/findings → #/risks, #/seccomp → #/workloads?control=
  // seccomp) keep old links working: swap the URL in place, no history entry.
  const redirect = route.redirect;
  useEffect(() => {
    if (redirect) navigate(redirect.view, redirect.params, { replace: true });
  }, [redirect, navigate]);

  const allNamespaces = isAllNamespaces(view, loc.params);

  // Namespace remembered per cluster — seeded from a deep-linked ns on first load.
  const [nsByCluster, setNsByCluster] = useState<Record<string, string>>(() => {
    const ns = new URLSearchParams(window.location.hash.split('?')[1] ?? '').get('ns');
    return ns ? { [activeCluster.id]: ns } : {};
  });
  const namespace = loc.params.ns ?? nsByCluster[activeCluster.id] ?? settings.defaultNamespace ?? 'default';

  // Map-only params (selected workload, focused node) travel with the map view
  // and are dropped when leaving it.
  const setView = useCallback(
    (v: View, extra: Record<string, string | undefined> = {}) =>
      navigate(v, { ns: loc.params.ns, pod: v === 'map' ? loc.params.pod : undefined, focus: v === 'map' ? loc.params.focus : undefined, ...extra }),
    [navigate, loc.params.ns, loc.params.pod, loc.params.focus],
  );
  const setNamespace = useCallback(
    (ns: string) => {
      setNsByCluster((prev) => ({ ...prev, [activeCluster.id]: ns }));
      // A namespace change clears the workload + focus. On a cluster-wide
      // view, picking a namespace is a filter: narrow to it (scope=ns). The
      // single-workload page has nothing to show in another namespace, so it
      // falls back to the Workloads list narrowed to the new one.
      if (view === 'workload') navigate('workloads', { ns, scope: 'ns' });
      else navigate(view, { ns, scope: CLUSTER_SCOPED_VIEWS.has(view) ? 'ns' : undefined, control: loc.params.control });
    },
    [navigate, view, activeCluster.id, loc.params.control],
  );
  const showAllNamespaces = useCallback(
    () => navigate(view, { ...loc.params, scope: undefined }),
    [navigate, view, loc.params],
  );
  // True while the workload page sits directly on top of the Workloads list
  // entry it was opened from (a push from that list). Back then pops that
  // entry — the list comes back with its scroll, filters and scope — instead
  // of pushing a second copy of it. The page's own tab/diff changes replace
  // the entry, so the list stays the previous one. A deep link has no list
  // below it, so Back navigates there.
  const listBelow = useRef(false);
  useEffect(() => {
    if (view !== 'workload') listBelow.current = false;
  }, [view]);
  const openWorkload = useCallback(
    (params: Record<string, string>) => {
      listBelow.current = view === 'workloads';
      navigate('workload', params);
    },
    [navigate, view],
  );
  const backToWorkloads = useCallback(() => {
    if (listBelow.current) {
      listBelow.current = false;
      window.history.back();
      return;
    }
    navigate('workloads', workloadsBackParams(loc.params));
  }, [navigate, loc.params]);
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
  // The desktop rail preference: expanded unless the user collapsed it.
  // Narrow screens never read it (they always show the icon column, see
  // `narrow` below), so a phone-first visit cannot leave desktop collapsed.
  const [railCollapsed, setRailCollapsed] = useState<boolean>(() => localStorage.getItem('kg-rail-collapsed') === '1');

  const { namespaces } = useNamespaces();
  // If the current selection isn't a namespace that actually has monitored pods
  // (the hardcoded 'default' usually isn't), resolve to the first real one so
  // the graph isn't empty on first paint. Derived rather than synced via an
  // effect — no extra render, and it can't loop.
  const effectiveNamespace =
    namespaces.length > 0 && !namespaces.includes(namespace) ? namespaces[0] : namespace;
  // Selected workload id from the URL (`?pod=<id>`). Derived before the data
  // hook because the hook needs it: selection is what opens a card, and an
  // open card is the only thing that reads stored compute history.
  const selectedPodId = loc.params.pod ?? null;
  const { pods, compute, allPodsLookup, services, loading, error, refreshData } = usePodData(effectiveNamespace, selectedPodId);
  // The header Refresh is the one refresh control. Views with their own
  // broker data (seccomp profiles, audit verdicts) reload when this ticks.
  const [refreshTick, setRefreshTick] = useState(0);
  const refreshAll = useCallback(() => {
    refreshData();
    setRefreshTick((t) => t + 1);
  }, [refreshData]);

  // Selected workload is derived from the URL (`?pod=<id>`) and resolved against
  // the loaded pods — so a deep link opens straight to that workload once data
  // arrives, and back/forward restores it.
  //
  // The raw id and the resolved pod are NOT interchangeable, and which one a
  // consumer gets matters now that selection also opens the card. `pods` holds
  // only this namespace's own workloads, while the map additionally draws
  // external peers, DaemonSet peers and contention culprits that NetworkGraph
  // synthesises for itself — none of which resolve here. So the graph gets the
  // raw id, which it matches against its own full node set; the DataTable and
  // the Policy Builder get the resolved pod, which genuinely needs a local
  // workload's traffic and syscalls. Passing the resolved id to the graph
  // would collapse every card the moment an external peer was selected.
  const selectedPod = useMemo(
    () => (selectedPodId ? pods.find((p) => p.id === selectedPodId) ?? null : null),
    [pods, selectedPodId],
  );
  // Selecting a card focuses it as well as opening it: one click means "show
  // me this workload", and the map isolates it with its direct peers.
  //
  // Focus stays a SEPARATE url param rather than being folded into `pod`,
  // because the two are not the same question and the escape hatch depends on
  // it: Esc (NetworkGraph) drops the focus and leaves the card open, so you
  // get the whole map back without losing what you were reading. Folding them
  // together would make Esc either close the card or do nothing.
  const selectPod = useCallback(
    (pod: PodNodeData | null) => navigate('map', paramsForSelection(pod?.id, loc.params.ns), { replace: true }),
    [navigate, loc.params.ns],
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
    // A single-workload page is meaningless in another cluster: land on the list.
    navigate(view === 'workload' ? 'workloads' : view, { ns: nsByCluster[activeCluster.id], pod: undefined, focus: undefined }, { replace: true });
  }, [activeCluster.id, nsByCluster, view, navigate]);

  // Keep the resolved namespace in the URL so the link is always shareable,
  // even before the user has explicitly picked one.
  useEffect(() => {
    if (!redirect && !loc.params.ns && namespaces.length > 0) {
      navigate(view, { ...loc.params, ns: effectiveNamespace }, { replace: true });
    }
  }, [redirect, loc.params, namespaces.length, effectiveNamespace, view, navigate]);

  // Narrow screens (below md, live on resize / rotation): the rail is a
  // 56px icon column, and expanding it opens an overlay over the content
  // rather than a 224px column beside it. The overlay is not a preference:
  // it closes on navigation, backdrop or Esc, and never touches the stored
  // desktop choice.
  const narrow = useMediaQuery(NARROW_QUERY);
  const [railOverlay, setRailOverlay] = useState(false);
  const railShowsCollapsed = narrow ? !railOverlay : railCollapsed;
  // The open overlay is a modal dialog (hooks/useDialogFocus): focus moves
  // into it, Tab stays in it, and every way of closing it (Esc, backdrop, a
  // nav pick, the collapse button) returns focus to the expand button.
  const railDialogRef = useRef<HTMLDivElement>(null);
  const railExpandRef = useRef<HTMLButtonElement>(null);
  const closeRailOverlay = useCallback(() => setRailOverlay(false), []);
  const toggleRail = useCallback(() => {
    if (narrow) {
      setRailOverlay((o) => !o);
      return;
    }
    setRailCollapsed((c) => {
      localStorage.setItem('kg-rail-collapsed', c ? '0' : '1');
      return !c;
    });
  }, [narrow]);
  useDialogFocus({ open: railOverlay, dialogRef: railDialogRef, returnFocusRef: railExpandRef, onClose: closeRailOverlay, initialFocus: 'nav button' });
  // Leaving the narrow layout drops the overlay, so it cannot pop back
  // open on the next resize to a phone width.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- reset UI state when the layout mode changes
    if (!narrow) setRailOverlay(false);
  }, [narrow]);

  // Calculate the right padding for content when AI panel is docked (in pixels)
  const contentPaddingRightPx = aiSidePanel.isSidePanel
    ? (aiSidePanel.isCollapsed ? UI_DIMENSIONS.AI_PANEL_COLLAPSED_WIDTH : aiSidePanel.width)
    : 0;

  const handlePodSelect = (pod: PodNodeData | null) => {
    selectPod(pod);
  };

  const handleBuildPolicy = (pod: PodNodeData) => {
    setPolicyBuilderInitialPod(pod);
    setPolicyBuilderInitialType(recommendedPolicyType(cni));
    setIsPolicyBuilderOpen(true);
  };

  // A finding's "Policy" action opens the tab relevant to that finding —
  // seccomp for sensitive syscalls, network (Cilium on a Cilium cluster) for
  // the traffic findings — not the default tab. Compute findings (D7) are a
  // `resources` action and never open the builder: policyTypeForFinding is
  // only called for `policy` kinds.
  const handleBuildPolicyForFinding = useCallback((pod: PodNodeData, kind: FindingKind) => {
    if (findingAction(kind) !== 'policy') return;
    setPolicyBuilderInitialPod(pod);
    setPolicyBuilderInitialType(policyTypeForFinding(kind, cni));
    setIsPolicyBuilderOpen(true);
  }, [cni]);

  // Rail entry: open the builder with the current workload if one is selected,
  // otherwise with no pod so it shows the workload picker.
  const openPolicyBuilder = useCallback(() => {
    setPolicyBuilderInitialPod(selectedPod && !selectedPod.isExternal ? selectedPod : null);
    setPolicyBuilderInitialType(recommendedPolicyType(cni));
    setIsPolicyBuilderOpen(true);
  }, [selectedPod, cni]);

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

  // "View workload" on a compute finding (D7): the pod may live in another
  // namespace (a noisy neighbour is cross-namespace by nature), so resolve
  // its identity from the cluster-wide pod list and switch namespace with it.
  const handleViewWorkload = useCallback((ns: string, podName: string) => {
    const record = allPodsLookup.find((p) => p.pod_namespace === ns && p.pod_name === podName);
    const identity = record?.pod_identity || podName;
    if (ns !== effectiveNamespace) setNsByCluster((prev) => ({ ...prev, [activeCluster.id]: ns }));
    navigate('map', { ns, pod: `${ns}-${identity}` });
  }, [allPodsLookup, effectiveNamespace, activeCluster.id, navigate]);

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
      { id: 'view-risks', group: 'Views', label: 'Risks', icon: TriangleAlert, keywords: 'findings signals triage posture', run: () => setView('risks') },
      { id: 'view-workloads', group: 'Views', label: 'Workloads', icon: Layers, keywords: 'coverage controls network seccomp', run: () => setView('workloads') },
      { id: 'view-seccomp', group: 'Views', label: 'Seccomp Profiles', icon: Lock, keywords: 'syscall publish enforce capture workloads', run: () => setView('workloads', { control: 'seccomp' }) },
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
      id: 'risks', label: 'Risks', icon: TriangleAlert, group: 'Views',
      hint: 'Prioritized runtime-security signals',
      active: view === 'risks', onClick: () => setView('risks'),
    },
    {
      id: 'map', label: 'Network Map', icon: Share2, group: 'Views', hint: 'Live pod traffic graph',
      active: view === 'map',
      onClick: () => setView('map'),
    },
    {
      id: 'workloads', label: 'Workloads', icon: Layers, group: 'Views',
      hint: 'Control coverage per workload: network policy, seccomp, capture',
      active: view === 'workloads' || view === 'workload', onClick: () => setView('workloads'),
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

  const SECTION_TITLE: Record<View, string> = { map: 'Network Map', risks: 'Risks', workloads: 'Workloads', workload: 'Workload' };
  const sectionTitle = view === 'workload' && loc.params.name ? loc.params.name : SECTION_TITLE[view];
  const sectionSubtitle =
    view === 'map'
      ? `${pods.length} pods`
      : view === 'workload'
        ? loc.params.kind ?? ''
        : '';

  return (
    <div className="flex h-screen bg-hubble-darker">
      {(() => {
        const rail = (
          <Sidebar
            items={navItems}
            version={__APP_VERSION__}
            topSlot={<ClusterSwitcher collapsed={railShowsCollapsed} />}
            footer={<AccountMenu collapsed={railShowsCollapsed} onOpenSettings={() => setSettingsOpen(true)} />}
            collapsed={railShowsCollapsed}
            onToggleCollapse={toggleRail}
            onNavigate={narrow ? closeRailOverlay : undefined}
            expandButtonRef={railExpandRef}
          />
        );
        if (!narrow) return rail;
        // Narrow: a fixed 56px column keeps the content still; the open
        // rail floats over it.
        return (
          <div className="relative w-14 shrink-0" data-testid="rail-slot">
            {railOverlay && (
              <button type="button" aria-label="Close sidebar" className="fixed inset-0 z-40 bg-black/40 cursor-default" onClick={closeRailOverlay} />
            )}
            {railOverlay ? (
              <div ref={railDialogRef} role="dialog" aria-modal="true" aria-label="Navigation" className="fixed inset-y-0 left-0 z-50 shadow-2xl">
                {rail}
              </div>
            ) : (
              <div className="h-full">{rail}</div>
            )}
          </div>
        );
      })()}

      <div
        className="flex-1 flex flex-col min-w-0 transition-all duration-300"
        style={{ paddingRight: `${contentPaddingRightPx}px` }}
      >
        {/* Top bar */}
        {/* Narrow widths: the search box, selector label, Refresh label and
            scope chip step down so the header never forces a page scroll. */}
        <header className="h-14 shrink-0 flex items-center justify-between gap-2 sm:gap-4 px-3 sm:px-5 border-b border-hubble-border bg-hubble-dark">
          <div className="min-w-0">
            <div className="flex items-center gap-2 min-w-0">
              <h1 className="text-sm font-semibold text-primary truncate">{sectionTitle}</h1>
              <div className="hidden sm:block">
                <ScopeChip
                  namespace={effectiveNamespace}
                  allNamespaces={allNamespaces}
                  onShowAll={CLUSTER_SCOPED_VIEWS.has(view) ? showAllNamespaces : undefined}
                />
              </div>
            </div>
            {sectionSubtitle && <p className="text-xs text-tertiary truncate">{sectionSubtitle}</p>}
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setPaletteOpen(true)}
              title="Search & commands"
              className="hidden lg:flex items-center gap-2 h-8 pl-2.5 pr-1.5 rounded-control border border-hubble-border bg-hubble-card text-tertiary hover:text-secondary hover:border-hubble-border-strong transition-colors"
            >
              <Search className="w-3.5 h-3.5" />
              <span className="text-xs">Search</span>
              <kbd className="text-[10px] font-mono border border-hubble-border rounded px-1 py-0.5 leading-none">{cmdKey}</kbd>
            </button>
            <NamespaceSelector
              selectedNamespace={allNamespaces ? '' : effectiveNamespace}
              onNamespaceChange={(ns) => (ns === '' ? showAllNamespaces() : setNamespace(ns))}
              namespaces={namespaces}
              allOption={CLUSTER_SCOPED_VIEWS.has(view)}
            />
            <Button
              variant="secondary"
              leftIcon={RefreshCw}
              onClick={refreshAll}
              disabled={loading}
              className={loading ? '[&_svg]:animate-spin' : ''}
              aria-label="Refresh"
              title="Refresh"
            >
              <span className="hidden lg:inline">Refresh</span>
            </Button>
          </div>
        </header>

        {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {view === 'workloads' ? (
          <Suspense fallback={null}>
            <WorkloadsView
              refreshTick={refreshTick}
              allPods={allPodsLookup}
              namespace={effectiveNamespace}
              allNamespaces={allNamespaces}
              control={loc.params.control === 'seccomp' ? 'seccomp' : undefined}
              onControlChange={(control) => navigate('workloads', { ...loc.params, control }, { replace: true })}
              onOpenWorkload={openWorkload}
            />
          </Suspense>
        ) : view === 'workload' ? (
          <Suspense fallback={null}>
            <WorkloadView
              refreshTick={refreshTick}
              // The URL's ns, not the resolved one: a profile-only workload
              // (scaled to zero) can live in a namespace with no live pods.
              ns={loc.params.ns ?? effectiveNamespace}
              kind={loc.params.kind ?? ''}
              name={loc.params.name ?? ''}
              tab={loc.params.tab}
              from={loc.params.from}
              to={loc.params.to}
              // Tabs and the diff selection replace the entry, so Back
              // (browser or the page's own link) returns to the list.
              onParamsChange={(patch) => navigate('workload', { ...loc.params, ...patch }, { replace: true })}
              pods={pods}
              onBack={backToWorkloads}
              onOpenInMap={(podId) => navigate('map', { ns: loc.params.ns, pod: podId })}
            />
          </Suspense>
        ) : view === 'risks' ? (
          <RisksRoute
            refreshTick={refreshTick}
            onOpenWorkloads={(control) => navigate('workloads', { ns: effectiveNamespace, scope: 'ns', control })}
            pods={pods}
            namespace={effectiveNamespace}
            onSelectPod={handleFindingSelect}
            onBuildPolicy={handleBuildPolicyForFinding}
            onOpenAudit={() => setIsAuditPanelOpen(true)}
            computeFindings={compute.findings}
            computeEnabled={compute.enabled}
            computeMeta={compute.findingsMeta}
            onViewWorkload={handleViewWorkload}
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
                onPodSelect={handlePodSelect}
                selectedPodId={selectedPodId}
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
                showContention={settings.showContention}
                onToggleContention={toggleContention}
                computeFindings={compute.findings}
                layoutDirection={settings.layoutDirection}
                onToggleLayoutDirection={() => updateSettings({ layoutDirection: settings.layoutDirection === 'LR' ? 'TB' : 'LR' })}
              />
            </div>

            {/* Collapsible Bottom Panel: Resize Handle + Data Table */}
            {/* The panel takes its CONTENT's height, capped at `tableHeight`,
                rather than always standing at the cap. With every section
                collapsed that is three header rows, and the map keeps the
                rest — which is the point of not repeating the workload's
                identity down here. Opening a section grows the panel back to
                the cap and scrolls inside it. `maxHeight` rather than
                `height` because a height transition cannot animate to
                `auto`. Dragging the handle sets the cap, so it still bounds
                the panel at its tallest and no longer pins it there. */}
            <div
              className="overflow-hidden transition-all duration-300 ease-in-out"
              style={{
                maxHeight: selectedPod ? `${tableHeight + 4}px` : '0px',
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
                className="border-t border-hubble-border bg-hubble-dark overflow-auto"
                style={{ maxHeight: `${tableHeight}px` }}
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
