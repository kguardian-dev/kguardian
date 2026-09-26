import type { HashLocation } from '../hooks/useHashLocation';

/**
 * The app's hash routes. Every location is shareable, so a route that is
 * renamed keeps working through legacyRedirect rather than 404-ing an old
 * bookmark or a link pasted into a ticket.
 */
export const VIEWS = ['map', 'risks', 'workloads', 'workload'] as const;
export type View = (typeof VIEWS)[number];

/** Where an unknown or empty hash lands. */
export const DEFAULT_VIEW: View = 'map';

type Params = Record<string, string>;

/** Retired route names that still resolve, via legacyRedirect. */
export const LEGACY_VIEWS: readonly string[] = ['findings', 'seccomp'];

/**
 * Old route → new route, carrying the old params across.
 *  - `#/findings` was renamed to `#/risks` (same view, same params).
 *  - `#/seccomp` was absorbed into the Workloads coverage table, opened on its
 *    seccomp columns and, when the link names a namespace, narrowed to it.
 *
 * A switch over literal names, deliberately: the input is the user-controlled
 * hash, and any keyed lookup of a function (an object literal would resolve
 * `#/constructor` to Object.prototype's) followed by a call is dynamic
 * dispatch on user input. Unknown names return undefined.
 */
export function legacyRedirect(view: string, params: Params): { view: View; params: Params } | undefined {
  switch (view) {
    case 'findings':
      return { view: 'risks', params };
    case 'seccomp':
      // The old view was namespace-scoped, so an old link keeps that scope.
      return { view: 'workloads', params: { ...params, control: 'seccomp', ...(params.ns ? { scope: 'ns' } : {}) } };
    default:
      return undefined;
  }
}

export interface ResolvedRoute {
  view: View;
  /** Set when the location is a legacy route: replace the URL with this. */
  redirect?: { view: View; params: Params };
}

export function resolveRoute(loc: HashLocation): ResolvedRoute {
  const target = legacyRedirect(loc.view, loc.params);
  if (target) return { view: target.view, redirect: target };
  if ((VIEWS as readonly string[]).includes(loc.view)) return { view: loc.view as View };
  return { view: DEFAULT_VIEW };
}

/** Views whose data is cluster-wide, so they can drop the namespace scope. */
export const CLUSTER_SCOPED_VIEWS: ReadonlySet<View> = new Set<View>(['workloads']);

/**
 * Whether a view is showing all namespaces. Cluster-scoped views default to
 * all namespaces (`scope=ns` narrows them to the header namespace); the rest
 * are always scoped to one namespace.
 */
export function isAllNamespaces(view: View, params: Params): boolean {
  return CLUSTER_SCOPED_VIEWS.has(view) && params.scope !== 'ns';
}

/** Where a workload page was opened from, so Back can return there. */
export interface WorkloadsContext {
  scope?: string;
  control?: string;
}

/**
 * Params for the workload security profile route. The Workloads list's
 * scope and control ride along (the workload page ignores them) so Back
 * restores the list exactly as it was.
 */
export function workloadParams(ns: string, kind: string, name: string, from: WorkloadsContext = {}): Params {
  const p: Params = { ns, kind, name };
  if (from.scope) p.scope = from.scope;
  if (from.control) p.control = from.control;
  return p;
}

/** Params for Back from a workload page: the list it came from. */
export function workloadsBackParams(params: Params): Params {
  const p: Params = {};
  if (params.ns) p.ns = params.ns;
  if (params.scope) p.scope = params.scope;
  if (params.control) p.control = params.control;
  return p;
}

/** Shareable href for a route — same encoding as useHashLocation's navigate. */
export function routeHref(view: View, params: Params): string {
  const q = new URLSearchParams(params).toString();
  return `#/${view}${q ? `?${q}` : ''}`;
}
