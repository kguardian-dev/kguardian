import type { HashLocation } from '../hooks/useHashLocation';

/**
 * The app's hash routes. Every location is shareable, so a route that is
 * renamed keeps working through LEGACY_REDIRECTS rather than 404-ing an old
 * bookmark or a link pasted into a ticket.
 */
export const VIEWS = ['map', 'risks', 'workloads', 'workload'] as const;
export type View = (typeof VIEWS)[number];

/** Where an unknown or empty hash lands. */
export const DEFAULT_VIEW: View = 'map';

type Params = Record<string, string>;

/**
 * Old route → new route, carrying the old params across.
 *  - `#/findings` was renamed to `#/risks` (same view, same params).
 *  - `#/seccomp` was absorbed into the Workloads coverage table, opened on its
 *    seccomp columns.
 */
export const LEGACY_REDIRECTS: Record<string, (params: Params) => { view: View; params: Params }> = {
  findings: (params) => ({ view: 'risks', params }),
  seccomp: (params) => ({ view: 'workloads', params: { ...params, control: 'seccomp' } }),
};

export interface ResolvedRoute {
  view: View;
  /** Set when the location is a legacy route: replace the URL with this. */
  redirect?: { view: View; params: Params };
}

export function resolveRoute(loc: HashLocation): ResolvedRoute {
  const legacy = LEGACY_REDIRECTS[loc.view];
  if (legacy) {
    const target = legacy(loc.params);
    return { view: target.view, redirect: target };
  }
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

/** Params for the placeholder workload profile route. */
export function workloadParams(ns: string, kind: string, name: string): Params {
  return { ns, kind, name };
}
