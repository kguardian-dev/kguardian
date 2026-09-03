/**
 * Focus mode is URL state (`?focus=<node id>`) so a focused view is shareable.
 * A focus is only meaningful while that node exists in the rendered set, but
 * "not present" is ambiguous before the graph has data: on a fresh load of a
 * shared link the pods arrive asynchronously. Exit (and drop the param) only
 * once nodes have loaded and the focused one is not among them — the #1393
 * self-heal, without clobbering a deep link during the initial fetch.
 */
export function shouldExitFocus(focusedId: string | null, nodeIds: Iterable<string>, loaded: boolean): boolean {
  if (!focusedId || !loaded) return false;
  for (const id of nodeIds) if (id === focusedId) return false;
  return true;
}
