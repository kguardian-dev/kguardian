// The url params the map view carries, and the one decision that binds two of
// them together.
//
// Selecting a card focuses it as well as opening it: one click means "show me
// this workload", and the map isolates it with its direct peers. That makes
// `pod` and `focus` move together, and this is the single place that says so.
//
// They stay SEPARATE params rather than being folded into one, because the
// escape hatch depends on it: NetworkGraph's Esc clears `focus` and leaves
// `pod` alone, so the whole map comes back without closing the card you were
// reading. One param would make Esc either close the card or do nothing.

/** Shaped for `useHashLocation`'s `navigate`, which takes an index signature. */
export type MapParams = Record<string, string | undefined>;

/**
 * The map params for a selection, or for clearing it.
 *
 * `focus` is derived from the incoming selection and never read back off the
 * current params. Carrying the existing focus forward would pin the map to
 * whichever card was focused first and leave every later selection isolating
 * the wrong workload.
 */
export function paramsForSelection(podId: string | null | undefined, ns: string | undefined): MapParams {
  return { ns, pod: podId ?? undefined, focus: podId ?? undefined };
}
