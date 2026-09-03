-- Whether the pod runs with `spec.hostNetwork: true`. A host-network
-- pod's IP IS the node IP, so a peer that resolves to such a pod is
-- node traffic: a NetworkPolicy podSelector on its labels can never
-- match it (the CNI sees node identity, not the pod), and every
-- generator has to render an ipBlock (Kubernetes) or host/remote-node
-- entities (Cilium) instead. NULL = unknown — a controller predating
-- the field and a row with no manifest to derive it from — and the
-- generators keep today's behaviour for NULL.
--
-- Added last so the positional Queryable/Insertable ordering of
-- broker/src/types.rs::PodDetail stays aligned with the physical
-- column order. AsChangeset skips None, so an older controller that
-- omits the field never nulls a value a newer one wrote.
ALTER TABLE pod_details ADD COLUMN IF NOT EXISTS host_network BOOLEAN;

-- Backfill from the stored manifest. The compacted pod_obj keeps
-- spec.hostNetwork when it was set, and the API server omits the
-- field when false, so a manifest with no spec.hostNetwork is a
-- non-host-network pod. Rows without a manifest stay NULL. Only rows
-- the new ingest has not yet stamped are touched.
UPDATE pod_details
   SET host_network = (pod_obj -> 'spec' ->> 'hostNetwork') IS NOT DISTINCT FROM 'true'
 WHERE host_network IS NULL
   AND pod_obj IS NOT NULL
   AND json_typeof(pod_obj) = 'object';
