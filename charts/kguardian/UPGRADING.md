# Upgrading the kguardian Helm chart

## chart 1.10.0: PostgreSQL 15 → 18

The `database.image.tag` default moved from `15-alpine` to `18-alpine`.
PostgreSQL major-version data directories are not forward-compatible, so
existing installations with `database.persistence.enabled=true` will not
start under PostgreSQL 18 against a PG15 PVC. The database pod will fail
its readiness probe with:

```
database files are incompatible with server
The data directory was initialized by PostgreSQL version 15, which is
not compatible with this version 18.x.
```

Pick one of the two paths below before running `helm upgrade`.

### Option 1 — drop the data and repopulate (recommended)

The kguardian database stores only ephemeral observability state:
captured pod traffic, syscall samples, and pod/service spec snapshots.
The controller and broker repopulate it from the live cluster state
once they reconnect, so dropping the PVC is non-destructive in practice.

```sh
# 1. Scale broker + controller down so nothing is writing.
kubectl -n <ns> scale deploy/kguardian-broker --replicas=0
kubectl -n <ns> rollout pause daemonset/kguardian-controller

# 2. Delete the database deployment + PVC.
kubectl -n <ns> delete deploy/kguardian-db
kubectl -n <ns> delete pvc <existing-claim-name>

# 3. Apply the new chart (creates a fresh PG18 data dir).
helm upgrade --install kguardian kguardian/kguardian \
  --namespace <ns> \
  --set database.persistence.existingClaim=<new-claim-name>

# 4. Resume the controller; broker will be re-created by the chart.
kubectl -n <ns> rollout resume daemonset/kguardian-controller
```

### Option 2 — pg_upgrade in place (preserves data)

Use this if you have downstream tooling that depends on continuity of
the database contents.

```sh
# 1. Take a logical backup as a safety net.
kubectl -n <ns> exec deploy/kguardian-db -- pg_dumpall -U rust > backup.sql

# 2. Stop the broker (drops live writers).
kubectl -n <ns> scale deploy/kguardian-broker --replicas=0

# 3. Run pg_upgrade against the existing PVC. Easiest is to mount it in
#    a one-shot Job that runs both PG15 and PG18 binaries, e.g.
#    tianon/postgres-upgrade:15-to-18, with both /var/lib/postgres/15 and
#    /var/lib/postgres/18 PVCs mounted. After it completes, repoint the
#    chart at the new (PG18) PVC via database.persistence.existingClaim.

# 4. Apply the new chart.
helm upgrade --install kguardian kguardian/kguardian \
  --namespace <ns> \
  --set database.persistence.existingClaim=<pg18-claim-name>
```

If neither path is acceptable, pin the previous tag and stay on PG15:

```yaml
database:
  image:
    tag: "15-alpine"
```

PG15 is still receiving security fixes through 2027-11-11.
