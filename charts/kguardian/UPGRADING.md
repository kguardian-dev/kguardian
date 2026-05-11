# Upgrading the kguardian Helm chart

## `broker.audit.retention.days: 0` now correctly disables retention

Earlier chart versions used a Helm `with` block to emit
`AUDIT_VERDICTS_RETENTION_DAYS`. Helm's `with` treats `0` as falsy and
skipped the block — so operators who set `days: 0` (the documented
"disable retention" value per values.yaml) did NOT propagate the env
var to the broker, and retention kept running at the in-broker
default of 30 days. The chart now uses an explicit `hasKey` check, so
`0` honours the disable intent.

If you'd been relying on `days: 0` as a working disable and noticed
audit_verdicts WAS retained at 30 days, your cluster's `audit_verdicts`
table likely has older rows than you expect. After upgrading:

```sh
# Inspect the row count + oldest entry.
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U rust -c "select count(*), min(observed_at) from audit_verdicts;"

# If you want to clear the historical accumulation that retention=0
# was supposed to prevent, do it explicitly after the chart upgrade:
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U rust -c "delete from audit_verdicts where observed_at < now() - interval '30 days';"
```

## Cross-major Postgres upgrades: `database.persistence.safeBoot`

The chart includes an init container (`assert-safe-boot`) that refuses
to start the database when the PVC contains a Postgres datadir for a
**different** major than the running image AND the current major's
datadir is empty. Without it the postgres image would silently `initdb`
over the empty location and leave the prior data sitting unused on the
volume — exactly how the chart's pre-1.10.0 mount-path bug surfaced as
"silent" data loss when the path was corrected.

If you're intentionally rolling forward across a major (after running
`pg_upgrade` offline, or otherwise migrating the data on disk yourself):

```yaml
database:
  persistence:
    safeBoot: false
```

Set it back to `true` once the upgrade lands so the next major catches
the same class of footgun.

## Before any chart upgrade: back up the database

The chart's bundled PostgreSQL Deployment + ReadWriteOnce PVC pattern is
fragile across template changes. Mount-path corrections (#845), image
tag bumps, or strategy changes can leave the new pod attached to the
PVC at a path PostgreSQL doesn't recognise — at which point `initdb`
runs over an empty subtree and the broker silently sees a fresh schema.
The data isn't recoverable after the fact.

### Automatic: `database.persistence.preUpgradeBackup`

The chart runs `pg_dumpall` as a Helm `pre-upgrade,pre-rollback` hook
when `database.persistence.preUpgradeBackup` is `true` (the default).
The dump streams to the Job's stdout — retrieve it with:

```sh
kubectl -n <ns> logs job/kguardian-db-pre-upgrade-backup > kguardian-db-$(date +%Y%m%d-%H%M).sql
```

The hook is best-effort: if the backup fails (DB unreachable,
`pg_dumpall` errors), it logs a warning but does NOT block the
upgrade. To skip entirely (for ephemeral test deployments) set
`database.persistence.preUpgradeBackup: false`.

### Manual fallback

Take a logical dump yourself if you want to capture state at a
specific moment that isn't tied to a chart upgrade:

```sh
kubectl -n <ns> exec deploy/kguardian-db -- \
  pg_dumpall -U "$POSTGRES_USER" --clean --if-exists \
  > kguardian-db-$(date +%Y%m%d-%H%M).sql
```

If an upgrade lands on an empty database, the broker's `/health`
endpoint reports `503 Database schema not up to date` and the kubelet
restarts the pod. Startup re-runs migrations against the new instance,
which is enough to bring the system back online — but historical rows
in `pod_traffic`, `pod_details`, and `audit_verdicts` are gone. The
dump above is what lets you restore them.

To restore:

```sh
kubectl -n <ns> cp kguardian-db-YYYYMMDD-HHMM.sql kguardian-db-<pod>:/tmp/restore.sql
kubectl -n <ns> exec deploy/kguardian-db -- \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /tmp/restore.sql
```

The kguardian data model is observability state, not source of truth —
losing it is recoverable (the controller repopulates pod/svc snapshots
from live cluster state on its next sync). The dump matters most for
`audit_verdicts`, which is a time series with no other source.

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
