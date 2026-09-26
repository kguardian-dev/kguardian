/**
 * Workload profile fixtures: raw responses captured from a v1.3 Broker build
 * (PR #1669), stored verbatim in ./captures as `{request, status, body}`.
 * Nothing here is written by hand. To refresh, re-capture from a Broker and
 * replace the JSON files, then fix whatever the tests say changed.
 *
 * Sample data is neutral (payments / observability / flux-system).
 */
import type { ProfileDiff, VersionList, WorkloadListPage, WorkloadProfile } from '../types/profile';

import listPage1Raw from './captures/list-page1-limit2.json';
import listPage2Raw from './captures/list-page2-after.json';
import listNamespaceRaw from './captures/list-namespace-payments.json';
import listSearchRaw from './captures/list-search-ledger.json';
import listStatusRiskRaw from './captures/list-status-risk.json';
import partialRaw from './captures/profile-unknown-partial-flux-system-source-controller.json';
import warnRaw from './captures/profile-warn-payments-checkout-after-fix.json';
import refundsRaw from './captures/profile-warn-payments-refunds-init-fails-restricted.json';
import ledgerRaw from './captures/profile-warn-payments-ledger-mixed-crashloop-stale.json';
import riskRaw from './captures/profile-risk-observability-node-exporter-hostpid-wouldDeny.json';
import unknownRaw from './captures/profile-unknown-observability-otel-collector-fresh.json';
import versionsRaw from './captures/versions-payments-checkout.json';
import versionsPageRaw from './captures/versions-payments-checkout-page.json';
import diffDefaultRaw from './captures/diff-payments-checkout-default.json';
import diff2to4Raw from './captures/diff-payments-checkout-2-to-4.json';
import diffTrimmedRaw from './captures/diff-payments-checkout-trimmed-predecessor.json';
import err404WorkloadRaw from './captures/error-404-workload-not-found.json';
import err404RevisionRaw from './captures/error-404-revision-not-found.json';
import err400StatusRaw from './captures/error-400-bad-status.json';
import err400OrderRaw from './captures/error-400-bad-order.json';

export interface Capture<T = unknown> {
  /** `METHOD /path?query` exactly as sent to the Broker. */
  request: string;
  status: number;
  body: T;
}

const cap = <T>(raw: unknown) => raw as Capture<T>;

// ── GET /workloads ───────────────────────────────────────────────────────
export const listPage1 = cap<WorkloadListPage>(listPage1Raw);
export const listPage2 = cap<WorkloadListPage>(listPage2Raw);
export const listNamespacePayments = cap<WorkloadListPage>(listNamespaceRaw);
export const listSearchLedger = cap<WorkloadListPage>(listSearchRaw);
export const listStatusRisk = cap<WorkloadListPage>(listStatusRiskRaw);

// ── GET …/profile ────────────────────────────────────────────────────────
// v1.3: posture is `ok` only when all four core dimensions are known and ok,
// and images is unknown until vulnerability data exists, so no real workload
// is posture `ok` today. `ok` still appears per dimension (partialProfile).
/** flux-system/Deployment/source-controller: posture unknown (partial); network, syscalls, compute ok. */
export const partialProfile = cap<WorkloadProfile>(partialRaw).body;
/** payments/Deployment/checkout: warn; 5 findings, 1 in attention; completed init container. */
export const checkoutProfile = cap<WorkloadProfile>(warnRaw).body;
/** payments/Deployment/refunds: warn; an init container fails restricted (level baseline); a patch. */
export const refundsProfile = cap<WorkloadProfile>(refundsRaw).body;
/** payments/Deployment/ledger: warn; mixed digests, CrashLoopBackOff, a stale sidecar. */
export const ledgerProfile = cap<WorkloadProfile>(ledgerRaw).body;
/** observability/DaemonSet/node-exporter: risk; hostNetwork + hostPID, audit would-deny, 6 findings. */
export const riskProfile = cap<WorkloadProfile>(riskRaw).body;
/** observability/Deployment/otel-collector: freshly seen, every dimension unknown. */
export const unknownProfile = cap<WorkloadProfile>(unknownRaw).body;

export const PROFILE_CAPTURES: Capture<WorkloadProfile>[] = [partialRaw, warnRaw, refundsRaw, ledgerRaw, riskRaw, unknownRaw].map((r) => cap<WorkloadProfile>(r));

// ── versions + diff (payments/Deployment/checkout; revision 1 trimmed) ───
export const checkoutVersions = cap<VersionList>(versionsRaw).body;
export const checkoutVersionsPage = cap<VersionList>(versionsPageRaw);
/** Default diff: latest vs its predecessor. */
export const checkoutDiff = cap<ProfileDiff>(diffDefaultRaw);
export const checkoutDiff2to4 = cap<ProfileDiff>(diff2to4Raw);
/** `?to=2` whose predecessor was trimmed: `fromTrimmed: true`, `from: null`. */
export const checkoutDiffTrimmed = cap<ProfileDiff>(diffTrimmedRaw);

// ── errors ────────────────────────────────────────────────────────────────
type ErrorBody = { error: string; message: string };
export const err404WorkloadNotFound = cap<ErrorBody>(err404WorkloadRaw);
export const err404RevisionNotFound = cap<ErrorBody>(err404RevisionRaw);
export const err400BadStatus = cap<ErrorBody>(err400StatusRaw);
export const err400BadOrder = cap<ErrorBody>(err400OrderRaw);

/** Every JSON capture, for a replaying fake fetch keyed on `request`. */
export const ALL_CAPTURES: Capture[] = [
  listPage1, listPage2, listNamespacePayments, listSearchLedger, listStatusRisk,
  ...PROFILE_CAPTURES,
  checkoutVersionsPage, cap(versionsRaw), checkoutDiff, checkoutDiff2to4, checkoutDiffTrimmed,
  err404WorkloadNotFound, err404RevisionNotFound, err400BadStatus, err400BadOrder,
];
