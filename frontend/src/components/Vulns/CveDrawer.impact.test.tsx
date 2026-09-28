// @vitest-environment jsdom
import { afterEach, expect, test } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { CveDrawer } from './CveDrawer';
import { ProfileApi } from '../../services/profileApi';
import { exposureOf, replayVulnApi } from '../../fixtures/vulns';
import { answer } from '../../fixtures/replay';
import type { Exposure } from '../../types/vulns';

afterEach(cleanup);

const noProfiles = new ProfileApi({ fetchImpl: (async () => new Response('', { status: 404 })) as typeof fetch });
const renderDrawer = (id: string, api = replayVulnApi().api, onAskAI: (p: string) => void = () => {}) =>
  render(<CveDrawer id={id} onClose={() => {}} onOpenWorkload={() => {}} onShowOnMap={() => {}} onAskAI={onAskAI} api={api} profileApi={noProfiles} />);
const workloadRow = (name: string) => screen.getAllByTestId('cve-workload').find((r) => r.textContent?.includes(name))!;

test('IMG-04: the funnel counts running workloads, so a finished init container of an exposed Deployment cannot put "exposed" above "running"', async () => {
  const base = exposureOf('CVE-2099-0002');
  const app = base.workloads[0];
  const e: Exposure = { ...base, workloads: [app, { ...app, container: 'config-init', running: false }] };
  renderDrawer(base.id, replayVulnApi([answer(`GET /vulnerabilities/${base.id}/exposure`, e)]).api);
  const impact = await screen.findByTestId('cve-impact');
  expect(impact.textContent).toMatch(/1 image carry it → 2 workload containers → 1 running workload → 1 with outside ingress$/);
});

test('captured: the funnel reads in one unit per step and the finished CronJob is not running', async () => {
  renderDrawer('CVE-2099-0001');
  const impact = await screen.findByTestId('cve-impact');
  expect(impact.textContent).toMatch(/3 images carry it → 3 workload containers → 2 running workloads → 1 with outside ingress$/);
});

test('IMG-06: the funnel counts node-only ingress apart from outside ingress, and is not red when nothing else got in', async () => {
  const both = exposureOf('CVE-2099-0006'); // grafana via another namespace, prometheus via a node (Broker 1.19.3: exposed: true)
  renderDrawer(both.id);
  const impact = await screen.findByTestId('cve-impact');
  expect(impact.textContent).toMatch(/2 running workloads → 1 with outside ingress · 1 with node ingress only$/);
  expect(impact.querySelector('.text-severity-critical')!.textContent).toBe('1');
  cleanup();
  const probesOnly: Exposure = { ...both, workloads: both.workloads.filter((w) => w.name === 'prometheus'), images: both.images };
  renderDrawer(both.id, replayVulnApi([answer(`GET /vulnerabilities/${both.id}/exposure`, probesOnly)]).api);
  const funnel = await screen.findByTestId('cve-impact');
  expect(funnel.textContent).toMatch(/1 running workload → 0 with outside ingress · 1 with node ingress only$/);
  expect(funnel.querySelector('.text-severity-critical')).toBeNull();
  expect(funnel.querySelector('[title*="kubelet"]')).not.toBeNull();
  cleanup();
  // Broker #1780 and later flag the same row exposed: false; the drawer reads the same.
  const newShape: Exposure = { ...probesOnly, workloads: probesOnly.workloads.map((w) => ({ ...w, network: { ...w.network!, exposed: false } })) };
  renderDrawer(both.id, replayVulnApi([answer(`GET /vulnerabilities/${both.id}/exposure`, newShape)]).api);
  const later = await screen.findByTestId('cve-impact');
  expect(later.textContent).toMatch(/1 running workload → 0 with outside ingress · 1 with node ingress only$/);
  await waitFor(() => expect(screen.getAllByTestId('cve-workload')).toHaveLength(1));
  expect(workloadRow('observability/prometheus').querySelector('td:last-child [data-factor="exposure"]')!.textContent).toBe('Node ingress only');
});

test('IMG-06: ingress from nodes alone renders as a neutral "Node ingress only" chip, not the red exposed chip', async () => {
  renderDrawer('CVE-2099-0006');
  await waitFor(() => expect(screen.getAllByTestId('cve-workload')).toHaveLength(2));
  const prometheus = workloadRow('observability/prometheus').querySelector('td:last-child [data-factor="exposure"]')!;
  expect(prometheus.textContent).toBe('Node ingress only');
  expect(prometheus.className).not.toMatch(/severity-critical/);
  expect(prometheus.getAttribute('title')).toMatch(/kubelet/);
  const grafana = workloadRow('observability/grafana').querySelector('td:last-child [data-factor="exposure"]')!;
  expect(grafana.textContent).toBe('Exposed: other namespace');
  expect(grafana.className).toMatch(/severity-critical/);
});

test('IMG-16: the AI prompt states the headline factors and the workload counts the drawer shows', async () => {
  const prompts: string[] = [];
  renderDrawer('CVE-2099-0001', replayVulnApi().api, (p) => prompts.push(p));
  await waitFor(() => expect(screen.getAllByTestId('cve-workload')).toHaveLength(3));
  await waitFor(() => expect(screen.queryByTestId('headline-pending')).toBeNull());
  fireEvent.click(screen.getByRole('button', { name: 'Ask AI' }));
  expect(prompts).toHaveLength(1);
  expect(prompts[0]).toMatch(/kguardian tier P0 from [^)]*KEV/);
  expect(prompts[0]).toContain('Executed');
  expect(prompts[0]).toContain('Exposed: public IP, unattributed peer, other namespace');
  expect(prompts[0]).not.toContain('in_use:');
  expect(prompts[0]).toContain('2 distinct workload(s) running');
});
