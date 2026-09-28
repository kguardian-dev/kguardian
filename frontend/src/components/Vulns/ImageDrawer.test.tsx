// @vitest-environment jsdom
import { afterEach, describe, expect, test } from 'vitest';
import { act, cleanup, render, screen, waitFor, within } from '@testing-library/react';
import { ImageDrawer } from './ImageDrawer';
import { digestOf, gatedVulnApi, imageVulns, replayVulnApi } from '../../fixtures/vulns';
import { answer } from '../../fixtures/replay';
import { shortDigest } from '../../utils/posture';

afterEach(cleanup);

const noop = () => {};
const drawer = (digest: string, api = replayVulnApi().api) => <ImageDrawer digest={digest} onClose={noop} onOpenCve={noop} onOpenWorkload={noop} api={api} />;
const unknown = `sha256:${'0'.repeat(64)}`;
const badDigest = 'digest must be sha256:<64 hex> or sha512:<128 hex>';

describe('ImageDrawer', () => {
  test('F-06: moving to a digest that fails resets the title, workloads and SBOM state of the previous image', async () => {
    const api = replayVulnApi().api;
    const { rerender } = render(drawer(digestOf('checkout'), api));
    await screen.findByText('payments/checkout');
    expect(screen.getByRole('dialog').textContent).toContain('ghcr.io/example/checkout:4.2.0');
    rerender(drawer(unknown, api));
    await screen.findByText('Image not in the inventory');
    const dialog = screen.getByRole('dialog');
    expect(dialog.textContent).not.toContain('ghcr.io/example/checkout');
    expect(dialog.textContent).toContain(shortDigest(unknown));
    expect(screen.queryByText('payments/checkout')).toBeNull();
    expect(screen.queryByText('No SBOM from any source.')).toBeNull();
    expect(screen.queryByTestId('sbom-report')).toBeNull();
  });

  test("F-06: a new digest whose vulnerabilities read is still in flight shows none of the previous image's findings or reports", async () => {
    const checkout = digestOf('checkout');
    const grafana = digestOf('grafana');
    const g = gatedVulnApi((l) => l.startsWith(`GET /images/${grafana}/vulnerabilities`));
    const dialogText = () => screen.getByRole('dialog').textContent ?? '';
    const { rerender } = render(drawer(checkout, g.api));
    await waitFor(() => expect(dialogText()).toContain('CVE-2099-0002'));
    expect(dialogText()).toContain('Grype');
    rerender(drawer(grafana, g.api));
    await screen.findByText('observability/grafana');
    await act(async () => { await new Promise((r) => setTimeout(r, 20)); });
    // grafana carries CVE-2099-0006 only, from Trivy Operator; the rest is checkout's.
    expect(dialogText()).not.toContain('CVE-2099-0002');
    expect(dialogText()).not.toContain('CVE-2099-0007');
    expect(dialogText()).not.toContain('Grype');
    expect(within(screen.getByRole('dialog')).getAllByLabelText('Loading').length).toBeGreaterThan(0);
    await act(() => g.release(/vulnerabilities/));
    await waitFor(() => expect(dialogText()).toContain('CVE-2099-0006'));
  });

  test('F-06: the image read failing does not drop a good SBOM read', async () => {
    const grafana = digestOf('grafana');
    render(drawer(grafana, replayVulnApi([answer(`GET /images/${grafana}`, 'busy', 503)]).api));
    const sbom = await screen.findByTestId('sbom-report');
    expect(within(sbom).getByText('Registry SBOM')).toBeTruthy();
    expect(screen.getByRole('alert').textContent).toMatch(/shedding reads/);
    expect(screen.queryByText('observability/grafana')).toBeNull();
  });

  test('F-06: the SBOM read failing leaves the workloads on screen and never says "No SBOM"', async () => {
    const grafana = digestOf('grafana');
    render(drawer(grafana, replayVulnApi([answer(`GET /images/${grafana}/sbom?limit=1`, 'busy', 503)]).api));
    await screen.findByText('observability/grafana');
    expect((await screen.findByTestId('sbom-unread')).textContent).toMatch(/Could not read the SBOMs/);
    expect(screen.queryByText('No SBOM from any source.')).toBeNull();
  });

  test('IMG-11: with no SBOM listed under the digest, the SBOM the matcher worked from is shown, not "No SBOM"', async () => {
    const ledger = digestOf('ledger');
    const page = imageVulns('ledger');
    const grype = { ...page.reports[0], source: 'grype', sbomSources: ['registry'], sbomTrust: 'unverified' as const };
    render(drawer(ledger, replayVulnApi([answer(`GET /images/${ledger}/vulnerabilities?limit=100`, { ...page, reports: [grype] })]).api));
    const matched = await screen.findByTestId('sbom-matched');
    expect(matched.textContent).toContain('Registry SBOM');
    expect(matched.textContent).toContain('used by Grype');
    expect(within(matched).getByText('Unverified')).toBeTruthy();
    expect(screen.queryByText('No SBOM from any source.')).toBeNull();
  });

  test('an image with no SBOM and no report naming one still reads "No SBOM from any source"', async () => {
    render(drawer(digestOf('ledger')));
    expect(await screen.findByText('No SBOM from any source.')).toBeTruthy();
  });

  test('IMG-17: a malformed digest is an error with no Retry, and no section claims anything about it', async () => {
    const api = replayVulnApi([answer('GET /images/latest', badDigest, 400), answer('GET /images/latest/sbom?limit=1', badDigest, 400)]).api;
    render(drawer('latest', api));
    expect((await screen.findByRole('alert')).textContent).toMatch(/digest must be sha256/);
    expect(screen.queryByRole('button', { name: /Retry/ })).toBeNull();
    expect(screen.queryByText('No SBOM from any source.')).toBeNull();
    expect(screen.queryByText('Vulnerabilities')).toBeNull();
  });
});
