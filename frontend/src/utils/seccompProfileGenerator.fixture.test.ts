import { expect, test } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSeccompProfile } from './seccompProfileGenerator';

// G2 generator parity — seccomp, consumer side.
// Runs every shared fixture through the frontend generator and asserts it
// produces the advisor-reference profile. The advisor Go suite
// (advisor/pkg/k8s/seccomp_fixture_test.go) asserts the same fixtures from the
// other language, so the two generators cannot silently diverge.

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '../../../test/fixtures/generators/seccomp',
);

interface SeccompFixture {
  name: string;
  input: { syscalls: string[]; arch: string };
  expected: unknown;
}

const fixtures = fs
  .readdirSync(fixturesDir)
  .filter((f) => f.endsWith('.json'))
  .map((f) => ({ file: f, data: JSON.parse(fs.readFileSync(path.join(fixturesDir, f), 'utf8')) as SeccompFixture }));

test('seccomp fixtures are discovered', () => {
  expect(fixtures.length).toBeGreaterThan(0);
});

for (const { file, data } of fixtures) {
  test(`seccomp parity: ${data.name} (${file})`, () => {
    const got = buildSeccompProfile(data.input.syscalls, data.input.arch);
    // Compare as parsed objects so cross-language serialization never matters.
    expect(JSON.parse(JSON.stringify(got))).toEqual(data.expected);
  });
}
