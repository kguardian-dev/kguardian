# Changelog

## 0.1.0 (2026-09-27)


### Features

* **supplychain-matcher:** Grype matcher sidecar ([20918ef](https://github.com/kguardian-dev/kguardian/commit/20918ef861ebfb0b94be2f6fff1523c53de6902c))


### Bug Fixes

* **deps:** containerd v2.3.6 in the supplychain matcher (GHSA-pg57-6jwg-q645) ([6c5eec7](https://github.com/kguardian-dev/kguardian/commit/6c5eec77ca41b4a8d97a0c6b55fbc97ef3728a0f))
* **deps:** update module github.com/klauspost/compress to v1.20.1 ([#1694](https://github.com/kguardian-dev/kguardian/issues/1694)) ([ab491aa](https://github.com/kguardian-dev/kguardian/commit/ab491aa8afc14324f1282b14d83ae2bade3c721e))
* **supplychain-matcher:** at most 16 file paths per finding; stream the response and answer 413 over 20 000 findings ([#1721](https://github.com/kguardian-dev/kguardian/issues/1721)) ([73d9ff5](https://github.com/kguardian-dev/kguardian/commit/73d9ff53543522512e4f1c724f669808ba0783ed))
* **supplychain-matcher:** own DB download client, https-only and address-guarded ([673af18](https://github.com/kguardian-dev/kguardian/commit/673af180648230f68aa4ebd1e49d4818a25108b4))
* **supplychain:** respect broker ingest caps; harden DB archive extraction path ([1bc16fe](https://github.com/kguardian-dev/kguardian/commit/1bc16fe4c2382d2c917835ef488548781304d3a9))
* **supplychain:** Trivy stays authoritative in the SBOM union and under the cap ([5775989](https://github.com/kguardian-dev/kguardian/commit/5775989717aa2661fa119a7dd11c24953c3c410e))

## Changelog
