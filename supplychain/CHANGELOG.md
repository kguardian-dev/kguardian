# Changelog

## 0.1.0 (2026-09-26)


### Features

* **supplychain:** add supplychain component with Trivy Operator source ([3a9898c](https://github.com/kguardian-dev/kguardian/commit/3a9898cf887a9f46cef489acfbcdf5e3a44ab5d5))
* **supplychain:** discover who signed every running image digest ([08d3410](https://github.com/kguardian-dev/kguardian/commit/08d341054f0ac79dab007cd4abee51fef295d9af))
* **supplychain:** match through the Grype sidecar when GRYPE_MATCHER_URL is set ([1ca5379](https://github.com/kguardian-dev/kguardian/commit/1ca537960b2389231e7dfeaa90eb69f1208e2304))
* **supplychain:** record the DSSE payload sha256 on registry SBOMs ([58e6be5](https://github.com/kguardian-dev/kguardian/commit/58e6be56a8bc9e727c47830ac30dc137eb588b58))
* **supplychain:** registry-attached SBOM source and matcher coordinator ([c717949](https://github.com/kguardian-dev/kguardian/commit/c71794959cce81bfbf81647c38954d52d417bd0c))


### Bug Fixes

* **supplychain:** anchor identity regexps, untrusted_root, identity-checked SBOM trust ([88cf846](https://github.com/kguardian-dev/kguardian/commit/88cf846c0e16c4066685167267fa86dad461393c))
* **supplychain:** classify embedded IPv4 and refuse reserved ranges in the registry guard ([ecf4f1a](https://github.com/kguardian-dev/kguardian/commit/ecf4f1ae64c06ae3a58d10fce93be7d0c2195c60))
* **supplychain:** copy every root Go file into the image build ([c25a678](https://github.com/kguardian-dev/kguardian/commit/c25a678cd266963023c82c97c89b8f047fceaa2f))
* **supplychain:** drop untrusted_identity; neutralise control characters; real signatures first ([b931eca](https://github.com/kguardian-dev/kguardian/commit/b931ecaaec11ec5747c7a188d059e5562ab47433))
* **supplychain:** guard registry lookups against SSRF, bound them in a worker pool ([73c6c5c](https://github.com/kguardian-dev/kguardian/commit/73c6c5cd4c0adf134c16521269f986ebd21c2cbd))
* **supplychain:** name every refused character class in the neutralisation detail ([34013f6](https://github.com/kguardian-dev/kguardian/commit/34013f606867553a8e411cb448521550176d5102))
* **supplychain:** neutralise bidi/format controls; reason codes in the contract ([127462d](https://github.com/kguardian-dev/kguardian/commit/127462d2468abf0346365729a2499a94abce41a8))
* **supplychain:** per-key retries, gzip + SBOM paging, one payload per digest ([5b405aa](https://github.com/kguardian-dev/kguardian/commit/5b405aa4a673b72e16401fac05c5c37bd605b890))
* **supplychain:** re-check tag-only correlation under the tracker lock ([6605729](https://github.com/kguardian-dev/kguardian/commit/6605729a96cb830efc7bafb45f14ca3d3cb92188))
* **supplychain:** registry SBOM payloads never copy the inventory digestKind ([dbc6e9a](https://github.com/kguardian-dev/kguardian/commit/dbc6e9a3431443cccaea7bf2e7b0aeb20983c540))
* **supplychain:** registry SBOMs only add - union input, subject binding, trust ([1a6a1df](https://github.com/kguardian-dev/kguardian/commit/1a6a1df08f118839b424c26fd700f594ca7d0759))
* **supplychain:** REGISTRY_LOOKUP_ENABLED defaults to false ([bd53aa0](https://github.com/kguardian-dev/kguardian/commit/bd53aa0ae5d565673b1f0251546d1db85e3e6e88))
* **supplychain:** REGISTRY_SBOM_ENABLED defaults to false ([c4a1b84](https://github.com/kguardian-dev/kguardian/commit/c4a1b84ff534d37d3b890258803ebb5a5dbe0351))
* **supplychain:** respect broker ingest caps; harden DB archive extraction path ([1bc16fe](https://github.com/kguardian-dev/kguardian/commit/1bc16fe4c2382d2c917835ef488548781304d3a9))
* **supplychain:** Trivy stays authoritative in the SBOM union and under the cap ([5775989](https://github.com/kguardian-dev/kguardian/commit/5775989717aa2661fa119a7dd11c24953c3c410e))


### Documentation

* **supplychain:** registry SBOM source, source priority contract and Grype status ([584eaba](https://github.com/kguardian-dev/kguardian/commit/584eaba3d9fb259a8e63d0e255361e4293b4342c))

## Changelog
