# Changelog

## [1.1.0](https://github.com/kguardian-dev/kguardian/compare/advisor-v1.0.0...advisor/v1.1.0) (2025-11-01)


### Features

* cilium l3 network policies ([09ba95c](https://github.com/kguardian-dev/kguardian/commit/09ba95c589cab1aeae83aea27186035063a24ce1))
* Expose get api to invoke podsyscall details ([d27612f](https://github.com/kguardian-dev/kguardian/commit/d27612feff19fe07fe5411bbed09e11c1dd18e91))
* initial seccomp integration with advisor ([a8bc978](https://github.com/kguardian-dev/kguardian/commit/a8bc978d36595134400d733331249a6586d14f44))
* reimplement cilium network policy generation ([1197589](https://github.com/kguardian-dev/kguardian/commit/1197589c0e2a40a30ea0bfc412bb85cbba16921a))


### Bug Fixes

* adding command twice ([e7ac73c](https://github.com/kguardian-dev/kguardian/commit/e7ac73c18d4a66fb5ed492184cfab78cccc1df39))
* adding missing file ([2d0bdf5](https://github.com/kguardian-dev/kguardian/commit/2d0bdf5a94aea14e869d417da137c4d7beae898c))
* advisor ingress netpol generation ([f3579fc](https://github.com/kguardian-dev/kguardian/commit/f3579fc83f18df11ae549d4ff57e09f36c68144f))
* **deps:** update kubernetes packages to v0.30.1 ([0be2f0b](https://github.com/kguardian-dev/kguardian/commit/0be2f0b0c3e9bd1e4a2d2264b30bcd7a7a69f287))
* **deps:** update kubernetes packages to v0.33.1 ([1668477](https://github.com/kguardian-dev/kguardian/commit/16684774faaa234399cd1ec9bfb2ce740858abd4))
* **deps:** update module github.com/cilium/cilium to v1.14.19 [security] ([9bd94d1](https://github.com/kguardian-dev/kguardian/commit/9bd94d11e734ec5ac17dde4fc385ca774a76ef9a))
* **deps:** update module github.com/cilium/cilium to v1.15.16 [security] ([d6639b0](https://github.com/kguardian-dev/kguardian/commit/d6639b0786e2da4bebf541b4e659b3a20001277c))
* **deps:** update module github.com/cilium/cilium to v1.17.4 ([cdfd804](https://github.com/kguardian-dev/kguardian/commit/cdfd8044c9fa25458fa26d848636b351df1e921b))
* **deps:** update module github.com/cilium/cilium to v1.18.2 ([84ae819](https://github.com/kguardian-dev/kguardian/commit/84ae819210a53df2dc39e24fbc20d003e0a6ceb8))
* **deps:** update module github.com/rs/zerolog to v1.33.0 ([c1188c9](https://github.com/kguardian-dev/kguardian/commit/c1188c9d1f6d01a942d9944b1dcff05b8bcf5d8c))
* **deps:** update module github.com/rs/zerolog to v1.34.0 ([b9f822c](https://github.com/kguardian-dev/kguardian/commit/b9f822c5b70b3a6abe30c9b7468d4cc8fc08bf84))
* **deps:** update module github.com/spf13/cobra to v1.10.1 ([38d79d0](https://github.com/kguardian-dev/kguardian/commit/38d79d0282da6ca0b959f0837d101319e0038f11))
* **deps:** update module github.com/spf13/cobra to v1.8.1 ([d1df7b8](https://github.com/kguardian-dev/kguardian/commit/d1df7b8bc839d0c101f2c180b9f5a02dcb9221e0))
* **deps:** update module github.com/stretchr/testify to v1.11.0 ([3aebc34](https://github.com/kguardian-dev/kguardian/commit/3aebc34bcebe048f70608345512df9b33793bdcc))
* **deps:** update module github.com/stretchr/testify to v1.11.1 ([34431c7](https://github.com/kguardian-dev/kguardian/commit/34431c7fc6b87880a146d70e99d8f75f61f5cd7a))
* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* golang issues ([3cf695e](https://github.com/kguardian-dev/kguardian/commit/3cf695e326e615b36f18d9a0ef2b445861aff248))
* golang issues ([6c780c6](https://github.com/kguardian-dev/kguardian/commit/6c780c6b574c6b09aa094d493fbbfc41480c955d))
* helm chart ([36ad10b](https://github.com/kguardian-dev/kguardian/commit/36ad10b0009579cceb4823a0c392c3fdb268e900))
* Make the arch as configurable ([f6b0dab](https://github.com/kguardian-dev/kguardian/commit/f6b0dab08fe12ea5887d7970201cbfee2b5c88ea))
* pod syscalls ([8f0adeb](https://github.com/kguardian-dev/kguardian/commit/8f0adeb8a34a59c3325ac5f70032d59d90ce212d))
* remove binary ([652a758](https://github.com/kguardian-dev/kguardian/commit/652a75803aa2d24bea8a0f98192e746758e75919))
* remove binary ([01ab608](https://github.com/kguardian-dev/kguardian/commit/01ab608fc0322788345e387f03a7e4dc0b7480ea))
* remove duplicate log ([a8ba5d2](https://github.com/kguardian-dev/kguardian/commit/a8ba5d22abceb38c39576bb0bacf1f3fa002017d))
* remove unnessary logs ([30c980e](https://github.com/kguardian-dev/kguardian/commit/30c980e6483479f0c7bcbb0e3ff615bb70017430))
* remove unused file ([15c93af](https://github.com/kguardian-dev/kguardian/commit/15c93af22acb8e7ca33b9162f33509ead853d750))
* trailing / missing in API call ([d2cbf98](https://github.com/kguardian-dev/kguardian/commit/d2cbf98d9a01bb8fece1e8182fa97efb4a282c6a))
* update cobra command structure ([2565f96](https://github.com/kguardian-dev/kguardian/commit/2565f96869db19d63d618dd93ffaa64ddf4a385d))
