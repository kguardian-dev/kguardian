# Changelog

## [1.9.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.9.0...chart/v1.9.1) (2026-03-01)


### Bug Fixes

* make containerd socket path configurable for k3s compatibility ([#708](https://github.com/kguardian-dev/kguardian/issues/708)) ([0017105](https://github.com/kguardian-dev/kguardian/commit/001710534c0e936f10fba8e7962137f8d481f5eb))

## [1.9.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.8.3...chart/v1.9.0) (2026-02-23)


### Features

* **chart:** pin image tags to release versions, remove CPU limits ([#688](https://github.com/kguardian-dev/kguardian/issues/688)) ([7565af5](https://github.com/kguardian-dev/kguardian/commit/7565af5b3f5835fa5e6c5ab33d3defda42496117))

## [1.8.3](https://github.com/kguardian-dev/kguardian/compare/chart/v1.8.2...chart/v1.8.3) (2026-02-22)


### Bug Fixes

* **frontend,llm-bridge,mcp-server:** remediate security, performance, and stability issues ([#670](https://github.com/kguardian-dev/kguardian/issues/670)) ([f319cc0](https://github.com/kguardian-dev/kguardian/commit/f319cc008a7134dc1b8382fbc8532696c5c8febe))

## [1.8.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.8.1...chart/v1.8.2) (2026-02-18)


### Bug Fixes

* **broker:** add DB readiness gate and migration retries ([#661](https://github.com/kguardian-dev/kguardian/issues/661)) ([3543a63](https://github.com/kguardian-dev/kguardian/commit/3543a63950a316c13782a055f52094c0d67339a5))

## [1.8.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.8.0...chart/v1.8.1) (2026-02-18)


### Bug Fixes

* **mcp-server:** add health endpoint for Kubernetes probes ([51bcdce](https://github.com/kguardian-dev/kguardian/commit/51bcdceff6c9fe5d33cf3d1fd57f86211887f7c2))

## [1.8.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.7.0...chart/v1.8.0) (2026-02-17)


### Features

* overall improvements and uplift ([2f6aa21](https://github.com/kguardian-dev/kguardian/commit/2f6aa216a217412bba14126365a96c4db0e7df62))
* overall improvements and uplift ([e7c223c](https://github.com/kguardian-dev/kguardian/commit/e7c223cd00147071eefb3285b110c75585a05a3c))

## [1.7.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.6.2...chart/v1.7.0) (2025-11-29)


### Features

* Store the pod owners selector label ([#509](https://github.com/kguardian-dev/kguardian/issues/509)) ([ac6641b](https://github.com/kguardian-dev/kguardian/commit/ac6641bcfd1321781e7e6dde098ce592fd9dd0b6))

## [1.6.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.6.1...chart/v1.6.2) (2025-11-12)


### Bug Fixes

* MCP resource will create its own managed service resource ([7ba395f](https://github.com/kguardian-dev/kguardian/commit/7ba395ffaaa2c8261c75812d53b3273a5a0c2cd5))

## [1.6.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.6.0...chart/v1.6.1) (2025-11-12)


### Bug Fixes

* helm chart description ([7d3511c](https://github.com/kguardian-dev/kguardian/commit/7d3511c6054a9f4b39785e555fdfd117ffc32326))

## [1.6.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.5.0...chart/v1.6.0) (2025-11-11)


### Features

* Add a new field in pod_details to get store pod identity ([#467](https://github.com/kguardian-dev/kguardian/issues/467)) ([0d78fa2](https://github.com/kguardian-dev/kguardian/commit/0d78fa242da1ffd88c4c5f820546151cb11ac5e5))

## [1.5.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.4.0...chart/v1.5.0) (2025-11-06)


### Features

* add LLM + MCP ([0364874](https://github.com/kguardian-dev/kguardian/commit/03648744eabcf6005ff6a35cf761df608e239a81))
* add LLM + MCP integration ([a165a51](https://github.com/kguardian-dev/kguardian/commit/a165a5168ef91afe71bdb17e726baeb5df024511))
* reimplement MCP server in Go using kmcp framework ([17f4ef4](https://github.com/kguardian-dev/kguardian/commit/17f4ef4eb3f853f5e7c5d11c33da277049e4e9b9))


### Bug Fixes

* connect llm-bridge to MCP server for all 6 tools ([d0e8d5a](https://github.com/kguardian-dev/kguardian/commit/d0e8d5a588ea7ddc46700de3f2c7b27875aba5f8))
* correct MCPServer CRD to match actual kmcp specification ([560b9ab](https://github.com/kguardian-dev/kguardian/commit/560b9ab031ebee8f531f36405bb6d43bce768560))
* default disable frontend value ([d975872](https://github.com/kguardian-dev/kguardian/commit/d9758725c406456ebfb224807876052a07414402))
* mcp api version ([4b39ef7](https://github.com/kguardian-dev/kguardian/commit/4b39ef71c0ed48dd2c9c983660f46563f3519486))
* update charts and align with kmcp ([cb850ab](https://github.com/kguardian-dev/kguardian/commit/cb850abae8aad484457ac69eb2f44b891b9af3f9))
* update workflows and helm docs for Go-based MCP server ([1c4a86f](https://github.com/kguardian-dev/kguardian/commit/1c4a86f72669ca2b23c5027b9af1d601e14e63b9))

## [1.4.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.3.2...chart/v1.4.0) (2025-11-01)


### Features

* update helm-docs ([1ed301c](https://github.com/kguardian-dev/kguardian/commit/1ed301c4e99073c35bfc2c19ddb24a85f94e9e3a))
* updating docs ([6193d8c](https://github.com/kguardian-dev/kguardian/commit/6193d8c93dd6ce2cb8ad7561e4af9fbc0cff51cf))
* updating docs ([1c92c65](https://github.com/kguardian-dev/kguardian/commit/1c92c6510dfd8c69e65ad9c3258af043390b33b8))


### Bug Fixes

* chart and dockerfile ([4f3892b](https://github.com/kguardian-dev/kguardian/commit/4f3892b0b4f096606fa38f7c93443b05c301254f))
* chart and dockerfile ([7914448](https://github.com/kguardian-dev/kguardian/commit/7914448f4cbe14616e33337a05d7d0f9e36a6d53))
* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* frontend builds and docs ([3db073c](https://github.com/kguardian-dev/kguardian/commit/3db073cc7ab39fb6a9f2fd8364c2e74e28a6bb5c))
* frontend builds and docs ([0441b2f](https://github.com/kguardian-dev/kguardian/commit/0441b2fcf76685c2f1ed319bf3f9845de0011d1b))
* release-please changelogs ([bb81def](https://github.com/kguardian-dev/kguardian/commit/bb81defdfdde39a0f6f00761dfb2fbd4bf6cc79f))
* remove nested charts/kguardian directory causing helm packaging failure ([a4f68e0](https://github.com/kguardian-dev/kguardian/commit/a4f68e0b6683ca77bbc3e3cd81ee182819e1d0f9))

## [1.3.2](https://github.com/kguardian-dev/kguardian/compare/charts/kguardian/v1.3.1...charts/kguardian/v1.3.2) (2025-11-01)


### Bug Fixes

* chart and dockerfile ([4f3892b](https://github.com/kguardian-dev/kguardian/commit/4f3892b0b4f096606fa38f7c93443b05c301254f))
* chart and dockerfile ([7914448](https://github.com/kguardian-dev/kguardian/commit/7914448f4cbe14616e33337a05d7d0f9e36a6d53))

## [1.3.1](https://github.com/kguardian-dev/kguardian/compare/charts/kguardian/v1.3.0...charts/kguardian/v1.3.1) (2025-11-01)


### Bug Fixes

* frontend builds and docs ([3db073c](https://github.com/kguardian-dev/kguardian/commit/3db073cc7ab39fb6a9f2fd8364c2e74e28a6bb5c))
* frontend builds and docs ([0441b2f](https://github.com/kguardian-dev/kguardian/commit/0441b2fcf76685c2f1ed319bf3f9845de0011d1b))

## [1.3.0](https://github.com/kguardian-dev/kguardian/compare/charts/kguardian/v1.2.0...charts/kguardian/v1.3.0) (2025-11-01)


### Features

* update helm-docs ([1ed301c](https://github.com/kguardian-dev/kguardian/commit/1ed301c4e99073c35bfc2c19ddb24a85f94e9e3a))
* updating docs ([6193d8c](https://github.com/kguardian-dev/kguardian/commit/6193d8c93dd6ce2cb8ad7561e4af9fbc0cff51cf))
* updating docs ([1c92c65](https://github.com/kguardian-dev/kguardian/commit/1c92c6510dfd8c69e65ad9c3258af043390b33b8))


### Bug Fixes

* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* release-please changelogs ([bb81def](https://github.com/kguardian-dev/kguardian/commit/bb81defdfdde39a0f6f00761dfb2fbd4bf6cc79f))
* remove nested charts/kguardian directory causing helm packaging failure ([a4f68e0](https://github.com/kguardian-dev/kguardian/commit/a4f68e0b6683ca77bbc3e3cd81ee182819e1d0f9))

## [1.2.0](https://github.com/kguardian-dev/kguardian/compare/kguardian-v1.1.2...kguardian-v1.2.0) (2025-11-01)


### Features

* update helm-docs ([1ed301c](https://github.com/kguardian-dev/kguardian/commit/1ed301c4e99073c35bfc2c19ddb24a85f94e9e3a))
* updating docs ([6193d8c](https://github.com/kguardian-dev/kguardian/commit/6193d8c93dd6ce2cb8ad7561e4af9fbc0cff51cf))
* updating docs ([1c92c65](https://github.com/kguardian-dev/kguardian/commit/1c92c6510dfd8c69e65ad9c3258af043390b33b8))


### Bug Fixes

* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* release-please changelogs ([bb81def](https://github.com/kguardian-dev/kguardian/commit/bb81defdfdde39a0f6f00761dfb2fbd4bf6cc79f))
* remove nested charts/kguardian directory causing helm packaging failure ([a4f68e0](https://github.com/kguardian-dev/kguardian/commit/a4f68e0b6683ca77bbc3e3cd81ee182819e1d0f9))

## [1.1.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.1.1...chart/v1.1.2) (2025-11-01)


### Bug Fixes

* remove nested charts/kguardian directory causing helm packaging failure ([a4f68e0](https://github.com/kguardian-dev/kguardian/commit/a4f68e0b6683ca77bbc3e3cd81ee182819e1d0f9))

## [1.1.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.1.0...chart/v1.1.1) (2025-11-01)


### Bug Fixes

* release-please changelogs ([bb81def](https://github.com/kguardian-dev/kguardian/commit/bb81defdfdde39a0f6f00761dfb2fbd4bf6cc79f))

## [1.1.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.0.1...chart/v1.1.0) (2025-11-01)


### Features

* update helm-docs ([1ed301c](https://github.com/kguardian-dev/kguardian/commit/1ed301c4e99073c35bfc2c19ddb24a85f94e9e3a))
* updating docs ([6193d8c](https://github.com/kguardian-dev/kguardian/commit/6193d8c93dd6ce2cb8ad7561e4af9fbc0cff51cf))
* updating docs ([1c92c65](https://github.com/kguardian-dev/kguardian/commit/1c92c6510dfd8c69e65ad9c3258af043390b33b8))

## [1.0.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.0.0...chart/v1.0.1) (2025-11-01)


### Bug Fixes

* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
