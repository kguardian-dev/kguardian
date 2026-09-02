# Changelog

## [1.20.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.19.2...chart/v1.20.0) (2026-09-02)


### Features

* **chart:** add the GitOps inputs consumers were patching by hand ([#1405](https://github.com/kguardian-dev/kguardian/issues/1405)) ([e545109](https://github.com/kguardian-dev/kguardian/commit/e5451097357265aa391f20ac959767827118b6c4))
* **chart:** wire telemetry v2 - nodes get RBAC + FEATURES env ([07836ec](https://github.com/kguardian-dev/kguardian/commit/07836ecc1d3fbf4aa19005c7516c4710a00ea6f8))
* **telemetry:** report environment signals in the check-in ([fcab3f4](https://github.com/kguardian-dev/kguardian/commit/fcab3f4bcd415e0485a2c982f2ac11e91e5e0aab))


### Bug Fixes

* **deps:** bump chart to the telemetry-v2 + dual-stack batch ([#1417](https://github.com/kguardian-dev/kguardian/issues/1417)) ([91f0acd](https://github.com/kguardian-dev/kguardian/commit/91f0acd0cfe6b091dbbddf64b6624120d9535595))

## [1.19.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.19.1...chart/v1.19.2) (2026-09-01)


### Bug Fixes

* **deps:** bump chart to frontend 1.13.1 ([#1397](https://github.com/kguardian-dev/kguardian/issues/1397)) ([f0ecc8d](https://github.com/kguardian-dev/kguardian/commit/f0ecc8d68c0aeeaf0b3f9f73883abd070ba78b8c))

## [1.19.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.19.0...chart/v1.19.1) (2026-09-01)


### Bug Fixes

* **deps:** bump chart to controller 1.10.1 and broker 1.13.1 ([#1390](https://github.com/kguardian-dev/kguardian/issues/1390)) ([d9bbc8f](https://github.com/kguardian-dev/kguardian/commit/d9bbc8f0f0fc135e40b2bd7a4c9c2d647c046f29))

## [1.19.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.18.0...chart/v1.19.0) (2026-09-01)


### Features

* capture IPv6 traffic and emit /128 peer rules ([#1370](https://github.com/kguardian-dev/kguardian/issues/1370)) ([c1bbf51](https://github.com/kguardian-dev/kguardian/commit/c1bbf51c0d9d8d2f8216081fbb7d6aa113541a5f))


### Bug Fixes

* **deps:** bump chart component images to the IPv6 release versions ([#1383](https://github.com/kguardian-dev/kguardian/issues/1383)) ([58220f6](https://github.com/kguardian-dev/kguardian/commit/58220f6cb379760665e36d38c62019d49d46dd45))

## [1.18.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.17.3...chart/v1.18.0) (2026-08-31)


### Features

* **chart:** opt-in SSO support (frontend.sso.*) for Gateway API + oauth2-proxy ([f6e2e78](https://github.com/kguardian-dev/kguardian/commit/f6e2e780348d329dc48f803b6fbcbcb4bdb88aa1))
* **chart:** ai.baseUrl, ai.model, and the ai.mcp.* endpoint toggle ([0dd63bd](https://github.com/kguardian-dev/kguardian/commit/0dd63bd8513ff5fe28643c4f4a4866a2320a8ff5))
* **frontend:** enterprise UI shell, design tokens, and shared primitives ([e0c88fb](https://github.com/kguardian-dev/kguardian/commit/e0c88fb195b778679e5f3068c4755d0eba710736))


### Bug Fixes

* **deps:** bump chart component images to the versions just released ([ba4089c](https://github.com/kguardian-dev/kguardian/commit/ba4089c9c969515ce7dda3c088813133bfab7569))


### Documentation

* **chart:** state the MCP auth rationale accurately ([c9c0c20](https://github.com/kguardian-dev/kguardian/commit/c9c0c200d097f07e4626ff2928c78984a2d726cb))

## [1.17.3](https://github.com/kguardian-dev/kguardian/compare/chart/v1.17.2...chart/v1.17.3) (2026-08-13)


### Bug Fixes

* **deps:** bump chart component images to security-patched versions ([#1285](https://github.com/kguardian-dev/kguardian/issues/1285)) ([c8f66cd](https://github.com/kguardian-dev/kguardian/commit/c8f66cdc2d737121f1b70ee4b3cecf0d0c68515a))
* **deps:** update ghcr.io/kguardian-dev/kguardian/controller docker tag to v1.9.3 ([#1281](https://github.com/kguardian-dev/kguardian/issues/1281)) ([a598165](https://github.com/kguardian-dev/kguardian/commit/a59816588b55748ce9b011b7b2a84bf1664166fc))
* **deps:** update ghcr.io/kguardian-dev/kguardian/evaluator docker tag to v0.3.4 ([#1282](https://github.com/kguardian-dev/kguardian/issues/1282)) ([50aba87](https://github.com/kguardian-dev/kguardian/commit/50aba87373849fe8a87852d310ba799ad9dc1e29))
* **deps:** update ghcr.io/kguardian-dev/kguardian/frontend docker tag to v1.11.4 ([#1283](https://github.com/kguardian-dev/kguardian/issues/1283)) ([1d72263](https://github.com/kguardian-dev/kguardian/commit/1d72263b21b7a567d59bd573cb46f3cb12d0e657))
* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.6.2 ([#1284](https://github.com/kguardian-dev/kguardian/issues/1284)) ([3bf3071](https://github.com/kguardian-dev/kguardian/commit/3bf3071ec1ead47ad02acec376072245e06f1959))

## [1.17.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.17.1...chart/v1.17.2) (2026-08-07)


### Bug Fixes

* **deps:** update controller image tag to 1.9.2 ([#1252](https://github.com/kguardian-dev/kguardian/issues/1252)) ([3a052f1](https://github.com/kguardian-dev/kguardian/commit/3a052f1a8866036f437aee4ab977c7706f99a254))
* **deps:** update ghcr.io/kguardian-dev/kguardian/broker docker tag to v1.12.3 ([c60092b](https://github.com/kguardian-dev/kguardian/commit/c60092b465860aa47f30499283489425d5a6db21))
* **deps:** update ghcr.io/kguardian-dev/kguardian/frontend docker tag to v1.11.3 ([#1213](https://github.com/kguardian-dev/kguardian/issues/1213)) ([2a86f0b](https://github.com/kguardian-dev/kguardian/commit/2a86f0b48f3e9f72593c9c74930d65694b62cdbf))
* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.6.1 ([#1214](https://github.com/kguardian-dev/kguardian/issues/1214)) ([13df28c](https://github.com/kguardian-dev/kguardian/commit/13df28cbea8918cf5b1c9366f04d3186a2ed44fe))

## [1.17.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.17.0...chart/v1.17.1) (2026-07-29)


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/frontend docker tag to v1.11.2 ([#1207](https://github.com/kguardian-dev/kguardian/issues/1207)) ([ebf37c3](https://github.com/kguardian-dev/kguardian/commit/ebf37c3c66e24cdc68fd0e5c9dda435725af8638))

## [1.17.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.16.0...chart/v1.17.0) (2026-07-28)


### Features

* **chart:** one-line ai.provider + ai.secret for the assistant ([#1192](https://github.com/kguardian-dev/kguardian/issues/1192)) ([1e7c505](https://github.com/kguardian-dev/kguardian/commit/1e7c505963a720828c1b63a46c57b25c7ed901ff))
* **chart:** single-workload AI assistant — retire mcp-server + advisor-serve ([e03d7bb](https://github.com/kguardian-dev/kguardian/commit/e03d7bb6d7ea25b09c626c7ea8e3376ffc239f05))
* **chart:** single-workload AI assistant — retire mcp-server + advisor-serve ([5c7e4f1](https://github.com/kguardian-dev/kguardian/commit/5c7e4f187f2d712168058a17d196d5bc0e33a221))


### Bug Fixes

* **chart:** default llm-bridge image to 1.6.0 for the advisor-free assistant ([7ea8184](https://github.com/kguardian-dev/kguardian/commit/7ea8184a7c51aec9f1ae5559ebe193e19b58eb62))
* **chart:** default llm-bridge image to 1.6.0 for the advisor-free assistant ([fc15494](https://github.com/kguardian-dev/kguardian/commit/fc154946a481ab65efae013d7760987df08869cc))
* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.5.0 ([#1182](https://github.com/kguardian-dev/kguardian/issues/1182)) ([d7909a5](https://github.com/kguardian-dev/kguardian/commit/d7909a5a5e9cd531044d999378384b13a1d185ae))


### Documentation

* **chart:** UPGRADING note for the ai.* one-line keys ([#1193](https://github.com/kguardian-dev/kguardian/issues/1193)) ([17ad965](https://github.com/kguardian-dev/kguardian/commit/17ad965d419f793ae69c6404d9245e5a88e03683))


### Code Refactoring

* **llm-bridge:** generate network policies in-process, drop advisor dep ([#1190](https://github.com/kguardian-dev/kguardian/issues/1190)) ([a0851cc](https://github.com/kguardian-dev/kguardian/commit/a0851cc05cdf070ec18067dbe7d6bdfe5ba6a686))

## [1.16.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.15.0...chart/v1.16.0) (2026-07-26)


### Features

* **llm-bridge:** run MCP tools in-process, drop the mcp-server hop (WS-B) ([#1180](https://github.com/kguardian-dev/kguardian/issues/1180)) ([8126fd4](https://github.com/kguardian-dev/kguardian/commit/8126fd49b59f9924713b77617f22af5401e6757f))


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.4.4 ([#1170](https://github.com/kguardian-dev/kguardian/issues/1170)) ([4306131](https://github.com/kguardian-dev/kguardian/commit/4306131dea30920d3a776d19d26588f348524f5f))

## [1.15.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.14.3...chart/v1.15.0) (2026-07-25)


### Features

* **chart:** ai.enabled umbrella toggle for the assistant path ([#1165](https://github.com/kguardian-dev/kguardian/issues/1165)) ([3fe4948](https://github.com/kguardian-dev/kguardian/commit/3fe49480d469b1f6062e97832931617714431a03))

## [1.14.3](https://github.com/kguardian-dev/kguardian/compare/chart/v1.14.2...chart/v1.14.3) (2026-07-24)


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/advisor docker tag to v1.6.2 ([#1154](https://github.com/kguardian-dev/kguardian/issues/1154)) ([c58e00a](https://github.com/kguardian-dev/kguardian/commit/c58e00a6ad6524b24199a055756124ef4be3d665))
* **deps:** update ghcr.io/kguardian-dev/kguardian/evaluator docker tag to v0.3.3 ([#1155](https://github.com/kguardian-dev/kguardian/issues/1155)) ([e07132f](https://github.com/kguardian-dev/kguardian/commit/e07132f1dd9dba0bd9d4f51b51f1ecabb7436a7c))
* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.4.3 ([#1153](https://github.com/kguardian-dev/kguardian/issues/1153)) ([345f127](https://github.com/kguardian-dev/kguardian/commit/345f12716a45120be26e0a2eac47c06034bc93d2))

## [1.14.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.14.1...chart/v1.14.2) (2026-07-21)


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/broker docker tag to v1.12.2 ([#1128](https://github.com/kguardian-dev/kguardian/issues/1128)) ([93a5a75](https://github.com/kguardian-dev/kguardian/commit/93a5a751e92b347f6bf85942c189c085abe50982))
* **deps:** update ghcr.io/kguardian-dev/kguardian/llm-bridge docker tag to v1.4.2 ([#1132](https://github.com/kguardian-dev/kguardian/issues/1132)) ([caec610](https://github.com/kguardian-dev/kguardian/commit/caec6104b0bf678eec768c6bcd5776bb1ee0b697))
* **deps:** update ghcr.io/kguardian-dev/kguardian/mcp-server docker tag to v1.5.1 ([#1133](https://github.com/kguardian-dev/kguardian/issues/1133)) ([32a66e1](https://github.com/kguardian-dev/kguardian/commit/32a66e156a2521d7a26d93de775d57d2acd4953d))

## [1.14.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.14.0...chart/v1.14.1) (2026-07-21)


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/broker docker tag to v1.12.1 ([#1121](https://github.com/kguardian-dev/kguardian/issues/1121)) ([88773cb](https://github.com/kguardian-dev/kguardian/commit/88773cb00fcf9383723a79680067a22368e0d898))

## [1.14.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.13.2...chart/v1.14.0) (2026-07-20)


### Features

* **broker:** anonymous daily version check-in and /version endpoint ([#1098](https://github.com/kguardian-dev/kguardian/issues/1098)) ([bc6accf](https://github.com/kguardian-dev/kguardian/commit/bc6accf90bbf95aece872195d6939eb3642a2b03))


### Bug Fixes

* **deps:** update ghcr.io/kguardian-dev/kguardian/broker docker tag to v1.12.0 ([#1101](https://github.com/kguardian-dev/kguardian/issues/1101)) ([7720b7d](https://github.com/kguardian-dev/kguardian/commit/7720b7de8455d56761b741fdc110cb47a50fce04))

## [1.13.2](https://github.com/kguardian-dev/kguardian/compare/chart/v1.13.1...chart/v1.13.2) (2026-07-19)


### Bug Fixes

* **charts:** track chart release in appVersion and release on image bumps ([#1096](https://github.com/kguardian-dev/kguardian/issues/1096)) ([7924050](https://github.com/kguardian-dev/kguardian/commit/792405030c2f40961b9efea2d3ff90ee2f77dd65))

## [1.13.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.13.0...chart/v1.13.1) (2026-07-19)


### Bug Fixes

* **broker:** add statement_timeout backstop on DB connections ([#1036](https://github.com/kguardian-dev/kguardian/issues/1036)) ([4d139c2](https://github.com/kguardian-dev/kguardian/commit/4d139c25512bee3f4b0e543fde0993cd1e29f2e6))

## [1.13.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.12.0...chart/v1.13.0) (2026-06-29)


### Features

* MCP/LLM integration uplift + data-path hardening ([572b31f](https://github.com/kguardian-dev/kguardian/commit/572b31fdcb470af9f6c844186fb9b8fa8cc8b83f))

## [1.12.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.11.1...chart/v1.12.0) (2026-06-01)


### Features

* massive-uplift production hardening release ([#888](https://github.com/kguardian-dev/kguardian/issues/888)) ([176a160](https://github.com/kguardian-dev/kguardian/commit/176a160ae4f63baf46a6b5372a2b91040c28961f))


### Bug Fixes

* **controller:** one-shot warn instead of stderr-flood on ring-buffer receiver close ([846d04d](https://github.com/kguardian-dev/kguardian/commit/846d04db1cb509659d18bba0f614d4bd9bf9e5e9))

## [1.11.1](https://github.com/kguardian-dev/kguardian/compare/chart/v1.11.0...chart/v1.11.1) (2026-05-09)


### Bug Fixes

* **broker:** /health checks schema state so kubelet self-heals on DB wipe ([#876](https://github.com/kguardian-dev/kguardian/issues/876)) ([919ae87](https://github.com/kguardian-dev/kguardian/commit/919ae8727818ff8042eb7bd46574b40bd124f65f))
* **chart:** use Recreate strategy on database deployment ([#870](https://github.com/kguardian-dev/kguardian/issues/870)) ([6f58dee](https://github.com/kguardian-dev/kguardian/commit/6f58dee9d36daf67dd74b24f53638069bd2939b5))

## [1.11.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.10.0...chart/v1.11.0) (2026-05-07)


### Features

* **chart:** enable evaluator by default ([#867](https://github.com/kguardian-dev/kguardian/issues/867)) ([3953760](https://github.com/kguardian-dev/kguardian/commit/3953760878f3139f761a7deccf617c4637e22885))

## [1.10.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.9.1...chart/v1.10.0) (2026-05-07)


### Features

* AuditNetworkPolicy — preview NetworkPolicy impact, end-to-end ([#851](https://github.com/kguardian-dev/kguardian/issues/851)) ([05acd27](https://github.com/kguardian-dev/kguardian/commit/05acd270883a0555384d9701be47c0b5503793e0))
* **broker:** audit_verdicts retention loop ([#858](https://github.com/kguardian-dev/kguardian/issues/858)) ([d1a309b](https://github.com/kguardian-dev/kguardian/commit/d1a309b258e2ecd6ff4741fdc133bd2b2e29203e))
* **chart,docs:** support external Postgres + configurable DB user/db, fix doc lies ([#848](https://github.com/kguardian-dev/kguardian/issues/848)) ([14a71c9](https://github.com/kguardian-dev/kguardian/commit/14a71c94a34d5d98785216adcd26a7e6295c7f0a))
* **chart:** startupProbe, topologySpreadConstraints, PDB, ServiceMonitor ([#849](https://github.com/kguardian-dev/kguardian/issues/849)) ([18386c0](https://github.com/kguardian-dev/kguardian/commit/18386c0ad9f31ad459ad25cc5ed85b7fc352cc4d))


### Bug Fixes

* **chart:** decouple MCP server from kagent/kmcp and fix broker OOM ([#749](https://github.com/kguardian-dev/kguardian/issues/749)) ([c4c226d](https://github.com/kguardian-dev/kguardian/commit/c4c226da31488d98c79ad253008b884e02f19441))
* **chart:** provision DB PVC by default, fix PGDATA mount path ([#845](https://github.com/kguardian-dev/kguardian/issues/845)) ([5467573](https://github.com/kguardian-dev/kguardian/commit/54675736f7b93385c9a3c5f6c249a3cd1d016303))
* **chart:** provision DB PVC when no existingClaim, fix PGDATA mount path ([5467573](https://github.com/kguardian-dev/kguardian/commit/54675736f7b93385c9a3c5f6c249a3cd1d016303))


### Documentation

* tier 0 — fix credibility-killers (broken links, wrong instructions, template cruft) ([#836](https://github.com/kguardian-dev/kguardian/issues/836)) ([6b58783](https://github.com/kguardian-dev/kguardian/commit/6b58783d8aeb92713de13e28a65dec6864d33f28))

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
