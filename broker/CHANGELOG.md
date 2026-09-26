# Changelog

## [1.19.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.18.2...broker/v1.19.0) (2026-09-26)


### Features

* **broker:** count a digest as running while its pod is live, with a configurable window ([3e0998c](https://github.com/kguardian-dev/kguardian/commit/3e0998cb3cf32fd8748c706fdd556ffc8ad528cf))
* **broker:** in-use tiers for vulnerability findings ([93d71e8](https://github.com/kguardian-dev/kguardian/commit/93d71e8056479751660838b3fbc8cfffd765d0df))
* **broker:** ingest and serve supply-chain vulnerabilities and SBOMs ([0b97948](https://github.com/kguardian-dev/kguardian/commit/0b979489a3eb953b7f941a7a368821a0ac2c2fd2))
* **broker:** key workload containers per digest so mixed-image workloads are visible ([207656e](https://github.com/kguardian-dev/kguardian/commit/207656ea2d65424b8aaf24dbf4eb295da822f598))
* **broker:** OpenVEX draft in the workload export bundle ([1cc299a](https://github.com/kguardian-dev/kguardian/commit/1cc299a376c51bfe067b97afaebf41ab53046d97))
* **broker:** per-image CycloneDX SBOMs in the workload export bundle ([7ae54f9](https://github.com/kguardian-dev/kguardian/commit/7ae54f98d945324154d1b097e37340e37b69d1ec))
* **broker:** pod security standards analyser for workload profiles ([637c743](https://github.com/kguardian-dev/kguardian/commit/637c7438df211b0f8065c5fabf054b897bdd64cd))
* **broker:** profile posture is never ok while a dimension is unknown ([7b6263d](https://github.com/kguardian-dev/kguardian/commit/7b6263d4d89a2151022732312dab32dc526c9489))
* **broker:** profile posture without scores, stale-aware PSS, stable versions ([53511bb](https://github.com/kguardian-dev/kguardian/commit/53511bbc7a2a595112e2f9af347a9a4e6b135c60))
* **broker:** prune pod_traffic with batched retention ([#1653](https://github.com/kguardian-dev/kguardian/issues/1653)) ([8e7f372](https://github.com/kguardian-dev/kguardian/commit/8e7f372c51a4cc7c2fbed4a6cb797eec5ae9aa7c))
* **broker:** runtime coverage ingest and kg_runtime_coverage ([627783a](https://github.com/kguardian-dev/kguardian/commit/627783ad98a90579d0010f5fb085708322599d82))
* **broker:** runtime executable inventory ingest, reads and retention ([7a2e640](https://github.com/kguardian-dev/kguardian/commit/7a2e6406240e3dafc298f5ccd140a1fe1e6b8760))
* **broker:** scoped bearer tokens, authorised per route after routing ([5d6fa99](https://github.com/kguardian-dev/kguardian/commit/5d6fa998aefcc9bdce17e49c1ee9396db61f7acb))
* **broker:** store and serve image signature results ([c4eaea6](https://github.com/kguardian-dev/kguardian/commit/c4eaea60cfa0e4ce92a0c7558ac36cae5a3e2a1b))
* **broker:** store image inventory keyed by digest ([ae3e5c8](https://github.com/kguardian-dev/kguardian/commit/ae3e5c824bf20c0e706d9878e905c36db2ef5b9e))
* **broker:** workload export bundle, network policy generator, profile drift ([#1675](https://github.com/kguardian-dev/kguardian/issues/1675)) ([c4ed5d5](https://github.com/kguardian-dev/kguardian/commit/c4ed5d50b653f637c8a39b568b4b68796076a339))
* **broker:** workload security profile read model, versions and diff ([4b9965e](https://github.com/kguardian-dev/kguardian/commit/4b9965e682ad492cd7a2676aac083c4ac7041ee4))
* **controller:** runtime inventory coverage heartbeats ([e9ac4e8](https://github.com/kguardian-dev/kguardian/commit/e9ac4e874f1da2c15471b6c3404c59fd6c61fa96))


### Bug Fixes

* **broker:** a CVE tier not computed yet is null, not P2 ([730126c](https://github.com/kguardian-dev/kguardian/commit/730126cdf8a48ea3ec482077b3d1458f2b16daf2))
* **broker:** an empty export SBOM says 0 components reported by its source ([fd2eb62](https://github.com/kguardian-dev/kguardian/commit/fd2eb62d3dbf2ed87d88f23cc025cd7af4743d3d))
* **broker:** bound supply-chain ingest memory and harden its semantics ([2e0edf2](https://github.com/kguardian-dev/kguardian/commit/2e0edf21baa51543877f5260698515169539debc))
* **broker:** bound the export SBOM load by rows read, not the header count ([9d626df](https://github.com/kguardian-dev/kguardian/commit/9d626df70922ab82d5c7ef089f9998db040a3dad))
* **broker:** byte-bounded summaries, bidi controls refused, reason whitelist ([774758c](https://github.com/kguardian-dev/kguardian/commit/774758c8fbc9b4ca15c56672dc1d2a18f55ad0d7))
* **broker:** carry export-bundle SBOMs as comments in the YAML stream ([2cbff4a](https://github.com/kguardian-dev/kguardian/commit/2cbff4a293cdab234b69cc8b081bdf88db682430))
* **broker:** coverage fails on lost or pending events, untracked libraries and incomplete paths ([0f34d06](https://github.com/kguardian-dev/kguardian/commit/0f34d06384a8864dd4b7f6241e47e34ee633252b))
* **broker:** document and test that the CVE facts rebuild replaces rows ([951ca61](https://github.com/kguardian-dev/kguardian/commit/951ca61a89d75b340092499371516d2c1eb69168))
* **broker:** exposure needs observed ingress; keep every fixed version ([9f7a25d](https://github.com/kguardian-dev/kguardian/commit/9f7a25d238b7e22907278bc9060b5c2b209585fb))
* **broker:** follow the supplychain trust and index_digest contract ([668d750](https://github.com/kguardian-dev/kguardian/commit/668d750a283b10d7250c9f7bff66e20d4d58658b))
* **broker:** honest read charges, whole-or-refused identities, verdict consistency ([07c65e5](https://github.com/kguardian-dev/kguardian/commit/07c65e5f8735c1e1e87698f32fe333d1245a5f79))
* **broker:** incomplete heartbeats are never covered; cap coverage batches while parsing ([b2b0f81](https://github.com/kguardian-dev/kguardian/commit/b2b0f818863b042e1df88d829a0033f42a5e6dde))
* **broker:** keep CVE-level KEV and EPSS in one row per CVE ([881b19b](https://github.com/kguardian-dev/kguardian/commit/881b19b663b96af1adf5b068350687a638beb227))
* **broker:** never treat a container as covered from partial use evidence ([a1d17e8](https://github.com/kguardian-dev/kguardian/commit/a1d17e8c87ad3ed8732c7a99b458f1bbe67d873f))
* **broker:** no line break can escape a comment in the export YAML ([951698d](https://github.com/kguardian-dev/kguardian/commit/951698dba8930288d4a96c5c03d759aeea6f325b))
* **broker:** only count digests whose container is actually running ([7ce08f8](https://github.com/kguardian-dev/kguardian/commit/7ce08f8e030872fc4debda95fe35d5e390605194))
* **broker:** put image inventory reads behind per-route authorisation ([1741726](https://github.com/kguardian-dev/kguardian/commit/1741726e396ffc177a9405569304ea560923817e))
* **broker:** rebuild CVE facts in their own short, table-locked transaction ([cc17844](https://github.com/kguardian-dev/kguardian/commit/cc17844245240444da8a1295000725762be68ad6))
* **broker:** refuse control characters in attestation posts; verdict contract ([08007b4](https://github.com/kguardian-dev/kguardian/commit/08007b44676ae0bfff1fa99a144eed1db8024a8b))
* **broker:** release a pod's old digests when it reports a container with no digest ([26cf6b1](https://github.com/kguardian-dev/kguardian/commit/26cf6b1896ebf98893febf28c2c60ddeb5017c18))
* **broker:** resolve KEV and EPSS per CVE across sources before tiering ([0c25f28](https://github.com/kguardian-dev/kguardian/commit/0c25f28871f8feda787d5fcf1c29cd0e3a710237))
* **broker:** test that an unfinished in-use pass never counts as complete ([a99e3b5](https://github.com/kguardian-dev/kguardian/commit/a99e3b5be72ed604f39f69ad197e881b16cd1b36))
* **broker:** the verdict follows the signature error classes ([da62a02](https://github.com/kguardian-dev/kguardian/commit/da62a022ae25da68d2f5def3233a1d8a3420354f))
* **broker:** tolerate reason codes from a newer supplychain ([1dbf3a1](https://github.com/kguardian-dev/kguardian/commit/1dbf3a19fa41497e3762ed4129f6f4492ea5cec1))
* **broker:** VEX cap keeps version groups whole; SBOM charge from real sizes ([00c2bb5](https://github.com/kguardian-dev/kguardian/commit/00c2bb5f5b6d89a99bd679524dd98bd19ef2177c))
* **broker:** workload runtime reads use the primary key prefix; live tests restore the coverage function ([9c587f9](https://github.com/kguardian-dev/kguardian/commit/9c587f901cb1bf8d65cad39dace2bff09af5ee4c))

## [1.18.2](https://github.com/kguardian-dev/kguardian/compare/broker/v1.18.1...broker/v1.18.2) (2026-09-23)


### Bug Fixes

* **broker:** cache the GET /seccomp/profiles body so pollers share one rebuild ([dc40064](https://github.com/kguardian-dev/kguardian/commit/dc400642f62e90f62fc70ac332ba351f5c0fba94))
* **broker:** cache the GET /seccomp/profiles body so pollers share one rebuild ([a8d0abe](https://github.com/kguardian-dev/kguardian/commit/a8d0abeaecfd1f2929cf1dbfd120138a853438ea))
* **broker:** prune node_compute_latest rows for nodes that left the cluster ([#1631](https://github.com/kguardian-dev/kguardian/issues/1631)) ([2d48b44](https://github.com/kguardian-dev/kguardian/commit/2d48b445fb2e16b15d3e816544d839cb6140f4dd))

## [1.18.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.18.0...broker/v1.18.1) (2026-09-16)


### Bug Fixes

* **broker:** drop pod annotations from /pod/info, which were most of its weight ([#1602](https://github.com/kguardian-dev/kguardian/issues/1602)) ([e4462c9](https://github.com/kguardian-dev/kguardian/commit/e4462c97ac028921bc779bb43daf93d005fbfb28))

## [1.18.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.17.0...broker/v1.18.0) (2026-09-14)


### Features

* capture kernel seccomp verdicts and surface them as denials ([#1574](https://github.com/kguardian-dev/kguardian/issues/1574)) ([0db143c](https://github.com/kguardian-dev/kguardian/commit/0db143cb2643756ad0b78f5c7133f7753e91f61d))

## [1.17.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.16.1...broker/v1.17.0) (2026-09-11)


### Features

* live compute gauges and noisy-neighbour detection ([#1531](https://github.com/kguardian-dev/kguardian/issues/1531)) ([62959c2](https://github.com/kguardian-dev/kguardian/commit/62959c2be3d1fb71611c0ab77308a5d56af6ac91))

## [1.16.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.16.0...broker/v1.16.1) (2026-09-09)


### Bug Fixes

* **broker:** stop the seccomp profile list allocating per syscall name ([1cae69b](https://github.com/kguardian-dev/kguardian/commit/1cae69bba1d5170c6d06f7249861c874955a6a94))
* **broker:** stop the seccomp profile list reading syscall blobs at all ([ce516b0](https://github.com/kguardian-dev/kguardian/commit/ce516b004244a09d2bdc5d6a87d12ec0a51f8d9d))
* **broker:** stop the seccomp profile list reading syscall blobs at all ([5af98b6](https://github.com/kguardian-dev/kguardian/commit/5af98b64c2d0e7a50010b9121bd314430e17bf64))
* stop the seccomp profile list allocating per-name, and admit it to the read budget ([f03903f](https://github.com/kguardian-dev/kguardian/commit/f03903f3a106fe3faafecbbac37f2b7fae7f68fe))

## [1.16.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.15.1...broker/v1.16.0) (2026-09-08)


### Features

* detect AWS VPC CNI and align the policy builder with what the cluster enforces ([#1478](https://github.com/kguardian-dev/kguardian/issues/1478)) ([231fe4a](https://github.com/kguardian-dev/kguardian/commit/231fe4a1b7196bdaa93b3429bc454d6c9c774f1d))


### Bug Fixes

* say why a connection was blocked instead of assuming a policy did it ([#1481](https://github.com/kguardian-dev/kguardian/issues/1481)) ([dbdb10c](https://github.com/kguardian-dev/kguardian/commit/dbdb10c212bbdb3219dc21dd0ab6f5fe1c84ccbf))
* stop silently dropping observed flows and bound broker reads ([#1473](https://github.com/kguardian-dev/kguardian/issues/1473)) ([00d8f00](https://github.com/kguardian-dev/kguardian/commit/00d8f004a28bc6c449ea9befaa356e023047581f))

## [1.15.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.15.0...broker/v1.15.1) (2026-09-03)


### Bug Fixes

* resolve peer identity at ingest and guard by-IP attribution on pod start time ([#1447](https://github.com/kguardian-dev/kguardian/issues/1447)) ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))
* resolve peer identity at ingest and guard by-IP attribution on pod start time ([#1447](https://github.com/kguardian-dev/kguardian/issues/1447)) ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))


### Documentation

* peer-attribution concepts page, API reference, UPGRADING. ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))

## [1.15.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.14.0...broker/v1.15.0) (2026-09-03)


### Features

* align policy generation with the cluster CNI ([#1421](https://github.com/kguardian-dev/kguardian/issues/1421)) ([c0d9aa6](https://github.com/kguardian-dev/kguardian/commit/c0d9aa67a33c079387ae930d78a88fb130c64339))
* per-workload seccomp profile distribution ([#1418](https://github.com/kguardian-dev/kguardian/issues/1418)) ([c93c9b4](https://github.com/kguardian-dev/kguardian/commit/c93c9b44cf54a3bffefd6a378ffc1b1c12afaf9a))
* tiered syscall capture and CR-driven seccomp profile distribution ([2f0b513](https://github.com/kguardian-dev/kguardian/commit/2f0b5133e2921d36c182863dbdae2d7e1ef0c5d7))
* tiered syscall capture and CR-driven seccomp profile distribution ([#1427](https://github.com/kguardian-dev/kguardian/issues/1427)) ([2f0b513](https://github.com/kguardian-dev/kguardian/commit/2f0b5133e2921d36c182863dbdae2d7e1ef0c5d7))


### Bug Fixes

* Cilium policies carry the namespace label for cross-namespace peers ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))
* record traffic to node IPs and render host-network peers correctly ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))
* record traffic to node IPs and render host-network peers correctly ([#1431](https://github.com/kguardian-dev/kguardian/issues/1431)) ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))

## [1.14.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.13.1...broker/v1.14.0) (2026-09-02)


### Features

* **broker:** aggregate environment signals into the check-in ([f0bb077](https://github.com/kguardian-dev/kguardian/commit/f0bb0777a15fe9b5db45e3809ef330b149ac1671))
* **telemetry:** report environment signals in the check-in ([fcab3f4](https://github.com/kguardian-dev/kguardian/commit/fcab3f4bcd415e0485a2c982f2ac11e91e5e0aab))


### Bug Fixes

* serve the frontend and broker on both IP families ([#1406](https://github.com/kguardian-dev/kguardian/issues/1406)) ([da56804](https://github.com/kguardian-dev/kguardian/commit/da568046cbd90e3f2f0ed37abb1495ce9d677e1a))

## [1.13.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.13.0...broker/v1.13.1) (2026-09-01)


### Bug Fixes

* **broker:** bound /pod/traffic/{name} like the cluster-wide endpoint ([10b34f7](https://github.com/kguardian-dev/kguardian/commit/10b34f7cdf5af36198125b22cafa9480b66d6a82))
* classify TCP direction from socket state, not a port heuristic ([593e925](https://github.com/kguardian-dev/kguardian/commit/593e9253655fa8f6ebf848018dbd3e6e57fc84b8))

## [1.13.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.12.4...broker/v1.13.0) (2026-09-01)


### Features

* capture IPv6 traffic and emit /128 peer rules ([#1370](https://github.com/kguardian-dev/kguardian/issues/1370)) ([c1bbf51](https://github.com/kguardian-dev/kguardian/commit/c1bbf51c0d9d8d2f8216081fbb7d6aa113541a5f))

## [1.12.4](https://github.com/kguardian-dev/kguardian/compare/broker/v1.12.3...broker/v1.12.4) (2026-08-12)


### Bug Fixes

* **deps:** patch vulnerable Rust transitives in broker + controller (security) ([#1264](https://github.com/kguardian-dev/kguardian/issues/1264)) ([b5f3117](https://github.com/kguardian-dev/kguardian/commit/b5f3117a717ee46dfff18d291a3352b9bb8b8e98))

## [1.12.3](https://github.com/kguardian-dev/kguardian/compare/broker/v1.12.2...broker/v1.12.3) (2026-07-28)


### Code Refactoring

* **broker:** remove dead single-row POST /pod/traffic endpoint ([#1166](https://github.com/kguardian-dev/kguardian/issues/1166)) ([6cc8b57](https://github.com/kguardian-dev/kguardian/commit/6cc8b57ccd02010b651ed578f8c9b46defb8073e))

## [1.12.2](https://github.com/kguardian-dev/kguardian/compare/broker/v1.12.1...broker/v1.12.2) (2026-07-21)


### Bug Fixes

* **broker:** ignore semver build metadata in version check comparisons ([#1126](https://github.com/kguardian-dev/kguardian/issues/1126)) ([5cde86a](https://github.com/kguardian-dev/kguardian/commit/5cde86aaba64a73742ae372a22f26f7c4aeb2a2f))

## [1.12.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.12.0...broker/v1.12.1) (2026-07-21)


### Bug Fixes

* **broker:** pin builder to rust:1-bookworm to match runtime glibc ([#1120](https://github.com/kguardian-dev/kguardian/issues/1120)) ([32c41c7](https://github.com/kguardian-dev/kguardian/commit/32c41c7e5f6ea6b2fcb0ab99e6832cfe08c61080))


### Documentation

* repo-wide accuracy pass — remove obsolete, untrue, and misleading content ([#1115](https://github.com/kguardian-dev/kguardian/issues/1115)) ([72e672d](https://github.com/kguardian-dev/kguardian/commit/72e672d26d62b7c416b5fb4b526b8a7e18c7ab81))

## [1.12.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.11.1...broker/v1.12.0) (2026-07-19)


### Features

* **broker:** anonymous daily version check-in and /version endpoint ([#1098](https://github.com/kguardian-dev/kguardian/issues/1098)) ([bc6accf](https://github.com/kguardian-dev/kguardian/commit/bc6accf90bbf95aece872195d6939eb3642a2b03))

## [1.11.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.11.0...broker/v1.11.1) (2026-07-19)


### Bug Fixes

* **broker:** add statement_timeout backstop on DB connections ([#1036](https://github.com/kguardian-dev/kguardian/issues/1036)) ([4d139c2](https://github.com/kguardian-dev/kguardian/commit/4d139c25512bee3f4b0e543fde0993cd1e29f2e6))
* **broker:** bound /pod/traffic to stop oversized-response failures ([#1034](https://github.com/kguardian-dev/kguardian/issues/1034)) ([bf10c4a](https://github.com/kguardian-dev/kguardian/commit/bf10c4a626da9d6351ce504efbe41f8d79a85c9c))

## [1.11.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.10.1...broker/v1.11.0) (2026-06-29)


### Features

* MCP/LLM integration uplift + data-path hardening ([572b31f](https://github.com/kguardian-dev/kguardian/commit/572b31fdcb470af9f6c844186fb9b8fa8cc8b83f))

## [1.10.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.10.0...broker/v1.10.1) (2026-06-09)


### Bug Fixes

* **deps:** update rust crate reqwest to 0.13 ([#855](https://github.com/kguardian-dev/kguardian/issues/855)) ([c47bec2](https://github.com/kguardian-dev/kguardian/commit/c47bec2760b81defd9062520b5ee23b56e0e52fe))

## [1.10.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.9.1...broker/v1.10.0) (2026-06-01)


### Features

* massive-uplift production hardening release ([#888](https://github.com/kguardian-dev/kguardian/issues/888)) ([176a160](https://github.com/kguardian-dev/kguardian/commit/176a160ae4f63baf46a6b5372a2b91040c28961f))


### Bug Fixes

* **controller:** one-shot warn instead of stderr-flood on ring-buffer receiver close ([846d04d](https://github.com/kguardian-dev/kguardian/commit/846d04db1cb509659d18bba0f614d4bd9bf9e5e9))

## [1.9.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.9.0...broker/v1.9.1) (2026-05-09)


### Bug Fixes

* **broker:** /health checks schema state so kubelet self-heals on DB wipe ([#876](https://github.com/kguardian-dev/kguardian/issues/876)) ([919ae87](https://github.com/kguardian-dev/kguardian/commit/919ae8727818ff8042eb7bd46574b40bd124f65f))

## [1.9.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.8.0...broker/v1.9.0) (2026-05-07)


### Features

* **broker:** audit_verdicts retention loop ([#858](https://github.com/kguardian-dev/kguardian/issues/858)) ([d1a309b](https://github.com/kguardian-dev/kguardian/commit/d1a309b258e2ecd6ff4741fdc133bd2b2e29203e))
* **frontend,broker:** audit verdicts panel — Allow + WouldDeny preview ([#859](https://github.com/kguardian-dev/kguardian/issues/859)) ([f44cc17](https://github.com/kguardian-dev/kguardian/commit/f44cc17af83a1de9ebd2160776dc5569aebb8d31))

## [1.8.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.7.1...broker/v1.8.0) (2026-05-07)


### Features

* AuditNetworkPolicy — preview NetworkPolicy impact, end-to-end ([#851](https://github.com/kguardian-dev/kguardian/issues/851)) ([05acd27](https://github.com/kguardian-dev/kguardian/commit/05acd270883a0555384d9701be47c0b5503793e0))

## [1.7.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.7.0...broker/v1.7.1) (2026-03-01)


### Bug Fixes

* **ci:** fix release-please extra-files paths and sync VERSION files ([#692](https://github.com/kguardian-dev/kguardian/issues/692)) ([452bcad](https://github.com/kguardian-dev/kguardian/commit/452bcad0f8a13388f758569036e239bf3776036b))

## [1.7.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.6.1...broker/v1.7.0) (2026-02-22)


### Features

* Upgrade crates ([#664](https://github.com/kguardian-dev/kguardian/issues/664)) ([0f8e1e0](https://github.com/kguardian-dev/kguardian/commit/0f8e1e0744d644bb5b588ceaaa740d07fbb514e8))


### Bug Fixes

* **frontend,llm-bridge,mcp-server:** remediate security, performance, and stability issues ([#670](https://github.com/kguardian-dev/kguardian/issues/670)) ([f319cc0](https://github.com/kguardian-dev/kguardian/commit/f319cc008a7134dc1b8382fbc8532696c5c8febe))

## [1.6.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.6.0...broker/v1.6.1) (2026-02-18)


### Bug Fixes

* **broker:** add DB readiness gate and migration retries ([#661](https://github.com/kguardian-dev/kguardian/issues/661)) ([3543a63](https://github.com/kguardian-dev/kguardian/commit/3543a63950a316c13782a055f52094c0d67339a5))

## [1.6.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.5.0...broker/v1.6.0) (2025-12-20)


### Features

* update rust crates ([#578](https://github.com/kguardian-dev/kguardian/issues/578)) ([8e07e0a](https://github.com/kguardian-dev/kguardian/commit/8e07e0a8b9caa68526f01fe90c0f27b1a23e6b38))

## [1.5.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.4.0...broker/v1.5.0) (2025-11-30)


### Features

* Store the pod owners selector label ([#509](https://github.com/kguardian-dev/kguardian/issues/509)) ([ac6641b](https://github.com/kguardian-dev/kguardian/commit/ac6641bcfd1321781e7e6dde098ce592fd9dd0b6))

## [1.4.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.3.0...broker/v1.4.0) (2025-11-11)


### Features

* Add a new field in pod_details to get store pod identity ([#467](https://github.com/kguardian-dev/kguardian/issues/467)) ([0d78fa2](https://github.com/kguardian-dev/kguardian/commit/0d78fa242da1ffd88c4c5f820546151cb11ac5e5))

## [1.3.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.2.0...broker/v1.3.0) (2025-11-06)


### Features

* Add new endpoint to broker api to get pod details by name ([#437](https://github.com/kguardian-dev/kguardian/issues/437)) ([393b0c1](https://github.com/kguardian-dev/kguardian/commit/393b0c1e11bf999168c84cfa325dd11e7de0b9ee))
* Track pod liveliness in the cluster ([9b5b692](https://github.com/kguardian-dev/kguardian/commit/9b5b6920f495c3b40e073026e0bdfb75f496f101))

## [1.2.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.1.1...broker/v1.2.0) (2025-11-05)


### Features

* performance improvements ([#418](https://github.com/kguardian-dev/kguardian/issues/418)) ([3fcbbb8](https://github.com/kguardian-dev/kguardian/commit/3fcbbb8a227885fd61e0a26812d5a429aec24803))

## [1.1.1](https://github.com/kguardian-dev/kguardian/compare/broker/v1.1.0...broker/v1.1.1) (2025-11-01)


### Bug Fixes

* release-please changelogs ([bb81def](https://github.com/kguardian-dev/kguardian/commit/bb81defdfdde39a0f6f00761dfb2fbd4bf6cc79f))

## [1.1.0](https://github.com/kguardian-dev/kguardian/compare/broker/v1.0.0...broker/v1.1.0) (2025-11-01)


### Features

* Expose get api to invoke podsyscall details ([d27612f](https://github.com/kguardian-dev/kguardian/commit/d27612feff19fe07fe5411bbed09e11c1dd18e91))
* Store syscall details in db ([934cab2](https://github.com/kguardian-dev/kguardian/commit/934cab22c591a4f443da5a33a720f8cce60cc15a))
* update packages ([8ac1788](https://github.com/kguardian-dev/kguardian/commit/8ac17889634e3fdfd73253de47a80c87a3d7c012))


### Bug Fixes

* cleanup ([613f16a](https://github.com/kguardian-dev/kguardian/commit/613f16a89c24b4d3ff5e4d299da0ef61cd6260ae))
* **deps:** update rust crate actix-web to v4.10.2 ([bb71e1a](https://github.com/kguardian-dev/kguardian/commit/bb71e1af5174ccecdb5919eaf3c05e43ee3806c4))
* **deps:** update rust crate actix-web to v4.6.0 ([6f45faf](https://github.com/kguardian-dev/kguardian/commit/6f45fafff5089b866318a2f0d578bebf8d74fd66))
* **deps:** update rust crate actix-web to v4.6.0 ([3de2e08](https://github.com/kguardian-dev/kguardian/commit/3de2e08b2975b3cd10e07bcd69d7f2606866f6c7))
* **deps:** update rust crate actix-web to v4.7.0 ([bf2b9ac](https://github.com/kguardian-dev/kguardian/commit/bf2b9ac8f2c8cf332641abae3583ca1ff954603b))
* **deps:** update rust crate actix-web to v4.7.0 ([2e2768d](https://github.com/kguardian-dev/kguardian/commit/2e2768d54a7b3dc0e20eb49e25591ec0cde6edd0))
* **deps:** update rust crate chrono to v0.4.39 ([6cadd09](https://github.com/kguardian-dev/kguardian/commit/6cadd0922b08e1eab86a7804e684d4179fc3f6a2))
* **deps:** update rust crate chrono to v0.4.39 ([00c1d4a](https://github.com/kguardian-dev/kguardian/commit/00c1d4a37805a351f3ca03e7d5f0f856b648a8ab))
* **deps:** update rust crate diesel to v2.2.10 ([eb3aad8](https://github.com/kguardian-dev/kguardian/commit/eb3aad8cc2766c7400166a5b3b4b816c68851e3b))
* **deps:** update rust crate diesel to v2.2.7 ([98b8b7b](https://github.com/kguardian-dev/kguardian/commit/98b8b7b716861658eef2113d7bf7b4a2beaebdd8))
* **deps:** update rust crate diesel_migrations to v2.3.0 ([#337](https://github.com/kguardian-dev/kguardian/issues/337)) ([776a8ae](https://github.com/kguardian-dev/kguardian/commit/776a8ae112fbf81ceede8c0f974fd30a94932418))
* **deps:** update rust crate serde_json to v1.0.139 ([293950f](https://github.com/kguardian-dev/kguardian/commit/293950fbaf4a98d5b939a966d745fbc5582c1ca5))
* **deps:** update rust crate serde_json to v1.0.140 ([2c66b1d](https://github.com/kguardian-dev/kguardian/commit/2c66b1d4ff94d41585cd2c93cc688c7999c5cd22))
* **deps:** update rust crate thiserror to v1.0.61 ([3a8a540](https://github.com/kguardian-dev/kguardian/commit/3a8a54098a3ce3de15705f854734d4f4b7e86685))
* **deps:** update rust crate thiserror to v1.0.61 ([1a9480d](https://github.com/kguardian-dev/kguardian/commit/1a9480d55eb33792ea22f2fb83ba636e8d04bc6b))
* **deps:** update rust crate thiserror to v2 ([d9636c0](https://github.com/kguardian-dev/kguardian/commit/d9636c09b59d94df7a62e0c7560b3c0fd2e78d8a))
* **deps:** update rust crate thiserror to v2 ([43c36bb](https://github.com/kguardian-dev/kguardian/commit/43c36bb1efdb448d4b94ad8d2e9b159e53b93bda))
* **deps:** update rust crate thiserror to v2.0.12 ([ab1f6a5](https://github.com/kguardian-dev/kguardian/commit/ab1f6a5599e58d8fe745d7c966fe9c2f99d6c52f))
* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* **deps:** update rust crate uuid to v1.18.1 ([#317](https://github.com/kguardian-dev/kguardian/issues/317)) ([1385d0a](https://github.com/kguardian-dev/kguardian/commit/1385d0a9a139c3def236181ae5b94fcc7c6cddcc))
* **deps:** update serde monorepo to v1.0.218 ([8be989b](https://github.com/kguardian-dev/kguardian/commit/8be989b2e33f2253362d8785b183d8f0dbff94e1))
* **deps:** update serde monorepo to v1.0.219 ([04694dc](https://github.com/kguardian-dev/kguardian/commit/04694dcbce8c9d6c539db5a9f24167a5ae7254bf))
* **deps:** update tokio-tracing monorepo ([a3a2db5](https://github.com/kguardian-dev/kguardian/commit/a3a2db5916163c0bfd1185c443b80b47b25a6ba1))
* **deps:** update tokio-tracing monorepo ([2e0ade3](https://github.com/kguardian-dev/kguardian/commit/2e0ade381fee773ef414ae058d382847b263d04c))
* Dockefile cleanups ([1dce05d](https://github.com/kguardian-dev/kguardian/commit/1dce05d032914290b2580c9b341a7c6497b75e86))
* Dockefile cleanups ([823da4c](https://github.com/kguardian-dev/kguardian/commit/823da4ce93a6999e3a7e8a720d5fdbd4f6d28641))
* linting ([6728f10](https://github.com/kguardian-dev/kguardian/commit/6728f1046bfc6361178dde0d796b1f8abc2aa0cc))
* send the syscall data as a batch and also introduce caching in network ([d13e517](https://github.com/kguardian-dev/kguardian/commit/d13e517d196f30dc42f7825881926cee9f3b29b5))
