# Changelog

## [1.8.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.7.0...llm-bridge/v1.8.0) (2026-08-31)


### Features

* **chart:** single-workload AI assistant — retire mcp-server + advisor-serve ([4105199](https://github.com/kguardian-dev/kguardian/commit/4105199f18bff1651a62cbae291b5d677bb87be8))
* **llm-bridge:** point any provider at an OpenAI-compatible gateway ([c367db1](https://github.com/kguardian-dev/kguardian/commit/c367db1d33831cb144a17eb24170b92657b1cddc))
* **llm-bridge:** run MCP tools in-process, drop the mcp-server hop (WS-B) ([#1180](https://github.com/kguardian-dev/kguardian/issues/1180)) ([b22488f](https://github.com/kguardian-dev/kguardian/commit/b22488f2735b36f6dcd5810201d5ec24a6544bc5))
* **llm-bridge:** serve the assistant's tools over MCP at /mcp ([f237d0e](https://github.com/kguardian-dev/kguardian/commit/f237d0edf7e9b50f799ff0db3ab9c7998ec3b905))
* MCP/LLM integration uplift + data-path hardening ([855da76](https://github.com/kguardian-dev/kguardian/commit/855da76fb03dece78862efe5468bc5ab7c524ad3))


### Bug Fixes

* **deps:** patch vulnerable npm transitives in frontend + llm-bridge (security) ([#1265](https://github.com/kguardian-dev/kguardian/issues/1265)) ([89bab3e](https://github.com/kguardian-dev/kguardian/commit/89bab3e627a8d6bd8aec0e62deb9133e83472b1c))
* **deps:** update dependency @anthropic-ai/sdk to ^0.107.0 ([#1005](https://github.com/kguardian-dev/kguardian/issues/1005)) ([91d1ff8](https://github.com/kguardian-dev/kguardian/commit/91d1ff8b99082614812fb296ee4c1b0895d4367b))
* **deps:** update dependency @anthropic-ai/sdk to ^0.110.0 ([#1022](https://github.com/kguardian-dev/kguardian/issues/1022)) ([9392516](https://github.com/kguardian-dev/kguardian/commit/9392516b63829c5d10dc727e0e12e4dd122dbbbf))
* **deps:** update dependency @anthropic-ai/sdk to ^0.111.0 ([#1050](https://github.com/kguardian-dev/kguardian/issues/1050)) ([79b6def](https://github.com/kguardian-dev/kguardian/commit/79b6def13fee289a921c8db37c4193c59972fa93))
* **deps:** update dependency @anthropic-ai/sdk to ^0.112.0 ([#1072](https://github.com/kguardian-dev/kguardian/issues/1072)) ([e530d96](https://github.com/kguardian-dev/kguardian/commit/e530d96be07506a60550fe81c8fd420d4d803a86))
* **deps:** update dependency @anthropic-ai/sdk to ^0.113.0 ([#1143](https://github.com/kguardian-dev/kguardian/issues/1143)) ([ec1f700](https://github.com/kguardian-dev/kguardian/commit/ec1f7006805769c717b872981650f0f78eec2d48))
* **deps:** update dependency @anthropic-ai/sdk to ^0.114.0 ([#1150](https://github.com/kguardian-dev/kguardian/issues/1150)) ([ff9cc2d](https://github.com/kguardian-dev/kguardian/commit/ff9cc2d6e94b3f24edcd2811a6f1877cf73ee6f4))
* **deps:** update dependency @anthropic-ai/sdk to ^0.115.0 ([#1159](https://github.com/kguardian-dev/kguardian/issues/1159)) ([05d8a31](https://github.com/kguardian-dev/kguardian/commit/05d8a31a15d62307586503b002f672148ffca4e3))
* **deps:** update dependency @anthropic-ai/sdk to ^0.116.0 ([#1257](https://github.com/kguardian-dev/kguardian/issues/1257)) ([3017c24](https://github.com/kguardian-dev/kguardian/commit/3017c242b0fefcf501113483ba72ad98340adb1f))
* **deps:** update dependency @anthropic-ai/sdk to ^0.117.0 ([#1292](https://github.com/kguardian-dev/kguardian/issues/1292)) ([f95108a](https://github.com/kguardian-dev/kguardian/commit/f95108a33f63d8edbe049751ae87b31fe2c56164))
* **deps:** update dependency @anthropic-ai/sdk to ^0.118.0 ([#1304](https://github.com/kguardian-dev/kguardian/issues/1304)) ([567670b](https://github.com/kguardian-dev/kguardian/commit/567670b442bf2a653ad4e781717615a0d8c0ae0c))
* **deps:** update dependency @anthropic-ai/sdk to ^0.119.0 ([#1307](https://github.com/kguardian-dev/kguardian/issues/1307)) ([93ec448](https://github.com/kguardian-dev/kguardian/commit/93ec448fc9cbae1fd570f75f5c3bd3a43a061b98))
* **deps:** update dependency @anthropic-ai/sdk to ^0.120.0 ([#1309](https://github.com/kguardian-dev/kguardian/issues/1309)) ([dc951af](https://github.com/kguardian-dev/kguardian/commit/dc951af995c236d136c658b4e0be2d8520855922))
* **deps:** update dependency @anthropic-ai/sdk to ^0.121.0 ([#1329](https://github.com/kguardian-dev/kguardian/issues/1329)) ([ac8034f](https://github.com/kguardian-dev/kguardian/commit/ac8034fcb7e4d9ceca1b8c7d7375c2097c15266f))
* **deps:** update dependency @anthropic-ai/sdk to ^0.122.0 ([#1332](https://github.com/kguardian-dev/kguardian/issues/1332)) ([2846358](https://github.com/kguardian-dev/kguardian/commit/284635834c358ba05fb68e77ceee07bab6339023))
* **llm-bridge:** harden AI streaming — resilience + error correctness ([#1039](https://github.com/kguardian-dev/kguardian/issues/1039)) ([1d69546](https://github.com/kguardian-dev/kguardian/commit/1d695460b7b6827d1968dd223c4680f92075ba5b))
* **llm-bridge:** remove pre-auth ReDoS in the MCP bearer parser ([f82fc51](https://github.com/kguardian-dev/kguardian/commit/f82fc51c986ced8026fb2c35ebef80d706265062))
* **llm-bridge:** validate seccomp arch — no silent broken profile on unknown arch ([e8e3f0b](https://github.com/kguardian-dev/kguardian/commit/e8e3f0b0868b4fc35801ece57972a3fc6108169d))
* **llm-bridge:** validate seccomp arch — no silent broken profile on unknown arch ([046c079](https://github.com/kguardian-dev/kguardian/commit/046c079492cba8b857dcf346bf3d3739be5e10ef))


### Documentation

* **chart:** state the MCP auth rationale accurately ([837de97](https://github.com/kguardian-dev/kguardian/commit/837de9700740d8ebb4d350fd3b88ef0a18fcb564))
* MCP endpoint and gateway configuration, plus accuracy fixes ([e965414](https://github.com/kguardian-dev/kguardian/commit/e965414a1e576a755a0e752d89c19d611fb5de8b))
* repo-wide accuracy pass — remove obsolete, untrue, and misleading content ([#1115](https://github.com/kguardian-dev/kguardian/issues/1115)) ([5b527a4](https://github.com/kguardian-dev/kguardian/commit/5b527a42526919eb61d5d4edc5e85554a845c2be))


### Code Refactoring

* **llm-bridge:** consolidate OpenAI-compatible providers, drop dead route ([#1179](https://github.com/kguardian-dev/kguardian/issues/1179)) ([81ba081](https://github.com/kguardian-dev/kguardian/commit/81ba0811eb308527bf8a5c921765ff2e5105491f))
* **llm-bridge:** generate network policies in-process, drop advisor dep ([#1190](https://github.com/kguardian-dev/kguardian/issues/1190)) ([81b2e82](https://github.com/kguardian-dev/kguardian/commit/81b2e82c03085c326733861dc86771a9f5747b09))
* **llm-bridge:** generate seccomp profiles in-process ([#1188](https://github.com/kguardian-dev/kguardian/issues/1188)) ([4af83c1](https://github.com/kguardian-dev/kguardian/commit/4af83c16e4e515de7d1fc926cec98ead6f510d4f))
* **llm-bridge:** read contract fixtures from test/fixtures; fix stale docs ([7f13947](https://github.com/kguardian-dev/kguardian/commit/7f13947d1abe99f929ad1ad6b5a0b69493236aa2))
* **llm-bridge:** retire stale broker naming and dead conversationId ([#1167](https://github.com/kguardian-dev/kguardian/issues/1167)) ([6f3f0e3](https://github.com/kguardian-dev/kguardian/commit/6f3f0e32b19a41f926838cf3d30b88494c7823a6))

## [1.7.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.6.2...llm-bridge/v1.7.0) (2026-08-31)


### Features

* **llm-bridge:** point any provider at an OpenAI-compatible gateway ([2a407e2](https://github.com/kguardian-dev/kguardian/commit/2a407e20da66b632afc4158c64e462525ba080c3))
* **llm-bridge:** serve the assistant's tools over MCP at /mcp ([d3678c4](https://github.com/kguardian-dev/kguardian/commit/d3678c4130c011927078f27c354f4800fac9a627))


### Bug Fixes

* **deps:** update dependency @anthropic-ai/sdk to ^0.117.0 ([#1292](https://github.com/kguardian-dev/kguardian/issues/1292)) ([855de19](https://github.com/kguardian-dev/kguardian/commit/855de1972f2ef3bc84cdf3a7640ced7afea14379))
* **deps:** update dependency @anthropic-ai/sdk to ^0.118.0 ([#1304](https://github.com/kguardian-dev/kguardian/issues/1304)) ([9cef1cb](https://github.com/kguardian-dev/kguardian/commit/9cef1cbb2a7b27733d53b37a318e1369d2139186))
* **deps:** update dependency @anthropic-ai/sdk to ^0.119.0 ([#1307](https://github.com/kguardian-dev/kguardian/issues/1307)) ([9e26b43](https://github.com/kguardian-dev/kguardian/commit/9e26b4367f3213ad519cd564308a6e77d6e93de6))
* **deps:** update dependency @anthropic-ai/sdk to ^0.120.0 ([#1309](https://github.com/kguardian-dev/kguardian/issues/1309)) ([d7e8c4d](https://github.com/kguardian-dev/kguardian/commit/d7e8c4d21224889457e047674f5fad13865855c2))
* **deps:** update dependency @anthropic-ai/sdk to ^0.121.0 ([#1329](https://github.com/kguardian-dev/kguardian/issues/1329)) ([b8c7e6f](https://github.com/kguardian-dev/kguardian/commit/b8c7e6fb432c08dcdba19ae07542760a3263566c))
* **deps:** update dependency @anthropic-ai/sdk to ^0.122.0 ([#1332](https://github.com/kguardian-dev/kguardian/issues/1332)) ([36964a3](https://github.com/kguardian-dev/kguardian/commit/36964a3ebaa5130ff1ff2e8d736394c535330486))
* **llm-bridge:** remove pre-auth ReDoS in the MCP bearer parser ([9819dbc](https://github.com/kguardian-dev/kguardian/commit/9819dbc0cedf0c398973d33a833ba27070df88af))


### Documentation

* **chart:** state the MCP auth rationale accurately ([c9c0c20](https://github.com/kguardian-dev/kguardian/commit/c9c0c200d097f07e4626ff2928c78984a2d726cb))
* MCP endpoint and gateway configuration, plus accuracy fixes ([cd3aee4](https://github.com/kguardian-dev/kguardian/commit/cd3aee4f6f6669781887e4420864ce54b2d227d8))

## [1.6.2](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.6.1...llm-bridge/v1.6.2) (2026-08-12)


### Bug Fixes

* **deps:** patch vulnerable npm transitives in frontend + llm-bridge (security) ([#1265](https://github.com/kguardian-dev/kguardian/issues/1265)) ([f3a86e3](https://github.com/kguardian-dev/kguardian/commit/f3a86e3a8b910425712dfcf887de1118fec9216f))
* **deps:** update dependency @anthropic-ai/sdk to ^0.116.0 ([#1257](https://github.com/kguardian-dev/kguardian/issues/1257)) ([ea923bd](https://github.com/kguardian-dev/kguardian/commit/ea923bdb3a898ecfe36d0e4084035c2041f0ee23))

## [1.6.1](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.6.0...llm-bridge/v1.6.1) (2026-07-28)


### Bug Fixes

* **llm-bridge:** validate seccomp arch — no silent broken profile on unknown arch ([76f08ca](https://github.com/kguardian-dev/kguardian/commit/76f08cafdca2447d8fca25212ac0fb2ea20fc846))
* **llm-bridge:** validate seccomp arch — no silent broken profile on unknown arch ([ed56c27](https://github.com/kguardian-dev/kguardian/commit/ed56c27f81d4dd804eeec85b806dff4b07c51807))

## [1.6.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.5.0...llm-bridge/v1.6.0) (2026-07-28)


### Features

* **chart:** single-workload AI assistant — retire mcp-server + advisor-serve ([e03d7bb](https://github.com/kguardian-dev/kguardian/commit/e03d7bb6d7ea25b09c626c7ea8e3376ffc239f05))


### Code Refactoring

* **llm-bridge:** generate network policies in-process, drop advisor dep ([#1190](https://github.com/kguardian-dev/kguardian/issues/1190)) ([a0851cc](https://github.com/kguardian-dev/kguardian/commit/a0851cc05cdf070ec18067dbe7d6bdfe5ba6a686))
* **llm-bridge:** generate seccomp profiles in-process ([#1188](https://github.com/kguardian-dev/kguardian/issues/1188)) ([3b8bef4](https://github.com/kguardian-dev/kguardian/commit/3b8bef4fc3815e7c6fd929a5a7e374b768f99755))
* **llm-bridge:** read contract fixtures from test/fixtures; fix stale docs ([84d3a58](https://github.com/kguardian-dev/kguardian/commit/84d3a587e2bcfee6c2d6d31c63d5552f8e3b8233))

## [1.5.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.4.4...llm-bridge/v1.5.0) (2026-07-26)


### Features

* **llm-bridge:** run MCP tools in-process, drop the mcp-server hop (WS-B) ([#1180](https://github.com/kguardian-dev/kguardian/issues/1180)) ([8126fd4](https://github.com/kguardian-dev/kguardian/commit/8126fd49b59f9924713b77617f22af5401e6757f))


### Code Refactoring

* **llm-bridge:** consolidate OpenAI-compatible providers, drop dead route ([#1179](https://github.com/kguardian-dev/kguardian/issues/1179)) ([32b56fd](https://github.com/kguardian-dev/kguardian/commit/32b56fdf6a5b2f8e00120a8b13acc689844409e9))
* **llm-bridge:** retire stale broker naming and dead conversationId ([#1167](https://github.com/kguardian-dev/kguardian/issues/1167)) ([cacedc4](https://github.com/kguardian-dev/kguardian/commit/cacedc4bd4e8bef3913214cab08298874c7a0a3f))

## [1.4.4](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.4.3...llm-bridge/v1.4.4) (2026-07-25)


### Bug Fixes

* **deps:** update dependency @anthropic-ai/sdk to ^0.115.0 ([#1159](https://github.com/kguardian-dev/kguardian/issues/1159)) ([0f59707](https://github.com/kguardian-dev/kguardian/commit/0f597070fd9bfac772810405f2db6852af21da6e))

## [1.4.3](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.4.2...llm-bridge/v1.4.3) (2026-07-23)


### Bug Fixes

* **deps:** update dependency @anthropic-ai/sdk to ^0.113.0 ([#1143](https://github.com/kguardian-dev/kguardian/issues/1143)) ([484b7d1](https://github.com/kguardian-dev/kguardian/commit/484b7d1244e48d206f756a3099929c16134e69c7))
* **deps:** update dependency @anthropic-ai/sdk to ^0.114.0 ([#1150](https://github.com/kguardian-dev/kguardian/issues/1150)) ([6123037](https://github.com/kguardian-dev/kguardian/commit/6123037dd250411818efb5d102fe6e6c20291b28))

## [1.4.2](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.4.1...llm-bridge/v1.4.2) (2026-07-21)


### Documentation

* repo-wide accuracy pass — remove obsolete, untrue, and misleading content ([#1115](https://github.com/kguardian-dev/kguardian/issues/1115)) ([72e672d](https://github.com/kguardian-dev/kguardian/commit/72e672d26d62b7c416b5fb4b526b8a7e18c7ab81))

## [1.4.1](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.4.0...llm-bridge/v1.4.1) (2026-07-19)


### Bug Fixes

* **deps:** update dependency @anthropic-ai/sdk to ^0.110.0 ([#1022](https://github.com/kguardian-dev/kguardian/issues/1022)) ([a23a684](https://github.com/kguardian-dev/kguardian/commit/a23a68457f8b3dcf48a577b1014da8019b248a83))
* **deps:** update dependency @anthropic-ai/sdk to ^0.111.0 ([#1050](https://github.com/kguardian-dev/kguardian/issues/1050)) ([e847663](https://github.com/kguardian-dev/kguardian/commit/e847663fee2b77786b8612a96222a20b4161229d))
* **deps:** update dependency @anthropic-ai/sdk to ^0.112.0 ([#1072](https://github.com/kguardian-dev/kguardian/issues/1072)) ([8a1a112](https://github.com/kguardian-dev/kguardian/commit/8a1a112f474f89869c4d85f5fdc062e3e170e426))
* **llm-bridge:** harden AI streaming — resilience + error correctness ([#1039](https://github.com/kguardian-dev/kguardian/issues/1039)) ([81fd7b0](https://github.com/kguardian-dev/kguardian/commit/81fd7b015cc3740302ae4d4212b01ce56ba6cc73))

## [1.4.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.3.0...llm-bridge/v1.4.0) (2026-06-29)


### Features

* MCP/LLM integration uplift + data-path hardening ([572b31f](https://github.com/kguardian-dev/kguardian/commit/572b31fdcb470af9f6c844186fb9b8fa8cc8b83f))


### Bug Fixes

* **deps:** update dependency @anthropic-ai/sdk to ^0.107.0 ([#1005](https://github.com/kguardian-dev/kguardian/issues/1005)) ([ef2a5f7](https://github.com/kguardian-dev/kguardian/commit/ef2a5f773dd3e8a18e9ed858d87af8ca1562621d))

## [1.3.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.2.3...llm-bridge/v1.3.0) (2026-06-01)


### Features

* massive-uplift production hardening release ([#888](https://github.com/kguardian-dev/kguardian/issues/888)) ([176a160](https://github.com/kguardian-dev/kguardian/commit/176a160ae4f63baf46a6b5372a2b91040c28961f))


### Bug Fixes

* **controller:** one-shot warn instead of stderr-flood on ring-buffer receiver close ([846d04d](https://github.com/kguardian-dev/kguardian/commit/846d04db1cb509659d18bba0f614d4bd9bf9e5e9))

## [1.2.3](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.2.2...llm-bridge/v1.2.3) (2026-03-07)


### Bug Fixes

* **mcp-server,llm-bridge,frontend:** fix LLM/MCP integration data pipeline ([#684](https://github.com/kguardian-dev/kguardian/issues/684)) ([66b78c6](https://github.com/kguardian-dev/kguardian/commit/66b78c6c6f181ab3c3b99a797154bfc50b260604))

## [1.2.2](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.2.1...llm-bridge/v1.2.2) (2026-02-22)


### Bug Fixes

* **frontend,llm-bridge,mcp-server:** remediate security, performance, and stability issues ([#670](https://github.com/kguardian-dev/kguardian/issues/670)) ([f319cc0](https://github.com/kguardian-dev/kguardian/commit/f319cc008a7134dc1b8382fbc8532696c5c8febe))

## [1.2.1](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.2.0...llm-bridge/v1.2.1) (2026-02-18)


### Bug Fixes

* **llm-bridge:** add MCP connection recovery on failure ([d1cd198](https://github.com/kguardian-dev/kguardian/commit/d1cd198e1feb788652a1b18571fd3dc18c0a4d33))
* **llm-bridge:** implement multi-round tool calling and preserve conversation history ([fd25a8c](https://github.com/kguardian-dev/kguardian/commit/fd25a8cb2de57981219ec904be4f86b838a56312))

## [1.2.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.1.0...llm-bridge/v1.2.0) (2026-02-17)


### Features

* overall improvements and uplift ([2f6aa21](https://github.com/kguardian-dev/kguardian/commit/2f6aa216a217412bba14126365a96c4db0e7df62))
* overall improvements and uplift ([e7c223c](https://github.com/kguardian-dev/kguardian/commit/e7c223cd00147071eefb3285b110c75585a05a3c))


### Bug Fixes

* llm with mcp ([0797192](https://github.com/kguardian-dev/kguardian/commit/079719225cabfdae169556af303a09c01d7e2243))
* llm with mcp ([453003f](https://github.com/kguardian-dev/kguardian/commit/453003ff9fbf2b00be1bb12d5c4f75b9f398727a))

## [1.1.1](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.1.0...llm-bridge/v1.1.1) (2025-12-20)


### Bug Fixes

* llm with mcp ([0797192](https://github.com/kguardian-dev/kguardian/commit/079719225cabfdae169556af303a09c01d7e2243))
* llm with mcp ([453003f](https://github.com/kguardian-dev/kguardian/commit/453003ff9fbf2b00be1bb12d5c4f75b9f398727a))

## [1.1.1](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.1.0...llm-bridge/v1.1.1) (2025-12-12)


### Bug Fixes

* llm with mcp ([0797192](https://github.com/kguardian-dev/kguardian/commit/079719225cabfdae169556af303a09c01d7e2243))
* llm with mcp ([453003f](https://github.com/kguardian-dev/kguardian/commit/453003ff9fbf2b00be1bb12d5c4f75b9f398727a))

## [1.1.0](https://github.com/kguardian-dev/kguardian/compare/llm-bridge/v1.0.0...llm-bridge/v1.1.0) (2025-11-06)


### Features

* add LLM + MCP ([0364874](https://github.com/kguardian-dev/kguardian/commit/03648744eabcf6005ff6a35cf761df608e239a81))
* add LLM + MCP integration ([a165a51](https://github.com/kguardian-dev/kguardian/commit/a165a5168ef91afe71bdb17e726baeb5df024511))


### Bug Fixes

* connect llm-bridge to MCP server for all 6 tools ([d0e8d5a](https://github.com/kguardian-dev/kguardian/commit/d0e8d5a588ea7ddc46700de3f2c7b27875aba5f8))
* **deps:** update dependency dotenv to v17 ([1f234d3](https://github.com/kguardian-dev/kguardian/commit/1f234d35873d01b7c828965d65d04979cfb82926))
* **deps:** update dependency dotenv to v17 ([def6bc7](https://github.com/kguardian-dev/kguardian/commit/def6bc7d92db00c8a29bd3700c1f914c0f918a43))
* **deps:** update dependency express to v5 ([a42ebe6](https://github.com/kguardian-dev/kguardian/commit/a42ebe65ff6d95cfd2c503fc23618aca31608260))
* **deps:** update dependency express to v5 ([a735730](https://github.com/kguardian-dev/kguardian/commit/a73573040ae9914ea9f3dbdb90e7266fa223d0c3))
* **deps:** update dependency zod to v4 ([29ac796](https://github.com/kguardian-dev/kguardian/commit/29ac79631a978fbf2434868f229f97c0efbec763))
* **deps:** update dependency zod to v4 ([7e71d16](https://github.com/kguardian-dev/kguardian/commit/7e71d160fced4cd46cfd0aeb0854ab3724169e57))
* docker builds ([0a449c8](https://github.com/kguardian-dev/kguardian/commit/0a449c859b93e839333955bcb6dd574042eaedc1))
* resolve OpenAI 400 error with proper tool message formatting ([b0e3adc](https://github.com/kguardian-dev/kguardian/commit/b0e3adcd1d4aad8078e74d87fd1d5bde9616a431))
