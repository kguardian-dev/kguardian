# Changelog

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
