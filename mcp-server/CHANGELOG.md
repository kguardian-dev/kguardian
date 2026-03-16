# Changelog

## [1.3.5](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.3.4...mcp-server/v1.3.5) (2026-03-16)


### Bug Fixes

* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.4.1 ([#766](https://github.com/kguardian-dev/kguardian/issues/766)) ([95680f1](https://github.com/kguardian-dev/kguardian/commit/95680f1808c60e644f0eebf157e5351f5b2df4a4))

## [1.3.4](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.3.3...mcp-server/v1.3.4) (2026-03-08)


### Bug Fixes

* **mcp-server,llm-bridge,frontend:** fix LLM/MCP integration data pipeline ([#684](https://github.com/kguardian-dev/kguardian/issues/684)) ([66b78c6](https://github.com/kguardian-dev/kguardian/commit/66b78c6c6f181ab3c3b99a797154bfc50b260604))

## [1.3.3](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.3.2...mcp-server/v1.3.3) (2026-03-01)


### Bug Fixes

* **ci:** fix release-please extra-files paths and sync VERSION files ([#692](https://github.com/kguardian-dev/kguardian/issues/692)) ([452bcad](https://github.com/kguardian-dev/kguardian/commit/452bcad0f8a13388f758569036e239bf3776036b))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.4.0 ([#715](https://github.com/kguardian-dev/kguardian/issues/715)) ([656a359](https://github.com/kguardian-dev/kguardian/commit/656a3597555be6ac47bb14a8904448bc7fa44be3))

## [1.3.2](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.3.1...mcp-server/v1.3.2) (2026-02-22)


### Bug Fixes

* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.3.1 ([#669](https://github.com/kguardian-dev/kguardian/issues/669)) ([4327a01](https://github.com/kguardian-dev/kguardian/commit/4327a0149c32d3c30640c143410d73a369edf7d9))
* **frontend,llm-bridge,mcp-server:** remediate security, performance, and stability issues ([#670](https://github.com/kguardian-dev/kguardian/issues/670)) ([f319cc0](https://github.com/kguardian-dev/kguardian/commit/f319cc008a7134dc1b8382fbc8532696c5c8febe))

## [1.3.1](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.3.0...mcp-server/v1.3.1) (2026-02-18)


### Bug Fixes

* **mcp-server:** add health endpoint for Kubernetes probes ([51bcdce](https://github.com/kguardian-dev/kguardian/commit/51bcdceff6c9fe5d33cf3d1fd57f86211887f7c2))
* **mcp-server:** return raw JSON in tool responses ([9e39a74](https://github.com/kguardian-dev/kguardian/commit/9e39a746862bc33b2e9cec156357b86d897b9809))

## [1.3.0](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.2.1...mcp-server/v1.3.0) (2026-02-17)


### Features

* overall improvements and uplift ([2f6aa21](https://github.com/kguardian-dev/kguardian/commit/2f6aa216a217412bba14126365a96c4db0e7df62))
* overall improvements and uplift ([e7c223c](https://github.com/kguardian-dev/kguardian/commit/e7c223cd00147071eefb3285b110c75585a05a3c))


### Bug Fixes

* add logging lib and improve overall logging ([3c437f7](https://github.com/kguardian-dev/kguardian/commit/3c437f7d7f75e683ccf33b59ca2ff4379a64eeb1))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.2.0 ([4be1189](https://github.com/kguardian-dev/kguardian/commit/4be11895b6f2a7a40bd2383915344b53103bd791))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.2.0 ([c9977ed](https://github.com/kguardian-dev/kguardian/commit/c9977ed7cc7af6b24ab8602146cf133acf672eca))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1.3.0 ([#642](https://github.com/kguardian-dev/kguardian/issues/642)) ([48422f0](https://github.com/kguardian-dev/kguardian/commit/48422f078853e109b47f93812f38938eaf3ef6d5))
* **deps:** update module github.com/sirupsen/logrus to v1.9.4 ([#611](https://github.com/kguardian-dev/kguardian/issues/611)) ([b09a37d](https://github.com/kguardian-dev/kguardian/commit/b09a37db79f4a439e8550b18d017c81c4b020216))
* release-please ([ed7dcad](https://github.com/kguardian-dev/kguardian/commit/ed7dcadf1f09bd6d624e36c4a47f9e1de6805b58))

## [1.2.1](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.2.0...mcp-server/v1.2.1) (2025-12-13)


### Bug Fixes

* llm with mcp ([0797192](https://github.com/kguardian-dev/kguardian/commit/079719225cabfdae169556af303a09c01d7e2243))
* llm with mcp ([453003f](https://github.com/kguardian-dev/kguardian/commit/453003ff9fbf2b00be1bb12d5c4f75b9f398727a))

## [1.2.0](https://github.com/kguardian-dev/kguardian/compare/mcp-server/v1.1.0...mcp-server/v1.2.0) (2025-11-06)


### Features

* add LLM + MCP ([0364874](https://github.com/kguardian-dev/kguardian/commit/03648744eabcf6005ff6a35cf761df608e239a81))
* add LLM + MCP integration ([a165a51](https://github.com/kguardian-dev/kguardian/commit/a165a5168ef91afe71bdb17e726baeb5df024511))
* enhance MCP server with comprehensive broker API tools ([369a9d2](https://github.com/kguardian-dev/kguardian/commit/369a9d227da0fed34b52ec110daba667e5e2ad62))
* reimplement MCP server in Go using kmcp framework ([17f4ef4](https://github.com/kguardian-dev/kguardian/commit/17f4ef4eb3f853f5e7c5d11c33da277049e4e9b9))


### Bug Fixes

* correct jsonschema tag format in MCP tool structs ([ed6642a](https://github.com/kguardian-dev/kguardian/commit/ed6642acbbf3043d1c043ee352b91c8b85f26395))
* correct MCPServer CRD to match actual kmcp specification ([560b9ab](https://github.com/kguardian-dev/kguardian/commit/560b9ab031ebee8f531f36405bb6d43bce768560))
* **deps:** update dependency zod to v4 ([29ac796](https://github.com/kguardian-dev/kguardian/commit/29ac79631a978fbf2434868f229f97c0efbec763))
* **deps:** update dependency zod to v4 ([7e71d16](https://github.com/kguardian-dev/kguardian/commit/7e71d160fced4cd46cfd0aeb0854ab3724169e57))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v0.8.0 ([d34f992](https://github.com/kguardian-dev/kguardian/commit/d34f99286651d908f2d7f3765f4ee8844dc67ac6))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v0.8.0 ([3f1a46f](https://github.com/kguardian-dev/kguardian/commit/3f1a46f2eecc12cfda5832473ace09c590432e52))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1 ([0c7ebb0](https://github.com/kguardian-dev/kguardian/commit/0c7ebb0e7658db8ef787531ea9332fe006ff87a9))
* **deps:** update module github.com/modelcontextprotocol/go-sdk to v1 ([6edc06d](https://github.com/kguardian-dev/kguardian/commit/6edc06d7bf8868ad6476df03627962de08a9dd34))
* docker builds ([0a449c8](https://github.com/kguardian-dev/kguardian/commit/0a449c859b93e839333955bcb6dd574042eaedc1))
* mcp api version ([4b39ef7](https://github.com/kguardian-dev/kguardian/commit/4b39ef71c0ed48dd2c9c983660f46563f3519486))
* release-please ([fc49294](https://github.com/kguardian-dev/kguardian/commit/fc49294bd4cf3306a81cefff8b6bca642afb49e3))
* update charts and align with kmcp ([cb850ab](https://github.com/kguardian-dev/kguardian/commit/cb850abae8aad484457ac69eb2f44b891b9af3f9))

## [1.1.0](https://github.com/kguardian-dev/kguardian/compare/chart/v1.0.0...chart/v1.1.0) (2025-11-06)


### Features

* add LLM + MCP ([0364874](https://github.com/kguardian-dev/kguardian/commit/03648744eabcf6005ff6a35cf761df608e239a81))
* add LLM + MCP integration ([a165a51](https://github.com/kguardian-dev/kguardian/commit/a165a5168ef91afe71bdb17e726baeb5df024511))
* enhance MCP server with comprehensive broker API tools ([369a9d2](https://github.com/kguardian-dev/kguardian/commit/369a9d227da0fed34b52ec110daba667e5e2ad62))
* reimplement MCP server in Go using kmcp framework ([17f4ef4](https://github.com/kguardian-dev/kguardian/commit/17f4ef4eb3f853f5e7c5d11c33da277049e4e9b9))


### Bug Fixes

* correct jsonschema tag format in MCP tool structs ([ed6642a](https://github.com/kguardian-dev/kguardian/commit/ed6642acbbf3043d1c043ee352b91c8b85f26395))
* correct MCPServer CRD to match actual kmcp specification ([560b9ab](https://github.com/kguardian-dev/kguardian/commit/560b9ab031ebee8f531f36405bb6d43bce768560))
* **deps:** update rust crate time to v0.3.37 ([1bd7ceb](https://github.com/kguardian-dev/kguardian/commit/1bd7cebd3323dc0308f18f664b50981505ba8237))
* **deps:** update rust crate time to v0.3.37 ([9cd083a](https://github.com/kguardian-dev/kguardian/commit/9cd083afe38326e92ce35f23f698e2b6ff7a5ac8))
* docker builds ([0a449c8](https://github.com/kguardian-dev/kguardian/commit/0a449c859b93e839333955bcb6dd574042eaedc1))
* mcp api version ([4b39ef7](https://github.com/kguardian-dev/kguardian/commit/4b39ef71c0ed48dd2c9c983660f46563f3519486))
* update charts and align with kmcp ([cb850ab](https://github.com/kguardian-dev/kguardian/commit/cb850abae8aad484457ac69eb2f44b891b9af3f9))
