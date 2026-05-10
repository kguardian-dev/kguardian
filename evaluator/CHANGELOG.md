# Changelog

## [0.2.2](https://github.com/kguardian-dev/kguardian/compare/evaluator/v0.2.1...evaluator/v0.2.2) (2026-05-09)


### Bug Fixes

* **controller:** one-shot warn instead of stderr-flood on ring-buffer receiver close ([846d04d](https://github.com/kguardian-dev/kguardian/commit/846d04db1cb509659d18bba0f614d4bd9bf9e5e9))
* **evaluator,controller:** two log-spam sources reported in the wild ([#880](https://github.com/kguardian-dev/kguardian/issues/880)) ([541b1dc](https://github.com/kguardian-dev/kguardian/commit/541b1dc301f585e0eaf8acc252f4863308414ac4))

## [0.2.1](https://github.com/kguardian-dev/kguardian/compare/evaluator/v0.2.0...evaluator/v0.2.1) (2026-05-09)


### Bug Fixes

* **evaluator:** plug informer-goroutine leak on cache-sync failure ([#872](https://github.com/kguardian-dev/kguardian/issues/872)) ([65ae885](https://github.com/kguardian-dev/kguardian/commit/65ae8851a9ac7f6c6ee1c67474bdde20671583cb))

## [0.2.0](https://github.com/kguardian-dev/kguardian/compare/evaluator/v0.1.0...evaluator/v0.2.0) (2026-05-07)


### Features

* AuditNetworkPolicy — preview NetworkPolicy impact, end-to-end ([#851](https://github.com/kguardian-dev/kguardian/issues/851)) ([05acd27](https://github.com/kguardian-dev/kguardian/commit/05acd270883a0555384d9701be47c0b5503793e0))
