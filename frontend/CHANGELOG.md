# Changelog

## [1.21.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.21.1...frontend/v1.21.2) (2026-10-10)


### Bug Fixes

* **frontend:** make the posture tiles clickable, and the Workloads tiles meaningful ([#1916](https://github.com/kguardian-dev/kguardian/issues/1916)) ([cc413b2](https://github.com/kguardian-dev/kguardian/commit/cc413b219e37daeff5bfe44c3e8a3dcad9902b36))

## [1.21.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.21.0...frontend/v1.21.1) (2026-09-30)


### Bug Fixes

* **llm-bridge:** update vulnerable npm dependencies and restrict the default CORS origin ([#1885](https://github.com/kguardian-dev/kguardian/issues/1885)) ([b7a879e](https://github.com/kguardian-dev/kguardian/commit/b7a879e3880298a02a8b306ad5d93e602126ce90))

## [1.21.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.8...frontend/v1.21.0) (2026-09-30)


### Features

* **frontend:** show node catalog provenance, coverage and not-assessable images ([#1861](https://github.com/kguardian-dev/kguardian/issues/1861)) ([b9d2032](https://github.com/kguardian-dev/kguardian/commit/b9d2032c93837e348553763b5d79f044dd27c9a4))

## [1.20.8](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.7...frontend/v1.20.8) (2026-09-29)


### Bug Fixes

* **frontend:** keep the assistant readable to screen readers beside a drawer ([0f82dde](https://github.com/kguardian-dev/kguardian/commit/0f82ddeda867ba82cd46faf00aaa0fd794513aef))
* **frontend:** never leave a drawer under a wide docked assistant ([b58fa23](https://github.com/kguardian-dev/kguardian/commit/b58fa23d38efb0096b600d8c8f204de9505f4ea5))
* **frontend:** open the docked assistant beside the CVE drawer, not over it ([c309530](https://github.com/kguardian-dev/kguardian/commit/c3095306082a64bd11a90c2e5de57e4a9205d020))
* **frontend:** open the docked assistant beside the CVE drawer, not over it ([27b8f6f](https://github.com/kguardian-dev/kguardian/commit/27b8f6fb079db7f231dc621317364b99284eb123))

## [1.20.7](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.6...frontend/v1.20.7) (2026-09-29)


### Bug Fixes

* **broker:** allow a Service's targetPort in generated egress rules ([82b8135](https://github.com/kguardian-dev/kguardian/commit/82b8135d3e9f92670e4ed80a0fd018cd79bc73df))
* **broker:** stop pod_compute_latest's TOAST churn and vacuum small tables when autovacuum lags ([703d64e](https://github.com/kguardian-dev/kguardian/commit/703d64e71db37caf86eb9fabd3e9558bba8e233f))
* **chart:** guard leader election settings and run the UI read-only ([1539fd6](https://github.com/kguardian-dev/kguardian/commit/1539fd6073102f02de8c033090c8e9c032f75996))
* **frontend:** allow a Service's targetPort, not its port, on generated egress rules ([f321785](https://github.com/kguardian-dev/kguardian/commit/f32178595ffb539f608d3b39c085f5b9f23c4b45))
* **frontend:** answer /oauth2/userinfo with 204 when no SSO proxy is in front ([4eea0ec](https://github.com/kguardian-dev/kguardian/commit/4eea0ec3e702534a80472a57f683ee39bb3a608a))
* **frontend:** attach a Service on the map only to pods in its namespace ([0bd3086](https://github.com/kguardian-dev/kguardian/commit/0bd308641663b3b0d43e8da8d74848c946b3b0d3))
* **frontend:** base each workload's fix chip on its own image ([cd8c266](https://github.com/kguardian-dev/kguardian/commit/cd8c266703b5ed30f7c9618dc071903713ec53c1))
* **frontend:** check the IP for a namespaceless row's only same-named pod ([6a3bd07](https://github.com/kguardian-dev/kguardian/commit/6a3bd077542d7c1cc9bc682acfb547757cb87330))
* **frontend:** count the culprits the broker leaves off in blame shares ([f331d3d](https://github.com/kguardian-dev/kguardian/commit/f331d3d53bb0b2279bc82c8e5002b483fe23a3d4))
* **frontend:** images list scope, fix chips, assistant links and the Esc lens ([1d3f8c5](https://github.com/kguardian-dev/kguardian/commit/1d3f8c50077c4f1afe51cc925b4bd8db8b8c8090))
* **frontend:** keep the assistant's page context within llm-bridge's limit ([9bfa8a6](https://github.com/kguardian-dev/kguardian/commit/9bfa8a64b7b304adc479538b0327659f49af3153))
* **frontend:** keep the lens chosen while focused when Esc leaves focus ([0dc6771](https://github.com/kguardian-dev/kguardian/commit/0dc677121f8a1465cff1293ec7e98ba881e47acb))
* **frontend:** match a row's capturing pod by name when it has no namespace ([ed6eb44](https://github.com/kguardian-dev/kguardian/commit/ed6eb44851a99994d83e167ef48f70fad9ae0433))
* **frontend:** name the capturing pod as the local side of aggregate-card rows ([c5d18f7](https://github.com/kguardian-dev/kguardian/commit/c5d18f7d09c1437f59b6f272c530332242062cf5))
* **frontend:** name the capturing pod on aggregate-card traffic rows ([6eb44e7](https://github.com/kguardian-dev/kguardian/commit/6eb44e728c7445e34cd260eecdfddfb104923e16))
* **frontend:** open every assistant link that leaves the page in a new tab ([a7909ec](https://github.com/kguardian-dev/kguardian/commit/a7909ecabb9ce555a2d5f18781995b1d2a805a44))
* **frontend:** resolve named targetPorts for host-network backends and keep digit-led port names ([37100fc](https://github.com/kguardian-dev/kguardian/commit/37100fc54bac179dfd56f7bcffceba71c908bd60))
* **frontend:** say "no CR" in the Workloads Drift column ([317898d](https://github.com/kguardian-dev/kguardian/commit/317898dfd9bb71a0a3fd97e24bc6abfa8306efeb))
* **frontend:** say blame shares are over the controller's top 20 culprits ([cf91d0d](https://github.com/kguardian-dev/kguardian/commit/cf91d0dd26470fd77f55d1a8a3976cfc5b417563))
* **frontend:** slim the runtime image and let it run read-only ([43bb038](https://github.com/kguardian-dev/kguardian/commit/43bb03858fe2dd6308c06e89a97baae98d942e97))
* **frontend:** start the Images list empty when the namespace changes ([2410975](https://github.com/kguardian-dev/kguardian/commit/24109750755ac509af6fb0f4839d910b48ebc7ea))
* **frontend:** tidy SSO detection, empty reply links and the Drift cell doc ([8ca5914](https://github.com/kguardian-dev/kguardian/commit/8ca59146b2ed004119cdedbb6f09c346063cbde7))
* **frontend:** warn in the seccomp editor when a syscall read failed ([05ac158](https://github.com/kguardian-dev/kguardian/commit/05ac158a0491bb740cecf2cc6fac13813e3767a5))

## [1.20.6](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.5...frontend/v1.20.6) (2026-09-29)


### Bug Fixes

* **frontend:** ask the image read for the drawer's CVE only ([75e2a59](https://github.com/kguardian-dev/kguardian/commit/75e2a59fe5354995b28cc3d431420593f73d88ad))
* **frontend:** back off the profile poll after a 401 or 403 ([8326110](https://github.com/kguardian-dev/kguardian/commit/8326110ccdd3f0aab5ddfeab0d80a6e6422fd807))
* **frontend:** clear the version diff while another revision pair loads ([d027154](https://github.com/kguardian-dev/kguardian/commit/d0271541d9991e0706d2f47ac0ada8dfa0581845))
* **frontend:** drop a workload's older versions when the view moves to another ([c9bf693](https://github.com/kguardian-dev/kguardian/commit/c9bf693d2aefe0ba906e84bdc5832eb42d6e05c5))
* **frontend:** finish the review round and use the broker's CVE filter and tier order ([ba2fd47](https://github.com/kguardian-dev/kguardian/commit/ba2fd476a035b16ce2963bdde760533363d93341))
* **frontend:** keep the CVE list in the Broker's tier order when it says so ([be48bb2](https://github.com/kguardian-dev/kguardian/commit/be48bb22ccce136372fd274504e3e7c6a0ffdde8))
* **frontend:** match CVE ids ignoring case and say which CVEs capped tiles cover ([0d740b3](https://github.com/kguardian-dev/kguardian/commit/0d740b33e1708a91d64801a0c213927553ebbe9e))
* **frontend:** note which cluster CIDRs a failed lookup still shows as external ([184e076](https://github.com/kguardian-dev/kguardian/commit/184e0761644e194a54fabaaed653b845dd48d475))
* **frontend:** rank tiers P0, unknown, P1, P2, Background everywhere ([ea466e2](https://github.com/kguardian-dev/kguardian/commit/ea466e2a754e78bee288d036865616d3a4280598))
* **frontend:** say a Service lookup failed instead of calling the peer a former holder ([087d164](https://github.com/kguardian-dev/kguardian/commit/087d164cb20c9f0d78f66180e03f7234d10a75f8))
* **frontend:** stop the seccomp list poll from outliving its test ([4fecec6](https://github.com/kguardian-dev/kguardian/commit/4fecec6ab45e470926312da355b01f7a2f2a3b51))
* **frontend:** tell a failed pod lookup from no pod, and use the Service listing, when the pod listing is down ([630f3ac](https://github.com/kguardian-dev/kguardian/commit/630f3acaf326b885eca2ec53ae7e8cfc3462b33e))
* **frontend:** treat a failed Service lookup as unattributed, not external ([a8a990d](https://github.com/kguardian-dev/kguardian/commit/a8a990d7438deb3a76f2397f12800bed197f9547))

## [1.20.5](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.4...frontend/v1.20.5) (2026-09-29)


### Bug Fixes

* **frontend:** back off the compute findings poll and retry a failed node read on the next tick ([49f39a9](https://github.com/kguardian-dev/kguardian/commit/49f39a933ad5b9e7e347d13aad63d657a4ccf80c))
* **frontend:** cap a namespace's per-pod reads and stop sending them once the Broker sheds ([2428c1d](https://github.com/kguardian-dev/kguardian/commit/2428c1d636b4ef147f810d2e842ef717ca1fa520))
* **frontend:** cover the network filter's unknown state and mark alt-less images in the assistant ([71bf3b3](https://github.com/kguardian-dev/kguardian/commit/71bf3b3b2ff31ea7a87c7d480722773129c75816))
* **frontend:** drop the previous lens's badges while a new lens or namespace loads ([6c2d00d](https://github.com/kguardian-dev/kguardian/commit/6c2d00d412c62350bce40519e69b5c6e78690d53))
* **frontend:** escape the whole peer address in the private-ip test's matcher ([a4b9b81](https://github.com/kguardian-dev/kguardian/commit/a4b9b81ade190199b1538af1c3fc354a056eadc1))
* **frontend:** fall back to default preferences when browser storage is blocked ([1f43d96](https://github.com/kguardian-dev/kguardian/commit/1f43d96b76d3d591e1b27d202fc24bf687e1b410))
* **frontend:** filter the workloads table by network policy, seccomp, drift and capture ([e982399](https://github.com/kguardian-dev/kguardian/commit/e982399b50a7e177d79d77d8e56c8943d242723b))
* **frontend:** fit the workloads table on a laptop screen ([85fa570](https://github.com/kguardian-dev/kguardian/commit/85fa570d8ae49d8316acc3ed18f16ce99374ba1c))
* **frontend:** generate network policies that match what the cluster will enforce ([8dfea63](https://github.com/kguardian-dev/kguardian/commit/8dfea6342ed47444565328cdf595622f441ac556))
* **frontend:** harden the assistant and the UI server, and make the workloads table usable ([8da9687](https://github.com/kguardian-dev/kguardian/commit/8da9687529f16d1f34e268bcb9f9976f31a7c70d))
* **frontend:** keep an empty selector when a peer's last label is removed ([d305177](https://github.com/kguardian-dev/kguardian/commit/d30517716fe347131d4d709f7517a85e06dfb61f))
* **frontend:** keep loaded findings when load more fails in the image drawer ([9a66b7c](https://github.com/kguardian-dev/kguardian/commit/9a66b7cff638558e9091396212cc128b2837b625))
* **frontend:** keep p0 and a consistent fix state when merging a cve's findings ([b10c704](https://github.com/kguardian-dev/kguardian/commit/b10c704ea8cb583ea29e215910bffeeae2e6cae8))
* **frontend:** keep proxy error pages out of profile and seccomp error messages ([990a05e](https://github.com/kguardian-dev/kguardian/commit/990a05e9aed06240365b9f6be1a7625736a92dfc))
* **frontend:** keep the map lens when selecting a card or leaving focus ([3d3f85b](https://github.com/kguardian-dev/kguardian/commit/3d3f85b6750c7cccde9de51133560fe745400962))
* **frontend:** keep the map when the Service listing fails, and say why reads are missing ([b7e312d](https://github.com/kguardian-dev/kguardian/commit/b7e312d45653df56ebc45f00cf3ba43c0da96047))
* **frontend:** leave rules with no peers out of the exported policy ([e669284](https://github.com/kguardian-dev/kguardian/commit/e66928456058e1f4ba53786046c752a3fbf06e42))
* **frontend:** measure a multi-replica card against every node its replicas run on ([314e0e4](https://github.com/kguardian-dev/kguardian/commit/314e0e4577819840f9355d5cb315cc431d301200))
* **frontend:** offer only what the seccompprofile crd accepts in the kguardian cr export ([695cddb](https://github.com/kguardian-dev/kguardian/commit/695cddb1badda989ac61e82406cee0e35141e455))
* **frontend:** read a multi-replica card's gauges from every replica ([72561da](https://github.com/kguardian-dev/kguardian/commit/72561da8de6d89f696500385c79bab91c6271ccd))
* **frontend:** read cve and digest url params the way the broker spells them ([7f45e0a](https://github.com/kguardian-dev/kguardian/commit/7f45e0ada6d89811c4cfb3acab1a5442462f269a))
* **frontend:** report a failed pod or service listing instead of an empty namespace ([8840973](https://github.com/kguardian-dev/kguardian/commit/88409731ed383ba635aa7b92c6a77d4d9acc67c5))
* **frontend:** restrict the server's host names, add security headers and narrow the llm-bridge proxy ([5d7bf0e](https://github.com/kguardian-dev/kguardian/commit/5d7bf0ec15c67f809cb50dda53e3d204893714d5))
* **frontend:** say a failed pod listing in the map header and the Policy Builder picker ([3096dae](https://github.com/kguardian-dev/kguardian/commit/3096dae8caef25583204151899a4d291b5874e9f))
* **frontend:** say on the map skeleton why a slow first load is taking so long ([a6ce85c](https://github.com/kguardian-dev/kguardian/commit/a6ce85c90c7fb156a223c8a2ec5a65482adf8a27))
* **frontend:** select service peers by the service's own selector ([eb05a3a](https://github.com/kguardian-dev/kguardian/commit/eb05a3aa9117d2d29e3560acbd240940156f9bdd))
* **frontend:** show broker failures as failures on the map, and fix multi-replica gauges ([ba13720](https://github.com/kguardian-dev/kguardian/commit/ba137209a14a26f1f4da986b045661110725d7b1))
* **frontend:** show the right tier and keep lists consistent on the images view ([32ec8a3](https://github.com/kguardian-dev/kguardian/commit/32ec8a3e78ccace0cafa8628f0d50a2877f8aeef))
* **frontend:** show the worst tier when an image carries a CVE in several packages ([845777f](https://github.com/kguardian-dev/kguardian/commit/845777f08476cb2f05a3a8e9e48a2ec3d43f812b))
* **frontend:** skip observed rows with no usable port when generating policies ([8411e5d](https://github.com/kguardian-dev/kguardian/commit/8411e5d2bb4d837ba34b119626772489a98316ac))
* **frontend:** stack the focus pill under the map toolbar so it cannot be covered ([d27aae1](https://github.com/kguardian-dev/kguardian/commit/d27aae1de83bd3456702e78c8a1dfc1e2d6009cc))
* **frontend:** stop calling the CVE table ranked by tier ([1dd8e80](https://github.com/kguardian-dev/kguardian/commit/1dd8e80c1f41507289b54f5bf34e990a83154ed5))
* **frontend:** stop EPSS labels rounding to 100%, 0% or a whole-percent threshold ([1977320](https://github.com/kguardian-dev/kguardian/commit/1977320747fe6b23169198839b8a8f48047f5985))
* **frontend:** stop exporting port 0 when a port field is cleared ([bc5bf76](https://github.com/kguardian-dev/kguardian/commit/bc5bf7645472ebff50bb4e0d49580e8f167266dd))
* **frontend:** stop labelling unresolved private and Internet peers as pods ([dc623b3](https://github.com/kguardian-dev/kguardian/commit/dc623b3ba68472cfd9ec51f0e384fe6777dfd198))
* **frontend:** stop load more from sticking or dropping a refresh on the images view ([4fba420](https://github.com/kguardian-dev/kguardian/commit/4fba420b6c6457e533bbb9ec84d0f90fee157f37))
* **frontend:** stop rebuilding the map's edges on a findings poll with the same answer ([af31747](https://github.com/kguardian-dev/kguardian/commit/af31747371d85bddfd272b74a2ba18524b530c34))
* **frontend:** stop rebuilding the map's traffic structures on every compute poll ([14a0d7a](https://github.com/kguardian-dev/kguardian/commit/14a0d7a01c0fba509cc0f665e0ff0312bc599641))
* **frontend:** stop the assistant loading images and keep its requests within the bridge's limits ([4379fbe](https://github.com/kguardian-dev/kguardian/commit/4379fbea677b1beba2d198052f4ce9b467d8b1e0))
* **frontend:** stop the cve drawer paging image findings after it closes or moves on ([b006c24](https://github.com/kguardian-dev/kguardian/commit/b006c24b2a88eea572d8facb6e2e1fc362108b51))
* **frontend:** stop the Risks view reading clean while pod or compute data is unknown ([3827f58](https://github.com/kguardian-dev/kguardian/commit/3827f58cadf54b648abf5058b410e2d64d94ef65))
* **frontend:** stop the workloads posture filter answering from stale or missing data ([fd2169b](https://github.com/kguardian-dev/kguardian/commit/fd2169b62a9595a5973f1011aa6afdd703d49065))
* **frontend:** time out seccomp reads and drop a previous workload's late profile ([05d3833](https://github.com/kguardian-dev/kguardian/commit/05d38338c3375464fd13aea2654b0585341a04dc))
* **frontend:** validate typed cidrs and clarify empty selectors and unknown service peers ([ac2168f](https://github.com/kguardian-dev/kguardian/commit/ac2168fa6f319f174b620dc4b687a20d757271d4))

## [1.20.4](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.3...frontend/v1.20.4) (2026-09-29)


### Bug Fixes

* **frontend:** label the policy builder's save button "Save Policy" for every format ([a8b627e](https://github.com/kguardian-dev/kguardian/commit/a8b627eb03154ddab1b2b62c03014b3b8b7d0c14))
* **frontend:** one save label for every policy format ([#1802](https://github.com/kguardian-dev/kguardian/issues/1802)) ([a8b627e](https://github.com/kguardian-dev/kguardian/commit/a8b627eb03154ddab1b2b62c03014b3b8b7d0c14))
* **frontend:** say when compute is unavailable in the workload panel ([#1801](https://github.com/kguardian-dev/kguardian/issues/1801)) ([5cd2a30](https://github.com/kguardian-dev/kguardian/commit/5cd2a304565ec3e1f82ad563c2aa65e4bb83c929))

## [1.20.3](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.2...frontend/v1.20.3) (2026-09-28)


### Bug Fixes

* **controller:** budget the pod loops and surface nodes that stop reporting pods ([43cbb55](https://github.com/kguardian-dev/kguardian/commit/43cbb55eda9c9a111464819924bf7d90c4284285))
* **frontend:** a namespace in an Images or Workloads link narrows to it ([#1790](https://github.com/kguardian-dev/kguardian/issues/1790)) ([79a3a35](https://github.com/kguardian-dev/kguardian/commit/79a3a35bafe8512f5612b45d0e42eb56be1db3d0))
* **frontend:** attribute gone stored peers to their workload and stop calling private addresses Internet ([#1771](https://github.com/kguardian-dev/kguardian/issues/1771)) ([de6e866](https://github.com/kguardian-dev/kguardian/commit/de6e866cae1910015055e3856def4ca2d3385090))
* **frontend:** broker timestamps as UTC; honest audit verdicts panel ([#1770](https://github.com/kguardian-dev/kguardian/issues/1770)) ([a2fcc9c](https://github.com/kguardian-dev/kguardian/commit/a2fcc9c8176c35c5a34b1147723c3d666e44ed97))
* **frontend:** hand focus to the textarea when a reply ends on the Stop button ([#1783](https://github.com/kguardian-dev/kguardian/issues/1783)) ([85c4ea8](https://github.com/kguardian-dev/kguardian/commit/85c4ea8d14ad09282dfce18012e7ddfb6d4d0590))
* **frontend:** honest workload views under slow or failing Broker reads ([#1775](https://github.com/kguardian-dev/kguardian/issues/1775)) ([bee7a65](https://github.com/kguardian-dev/kguardian/commit/bee7a65dcc9a1bf28ddbb5a40b2adae92eb03408))
* **frontend:** Images view counts, drawer state and admission policy reads ([#1776](https://github.com/kguardian-dev/kguardian/issues/1776)) ([51f42a1](https://github.com/kguardian-dev/kguardian/commit/51f42a12ea118c676ab9cc35bddb0a2b295f23af))
* **frontend:** make the Policy Builder honest about deny-all and selector-less Service peers ([#1773](https://github.com/kguardian-dev/kguardian/issues/1773)) ([381a74b](https://github.com/kguardian-dev/kguardian/commit/381a74b93a25e88c531bdcb9d78e5ae25c27a2c0))
* **frontend:** read the 503 body so a database timeout is not called a read-budget shed ([#1787](https://github.com/kguardian-dev/kguardian/issues/1787)) ([dde76df](https://github.com/kguardian-dev/kguardian/commit/dde76df59d599ec70c7fac4371077e51eb38ad1d))
* **frontend:** return focus from the docked assistant to what opened it ([#1784](https://github.com/kguardian-dev/kguardian/issues/1784)) ([6216669](https://github.com/kguardian-dev/kguardian/commit/6216669bfcb0ea463bcfdf41dfbac29f01946332))
* **frontend:** sequence pod-data runs and make the map honest about what it is not showing ([#1777](https://github.com/kguardian-dev/kguardian/issues/1777)) ([e7e2e42](https://github.com/kguardian-dev/kguardian/commit/e7e2e42b2fb7f480aa7455c0f616612e5495172e))
* **frontend:** show a banner when nodes stop reporting pods ([6d2c22e](https://github.com/kguardian-dev/kguardian/commit/6d2c22eb454f2cc0e5aae7d54cb3d876f893d762))
* **frontend:** topmost dialog owns Escape and Tab; dialog focus, names and accent contrast ([#1772](https://github.com/kguardian-dev/kguardian/issues/1772)) ([2f261a1](https://github.com/kguardian-dev/kguardian/commit/2f261a1432c88066ed0e4089049ca2ebebeb7429))
* **frontend:** type never-computed workload list items so every reader guards them ([#1786](https://github.com/kguardian-dev/kguardian/issues/1786)) ([6ad5c19](https://github.com/kguardian-dev/kguardian/commit/6ad5c19eb0d1345d52ff6e96c1d188c7082dbc9c))

## [1.20.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.1...frontend/v1.20.2) (2026-09-28)


### Bug Fixes

* **frontend:** read the namespace picker from /pod/namespaces instead of the whole pod listing ([3a6c3af](https://github.com/kguardian-dev/kguardian/commit/3a6c3aff54b2b07949ee7be4c3adea3ac201845e))
* serve the namespace picker without the whole pod listing and prune dead pods on their own window ([f5f5077](https://github.com/kguardian-dev/kguardian/commit/f5f507725b6ef7d9d5236ba93de7dc1736cdb780))

## [1.20.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.20.0...frontend/v1.20.1) (2026-09-27)


### Bug Fixes

* name the aarch64 seccomp architecture SCMP_ARCH_AARCH64 so arm64 pods can start ([#1742](https://github.com/kguardian-dev/kguardian/issues/1742)) ([acb1cbd](https://github.com/kguardian-dev/kguardian/commit/acb1cbda8068ede73f37a30acf13787fa2485e01))

## [1.20.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.19.0...frontend/v1.20.0) (2026-09-27)


### Features

* **frontend:** broker read token on an allowlisted /api proxy ([ce2f5f9](https://github.com/kguardian-dev/kguardian/commit/ce2f5f9937e45163b39e35041760b1fbfa7af0d8))
* **frontend:** capabilities and drift panels on the workload page, from runtime-backed captures ([713a76d](https://github.com/kguardian-dev/kguardian/commit/713a76d78c845766fadfacdd78b9a04adc45477b))
* **frontend:** image signature verdicts in Images, the workload page and the map, and admission policy export ([92b7ba3](https://github.com/kguardian-dev/kguardian/commit/92b7ba31727f250be57cc85a946f148d0a23364a))
* **frontend:** Images view, CVE triage drawer and map lenses ([6c753e2](https://github.com/kguardian-dev/kguardian/commit/6c753e2fc6bdc1f4229d59399c1ee9d318efb890))
* **frontend:** ImageTrustPolicy results on the workload page (contract v1.9) ([0966263](https://github.com/kguardian-dev/kguardian/commit/096626310ba9842a36694eb5747beb2e9949808c))
* **frontend:** label drift findings and show drift checks not evaluated ([6466c8c](https://github.com/kguardian-dev/kguardian/commit/6466c8c8fbd3871779e4e288761fe89aedceda7d))
* **frontend:** render the Broker's risk tiers instead of computing them ([3f382d4](https://github.com/kguardian-dev/kguardian/commit/3f382d4bad1e67a57f05fa43bb4d884f42418d79))
* **frontend:** runtime security foundations - Risks, Workloads coverage and severity palette ([#1654](https://github.com/kguardian-dev/kguardian/issues/1654)) ([264f873](https://github.com/kguardian-dev/kguardian/commit/264f8734623c7a619744b10287f3e11f5ef339e6))
* **frontend:** workload security profile page ([#1672](https://github.com/kguardian-dev/kguardian/issues/1672)) ([829eea3](https://github.com/kguardian-dev/kguardian/commit/829eea379170d8cc20a2f0196815309872885408))


### Bug Fixes

* **frontend:** call the no-lens option None so the map has one Traffic control ([5e0fdcd](https://github.com/kguardian-dev/kguardian/commit/5e0fdcda0f69f8043fb58b0361c1649576bbfc11))
* **frontend:** CVE drawer headline is the worst case over every workload ([cc5df19](https://github.com/kguardian-dev/kguardian/commit/cc5df1982b645e93dc8b291af4d8d092bcc09909))
* **frontend:** drift gaps tolerate a drift block without evaluated ([aeb1d76](https://github.com/kguardian-dev/kguardian/commit/aeb1d76bac8ecc4a7b0d69db9ad47508b96cf2db))
* **frontend:** drop the raw digest kind and use one No SBOM treatment ([1203cb3](https://github.com/kguardian-dev/kguardian/commit/1203cb38d3341f14ef36f234d282b772a79429d6))
* **frontend:** Esc from the page body closes only the topmost dialog ([#1688](https://github.com/kguardian-dev/kguardian/issues/1688)) ([f682560](https://github.com/kguardian-dev/kguardian/commit/f682560d9d3559ce06f2c8fe97a75a51c941496d))
* **frontend:** give the AI assistant dialog an accessible name ([7554926](https://github.com/kguardian-dev/kguardian/commit/75549262a3fae8a5cf9b865901de2af742a358f0))
* **frontend:** image trust counts must be safe integers ([d31e29c](https://github.com/kguardian-dev/kguardian/commit/d31e29c7a7fbb17c63c80ac62b202f891bddcc61))
* **frontend:** image trust counts that are not whole non-negative numbers read as unknown ([2c2d5f1](https://github.com/kguardian-dev/kguardian/commit/2c2d5f13f10fb66fbd7174f5678af84186ade1d9))
* **frontend:** image trust results the counts do not account for read as unknown ([670b175](https://github.com/kguardian-dev/kguardian/commit/670b1757e62787f48649a8176de5c2afbd5cbe30))
* **frontend:** keep focus on the rail toggle when the rail changes shape ([fb8d12c](https://github.com/kguardian-dev/kguardian/commit/fb8d12c4ee07303d3f55114a4e1131bda681552e))
* **frontend:** keep the page title readable when the rail or AI panel narrows the header ([8e7119d](https://github.com/kguardian-dev/kguardian/commit/8e7119df9974c55a08d26e3c18104368d9b5458b))
* **frontend:** keep the phone layout usable (rail overlay, map toolbar) ([#1684](https://github.com/kguardian-dev/kguardian/issues/1684)) ([2325251](https://github.com/kguardian-dev/kguardian/commit/232525134140266f752bcdbbb78049e4df18edff))
* **frontend:** map lens is a select below xl so it never covers the summary ([9ffe3d5](https://github.com/kguardian-dev/kguardian/commit/9ffe3d54332d4f4b2cda87cf12c869763cdfc1cc))
* **frontend:** map lens shows a failed or capped read as unknown, never as none ([b0aeab5](https://github.com/kguardian-dev/kguardian/commit/b0aeab5f8ebd483a1f7c0104f087e5d34c4210b6))
* **frontend:** mark a headline tier as a floor when rows are unknown, show in-flight rows as pending ([831fe86](https://github.com/kguardian-dev/kguardian/commit/831fe8609324158074a5e8347c7b08efabc6eb5c))
* **frontend:** name the command palette, audit verdicts and policy editor dialogs ([4a05d1c](https://github.com/kguardian-dev/kguardian/commit/4a05d1cddb28e13b09a9f487912d8985b22dd23d))
* **frontend:** no findings with drift checks not evaluated is not a clean bill ([b30bdbf](https://github.com/kguardian-dev/kguardian/commit/b30bdbf530d118b2e2b8f69c512adbfec1b204a6))
* **frontend:** older brokers' unevaluated drift checks are not shown as clean ([e6495e8](https://github.com/kguardian-dev/kguardian/commit/e6495e8de0f1d72eb18a6726fde44157e16e7a02))
* **frontend:** quieter unknown counts on tiles, keep package versions on one line ([0324b9d](https://github.com/kguardian-dev/kguardian/commit/0324b9dc15e4cdb4b9fa93abffe374ad7af5f35c))
* **frontend:** read the floor tier badge as 'at least', spell out a Background floor ([5bba482](https://github.com/kguardian-dev/kguardian/commit/5bba4826f06bc464e4e95ff9ba7c7e54121cacec))
* **frontend:** say where findings come from: Trivy Operator and the opt-in Grype matcher ([6a52c3a](https://github.com/kguardian-dev/kguardian/commit/6a52c3a75d36a151f8a8e1bcfc82890fb8ec69d2))
* **frontend:** settle each image read on its own so one failure does not blank the row ([b6cf191](https://github.com/kguardian-dev/kguardian/commit/b6cf19183304394e90936d34138c7c53fa01a78c))
* **frontend:** show KEV and EPSS as not reported, and count unknowns on the tiles ([b41df8e](https://github.com/kguardian-dev/kguardian/commit/b41df8e79fdb969c4b5f228f912c0ba6e579b50c))
* **frontend:** signature lens never falls back to the SBOM state, and verified needs a signer ([527cb17](https://github.com/kguardian-dev/kguardian/commit/527cb177e6788b49b38cfa27d179318ffa345324))
* **frontend:** size the map toolbar to the map, not the window ([663101d](https://github.com/kguardian-dev/kguardian/commit/663101d5cbaf2366529959326177cecc96c484ef))
* **frontend:** stack image and CVE columns on phones, honest unread tiles ([fcba3d5](https://github.com/kguardian-dev/kguardian/commit/fcba3d56d77281682ec8bb1c61a55ed9a8c0a41d))
* **frontend:** stack the image findings table on phones ([8b11f72](https://github.com/kguardian-dev/kguardian/commit/8b11f727e927a3bd19ec68f98f8d49e0c44facb9))
* **frontend:** stacked dialogs keep Tab inside and return focus to their opener ([#1693](https://github.com/kguardian-dev/kguardian/issues/1693)) ([9b7021c](https://github.com/kguardian-dev/kguardian/commit/9b7021ca175924bcc671e5f1b34f002b08c0e92e))
* **frontend:** take the CVE drawer headline from the first-listed workload ([d6dd4be](https://github.com/kguardian-dev/kguardian/commit/d6dd4be63a4f48436b7d206afb229e8eeb43f7aa))
* **frontend:** the supply chain chip reads the profile's supplyChain (contract v1.8) ([#1705](https://github.com/kguardian-dev/kguardian/issues/1705)) ([7dc403c](https://github.com/kguardian-dev/kguardian/commit/7dc403cc3e6f92092733aa517a55a59eb3241482))
* **frontend:** time out supply-chain reads after 15s with a retryable error ([b4b4d31](https://github.com/kguardian-dev/kguardian/commit/b4b4d31ea4faba101fb398b0f5a3d17a7d4d6381))
* **frontend:** time out workload profile reads after 15s instead of hanging ([7ef8dd7](https://github.com/kguardian-dev/kguardian/commit/7ef8dd7fab34ff1a17c416be2981f5b9396697d2))
* **frontend:** visible Background caveat, null tier read as not computed, current Ask AI in-use wording ([92e9546](https://github.com/kguardian-dev/kguardian/commit/92e9546e20dddb8f0b129cfc0c03dddf52fa95b1))

## [1.19.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.18.0...frontend/v1.19.0) (2026-09-16)


### Features

* **frontend:** selecting a card focuses it, and the panel opens shut ([#1590](https://github.com/kguardian-dev/kguardian/issues/1590)) ([975055c](https://github.com/kguardian-dev/kguardian/commit/975055cc408c91b862e33f5e751b6aa3915ad15c))
* **frontend:** show denied flows on the card, and keep the panel's three sections ([#1598](https://github.com/kguardian-dev/kguardian/issues/1598)) ([2b52b37](https://github.com/kguardian-dev/kguardian/commit/2b52b37e89ff7a0099ecf454ab8b499415fe0600))
* **frontend:** summarise each flow and tally the verdicts on the traffic table ([#1606](https://github.com/kguardian-dev/kguardian/issues/1606)) ([9f46f15](https://github.com/kguardian-dev/kguardian/commit/9f46f150997f3f1961cf3829155dbe2cd9197d9f))


### Bug Fixes

* **frontend:** fetch the pod inventory once per load, not once per caller ([#1604](https://github.com/kguardian-dev/kguardian/issues/1604)) ([90b8b8c](https://github.com/kguardian-dev/kguardian/commit/90b8b8c66ea148af944cb9c5aa4ea47c1d9694fa))
* **frontend:** focus draws only the focused card's own paths, and drops the denial badge ([#1601](https://github.com/kguardian-dev/kguardian/issues/1601)) ([7059d69](https://github.com/kguardian-dev/kguardian/commit/7059d6961b023b4e2c08d457def0e7190a53beac))
* **frontend:** make the policy builder's format tabs consistent and readable ([#1605](https://github.com/kguardian-dev/kguardian/issues/1605)) ([02961fd](https://github.com/kguardian-dev/kguardian/commit/02961fdd487c8d33ed89229805f00a9fc90f3e7f))

## [1.18.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.17.2...frontend/v1.18.0) (2026-09-14)


### Features

* **frontend:** selecting a card on the map opens it ([#1575](https://github.com/kguardian-dev/kguardian/issues/1575)) ([26eaad7](https://github.com/kguardian-dev/kguardian/commit/26eaad79d6ffab81bbc8c78fe2b87809692f0981))

## [1.17.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.17.1...frontend/v1.17.2) (2026-09-14)


### Bug Fixes

* **frontend:** seed node compute sparklines from stored history ([#1577](https://github.com/kguardian-dev/kguardian/issues/1577)) ([860dc16](https://github.com/kguardian-dev/kguardian/commit/860dc168907376201606633eea5e69d6b75b0caa))

## [1.17.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.17.0...frontend/v1.17.1) (2026-09-13)


### Bug Fixes

* **frontend:** decorate Service map nodes from the resolved backing pod, not an IP map ([#1569](https://github.com/kguardian-dev/kguardian/issues/1569)) ([39701f0](https://github.com/kguardian-dev/kguardian/commit/39701f0899d4cd0f1aac10b64cf745bcae6c414f)), closes [#1565](https://github.com/kguardian-dev/kguardian/issues/1565)

## [1.17.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.16.0...frontend/v1.17.0) (2026-09-11)


### Features

* live compute gauges and noisy-neighbour detection ([#1531](https://github.com/kguardian-dev/kguardian/issues/1531)) ([62959c2](https://github.com/kguardian-dev/kguardian/commit/62959c2be3d1fb71611c0ab77308a5d56af6ac91))

## [1.16.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.15.0...frontend/v1.16.0) (2026-09-08)


### ⚠ BREAKING CHANGES

* database.persistence.preUpgradeBackup now defaults to false. Installs relying on the pre-upgrade pg_dumpall will no longer get one. Set `database.persistence.preUpgradeBackup=true` to restore the previous behaviour, noting that the dump goes to container stdout and therefore into whatever aggregates pod logs.

### Features

* detect AWS VPC CNI and align the policy builder with what the cluster enforces ([#1478](https://github.com/kguardian-dev/kguardian/issues/1478)) ([231fe4a](https://github.com/kguardian-dev/kguardian/commit/231fe4a1b7196bdaa93b3429bc454d6c9c774f1d))


### Bug Fixes

* say why a connection was blocked instead of assuming a policy did it ([#1481](https://github.com/kguardian-dev/kguardian/issues/1481)) ([dbdb10c](https://github.com/kguardian-dev/kguardian/commit/dbdb10c212bbdb3219dc21dd0ab6f5fe1c84ccbf))
* stop losing observed flows, reject unusable seccomp profiles, and correct unsafe chart defaults ([#1503](https://github.com/kguardian-dev/kguardian/issues/1503)) ([4a504ef](https://github.com/kguardian-dev/kguardian/commit/4a504ef3f17b6344d504c6dcb4ffe46028477ffc))

## [1.15.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.14.0...frontend/v1.15.0) (2026-09-03)


### Features

* **frontend:** map toggle to hide DaemonSet and host-network peers by default ([#1439](https://github.com/kguardian-dev/kguardian/issues/1439)) ([774e665](https://github.com/kguardian-dev/kguardian/commit/774e665236201843e0548640ec9aa5d5727aa4dc))


### Bug Fixes

* resolve peer identity at ingest and guard by-IP attribution on pod start time ([#1447](https://github.com/kguardian-dev/kguardian/issues/1447)) ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))
* resolve peer identity at ingest and guard by-IP attribution on pod start time ([#1447](https://github.com/kguardian-dev/kguardian/issues/1447)) ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))


### Documentation

* peer-attribution concepts page, API reference, UPGRADING. ([fb6dfed](https://github.com/kguardian-dev/kguardian/commit/fb6dfed55a4be4990ba3f5358764ad3e50a0687b))

## [1.14.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.13.2...frontend/v1.14.0) (2026-09-03)


### Features

* align policy generation with the cluster CNI ([#1421](https://github.com/kguardian-dev/kguardian/issues/1421)) ([c0d9aa6](https://github.com/kguardian-dev/kguardian/commit/c0d9aa67a33c079387ae930d78a88fb130c64339))
* tiered syscall capture and CR-driven seccomp profile distribution ([2f0b513](https://github.com/kguardian-dev/kguardian/commit/2f0b5133e2921d36c182863dbdae2d7e1ef0c5d7))
* tiered syscall capture and CR-driven seccomp profile distribution ([#1427](https://github.com/kguardian-dev/kguardian/issues/1427)) ([2f0b513](https://github.com/kguardian-dev/kguardian/commit/2f0b5133e2921d36c182863dbdae2d7e1ef0c5d7))


### Bug Fixes

* Cilium policies carry the namespace label for cross-namespace peers ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))
* **frontend:** open the relevant policy tab from findings; make graph focus shareable via URL ([#1429](https://github.com/kguardian-dev/kguardian/issues/1429)) ([e35f1b1](https://github.com/kguardian-dev/kguardian/commit/e35f1b180f543840b3f39d7ed2d5c9d1bbd20bb6))
* record traffic to node IPs and render host-network peers correctly ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))
* record traffic to node IPs and render host-network peers correctly ([#1431](https://github.com/kguardian-dev/kguardian/issues/1431)) ([515de3d](https://github.com/kguardian-dev/kguardian/commit/515de3db9c9607ea2381fad0ab394cb732b169b0))

## [1.13.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.13.1...frontend/v1.13.2) (2026-09-02)


### Bug Fixes

* **frontend:** list syscalls in a consistent order everywhere ([#1407](https://github.com/kguardian-dev/kguardian/issues/1407)) ([25a3fdd](https://github.com/kguardian-dev/kguardian/commit/25a3fdd75879aa890f7f41297cbeafa52f6a0157))
* serve the frontend and broker on both IP families ([#1406](https://github.com/kguardian-dev/kguardian/issues/1406)) ([da56804](https://github.com/kguardian-dev/kguardian/commit/da568046cbd90e3f2f0ed37abb1495ce9d677e1a))

## [1.13.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.13.0...frontend/v1.13.1) (2026-09-01)


### Bug Fixes

* **frontend:** exit focus mode when the focused node disappears; keep the focus button on the card ([#1393](https://github.com/kguardian-dev/kguardian/issues/1393)) ([50ae021](https://github.com/kguardian-dev/kguardian/commit/50ae02196cba74c1d5db33b77fcb8ee58df0075c))

## [1.13.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.12.0...frontend/v1.13.0) (2026-09-01)


### Features

* capture IPv6 traffic and emit /128 peer rules ([#1370](https://github.com/kguardian-dev/kguardian/issues/1370)) ([c1bbf51](https://github.com/kguardian-dev/kguardian/commit/c1bbf51c0d9d8d2f8216081fbb7d6aa113541a5f))

## [1.12.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.11.4...frontend/v1.12.0) (2026-08-31)


### Features

* **frontend:** enterprise UI shell, design tokens, and shared primitives ([e0c88fb](https://github.com/kguardian-dev/kguardian/commit/e0c88fb195b778679e5f3068c4755d0eba710736))


### Bug Fixes

* **frontend:** drop the demo cluster; document SSO alongside the other chart options ([4d7136b](https://github.com/kguardian-dev/kguardian/commit/4d7136b636983dcf02e01d69753694425fb42e5a))

## [1.11.4](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.11.3...frontend/v1.11.4) (2026-08-12)


### Bug Fixes

* **deps:** patch vulnerable npm transitives in frontend + llm-bridge (security) ([#1265](https://github.com/kguardian-dev/kguardian/issues/1265)) ([f3a86e3](https://github.com/kguardian-dev/kguardian/commit/f3a86e3a8b910425712dfcf887de1118fec9216f))

## [1.11.3](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.11.2...frontend/v1.11.3) (2026-07-29)


### Bug Fixes

* **frontend:** seccomp arch guard parity + missing tool label ([cbff5ac](https://github.com/kguardian-dev/kguardian/commit/cbff5ac354141929ef8df234ebfb7ed5a224cac2))
* **frontend:** seccomp arch guard parity + missing tool label ([c889edf](https://github.com/kguardian-dev/kguardian/commit/c889edf57624e03bdfd1650dda8608384a527718))

## [1.11.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.11.1...frontend/v1.11.2) (2026-07-28)


### Code Refactoring

* **frontend:** single-source the AIAssistant chrome ([#1169](https://github.com/kguardian-dev/kguardian/issues/1169)) ([4be4d92](https://github.com/kguardian-dev/kguardian/commit/4be4d92797e29f322c8c807688df7c9933727413))

## [1.11.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.11.0...frontend/v1.11.1) (2026-07-19)


### Bug Fixes

* **deps:** update dependency elkjs to ^0.12.0 ([#1075](https://github.com/kguardian-dev/kguardian/issues/1075)) ([be9027a](https://github.com/kguardian-dev/kguardian/commit/be9027ae31a5a5ffa553c1589db3febdeff76faf))

## [1.11.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.10.0...frontend/v1.11.0) (2026-06-29)


### Features

* MCP/LLM integration uplift + data-path hardening ([572b31f](https://github.com/kguardian-dev/kguardian/commit/572b31fdcb470af9f6c844186fb9b8fa8cc8b83f))

## [1.10.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.9.0...frontend/v1.10.0) (2026-06-01)


### Features

* massive-uplift production hardening release ([#888](https://github.com/kguardian-dev/kguardian/issues/888)) ([176a160](https://github.com/kguardian-dev/kguardian/commit/176a160ae4f63baf46a6b5372a2b91040c28961f))


### Bug Fixes

* **controller:** one-shot warn instead of stderr-flood on ring-buffer receiver close ([846d04d](https://github.com/kguardian-dev/kguardian/commit/846d04db1cb509659d18bba0f614d4bd9bf9e5e9))

## [1.9.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.8.1...frontend/v1.9.0) (2026-05-07)


### Features

* **frontend,broker:** audit verdicts panel — Allow + WouldDeny preview ([#859](https://github.com/kguardian-dev/kguardian/issues/859)) ([f44cc17](https://github.com/kguardian-dev/kguardian/commit/f44cc17af83a1de9ebd2160776dc5569aebb8d31))


### Bug Fixes

* **deps:** update dependency lucide-react to v1 ([#779](https://github.com/kguardian-dev/kguardian/issues/779)) ([4b83f0f](https://github.com/kguardian-dev/kguardian/commit/4b83f0f0c93a9fa37b75ce7cb9a724bba25a50ca))

## [1.8.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.8.0...frontend/v1.8.1) (2026-03-07)


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.576.0 ([#728](https://github.com/kguardian-dev/kguardian/issues/728)) ([7c1722e](https://github.com/kguardian-dev/kguardian/commit/7c1722e8e960da6272e514eae2829463be9772a4))
* **deps:** update dependency lucide-react to ^0.577.0 ([#736](https://github.com/kguardian-dev/kguardian/issues/736)) ([089e140](https://github.com/kguardian-dev/kguardian/commit/089e140bed58d3c22de901bc92a8ec98e981ace5))
* **mcp-server,llm-bridge,frontend:** fix LLM/MCP integration data pipeline ([#684](https://github.com/kguardian-dev/kguardian/issues/684)) ([66b78c6](https://github.com/kguardian-dev/kguardian/commit/66b78c6c6f181ab3c3b99a797154bfc50b260604))

## [1.8.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.7.1...frontend/v1.8.0) (2026-03-01)


### Features

* **frontend:** Cilium network policy UI and release-please cleanup ([#717](https://github.com/kguardian-dev/kguardian/issues/717)) ([d475812](https://github.com/kguardian-dev/kguardian/commit/d4758122761f27c4c710a6e919a5aa0a9d19c8f7))


### Bug Fixes

* **ci:** fix release-please extra-files paths and sync VERSION files ([#692](https://github.com/kguardian-dev/kguardian/issues/692)) ([452bcad](https://github.com/kguardian-dev/kguardian/commit/452bcad0f8a13388f758569036e239bf3776036b))
* deduplicate service/pod traffic in graph and NetworkPolicy ([#687](https://github.com/kguardian-dev/kguardian/issues/687)) ([e4b8f81](https://github.com/kguardian-dev/kguardian/commit/e4b8f811f83cd3fc557061c835efc6cb2d95bb07))
* **frontend:** deduplicate service/pod traffic in graph and NetworkPolicy generator ([e4b8f81](https://github.com/kguardian-dev/kguardian/commit/e4b8f811f83cd3fc557061c835efc6cb2d95bb07))
* **ui:** correctly classify cross-namespace pods and deduplicate serv… ([#720](https://github.com/kguardian-dev/kguardian/issues/720)) ([966e06f](https://github.com/kguardian-dev/kguardian/commit/966e06fbb45d3653a336830ae59263297d45b886))
* **ui:** correctly classify cross-namespace pods and deduplicate service/pod traffic in graph ([966e06f](https://github.com/kguardian-dev/kguardian/commit/966e06fbb45d3653a336830ae59263297d45b886))

## [1.7.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.7.0...frontend/v1.7.1) (2026-02-22)


### Bug Fixes

* **frontend,llm-bridge,mcp-server:** remediate security, performance, and stability issues ([#670](https://github.com/kguardian-dev/kguardian/issues/670)) ([f319cc0](https://github.com/kguardian-dev/kguardian/commit/f319cc008a7134dc1b8382fbc8532696c5c8febe))

## [1.7.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.6.3...frontend/v1.7.0) (2026-02-18)


### Features

* **frontend:** pass namespace and pod context to AI assistant ([b41b5f6](https://github.com/kguardian-dev/kguardian/commit/b41b5f68b9000c28735a8d0815375c441ba4a777))
* **frontend:** render AI responses as markdown ([61cc613](https://github.com/kguardian-dev/kguardian/commit/61cc6136cd31c689707c4667a8ecb3884096c086))


### Bug Fixes

* **frontend:** resolve cross-namespace traffic incorrectly shown as external ([01ab0ea](https://github.com/kguardian-dev/kguardian/commit/01ab0ea9c3d8ec9763e786173b32b5f33f3a524b))

## [1.6.3](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.6.2...frontend/v1.6.3) (2026-02-17)


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.574.0 ([#624](https://github.com/kguardian-dev/kguardian/issues/624)) ([8f30554](https://github.com/kguardian-dev/kguardian/commit/8f30554fd509a9f3ff1b40e0128156f9d577e072))

## [1.6.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.6.1...frontend/v1.6.2) (2025-12-20)


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.560.0 ([4de1f43](https://github.com/kguardian-dev/kguardian/commit/4de1f431db881d3e5b36bfd0a2e165da6a88e688))
* **deps:** update dependency lucide-react to ^0.560.0 ([7fcd400](https://github.com/kguardian-dev/kguardian/commit/7fcd4006fc6a9c82281392b0b1f59e08b5133cff))
* **deps:** update dependency lucide-react to ^0.561.0 ([40b765d](https://github.com/kguardian-dev/kguardian/commit/40b765da6703f139817c923229c4a669a08fb449))
* **deps:** update dependency lucide-react to ^0.561.0 ([fc66333](https://github.com/kguardian-dev/kguardian/commit/fc663335426cf54bc70c9fa0839a3726b4f1cdd4))
* **deps:** update dependency lucide-react to ^0.562.0 ([72c326c](https://github.com/kguardian-dev/kguardian/commit/72c326c5d6c941f348f8ebc960a61fef90e29f59))
* **deps:** update dependency lucide-react to ^0.562.0 ([d21729c](https://github.com/kguardian-dev/kguardian/commit/d21729c73ad9a8d9acea85e5f004df70a7f3a97d))

## [1.6.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.6.0...frontend/v1.6.1) (2025-12-07)


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.556.0 ([2d92145](https://github.com/kguardian-dev/kguardian/commit/2d92145d55be6e0f30db20a02c021487d32c05a7))
* **deps:** update dependency lucide-react to ^0.556.0 ([db5469f](https://github.com/kguardian-dev/kguardian/commit/db5469fa3042ef0a77980157451b531c4fac3251))
* frontend label logic ([ffc3568](https://github.com/kguardian-dev/kguardian/commit/ffc356888beb93f255d485382ccb0b6aea427192))
* frontend label logic ([3b111d0](https://github.com/kguardian-dev/kguardian/commit/3b111d04d2993ccd6110e2e568d1616f5694831f))

## [1.6.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.5.0...frontend/v1.6.0) (2025-11-30)


### Features

* enable visual data loading sequence on identity changes when building policies ([8195bb7](https://github.com/kguardian-dev/kguardian/commit/8195bb7dea7a5476591a58e278f670ab9e843c27))


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.554.0 ([8576bbe](https://github.com/kguardian-dev/kguardian/commit/8576bbe91cc3c20751ff2286625ccbffd5e2bfe4))
* **deps:** update dependency lucide-react to ^0.554.0 ([d1a97e4](https://github.com/kguardian-dev/kguardian/commit/d1a97e476fa42a49ab01338fce7d727336d60600))
* **deps:** update dependency lucide-react to ^0.555.0 ([da35e5c](https://github.com/kguardian-dev/kguardian/commit/da35e5c46c8a970ce805a9332f1be31bf6b0bb55))
* **deps:** update dependency lucide-react to ^0.555.0 ([75c7843](https://github.com/kguardian-dev/kguardian/commit/75c7843eac0b3506798476dfc068aa650c751251))

## [1.5.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.4.0...frontend/v1.5.0) (2025-11-12)


### Features

* group by identity ([8160109](https://github.com/kguardian-dev/kguardian/commit/816010916a0027379c633bb6c15687929d1e8e59))


### Bug Fixes

* **deps:** update dependency lucide-react to ^0.553.0 ([19f53f5](https://github.com/kguardian-dev/kguardian/commit/19f53f5a8020dd80ef91ba4bc20775070181dc22))
* scaling namespaces and AI chat ([bd898e8](https://github.com/kguardian-dev/kguardian/commit/bd898e86527b1cd42fd8d1fdad0f26ea67a99df7))

## [1.4.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.3.0...frontend/v1.4.0) (2025-11-11)


### Features

* add decision column to Network Traffic table ([d6f5566](https://github.com/kguardian-dev/kguardian/commit/d6f556637e3f9f33e273ff7f9f89d2540eaf9f06))
* add filtering functionality to Network Traffic table ([c25829a](https://github.com/kguardian-dev/kguardian/commit/c25829a6cf7f1e9655248136837b321a922ceadd))
* normalise identity names in frontend ([1b5a168](https://github.com/kguardian-dev/kguardian/commit/1b5a168c7eed2518dfe95031107f0f6666ccec1f))
* normalise the names of identites ([48f3136](https://github.com/kguardian-dev/kguardian/commit/48f3136b480b799e912a0a95c14317ff24710ac6))

## [1.3.0](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.11...frontend/v1.3.0) (2025-11-06)


### Features

* add dock for ai assistant ([6a568eb](https://github.com/kguardian-dev/kguardian/commit/6a568eb0dd86911a9731f2564dd3d43c507945ae))
* add LLM + MCP ([0364874](https://github.com/kguardian-dev/kguardian/commit/03648744eabcf6005ff6a35cf761df608e239a81))
* add LLM + MCP integration ([a165a51](https://github.com/kguardian-dev/kguardian/commit/a165a5168ef91afe71bdb17e726baeb5df024511))


### Bug Fixes

* docker builds ([0a449c8](https://github.com/kguardian-dev/kguardian/commit/0a449c859b93e839333955bcb6dd574042eaedc1))

## [1.2.11](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.10...frontend/v1.2.11) (2025-11-03)


### Bug Fixes

* **deps:** update dependency @types/node to v24.10.0 ([4d0885c](https://github.com/kguardian-dev/kguardian/commit/4d0885cb8f6e0bec64cd3afc9bfb3367936eee95))

## [1.2.10](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.9...frontend/v1.2.10) (2025-11-01)


### Bug Fixes

* frontend lock ([a60b51c](https://github.com/kguardian-dev/kguardian/commit/a60b51c6527dbb88f67eca3082f34b89d6b3b32c))

## [1.2.9](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.8...frontend/v1.2.9) (2025-11-01)


### Bug Fixes

* frontend to use serve ([cbadc00](https://github.com/kguardian-dev/kguardian/commit/cbadc001092b0a86c5f986d44e2698f6e2c91939))

## [1.2.8](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.7...frontend/v1.2.8) (2025-11-01)


### Bug Fixes

* vite hosts ([283be54](https://github.com/kguardian-dev/kguardian/commit/283be548e716b13ce91856e5063d5d2b64942521))

## [1.2.7](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.6...frontend/v1.2.7) (2025-11-01)


### Bug Fixes

* update frontend to allow all hosts ([6a7d405](https://github.com/kguardian-dev/kguardian/commit/6a7d405ab3341e4a32bbe2846e6d367f2d3efa24))

## [1.2.6](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.5...frontend/v1.2.6) (2025-11-01)


### Bug Fixes

* update frontend ([b9bf89a](https://github.com/kguardian-dev/kguardian/commit/b9bf89a630d59da2675fc9cad477a2ff3db98123))

## [1.2.5](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.4...frontend/v1.2.5) (2025-11-01)


### Bug Fixes

* frontend dep ([8feef7b](https://github.com/kguardian-dev/kguardian/commit/8feef7b5742335ec53e81efb85a2be72f5a2d543))

## [1.2.4](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.3...frontend/v1.2.4) (2025-11-01)


### Bug Fixes

* chart and dockerfile ([4f3892b](https://github.com/kguardian-dev/kguardian/commit/4f3892b0b4f096606fa38f7c93443b05c301254f))
* chart and dockerfile ([7914448](https://github.com/kguardian-dev/kguardian/commit/7914448f4cbe14616e33337a05d7d0f9e36a6d53))

## [1.2.3](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.2...frontend/v1.2.3) (2025-11-01)


### Bug Fixes

* frontend builds and docs ([3db073c](https://github.com/kguardian-dev/kguardian/commit/3db073cc7ab39fb6a9f2fd8364c2e74e28a6bb5c))
* frontend builds and docs ([0441b2f](https://github.com/kguardian-dev/kguardian/commit/0441b2fcf76685c2f1ed319bf3f9845de0011d1b))

## [1.2.2](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.1...frontend/v1.2.2) (2025-11-01)


### Bug Fixes

* frontend using env ([f336ab8](https://github.com/kguardian-dev/kguardian/commit/f336ab8feaf2fea8582f0c2bf1525a64d94fb5c2))

## [1.2.1](https://github.com/kguardian-dev/kguardian/compare/frontend/v1.2.0...frontend/v1.2.1) (2025-11-01)


### Bug Fixes

* release please ([aaba02c](https://github.com/kguardian-dev/kguardian/commit/aaba02c9b292cb9130a23e2c9a5841f3692b4c06))
