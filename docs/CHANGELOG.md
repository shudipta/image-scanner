---
title: Changelog | Scanner
description: Changelog
menu:
  product_scanner_0.1.0:
    identifier: changelog-scanner
    name: Changelog
    parent: welcome
    weight: 10
product_name: scanner
menu_name: product_scanner_0.1.0
section_menu_id: welcome
url: /products/scanner/0.1.0/welcome/changelog/
aliases:
  - /products/scanner/0.1.0/CHANGELOG/
---

# Change Log

## [Unreleased](https://github.com/soter/scanner/tree/HEAD)

**Fixed bugs:**

- Fix clair installation instructions [\#13](https://github.com/soter/scanner/pull/13) ([tamalsaha](https://github.com/tamalsaha))

**Closed issues:**

- Handle Docker registry credentials properly [\#29](https://github.com/soter/scanner/issues/29)
- Perform as a Image review process [\#8](https://github.com/soter/scanner/issues/8)
- Add WorkloadReview api [\#5](https://github.com/soter/scanner/issues/5)

**Merged pull requests:**

- Add installer flag for --postgres-storage-class [\#46](https://github.com/soter/scanner/pull/46) ([tamalsaha](https://github.com/tamalsaha))
- Bring parity between chart and installer script [\#45](https://github.com/soter/scanner/pull/45) ([tamalsaha](https://github.com/tamalsaha))
- Fix installer [\#44](https://github.com/soter/scanner/pull/44) ([tamalsaha](https://github.com/tamalsaha))
- Update pkg path to appscode/scanner [\#42](https://github.com/soter/scanner/pull/42) ([tamalsaha](https://github.com/tamalsaha))
- Use separate endpoint per workload kind [\#41](https://github.com/soter/scanner/pull/41) ([tamalsaha](https://github.com/tamalsaha))
- Update Vulnerabilities api [\#40](https://github.com/soter/scanner/pull/40) ([tamalsaha](https://github.com/tamalsaha))
- Apply failure policy ignore [\#39](https://github.com/soter/scanner/pull/39) ([tamalsaha](https://github.com/tamalsaha))
- Use workload list method [\#38](https://github.com/soter/scanner/pull/38) ([tamalsaha](https://github.com/tamalsaha))
- Move main files to root pkg [\#37](https://github.com/soter/scanner/pull/37) ([tamalsaha](https://github.com/tamalsaha))
- Creater and Geter for Image Review api [\#36](https://github.com/soter/scanner/pull/36) ([shudipta](https://github.com/shudipta))
- Merge clair packgaes into one [\#35](https://github.com/soter/scanner/pull/35) ([tamalsaha](https://github.com/tamalsaha))
- Fix installer [\#34](https://github.com/soter/scanner/pull/34) ([tamalsaha](https://github.com/tamalsaha))
- Update docs for clair setup [\#33](https://github.com/soter/scanner/pull/33) ([shudipta](https://github.com/shudipta))
- Secure clair with tls [\#32](https://github.com/soter/scanner/pull/32) ([shudipta](https://github.com/shudipta))
- Tests are added [\#30](https://github.com/soter/scanner/pull/30) ([shudipta](https://github.com/shudipta))
- Refactor scanner [\#27](https://github.com/soter/scanner/pull/27) ([tamalsaha](https://github.com/tamalsaha))
- Rename api group to soter.ac [\#26](https://github.com/soter/scanner/pull/26) ([tamalsaha](https://github.com/tamalsaha))
- Enable swagger paths for server [\#25](https://github.com/soter/scanner/pull/25) ([tamalsaha](https://github.com/tamalsaha))
- Fix apiservice for scanner [\#24](https://github.com/soter/scanner/pull/24) ([tamalsaha](https://github.com/tamalsaha))
- Api v3 for clair [\#23](https://github.com/soter/scanner/pull/23) ([shudipta](https://github.com/shudipta))
- Remove cache reference [\#22](https://github.com/soter/scanner/pull/22) ([tamalsaha](https://github.com/tamalsaha))
- Remove --rbac flag [\#21](https://github.com/soter/scanner/pull/21) ([tamalsaha](https://github.com/tamalsaha))
- Increase qps and burst limits [\#20](https://github.com/soter/scanner/pull/20) ([tamalsaha](https://github.com/tamalsaha))
- Expose metrics via apiserver handler [\#19](https://github.com/soter/scanner/pull/19) ([tamalsaha](https://github.com/tamalsaha))
- Removal used lru-cache for features and vulnerablilities [\#18](https://github.com/soter/scanner/pull/18) ([shudipta](https://github.com/shudipta))
- Update chart repository location [\#17](https://github.com/soter/scanner/pull/17) ([tamalsaha](https://github.com/tamalsaha))
- Change script location to master [\#16](https://github.com/soter/scanner/pull/16) ([tamalsaha](https://github.com/tamalsaha))
- Run go fmt [\#15](https://github.com/soter/scanner/pull/15) ([tamalsaha](https://github.com/tamalsaha))
- Change image name parsing part and added test for creating CronJob [\#14](https://github.com/soter/scanner/pull/14) ([shudipta](https://github.com/shudipta))
- Add chart [\#12](https://github.com/soter/scanner/pull/12) ([tamalsaha](https://github.com/tamalsaha))
- Generate swagger.json [\#11](https://github.com/soter/scanner/pull/11) ([tamalsaha](https://github.com/tamalsaha))
- Add WorkloadReview api [\#10](https://github.com/soter/scanner/pull/10) ([tamalsaha](https://github.com/tamalsaha))
- Running Clair in Minikube [\#9](https://github.com/soter/scanner/pull/9) ([shudipta](https://github.com/shudipta))
- Add WorkloadReview api [\#7](https://github.com/soter/scanner/pull/7) ([tamalsaha](https://github.com/tamalsaha))
- Pre-Cache for each workload those are already running [\#6](https://github.com/soter/scanner/pull/6) ([shudipta](https://github.com/shudipta))
- Rename --analytics to --enable-analytics [\#4](https://github.com/soter/scanner/pull/4) ([tamalsaha](https://github.com/tamalsaha))
- Scan Image for Vulnerabilities [\#3](https://github.com/soter/scanner/pull/3) ([shudipta](https://github.com/shudipta))
- Fix docker build script [\#2](https://github.com/soter/scanner/pull/2) ([tamalsaha](https://github.com/tamalsaha))
- Add project skeleton [\#1](https://github.com/soter/scanner/pull/1) ([tamalsaha](https://github.com/tamalsaha))



\* *This Change Log was automatically generated by [github_changelog_generator](https://github.com/skywinder/Github-Changelog-Generator)*