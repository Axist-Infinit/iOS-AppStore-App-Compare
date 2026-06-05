# Prompt for Codex CLI: triage failed Signal-iOS release builds

Read `CODEX_CONTEXT.md` and `out/build_logs/build_status.csv`.

Task:

1. Identify which Signal-iOS tags failed to build.
2. Group failures by cause: dependency bootstrap, Xcode version, signing/team config, workspace/scheme changes, submodule failure, Swift/package/cocoapods issue, or project layout change.
3. Do not modify the main comparison script unless necessary.
4. Add small compatibility patches/wrappers to the build script where possible.
5. Keep a reduced config containing only successfully built archives.
6. Prioritize the App Store matching release and nearby releases before older historical versions.

Output expected:

- `out/build_logs/build_failure_triage.md`
- `config.signal_releases_existing.json`
- Any safe build-script patches needed to improve success rate.

Do not add any FairPlay decryption, DRM bypass, jailbreak dumping, or third-party app binary dumping logic.
