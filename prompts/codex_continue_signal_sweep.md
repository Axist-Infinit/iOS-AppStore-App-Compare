# Prompt for Codex CLI: continue Signal iOS release metadata sweep

You are working in the `signal_ios_metadata_lab` directory. Read `CODEX_CONTEXT.md`, `QUICKSTART.md`, `config.example.json`, and `scripts/ios_multiversion_meta_compare.py` first.

Task:

1. Use `scripts/harvest_signal_ios_releases.py` to create a large release matrix from `signalapp/Signal-iOS` GitHub releases.
2. Generate a config that compares my captured `artifacts/appstore/Signal-AppStore.ipa` against local archives at `artifacts/local/Signal-<tag>.xcarchive`.
3. Help me build or ingest as many local Signal-iOS release archives as possible.
4. Run `scripts/ios_multiversion_meta_compare.py` and improve the report if needed.
5. Preserve the no-FairPlay-decryption boundary. This workflow is for metadata/package comparison, not DRM circumvention.

Preferred commands:

```bash
python3 scripts/harvest_signal_ios_releases.py --limit 80 --out matrices --config-out config.signal_releases_80.json
bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
python3 scripts/ios_multiversion_meta_compare.py --config config.signal_releases_80.json --out out/signal_release_sweep_80
```

When something fails:

- Do not discard the whole sweep.
- Record failed tags in `out/build_logs/build_status.csv`.
- Continue to the next tag.
- Generate a reduced config using only archives that exist.
- Prioritize fixing the exact App Store matching release first, then adjacent releases, then older releases.
