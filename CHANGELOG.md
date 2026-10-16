# Changelog

## 1.0.0

Policy updated 2026-10-15.

- Mod package check (`-run=ModGate -Package=...` or Tools > ModGate). It reads folders, `.pak`, IoStore `.utoc`/`.ucas`, `.zip` and package files without loading them.
- Rules M1–M11: Blueprint script, dangerous engine functions (matched by import hash), native code, script files, command text, config files, file-type allow list, fail-closed inspection, unnamed native references, shader code and game classes used.
- Two profiles: `data-only` (default) and `blueprint-mods` (harm reduction).
- Project audit (`-Audit`): checks the `LaunchURL` allow-list against the engine's own filter, lists dangerous functions that Blueprints can reach, and lists project functions to review. `-Fix` writes `[SystemLibrary.LaunchURLFilter https]` after a backup.
- JSON and HTML reports, written atomically. Exit codes: 0 clean, 1 warnings, 2 blocked, 3 input error.
- Editor menu scans run in a separate process.
- Integrity checks: every container entry is verified against its stored hash (IoStore BLAKE3, pak SHA-1, zip CRC-32), so damaged downloads fail closed. IoStore containers are read by ModGate's own bounds-checked reader.
- Policy file `Resources/ModGatePolicy.json`; `-Policy=` and `-Profile=` take your own.
