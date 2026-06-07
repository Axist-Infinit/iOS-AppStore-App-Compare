# On-device decryption runbook (opt-in)

This is the **opt-in** tier of the kit. Everything else compares metadata and
package structure and never touches encrypted code. This tier captures a
**decrypted copy of the App Store binary** so the *shipped* code surface can be
compared against a source build — using a device you own.

## Why this is needed and what it is

App Store executables are FairPlay-encrypted at rest (`cryptid 1`) and decrypted
in memory by iOS at launch. The standard security-research way to analyze the
shipped binary is to dump that already-decrypted image off a device you control
(OWASP MASTG methodology). This kit **orchestrates a standard open-source dumper**
(`bagbak` or `frida-ios-dump`); it adds no decryption, signing, or protection-
bypass logic of its own.

## Boundary

Do this only with all of the following true:

- a **jailbroken iOS device you own**,
- an **Apple ID you control**,
- an **app you lawfully downloaded**,
- analysis you are **authorized** to perform.

Do **not** redistribute decrypted binaries or any protected App Store code. This
runbook intentionally does **not** cover code-signing bypass, DRM circumvention,
or protected-executable recovery for redistribution — none of that is required to
reverse-engineer Signal, and it is out of scope for this kit.

## Prerequisites

- A dumper on the host: `npm i -g bagbak`, or the
  [frida-ios-dump](https://github.com/AloneMonkey/frida-ios-dump) fork.
- `frida` on the host and `frida-server` running on the device, reachable over USB.
- Signal installed on the device from the App Store.

## Steps

```bash
# 1. Dump the decrypted app (refuses to run without the ownership flag).
./scripts/decrypt_on_device.sh --i-own-this-device --bundle org.whispersystems.signal

# -> writes artifacts/decrypted/Signal-decrypted.ipa and verifies cryptid == 0
#    using the kit's own scripts/macho.py reader.
```

```bash
# 2. Compare the decrypted App Store binary against a matching source build.
#    Add it to a config as a distinct role, e.g.:
```

```json
{
  "project": "Signal decrypted vs source",
  "hash_mode": "notable",
  "reference": {
    "id": "signal_appstore_decrypted",
    "role": "appstore_decrypted",
    "path": "artifacts/decrypted/Signal-decrypted.ipa"
  },
  "artifacts": [
    {
      "id": "signal_local_8_13_0_1623",
      "role": "local_release_tag_exact",
      "path": "artifacts/local/Signal-8.13.0.1623.xcarchive",
      "expected_git_ref": "8.13.0.1623"
    }
  ]
}
```

```bash
python3 scripts/ios_multiversion_meta_compare.py --config config.decrypted.json --out out/decrypted
```

Because the dumped binary is unencrypted (`cryptid 0`), its linked libraries,
load commands, and (in a later phase) symbol/Obj-C/Swift class surface become
directly comparable to the source build — the real "does the shipped binary
correspond to published source?" question.

## Optional: observational runtime inspection

`scripts/frida/enumerate_modules.js` lists loaded modules and a sample of
app-specific Objective-C classes at runtime. It is read-only — it hooks and
patches nothing — and is useful to correlate the running build with the static
metadata.

```bash
frida -U -f org.whispersystems.signal -l scripts/frida/enumerate_modules.js --no-pause
```
