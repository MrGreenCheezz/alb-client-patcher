# Albion Online local-server client patcher

[Русская версия: README.ru.md](README.ru.md)

The tool takes the **original** `GameAssembly.dll` of client build 1.32.030.345319 and produces a
file for a **local** server: login/status server addresses → `127.0.0.1:5055`, and the mandatory
BattlEye check is disabled. The input file is never modified — the result is written as a separate file.

Transparency: every edit lives in `manifest.json` (VA address, bytes BEFORE and AFTER, meaning, what
proves it); the patcher only verifies and applies them, and writes `patch_report.txt` after every run
with the full list of changes and the sha256 of input and output. The code does not invent patches:
if the bytes at an address do not match the manifest, it stops instead of "trying something else".
The tool prints its messages in Russian.

## Files

| File | What it is |
|---|---|
| `patch_albion.py` | the patcher itself: Python 3, standard library only (no pip packages) |
| `manifest.json` | description of all edits: addresses, bytes before/after, meaning, evidence, build sha256 |
| `patch_client.bat` | Windows double-click run: list of edits → patch → copy into the client folder with a backup |
| `tests/test_patcher.py` | 23 checks of the tool itself (run: `python -I tests/test_patcher.py`) |
| `out/GameAssembly.dll`, `out/patch_report.txt` | result and report of the last run (not meant to be committed) |

## Running it

Windows (from the `patcher` folder):

```
patch_client.bat                                  game\GameAssembly.dll -> out\ + copy into game-local\
patch_client.bat D:\path\GameAssembly.dll         patch only, copy nothing
patch_client.bat D:\path\GameAssembly.dll D:\client-folder   copy the result into another folder
```

Any OS, explicit form (exactly what the batch file does):

```
python patch_albion.py --list                     show every edit and exit (does not read the DLL at all)
python patch_albion.py                            patch ../game/GameAssembly.dll -> out/GameAssembly.dll
python patch_albion.py <input> -o <output>        explicit paths
python patch_albion.py --check-only               verification only: what would change, writes nothing
python patch_albion.py --group battleye           only one group of edits (id from the manifest)
python patch_albion.py -o <output> --copy-to <client-dir>    old client file -> .bak-<sha8>-<timestamp>
python patch_albion.py -o <output> --cmp-with <reference>    byte-compare the result with a reference file
python patch_albion.py --strict-sha               require the input to be exactly the original build
```

Exit codes: `0` success, `2` the file did not match (build/bytes), `3` path or argument error.

After patching, start the client with the plain `Albion-Online.exe` (not `Albion-Online_BE.exe`) from the
folder that received the patched `GameAssembly.dll`; the `BattlEye` folder does not have to be deleted.

## What exactly changes (8 sites, 34 bytes)

### Group `login_addr` — login and status servers → 127.0.0.1:5055

The method `dwu..cctor` (VA `0x1818D7BF0`) builds the list of live regions: the login server address is
loaded with `mov rdx,[rip+disp32]` and the status server address with `mov r9,[rip+disp32]`; both read the
8 bytes of a string-literal slot in `.data`. The patch changes **only the 4 displacement bytes** so that all
six loads read the slot of the string `127.0.0.1:5055` — the very slot this method already uses for the dev
environment, so no strings and no metadata are touched.

| Address (disp32) | Before | After | Region |
|---|---|---|---|
| `0x1818D8031` | `ebb84f03` | `339f4e03` | West: loginserver.live.albion.zone:5055 |
| `0x1818D80DC` | `784f4f03` | `889e4e03` | Europe: live03-loginserver.ams.albion.zone:5055 |
| `0x1818D8181` | `234c4f03` | `e39d4e03` | East: live02-loginserver.sg.albion.zone:5055 |
| `0x1818D8023` | `294c4f03` | `419f4e03` | West: live01-win-status.dc02.albion.zone:5055 |
| `0x1818D80CE` | `de504f03` | `969e4e03` | Europe: live03-win-status.ams.albion.zone:5055 |
| `0x1818D8173` | `894d4f03` | `f19d4e03` | East: live02-win-status.sg.albion.zone:5055 |

The destination slot `0x184DC1F68` holds the metadata-encoded reference `0xa000151b` to the literal
`127.0.0.1:5055` (the string lives at `global-metadata.dat:0x36eb4`); the patcher checks this value first.

### Group `battleye` — the mandatory BattlEye check

At startup the client calls `ci7.bo(platform)`, which brings BattlEye up (`cix.Init` → LoadLibrary
`BEClient_x64` → the `Init` export); on failure it logs "Unable to call Init() for BattlEye" and prepares
the "Disconnected by BattlEye" message. Patch 1 disables the call itself; patch 2 is the safety net for the
second path — the failure branch jumps straight to the method epilogue, skipping the log and the message.
All other BattlEye code skips itself when the BE interface was never loaded (`dhb.c() == false`), which was
verified by disassembly earlier in this project.

| Address | Before | After | Meaning |
|---|---|---|---|
| `0x1819091ED` | `e8befa06ff` (`call ci7.bo`) | `9090909090` | the startup call that loads BattlEye is skipped entirely |
| `0x180B291DF` | `488b0dd20a` | `e97b000000` (`jmp 0x180B2925F`) | "Init failed" branch → straight to the `dhb.b(string)` epilogue |

## How the patcher makes sure the edits landed in the right places

1. It reads the PE headers: PE32+, image base `0x180000000`; the address → file offset mapping comes from the section table.
2. It compares the input sha256 with the original build recorded in the manifest (mismatch = warning and continuation:
   the per-site byte checks are stricter; to make it a stop, use `--strict-sha`).
3. It checks the precondition: slot `0x184DC1F68` contains `0xa000151b`.
4. For every site: the "before" bytes or the "already patched" bytes, plus semantics (that the `call` really targets
   `ci7.bo` at `0x180978CB0`, that the `jmp` after the patch lands on the epilogue `0x180B2925F`, that each disp32 points
   exactly at the declared slot). On any mismatch it stops, names the address and the expected bytes, and writes no output file.
5. Finally: the output sha256 is compared with the manifest reference `985c105a…` — that is exactly the build on which this
   patch was already verified by running the game (see the project journal `../WORKLOG.md`: the client sent status requests
   to 127.0.0.1:5055).

The tests (`python -I tests/test_patcher.py`) verify: the result is byte-identical to the reference
`../work/GameAssembly.dll`; running it again changes nothing; an intermediate state (`login_addr` first, then
`battleye`) reaches the same reference; a flipped byte stops with no file written; `--check-only` writes nothing;
`--copy-to` backs up the old file; and the sha256 values declared in the manifest match the real files.

## Your own server address, your own build, a new patch

- **A different address instead of `127.0.0.1:5055`:** in the manifest, for the six `login_addr` sites set `new_target` to the
  slot of the string you want and `after` to the little-endian encoding of `new_target - (address + 4)` (the patcher recomputes
  and re-checks it). Keeping `127.0.0.1` and forwarding the port on your own machine is simpler.
- **A different client build:** the patcher stops at the first byte mismatch. Collect the new addresses (decompile `dwu..cctor`
  and `dhb.b`/`ci7.bo`; scripts in `../analysis/tools/`) and write them into the manifest — no code changes needed.
- **A new edit:** add a `{va, before, after, note}` object to `sites` in any group; add `verify` if you want the patcher to check
  semantics as well (opcode / call target / jmp target).

## Notes

- The PE checksum is not recomputed (Windows does not verify it for ordinary DLLs; the previously working address patcher
  behaved the same way). If your launcher ever complains about the checksum, ask and I will add a recomputation.
- The patch changes only the managed code inside `GameAssembly.dll`; `Albion-Online_BE.exe`, the `BattlEye` folder and the
  metadata are untouched.
- A client with BattlEye disabled is meant for a **local** server. Do not log into the official servers with it: the servers
  require BattlEye themselves, which is a question of the game's rules, not of the patch's quality.
- The patched `GameAssembly.dll` is Sandbox Interactive's file, not mine: redistributing it is their right. This repository
  holds only my own code and the byte-level notes about it.
