# AlbionLocal client patcher

This `patcher` folder contains the standalone dynamic patcher scripts and the patch instruction.
Albion Online client files stay in the parent `AlbionLocal` folder.

The patcher does two things:

- redirects the built-in Albion login/status server addresses to `127.0.0.1:5055`;
- disables BattlEye startup by NOPing the game code that calls the BattlEye `Init` function.

An optional safety patch also jumps over the "Unable to call Init() for BattlEye" failure message.

## Quick start

Run this from the parent `AlbionLocal` folder:

```bat
patcher\patch_client.bat
```

Then start the game directly:

```bat
game\Albion-Online.exe
```

Do not use `Albion-Online_BE.exe`. The patcher keeps the original `GameAssembly.dll` unchanged until
`patch_client.bat` verifies a patched output, creates a timestamped backup, and replaces the original.

## What is patched

- six login/status endpoint string references in `GameAssembly.dll`;
- one BattlEye `Init` call site, replaced with five NOP bytes;
- one optional BattlEye failure-message load, replaced with `jmp +0x7b`.

The patch does not add files, does not change `global-metadata.dat`, and does not change the file size of `GameAssembly.dll`.

## Dynamic locator

The patcher is not hard-coded to one old client build. It locates patch sites from stable structures:

- reads `global-metadata.dat` v27+ string literals;
- finds matching encoded string-reference slots in `GameAssembly.dll` `.data`;
- finds the six rip-relative content-mov loads that reference the server strings;
- rewrites only those disp32 values to the in-client `127.0.0.1:5055` string object;
- finds the BattlEye `Init`-like function by a wildcarded x64 signature;
- NOPs the unique direct `E8` call to that function;
- optionally finds the unique content-mov that loads the BattlEye init failure string and replaces it with a jump.

If a future client build keeps the same IL2CPP metadata format and the same code shapes, the patcher can find
the new addresses by itself. If a required string or shape is missing/ambiguous, it prints an English error and
writes no output.

## Manual patch command

The batch file is the normal Windows entry point. For manual testing or a custom output path:

```bat
python patcher\patch_albion.py ^
  --dll game\GameAssembly.dll ^
  --metadata game\Albion-Online_Data\il2cpp_data\Metadata\global-metadata.dat ^
  --output work\GameAssembly.dll.new
```

Dry run:

```bat
python patcher\patch_albion.py --dry-run
```

Useful options:

- `--dll PATH`: input `GameAssembly.dll`;
- `--metadata PATH`: matching `global-metadata.dat`;
- `--output PATH`: output DLL, default is `<input>.new`;
- `--dry-run`: locate and report patches, do not write output;
- `--no-be`: do not patch BattlEye startup;
- `--no-insurance`: do not apply the optional failure-message jump;
- `--dev-string STRING`: replacement string, default `127.0.0.1:5055`;
- `--server-string STRING`: original server string to redirect, repeatable.

## Verified here

- Python patcher output for the old reference original equals the known golden patched DLL byte for byte.
- Python patcher on the current `1.32.040.346594` build finds six server redirects, BE call `0x18192650d`, and the
  optional insurance site `0x180b2d39f`.
- `python3 patcher/test_patcher.py` passes foreign-build rejection, `--dry-run`, and idempotency tests.
- `python3 patcher/test_patcher.py --include-golden` passes the old original vs golden comparison.

## Files

Paths below are relative to the parent `AlbionLocal` folder.

- `patcher\patch_albion.py` - main patcher, English output, Python 3 standard library only.
- `patcher\test_patcher.py` - tests, English output, Python 3 standard library only.
- `patcher\patch_client.bat` - Windows wrapper: verify, patch, backup, replace.
- `patcher\README.md` - English instruction for this patcher.
- `work\GameAssembly.dll.new` - ready patched DLL for the current build.
- `work\new\` - copies of the current `GameAssembly.dll` and metadata used for verification.
- `work\ref\` - copies of the old reference original, golden patched DLL, and metadata.

## Known limits

This was checked in Linux with file analysis and patch bytes, not by launching the game GUI here.
The real login/anti-cheat behavior must be checked on Windows by starting the patched client against the local
server on `127.0.0.1:5055`.
